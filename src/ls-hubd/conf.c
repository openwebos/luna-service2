/* @@@LICENSE
*
*      Copyright (c) 2008-2014 LG Electronics, Inc.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* LICENSE@@@ */

#include <sys/types.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#else
#define HAVE_SYS_INOTIFY_H
#endif

#ifdef HAVE_SYS_INOTIFY_H
#include <sys/inotify.h>
#define INOTIFY_MASK    (IN_MODIFY | IN_CREATE | IN_DELETE | IN_MOVE)
#endif

#include "hub.h"
#include "error.h"
#include "transport_utils.h"
#include "conf.h"
#include "security.h"
#include "watchdog.h"

#define PIPE_READ_END   0
#define PIPE_WRITE_END  1

#define MAX_KEYS_IN_GROUP   15
#define MAX_GROUPS          10

/**
 * Default values for the two special "exePath" values recognized for JS services and mojo apps
 */
#define DEFAULT_TRITON_SERVICE_EXE_PATH     "js"
#define DEFAULT_MOJO_APP_EXE_PATH           "mojo-app"

typedef bool (_ConfigKeyUser)(const void *value, void *ctxt, LSError *lserror);

typedef bool (_ConfigKeyGetValue)(GKeyFile *key_file, const char *group_name,
                                    const char *key, _ConfigKeyUser *user, void *ctxt, LSError *lserror);

/**
 * Represents a "key" in a "keyfile"
 */
typedef struct _ConfigKey {
    const char *key;                    /**< key name */
    _ConfigKeyGetValue *get_value;      /**< function to get a value with this key name */
    _ConfigKeyUser *user_cb;            /**< user callback called with data from "get_value" callback */
    void *user_ctxt;                    /**< context passed to user callback */
} _ConfigKey;

/**
 * Represents a "group" in a "keyfile"
 */
typedef struct _ConfigGroup {
    const char *group_name;             /**< group name */
    _ConfigKey keys[MAX_KEYS_IN_GROUP]; /**< set of keys in the group */
} _ConfigGroup;

/**
 * Represents a complete "keyfile"
 */
typedef struct _ConfigDOM {
    _ConfigGroup groups[MAX_GROUPS];    /**< all groups in file */
} _ConfigDOM;

bool
_ConfigKeyGetStringList(GKeyFile *key_file, const char *group_name,
                        const char *key, _ConfigKeyUser *user, void *ctxt, LSError *lserror);
bool
_ConfigKeyGetInt(GKeyFile *key_file, const char *group_name,
                 const char *key, _ConfigKeyUser *user, void *ctxt, LSError *lserror);
bool
_ConfigKeySetInt(const int *value, int *conf_var, LSError *lserror);
bool
_ConfigKeyGetBool(GKeyFile *key_file, const char *group_name,
                  const char *key, _ConfigKeyUser *user, void *ctxt, LSError *lserror);
bool
_ConfigKeySetBool(const bool *value, bool *conf_var, LSError *lserror);
bool
_ConfigKeyGetString(GKeyFile *key_file, const char *group_name,
                    const char *key, _ConfigKeyUser *user, void *ctxt, LSError *lserror);
bool
_ConfigKeySetString(const char *value, const char **conf_var, LSError *lserror);

static bool
_ConfigKeyProcessDynamicServiceExecPrefix(char *value, const char **conf_var, LSError *lserror);
static bool
_ConfigKeyProcessWatchdogFailureMode(char *mode_str, LSHubWatchdogFailureMode *conf_var, LSError *lserror);
static bool
_ConfigParseFile(const char *path, const _ConfigDOM *dom, LSError *lserror);

void _ConfigFreeSettings(void);

/**
 * Keyfile format:
 *
 * [General]
 * LocalSocketDirectory=/path/to/some/dir
 * PidDirectory=/path/to/some/dir
 * LogServiceStatus=false
 * ConnectTimeout=time_ms
 *
 * [Watchdog]
 * Timeout=time_sec
 * FailureMode=crash (or rdx or noop)
 *
 * [Dynamic Services]
 * Directories=/path/to/some/dir;/another/path/to/some
 * ExecPrefix=/path/to/some/bin
 * LaunchTimeout=time_ms
 *
 * [Security]
 * Enabled=bool
 * Directories=/path/to/some/dir;/another/path/to/some/dir
 * SysMgrExePath=/path/to/LunaSysMgr
 * WebAppMgrExePath=/path/to/WebAppMgr
 * WebAppMgr2ExePath=/path/to/QtWebProcess // used by WAM2
 * JsServiceExePath=js
 * MojoAppExePath=mojo-app
 * MojoAppsAllowAllOutboundByDefault=bool
 * AllowNullOutboundByDefault=bool
 */
static _ConfigDOM conf_file_dom = {
    .groups = {
        {
            .group_name = "General",
            .keys = {
                {
                    .key = "LocalSocketDirectory",
                    .get_value = _ConfigKeyGetString,
                    .user_cb = (_ConfigKeyUser*)_ConfigKeySetString,
                    .user_ctxt = &g_conf_local_socket_path,
                },
                {
                    .key = "PidDirectory",
                    .get_value = _ConfigKeyGetString,
                    .user_cb = (_ConfigKeyUser*)_ConfigKeySetString,
                    .user_ctxt = &g_conf_pid_dir,
                },
                {
                    .key = "LogServiceStatus",
                    .get_value = _ConfigKeyGetBool,
                    .user_cb = (_ConfigKeyUser*)_ConfigKeySetBool,
                    .user_ctxt = &g_conf_log_service_status,
                },
                {
                    .key = "ConnectTimeout",
                    .get_value = _ConfigKeyGetInt,
                    .user_cb = (_ConfigKeyUser*)_ConfigKeySetInt,
                    .user_ctxt = &g_conf_connect_timeout_ms,
                },
                { NULL }
            }
        },
        {
            .group_name = "Watchdog",
            .keys = {
                {
                    .key = "Timeout",
                    .get_value = _ConfigKeyGetInt,
                    .user_cb = (_ConfigKeyUser*)_ConfigKeySetInt,
                    .user_ctxt = &g_conf_watchdog_timeout_sec,
                },
                {
                    .key = "FailureMode",
                    .get_value = _ConfigKeyGetString,
                    .user_cb = (_ConfigKeyUser*)_ConfigKeyProcessWatchdogFailureMode,
                    .user_ctxt = &g_conf_watchdog_failure_mode,
                },
                { NULL }
            }
        },
        {
            .group_name = "Dynamic Services",
            .keys = {
                {
                    .key = "ExecPrefix",
                    .get_value = _ConfigKeyGetString,
                    .user_cb = (_ConfigKeyUser*)_ConfigKeyProcessDynamicServiceExecPrefix,
                    .user_ctxt = &g_conf_dynamic_service_exec_prefix,
                },
                {
                    .key = "Directories",
                    .get_value = _ConfigKeyGetStringList,
                    .user_cb = (_ConfigKeyUser*)ConfigKeyProcessDynamicServiceDirs,
                    .user_ctxt = GINT_TO_POINTER(STEADY_DIRS),
                },
                {
                    .key = "VolatileDirectories",
                    .get_value = _ConfigKeyGetStringList,
                    .user_cb = (_ConfigKeyUser*)ConfigKeyProcessDynamicServiceDirs,
                    .user_ctxt = GINT_TO_POINTER(VOLATILE_DIRS),
                },
                {
                    .key = "LaunchTimeout",
                    .get_value = _ConfigKeyGetInt,
                    .user_cb = (_ConfigKeyUser*)_ConfigKeySetInt,
                    .user_ctxt = &g_conf_query_name_timeout_ms,
                },
                { NULL }
            }
        },
        {
            .group_name = "Security",
            .keys = {
                {
                    .key = "Enabled",
                    .get_value = _ConfigKeyGetBool,
                    .user_cb = (_ConfigKeyUser*)_ConfigKeySetBool,
                    .user_ctxt = &g_conf_security_enabled,
                },
                {
                    .key = "MonitorExePath",
                    .get_value = _ConfigKeyGetString,
                    .user_cb = (_ConfigKeyUser*) _ConfigKeySetString,
                    .user_ctxt = &g_conf_monitor_exe_path,
                },
                {
                    .key = "MonitorPubExePath",
                    .get_value = _ConfigKeyGetString,
                    .user_cb = (_ConfigKeyUser*) _ConfigKeySetString,
                    .user_ctxt = &g_conf_monitor_pub_exe_path,
                },
                {
                    .key = "SysMgrExePath",
                    .get_value = _ConfigKeyGetString,
                    .user_cb = (_ConfigKeyUser*) _ConfigKeySetString,
                    .user_ctxt = &g_conf_sysmgr_exe_path,
                },
                {
                    .key = "WebAppMgrExePath",
                    .get_value = _ConfigKeyGetString,
                    .user_cb = (_ConfigKeyUser*) _ConfigKeySetString,
                    .user_ctxt = &g_conf_webappmgr_exe_path,
                },
                {
                    .key = "WebAppMgr2ExePath",
                    .get_value = _ConfigKeyGetString,
                    .user_cb = (_ConfigKeyUser*) _ConfigKeySetString,
                    .user_ctxt = &g_conf_webappmgr2_exe_path,
                },
                {
                    .key = "JsServiceExePath",
                    .get_value = _ConfigKeyGetString,
                    .user_cb = (_ConfigKeyUser*) _ConfigKeySetString,
                    .user_ctxt = &g_conf_triton_service_exe_path,
                },
                {
                    .key = "MojoAppExePath",
                    .get_value = _ConfigKeyGetString,
                    .user_cb = (_ConfigKeyUser*) _ConfigKeySetString,
                    .user_ctxt = &g_conf_mojo_app_exe_path,
                },
                {
                    .key = "MojoAppsAllowAllOutboundByDefault",
                    .get_value = _ConfigKeyGetBool,
                    .user_cb = (_ConfigKeyUser*)_ConfigKeySetBool,
                    .user_ctxt = &g_conf_mojo_apps_allow_all_outbound_by_default,
                },
                {
                    .key = "AllowNullOutboundByDefault",
                    .get_value = _ConfigKeyGetBool,
                    .user_cb = (_ConfigKeyUser*)_ConfigKeySetBool,
                    .user_ctxt = &g_conf_allow_null_outbound_by_default,
                },
                {
                    /* Keep this after the others since it depends on the
                     * other settings to be set */
                    .key = "Directories",
                    .get_value = _ConfigKeyGetStringList,
                    .user_cb = (_ConfigKeyUser*) ProcessRoleDirectories,
                    .user_ctxt = GINT_TO_POINTER(STEADY_DIRS),
                },
                {
                    /* Keep this after the others since it depends on the
                     * other settings to be set */
                    .key = "VolatileDirectories",
                    .get_value = _ConfigKeyGetStringList,
                    .user_cb = (_ConfigKeyUser*) ProcessRoleDirectories,
                    .user_ctxt = GINT_TO_POINTER(VOLATILE_DIRS),
                },
                { NULL }
            }
        },
        { NULL }
    }
};

/* config globals */
int g_conf_watchdog_timeout_sec = 60;           /**< watchdog timeout in seconds */
LSHubWatchdogFailureMode g_conf_watchdog_failure_mode = LSHubWatchdogFailureModeNoop;   /**< behavior of watchdog when it detects a failure */
int g_conf_query_name_timeout_ms = 20000;       /**< timeout in ms for a "QueryName" message */
bool g_conf_security_enabled = true;            /**< enable/disable security checks */
bool g_conf_log_service_status = false;         /**< enable service status logging */
char *g_conf_dynamic_service_exec_prefix = NULL; /**< prefix added to Exec in service file
                                                      when launching dynamic service */
int g_conf_connect_timeout_ms = 20000;          /**< timeout in ms for connect() to complete */
char *g_conf_monitor_exe_path = NULL;           /**< path to ls-monitor */
char *g_conf_monitor_pub_exe_path = NULL;       /**< path to ls-monitor-pub */
char *g_conf_sysmgr_exe_path = NULL;            /**< path to LunaSysMgr */
char *g_conf_webappmgr_exe_path = NULL;         /**< path to WebAppMgr (with the separation of LunaSysMgr and WebAppMgr into two separate components,
                                                     there is now a second executable that must be granted special permissions) */
char *g_conf_webappmgr2_exe_path = NULL;         /**< path to WebAppMgr2, which is its QtWebProcess instance */
char *g_conf_triton_service_exe_path = NULL;    /**< special "exePath" value for JS services */
char *g_conf_mojo_app_exe_path = NULL;          /**< special "exePath" value for mojo apps */
bool g_conf_mojo_apps_allow_all_outbound_by_default = false; /**< whether to allow mojo apps "*" outbound permissions by default */
bool g_conf_allow_null_outbound_by_default = false; /**< whether to allow connections with "NULL" service names "*" outbound permissions by default */
char *g_conf_pid_dir = NULL;                    /**< PID file directory */
char *g_conf_local_socket_path = NULL;          /**< directory that contains domain sockets */

/* static -- local to this file */
static char *config_file_path = NULL;                /**< full path to config file */
static char *config_file_name = NULL;                /**< filename only */
static gchar **service_volatile_dirs = NULL;         /**< volatile directories with service description files*/
extern gchar **roles_volatile_dirs;                  /**< volatile directories with role files*/

#ifdef HAVE_SYS_INOTIFY_H
static int inotify_watch_id = -1;
static int inotify_conf_file_wd = -1;
#endif

enum RELOAD_EVENTS_ENUM {RELOAD_UNKNOWN = 0, RELOAD_CONFIGURATION, RESCAN_VOLATILE}; /**< Items is used to designate directories in parsers of roles/sevices*/
static int config_reload_pipe[2] = {-1, -1};    /**< used for alerting mainloop
                                                     about SIGHUP signal to reload
                                                     the config file */

/**
 *******************************************************************************
 * @brief SIGHUP|SIGUSR1 signal handler that notifies the mainloop that we should
 * reload the config file or rescan volatile directories.
 *
 * @param  signal  SIGHUP|SIGUSR1
 *******************************************************************************
 */
static void
_ConfigHandleSignal(int signal)
{
    /* See signal(7) for list of async-signal-safe functions */
    LOG_LS_DEBUG("%s: handling signal: %d\n", __func__, signal);
    int reload = RELOAD_UNKNOWN;
    switch (signal) {
        case SIGHUP: reload = RELOAD_CONFIGURATION; break;
        case SIGUSR1: reload = RESCAN_VOLATILE; break;
    }
    int write_size = sizeof(reload);
    int ret = write(config_reload_pipe[PIPE_WRITE_END], &reload, write_size);

    if (ret != write_size)
    {
        LOG_LS_ERROR(MSGID_LSHUB_PIPE_ERR, 0, "Unable to write to reload pipe");
    }
}

#ifdef HAVE_SYS_INOTIFY_H
/**
 *******************************************************************************
 * @brief Called when inotify on config file directory is triggered.
 *
 * @param  channel      IN  channel
 * @param  condition    IN  condition
 * @param  data         IN  user data
 *
 * @retval  TRUE, always
 *******************************************************************************
 */
gboolean
ConfigInotifyCallback(GIOChannel *channel, GIOCondition condition, gpointer data)
{
    GError *error = NULL;

    gsize bytes_read;
    gchar event_buf[256];

    GIOStatus status = g_io_channel_read_chars(channel, event_buf, sizeof(event_buf), &bytes_read, &error);

    if (status != G_IO_STATUS_NORMAL)
    {
        LOG_LS_ERROR(MSGID_LSHUB_INOTIFY_ERR, 2,
                     PMLOGKFV("ERROR_CODE", "%d", error->code),
                     PMLOGKS("ERROR", error->message),
                     "Error reading inotify event: \"%s\"", error->message);
        g_error_free(error);
        return TRUE;
    }

    int offset = 0;

    while (offset < bytes_read)
    {
        struct inotify_event *event = (struct inotify_event*)&event_buf[offset];

        LOG_LS_DEBUG("%s: event: wd: %d, mask: %08X, cookie: %d, len: %d, name: \"%s\"\n",
                    __func__, event->wd, event->mask,
                    event->cookie, event->len, event->len > 0 ? event->name : NULL);

        if ((event->mask & INOTIFY_MASK) && (event->wd == inotify_conf_file_wd)
            && event->len > 0 && strcmp(event->name, config_file_name) == 0)
        {
            LOG_LS_DEBUG("%s: config file modified; sending SIGHUP\n", __func__);
            if (kill(getpid(), SIGHUP) != 0)
            {
                LOG_LS_ERROR(MSGID_LSHUB_INOTIFY_ERR, 2,
                             PMLOGKFV("ERROR_CODE", "%d", errno),
                             PMLOGKS("ERROR", g_strerror(errno)),
                             "Error sending SIGHUP: %d", errno);
            }
        }
        offset += sizeof(struct inotify_event) + event->len;
    }

    return TRUE;    /* FALSE means remove */
}
#endif

/**
 *******************************************************************************
 * @brief Called when we need to re-load the config file.
 *
 * @param  channel      IN  channel
 * @param  condition    IN  condition
 * @param  data         IN  user data
 *
 * @retval  TRUE, always
 *******************************************************************************
 */
gboolean
_ConfigParseFileWrapper(GIOChannel *channel, GIOCondition condition, gpointer data)
{
    GError *error = NULL;
    int read_data = 0;
    gsize bytes_read = 0;

    LOG_LS_DEBUG("%s: parsing config file\n", __func__);

    GIOStatus status = g_io_channel_read_chars(channel, (gchar*)&read_data, sizeof(read_data),
                                               &bytes_read, &error);

    if (status != G_IO_STATUS_NORMAL)
    {
        LOG_LS_ERROR(MSGID_LSHUB_PIPE_ERR, 2,
                     PMLOGKFV("ERROR_CODE", "%d", error->code),
                     PMLOGKS("ERROR", error->message),
                     "Error reading config pipe: \"%s\"", error->message);
        g_error_free(error);
        return TRUE;
    }

    LSError lserror;
    LSErrorInit(&lserror);

    switch(read_data)
    {
        case RELOAD_CONFIGURATION:
            if (!ConfigParseFile(config_file_path, &lserror))
            {
                LOG_LSERROR(MSGID_LSHUB_CONF_FILE_ERROR, &lserror);
                LSErrorFree(&lserror);
            }
            break;
        case RESCAN_VOLATILE:
            if (!ConfigKeyProcessDynamicServiceDirs((const char**)service_volatile_dirs, GINT_TO_POINTER(VOLATILE_DIRS), &lserror))
            {
                LOG_LSERROR(MSGID_LSHUB_CONF_FILE_ERROR, &lserror);
                LSErrorFree(&lserror);
            }
            if (!ProcessRoleDirectories((const char**)roles_volatile_dirs, GINT_TO_POINTER(VOLATILE_DIRS), &lserror))
            {
                LOG_LSERROR(MSGID_LSHUB_CONF_FILE_ERROR, &lserror);
                LSErrorFree(&lserror);
            }
            break;
    }

    /* Send out a signal that we've completed the scanning */
    (void)LSHubSendConfScanCompleteSignal();

    return TRUE;    /* FALSE means remove */
}

/**
 *******************************************************************************
 * @brief Create a GIOChannel suitable for binary data.
 *
 * @param  fd       IN  existing fd to convert to channel
 * @param  lserror  OUT set on error
 *
 * @retval  channel on success
 * @retval  NULL on failure
 *******************************************************************************
 */
GIOChannel*
_ConfigCreateBinaryChannel(int fd, LSError *lserror)
{
    GError *error = NULL;

    GIOChannel *channel = g_io_channel_unix_new(fd);

    if (G_IO_STATUS_NORMAL != g_io_channel_set_encoding(channel, NULL, &error))
    {
        _LSErrorSetFromGError(lserror, MSGID_LS_CHANNEL_ERR, error);
        return NULL;
    }

    g_io_channel_set_buffered(channel, FALSE);
    g_io_channel_set_close_on_unref(channel, TRUE);

    return channel;
}

/**
 *******************************************************************************
 * @brief Set up an inotify watch and a signal handler for config file.
 *
 * @param  conf_file    IN  path to config file
 * @param  lserror      OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
ConfigSetupInotify(const char* conf_file, LSError *lserror)
{
    int inotify_fd = -1;
    GIOChannel *config_reload_channel = NULL;
    GIOChannel *inotify_channel = NULL;

    LOG_LS_DEBUG("%s: setting up inotify and signal handler\n", __func__);

    /* install signal handler */
    if (pipe(config_reload_pipe) != 0)
    {
        _LSErrorSetFromErrno(lserror, MSGID_LS_PIPE_ERR, errno);
        return false;
    }

    config_reload_channel = _ConfigCreateBinaryChannel(config_reload_pipe[PIPE_READ_END], lserror);

    if (!config_reload_channel)
    {
        goto error;
    }

    g_io_add_watch(config_reload_channel, G_IO_IN | G_IO_ERR | G_IO_HUP,
                   _ConfigParseFileWrapper, NULL);

    g_io_channel_unref(config_reload_channel);

    _LSTransportSetupSignalHandler(SIGHUP, _ConfigHandleSignal);
    _LSTransportSetupSignalHandler(SIGUSR1, _ConfigHandleSignal);

#ifdef HAVE_SYS_INOTIFY_H
    /* add inotify on config file */
    inotify_fd = inotify_init();

    if (inotify_fd < 0)
    {
        _LSErrorSetFromErrno(lserror, MSGID_LSHUB_INOTIFY_ERR, errno);
        goto error;
    }

    /* set a watch on the directory where the config file lives instead
     * of the config file itself, since most editors will create temporary
     * files and delete the original file */
    char *dir_name = g_path_get_dirname(conf_file);

    inotify_conf_file_wd = inotify_add_watch(inotify_fd, dir_name, INOTIFY_MASK /*IN_ALL_EVENTS*/);

    g_free(dir_name);

    if (inotify_conf_file_wd < 0)
    {
        _LSErrorSetFromErrno(lserror, MSGID_LSHUB_INOTIFY_ERR, errno);
        goto error;
    }

    inotify_channel = _ConfigCreateBinaryChannel(inotify_fd, lserror);

    if (!inotify_channel)
    {
        goto error;
    }

    inotify_watch_id = g_io_add_watch(inotify_channel, G_IO_IN,
                                      ConfigInotifyCallback, &inotify_conf_file_wd);

    g_io_channel_unref(inotify_channel);

#endif  /* HAVE_SYS_INOTIFY_H */

    return true;

error:
    if (inotify_fd != -1)
    {
        close(inotify_fd);
    }

    if (config_reload_channel)
    {
        g_io_channel_unref(config_reload_channel);
    }
    else if (config_reload_pipe[PIPE_READ_END] != -1)
    {
        close(config_reload_pipe[PIPE_READ_END]);
    }

    if (config_reload_pipe[PIPE_WRITE_END] != -1) close(config_reload_pipe[PIPE_WRITE_END]);

    return false;
}

bool
_ConfigKeyGetInt(GKeyFile *key_file, const char *group_name,
                 const char *key, _ConfigKeyUser *user, void *ctxt, LSError *lserror)
{
    GError *error = NULL;
    int value = g_key_file_get_integer(key_file, group_name, key, &error);

    if (error)
    {
        _LSErrorSetFromGError(lserror, MSGID_LSHUB_KEYFILE_ERR, error);
        return false;
    }

    return (*user)(&value, ctxt, lserror);
}

bool
_ConfigKeySetInt(const int *value, int *conf_var, LSError *lserror)
{
    LS_ASSERT(value != NULL);
    LS_ASSERT(conf_var != NULL);

    *conf_var = *value;
    return true;
}

bool
_ConfigKeyGetBool(GKeyFile *key_file, const char *group_name,
                  const char *key, _ConfigKeyUser *user, void *ctxt, LSError *lserror)
{
    GError *error = NULL;
    bool value = g_key_file_get_boolean(key_file, group_name, key, &error);

    if (error)
    {
        _LSErrorSetFromGError(lserror, MSGID_LSHUB_KEYFILE_ERR, error);
        return false;
    }

    return (*user)(&value, ctxt, lserror);
}

bool
_ConfigKeySetBool(const bool *value, bool *conf_var, LSError *lserror)
{
    LS_ASSERT(value != NULL);
    LS_ASSERT(conf_var != NULL);

    *conf_var = *value;
    return true;
}

bool
_ConfigKeyGetString(GKeyFile *key_file, const char *group_name,
                    const char *key, _ConfigKeyUser *user, void *ctxt, LSError *lserror)
{
    GError *error = NULL;
    char *value = g_key_file_get_string(key_file, group_name, key, &error);

    if (error)
    {
        _LSErrorSetFromGError(lserror, MSGID_LSHUB_KEYFILE_ERR, error);
        return false;
    }

    return (*user)(value, ctxt, lserror);
}

bool
_ConfigKeySetString(const char *value, const char **conf_var, LSError *lserror)
{
    LS_ASSERT(conf_var != NULL);

    /* free any previously allocated value */
    if (*conf_var != NULL)
    {
        g_free((char*)*conf_var);
    }

    *conf_var = value;
    return true;
}

/**
 *******************************************************************************
 * @brief Parses a key of type "string list" and calls user callback.
 *
 * @param  key_file     IN  key file
 * @param  group_name   IN  group name
 * @param  key          IN  key to parse
 * @param  user         IN  user callback
 * @param  ctxt         IN  user context
 * @param  lserror      OUT set on error
 *
 * @retval true on success
 * @retval false on failure
 *******************************************************************************
 */
bool
_ConfigKeyGetStringList(GKeyFile *key_file, const char *group_name,
                        const char *key, _ConfigKeyUser *user, void *ctxt, LSError *lserror)
{
    GError *error = NULL;

    gchar **value = g_key_file_get_string_list(key_file, group_name, key, NULL, &error);

    if (!value)
    {
        _LSErrorSetFromGError(lserror, MSGID_LSHUB_KEYFILE_ERR, error);
        return false;
    }

    bool ret = (*user)(value, ctxt, lserror);

    g_strfreev(value);

    return ret;
}

/**
 *******************************************************************************
 * @brief Set default config settings for remaining unset values.
 *******************************************************************************
 */
void
ConfigSetDefaults(void)
{
    /* NOTE: All strings should be copied since they are free'd when we reload
     * the conf file */
    if (!g_conf_monitor_exe_path)
    {
        g_conf_monitor_exe_path = g_strdup(DEFAULT_MONITOR_EXE_PATH);
    }

    if (!g_conf_sysmgr_exe_path)
    {
        g_conf_sysmgr_exe_path = g_strdup(DEFAULT_SYSMGR_EXE_PATH);
    }

    if (!g_conf_webappmgr_exe_path)
    {
        g_conf_webappmgr_exe_path = g_strdup(DEFAULT_WEBAPPMGR_EXE_PATH);
    }

    if (!g_conf_webappmgr2_exe_path)
    {
        g_conf_webappmgr2_exe_path = g_strdup(DEFAULT_WEBAPPMGR2_EXE_PATH);
    }

    if (!g_conf_triton_service_exe_path)
    {
        g_conf_triton_service_exe_path = g_strdup(DEFAULT_TRITON_SERVICE_EXE_PATH);
    }

    if (!g_conf_mojo_app_exe_path)
    {
        g_conf_mojo_app_exe_path = g_strdup(DEFAULT_MOJO_APP_EXE_PATH);
    }
}

/**
 *******************************************************************************
 * @brief Free config file settings
 *******************************************************************************
 */
void
_ConfigFreeSettings(void)
{
    if (g_conf_dynamic_service_exec_prefix)
    {
        g_free(g_conf_dynamic_service_exec_prefix);
    }
    g_conf_dynamic_service_exec_prefix = NULL;

    if (g_conf_monitor_exe_path)
    {
        g_free(g_conf_monitor_exe_path);
    }
    g_conf_monitor_exe_path = NULL;

    if (g_conf_sysmgr_exe_path)
    {
        g_free(g_conf_sysmgr_exe_path);
    }
    g_conf_sysmgr_exe_path = NULL;

    if (g_conf_webappmgr_exe_path)
    {
        g_free(g_conf_webappmgr_exe_path);
    }
    g_conf_webappmgr_exe_path = NULL;

    if (g_conf_webappmgr2_exe_path)
    {
        g_free(g_conf_webappmgr2_exe_path);
    }
    g_conf_webappmgr2_exe_path = NULL;

    if (g_conf_triton_service_exe_path)
    {
        g_free(g_conf_triton_service_exe_path);
    }
    g_conf_triton_service_exe_path = NULL;

    if (g_conf_mojo_app_exe_path)
    {
        g_free(g_conf_mojo_app_exe_path);
    }
    g_conf_mojo_app_exe_path = NULL;
}

static bool
_ConfigKeyProcessDynamicServiceExecPrefix(char *value, const char **conf_var, LSError *lserror)
{
    /* use NULL instead of empty string since we don't want to prefix an empty
     * string with the path */
    if (value && value[0] == '\0')
    {
        g_free(value);
        value = NULL;
    }

    return _ConfigKeySetString(value, conf_var, lserror);
}

/**
 *******************************************************************************
 * @brief Set the watchdog failure mode.
 *
 * @param  mode_str     IN  failure mode string
 * @param  conf_var     OUT numeric failure mode
 * @param  lserror      OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
static bool
_ConfigKeyProcessWatchdogFailureMode(char *mode_str, LSHubWatchdogFailureMode *conf_var, LSError *lserror)
{
    LS_ASSERT(mode_str != NULL);
    LS_ASSERT(conf_var != NULL);

    *conf_var = LSHubWatchdogProcessFailureMode(mode_str);

    /* we don't need to save the string */
    g_free(mode_str);

    return true;
}

/**
 *******************************************************************************
 * @brief Parse dynamic services from steady directories and load dynamic service map.
 * This function can safely be called multiple times to reload data.
 * The service map is reset before loading data.
 *
 * @param  *dirs    IN  array of directories
 * @param  ctxt     IN  unused
 * @param  lserror  OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
ConfigKeyProcessDynamicServiceDirs(const char **dirs, void *ctxt, LSError *lserror)
{
    /* process all the service files in the specified directories */

    bool is_volatile_dir = (GPOINTER_TO_INT(ctxt) == VOLATILE_DIRS);
    const char **cur_dir = NULL;

    if (!ServiceInitMap(lserror, is_volatile_dir))
    {
        return false;
    }

    for (cur_dir = dirs; cur_dir != NULL && *cur_dir != NULL; cur_dir++)
    {
        if (!ParseServiceDirectory(*cur_dir, lserror, is_volatile_dir))
        {
            LOG_LSERROR(MSGID_LSHUB_ROLE_FILE_ERR, lserror);
            LSErrorFree(lserror);
        }
    }

    if (is_volatile_dir)
    {
        if (service_volatile_dirs != (gchar**)dirs)
        {
            g_strfreev(service_volatile_dirs);
            service_volatile_dirs = g_strdupv((gchar**)dirs);
        }
    }

    return true;
}

/**
 *******************************************************************************
 * @brief Parse the keys in a "keyfile", calling the user callback as
 * appropriate.
 *
 * @param  key_file     IN   key file
 * @param  group        IN   parent group
 * @param  lserror      OUT  set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
_ConfigParseKeys(GKeyFile *key_file, const _ConfigGroup *group, LSError *lserror)
{
    bool ret = false;
    GError *error = NULL;
    gsize key_len = 0;

    char **keys = g_key_file_get_keys(key_file, group->group_name, &key_len, &error);

    if (!keys)
    {
        _LSErrorSetFromGError(lserror, MSGID_LSHUB_KEYFILE_ERR, error);
        return false;
    }

    int i;
    const _ConfigKey *cur_key = &group->keys[0];
    for (; cur_key->key != NULL; cur_key++)
    {
        for (i = 0; i < key_len; i++)
        {
            if (strcmp(cur_key->key, keys[i]) == 0)
            {
                if (!cur_key->get_value(key_file, group->group_name, cur_key->key, cur_key->user_cb, cur_key->user_ctxt, lserror))
                {
                    goto exit;
                }
                break;
            }
        }
    }

    ret = true;

exit:

    g_strfreev(keys);

    return ret;
}

static

/**
 *******************************************************************************
 * @brief Parse the config file according to the given DOM.
 *
 * @param  path     IN  path to config file
 * @param  dom      IN  DOM representation
 * @param  lserror  OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
_ConfigParseFile(const char *path, const _ConfigDOM *dom, LSError *lserror)
{
    bool ret = false;
    GError *gerror = NULL;
    GKeyFile *key_file = NULL;
    char **groups = NULL;

    LOG_LS_DEBUG("%s: parsing file: \"%s\"\n", __func__, path);

    /* Free old settings */
    _ConfigFreeSettings();

    /* Set the defaults */
    ConfigSetDefaults();

    key_file = g_key_file_new();

    if (!g_key_file_load_from_file(key_file, path, G_KEY_FILE_NONE, &gerror))
    {
        _LSErrorSet(lserror, MSGID_LSHUB_KEYFILE_ERR, -1, "Error loading key file: \"%s\"\n", gerror->message);
        goto error;
    }

    gsize group_len = 0;
    groups = g_key_file_get_groups(key_file, &group_len);

    if (!groups)
    {
        _LSErrorSet(lserror, MSGID_LSHUB_KEYFILE_ERR, -1, "No groups in config file: \"%s\"\n", path);
        goto error;
    }

    int i = 0;
    const _ConfigGroup *cur_group = &dom->groups[0];
    for (; cur_group->group_name != NULL; cur_group++)
    {
        for (i = 0; i < group_len; i++)
        {
            if (strcmp(cur_group->group_name, groups[i]) == 0)
            {
                if (!_ConfigParseKeys(key_file, cur_group, lserror))
                {
                    goto error;
                }
                break;
            }
        }
    }
    ret = true;

error:
    /* free up memory */
    if (key_file) g_key_file_free(key_file);
    g_strfreev(groups);
    if (gerror) g_error_free(gerror);

    return ret;
}

/**
 *******************************************************************************
 * @brief Parse the config file.
 *
 * @param  path     IN  path to config file
 * @param  lserror  OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
ConfigParseFile(const char *path, LSError *lserror)
{
    LS_ASSERT(path != NULL);

    if (!config_file_path)
    {
        config_file_path = g_strdup(path);
        config_file_name = g_path_get_basename(path);
    }

    return _ConfigParseFile(path, &conf_file_dom, lserror);
}

void
ConfigCleanup()
{
    g_free(config_file_path);
    g_free(config_file_name);

    _ConfigFreeSettings();

    /* inotify fd and read end of pipe fd are closed when the channel
     * is unref'd (in this case when watch is destroyed) */
}
