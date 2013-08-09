/* @@@LICENSE
*
*      Copyright (c) 2008-2013 LG Electronics, Inc.
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <libgen.h>
#include <glib.h>

#include "hub.h"
#include "conf.h"
#include "log.h"
#include "security.h"
#include "watchdog.h"
#include "transport.h"
#include "transport_utils.h"
#include "transport_client.h"
#include "transport_security.h"
#include "timersource.h"
#include "utils.h"

/**
 * @defgroup LunaServiceHub
 * @ingroup  LunaServiceInternals
 * @brief    The hub for LunaService
 */

/**
 * @addtogroup LunaServiceHub
 * @{
 */

/* define DEBUG for some extra print statements */
#undef DEBUG

/** name of launch helper binary */
#define LUNA_HELPER_NAME    "luna-helper"

/** public hub pid file */
#define HUB_PUBLIC_LOCK_FILENAME        "ls-hubd.public.pid"

/** private hub pid file */
#define HUB_PRIVATE_LOCK_FILENAME       "ls-hubd.private.pid"

#define MESSAGE_TIMEOUT_GRANULARITY_MS 100  /**< glib timer granularity for message timeouts */

char **pid_dir = NULL;                  /**< pid file directory */

char *conf_file =  NULL;

char **local_socket_path = NULL;        /**< ptr to socket file directory,
                                              we use a ptr here since the conf
                                              file can be reloaded and change the
                                              underlying ptr */

gboolean enable_inet = FALSE;               /**< true if using inet sockets (default is unix domain sockets */

gboolean use_syslog = FALSE;                /**< true if logging should go to syslog */
gboolean use_pmloglib = FALSE;              /**< true if logging should go through pmloglib */

char *service_dir = "/tmp/";        /**< service file directory */

#define SERVICE_FILE_SUFFIX ".service"      /**< service file suffix */

/** Allowed service file group names */
const char* service_group_names[] = {
    "D-BUS Service",
    "DBUS Service",
    "Palm Service",
    "Luna Service",
};

/**< FIXME: workaround for non-conformant media service */
static char *media_service_names[] = {
    "com.palm.mediad",
    "com.palm.media",
    "com.palm.umediapipeline",
    "com.palm.umediaserver",
    "com.palm.umediapipelinectrl"
};

#define SERVICE_NAME_KEY    "Name"          /**< key for defining service name */
#define SERVICE_EXEC_KEY    "Exec"          /**< key for executable path for 
                                                 service */
#define SERVICE_TYPE_KEY    "Type"          /**< type of service (dynamic or static) */

#define SERVICE_TYPE_DYNAMIC    "dynamic"
#define SERVICE_TYPE_STATIC     "static"

typedef enum _DynamicServiceState {
    _DynamicServiceStateInvalid = -1,      /**< not a dynamic service */
    _DynamicServiceStateStopped,           /**< not running */
    _DynamicServiceStateSpawned,           /**< spawned, but hasn't registered name 
                                                with hub yet */
    _DynamicServiceStateRunning,           /**< name registered with hub and 
                                                service was launched manually */
    _DynamicServiceStateRunningDynamic,    /**< name registered with hub and
                                                service was launched dynamically */
} _DynamicServiceState;

/* TODO: make the transport a shared library, so the hub can link it in as
 * well */


#if 0
typedef struct LSTransportConnectionHub {
    _LSTransportChannel listen_channel;

    GHashTable *nodes;    /**< hash of connected nodes */
} _LSTransportConnectionHub;
#endif

typedef struct _ConnectedClients {
    GHashTable *by_unique_name; /**< hash from unique name to _ClientId */
    GHashTable *by_fd;          /**< hash from fd to _ClientId */
} _ConnectedClients;

extern char **environ;

extern int _ls_debug_tracing;

static GMainLoop *mainloop = NULL;

static _LSTransport *hub_transport = NULL;

static GHashTable *pending = NULL;              /**< hash of service name to _ClientId */
static GHashTable *available_services = NULL;   /**< hash of service name to _ClientId */

static _ConnectedClients connected_clients;     /**< all connected clients
                                                     TODO: may want to build this 
                                                     into transport layer */

static GSList *waiting_for_service = NULL;      /**< list of messages waiting for a
                                                  service that is in the pending list;
                                                  it's assumed that this will not
                                                  happen very often, so we use a list */

static GSList *waiting_for_connect = NULL;      /**< list of messages waiting for a
                                                  connect() to complete;
                                                  this isn't strictly necessary, but
                                                  is useful for debugging so we can
                                                  dump out the state */

/**
 * Keeps track of the state of running dynamic services
 *
 * HASH: service name to _Service ptr 
 */
static GHashTable *dynamic_service_states = NULL;

/**
 * Set of all services. The service files are scanned and loaded
 * into this hash, but state is not tracked by these.
 *
 * HASH: service name to _Service ptr
 */
static GHashTable *all_services = NULL;

// NOTE: All connected nodes are available in the clients hash in transport


typedef struct _LSTransportBodyRequestNameLocalReply {
    long err_code;
    char *name;
} _LSTransportBodyRequestNameLocalReply;

typedef struct _LocalName {
    char *name;
} _LocalName;

typedef struct _InetName {
} _InetName;

typedef struct _ClientId {
    int ref;                    /**< ref count */
    char *service_name;         /**< service name (or NULL if it doesn't have one */
    _LSTransportClient *client; /**< underlying transport client, so we can 
                                     initiate messages */
    _LocalName local;           /**< local name */
    _InetName inet;             /**< inet name */
   bool is_monitor;             /**< true if this client is the monitor */ 
} _ClientId;

typedef struct _SignalMap {
    GHashTable *category_map;   /**< category to _LSTransportClient list */
    GHashTable *method_map;     /**< category/method to _LSTransportClient list */

    /* 
     * TODO: fast way to go from _LSTransportClient to any categories and
     * methods to that it has registered 
     *
     * this reverse lookup is so that we can quickly remove all items in the
     * above hash table for a client that goes down
     */
    GHashTable *client_map;     /**< _LSTransportClient* to items (elements) in
                                     the above hashed lists */
} _SignalMap;

static _SignalMap *signal_map = NULL;    /**< keeps track of signals */

static _ClientId *monitor = NULL;	 /**< non-NULL when a monitor is connected */

typedef struct _LSTransportClientList {
    GList *list; 
} _LSTransportClientList;

typedef struct _LSTransportClientMap {
    GHashTable *map;
} _LSTransportClientMap;

typedef struct _Service {
    int ref;                    /**< ref count */
    char **service_names;       /**< names of services provided (currently only
                                     support one service) */
    int num_services;           /**< number of services provided by executable */
    char *exec_path;            /**< executable path for this service */
    GPid pid;                   /**< pid when running (0 otherwise)  */
    _DynamicServiceState state; /**< see @ref _DynamicServiceState */
    bool respawn_on_exit;       /**< true if we should respawn the service again
                                     when it goes down */
    bool uses_launch_helper;    /**< legacy support for launching a service
                                     indirectly with luna-helper */
    bool is_dynamic;            /**< true if dynamic; false if static */
    char *service_file_dir;     /**< directory where the service file for this service lives */
    char *service_file_name;    /**< file name of the service file for this service */
} _Service;              /**< struct representing a dynamic service */

static void _LSHubCleanupSocketLocal(const char *unique_name);
static bool _LSHubRemoveClientSignals(_LSTransportClient *client);
static void _LSHubSendSignal(_LSTransportClient *client, void *dummy, _LSTransportMessage *message);
static void _LSHubHandleSignal(_LSTransportMessage *message, bool generated_by_hub);
static void _LSHubSignalRegisterAllServicesItem(gpointer key, gpointer value, gpointer user_data);
static gchar * _LSHubSignalRegisterAllServices(GHashTable *table);

static void _LSHubClientIdLocalRef(_ClientId *id);
static void _LSHubClientIdLocalUnref(_ClientId *id);

static void _LSHubSendMonitorMessage(int fd, _ClientId *id, const char *unique_name);

static bool _LSHubSendServiceWaitListReply(_ClientId *id, bool success, bool is_dynamic, LSError *lserror);

static void _LSHubAddPendingConnect(_LSTransportMessage *message, _LSTransportClient *client, int fd);
static void _LSHubAddMessageTimeout(_LSTransportMessage *message, int timeout_ms, GSourceFunc callback);
static void _LSHubRemoveMessageTimeout(_LSTransportMessage *message);
static void _LSHubAddConnectMessageTimeout(_LSTransportMessage *message);
static void _LSHubRemoveConnectMessageTimeout(_LSTransportMessage *message);

bool _DynamicServiceLaunch(_Service *service, LSError *lserror);

/** 
 *******************************************************************************
 * @brief Allocate a new service data structure.
 * 
 * @param  service_names    IN  array of service names provided
 * @param  num_services     IN  number of services in @ref service_names 
 * @param  exec_path        IN  path to executable (including args)
 * @param  is_dynamic       IN  true for dynamic service, false for static
 * @param  service_file_dir IN	service file directory
 * @param  service_file_name IN name of service file (no directory)
 * 
 * @retval service on success
 * @retval NULL on failure 
 *******************************************************************************
 */
_Service*
_ServiceNew(const char *service_names[], int num_services, char *exec_path, bool is_dynamic,
            char *service_file_dir, char *service_file_name)
{
    int i = 0;
    
    _Service *ret = g_new0(_Service, 1);
    if (ret)
    {
        ret->uses_launch_helper = false;

        ret->service_names = g_new0(char*, num_services);

        if (!ret->service_names)
        {
            goto error;
        }
        
        for (i = 0; i < num_services; i++)
        {
            _LSWarnOnDeprecatedName(service_names[i]);

            ret->service_names[i] = g_strdup(service_names[i]);

            if (!ret->service_names[i])
            {
                goto error;
            }
        }
        ret->num_services = num_services;
        ret->exec_path = g_strdup(exec_path);

        if (!ret->exec_path)
        {
            goto error;
        }

        ret->state = _DynamicServiceStateInvalid;

        /* LEGACY: check whether we're launching with luna-helper */
        if (strstr(ret->exec_path, LUNA_HELPER_NAME))
        {
            ret->uses_launch_helper = true;
        }

        ret->is_dynamic = is_dynamic;

        ret->service_file_dir = g_strdup(service_file_dir);
        ret->service_file_name = g_strdup(service_file_name);

    }
    return ret;

error:
    if (ret->service_names)
    {
        for (i = 0; i < num_services; i++)
        {
            if (ret->service_names[i])
            {
                g_free(ret->service_names[i]);
            }
        }
        g_free(ret->service_names);
    }
    if (ret->exec_path) g_free(ret->exec_path);
    if (ret->service_file_dir) g_free(ret->service_file_dir);
    if (ret->service_file_name) g_free(ret->service_file_name);
    if (ret) g_free(ret);
    return NULL;
}

/** 
 *******************************************************************************
 * @brief Allocate new service data structure with ref count of 1.
 * 
 * @param  service_names    IN  array of service names provided
 * @param  num_services     IN  number of services in @ref service_names 
 * @param  exec_path        IN  path to executable (including args)
 * @param  is_dynamic       IN  true means dynamic service, false means static
 * @param  service_file_dir IN	service file directory
 * @param  service_file_name IN	name of service file (no directory)
 * 
 * @retval service on success
 * @retval NULL on failure 
 *******************************************************************************
 */
_Service*
_ServiceNewRef(const char *service_names[], int num_services, char *exec_path,
               bool is_dynamic, char *service_file_dir, char *service_file_name)
{
    _Service *ret = _ServiceNew(service_names, num_services, exec_path, is_dynamic,
                                service_file_dir, service_file_name);
    if (ret)
    {
        ret->ref = 1;
    }
    return ret;
}

/** 
 *******************************************************************************
 * @brief Increment ref count for service.
 * 
 * @param  service  IN  service 
 *******************************************************************************
 */
void
_ServiceRef(_Service *service)
{
    LS_ASSERT(service != NULL);
    LS_ASSERT(g_atomic_int_get(&service->ref) > 0);

    g_atomic_int_inc(&service->ref);
}

/** 
 *******************************************************************************
 * @brief Free data structure allocated for service.
 * 
 * @param  service  IN  service
 *******************************************************************************
 */
void
_ServiceFree(_Service *service)
{
    LS_ASSERT(service != NULL);
    LS_ASSERT(g_atomic_int_get(&service->ref) == 0);

    if (service->service_names)
    {
        int i;
        for (i = 0; i < service->num_services; i++)
        {
            if (service->service_names[i])
            {
                g_free(service->service_names[i]);
            }
        }
        g_free(service->service_names);
    }
    if (service->exec_path) g_free(service->exec_path);

    if (service->service_file_dir) g_free(service->service_file_dir);
    if (service->service_file_name) g_free(service->service_file_name);

#ifdef MEMCHECK
    memset(service, 0xFF, sizeof(_Service));
#endif

    g_free(service);
}

/** 
 *******************************************************************************
 * @brief Decrement ref count for service.
 * 
 * @param  service  IN  service
 *******************************************************************************
 */
void
_ServiceUnref(_Service *service)
{
    LS_ASSERT(service != NULL);
    LS_ASSERT(g_atomic_int_get(&service->ref) > 0);

    if (g_atomic_int_dec_and_test(&service->ref))
    {
        _ServiceFree(service);
    }
}

#if 1
void
_ServicePrint(const _Service *service)
{
    if (service)
    {
        g_critical("service_name: \"%s\", exec_path: \"%s\", pid: %d, state: %d, respawn_on_exit: \"%s\", uses_launch_helper: \"%s\"", service->service_names[0], service->exec_path, service->pid, service->state, service->respawn_on_exit ? "true" : "false", service->uses_launch_helper ? "true" : "false");
    }
    else
    {
        g_critical("service is NULL");
    }
}
#endif

/** 
 *******************************************************************************
 * @brief Add service to service map. Hash of service name to service ptr.
 * 
 * @param  service  IN  service to add 
 * @param  lserror  OUT set on error 
 * 
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
_ServiceMapAdd(_Service *service, LSError *lserror)
{
    LS_ASSERT(service != NULL);
    LS_ASSERT(lserror != NULL);

    int i = 0;

     for (i = 0; i < service->num_services; i++)
    {
        _ls_verbose("%s: adding service name: \"%s\" to service map\n", __func__, service->service_names[i]);
        _ServiceRef(service);
        g_hash_table_replace(all_services, service->service_names[i], service);
    }
    return true;
}

/** 
 *******************************************************************************
 * @brief Remove all services provided by the given service from the service map.
 * 
 * @param  service  IN  service
 * 
 * @retval  true on success
 * @retval  false on failure (service not found in map)
 *******************************************************************************
 */
bool
_ServiceMapRemove(_Service *service)
{
    LS_ASSERT(service != NULL);

    int i = 0;
    bool ret = true;

    for (i = 0; i < service->num_services; i++)
    {
        /* unref'ing of the service done by the hash table */
        if (!g_hash_table_remove(all_services, service->service_names[i]))
        {
            ret = false;
        }
    }
    return ret;
}

/** 
 *******************************************************************************
 * @brief Look up a service in the service map by name.
 * 
 * @param  service_name     IN  name of service (e.g., com.palm.foo)
 * 
 * @retval  service on success
 * @retval  NULL on failure
 *******************************************************************************
 */
_Service*
_ServiceMapLookup(const char *service_name)
{
    LS_ASSERT(service_name != NULL);
    return g_hash_table_lookup(all_services, service_name);
}

/** 
 *******************************************************************************
 * @brief Add dynamic service to dynamic service state map. Hash of service name to 
 * service ptr (dynamic).
 * 
 * @param  service  IN  service to add 
 * @param  lserror  OUT set on error 
 * 
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
_DynamicServiceStateMapAdd(_Service *service, LSError *lserror)
{
    LS_ASSERT(service != NULL);
    LS_ASSERT(service->num_services == 1);
    LS_ASSERT(service->is_dynamic == true);
    LS_ASSERT(lserror != NULL);

    _ls_verbose("%s: adding service name: \"%s\" to dynamic map\n",
                __func__, service->service_names[0]);
    
    _ServiceRef(service);
    g_hash_table_replace(dynamic_service_states, service->service_names[0], service);
    return true;
}

/** 
 *******************************************************************************
 * @brief Remove the dynamic service state from the dynamic service state map.
 * 
 * @param  service  IN service (dynamic)
 * 
 * @retval  true on success
 * @retval  false on failure (service not found in map)
 *******************************************************************************
 */
bool
_DynamicServiceStateMapRemove(_Service *service)
{
    LS_ASSERT(service != NULL);
    LS_ASSERT(service->num_services == 1);

    /* unref'ing of the service done by the hash table */
    if (!g_hash_table_remove(dynamic_service_states, service->service_names[0]))
    {
        return false;
    }
    return true;
}

/** 
 *******************************************************************************
 * @brief Look up a dynamic service in the dynamic service state map by name.
 * 
 * @param  service_name     IN  name of dynamic service (e.g., com.palm.foo)
 * 
 * @retval  service on success
 * @retval  NULL on failure
 *******************************************************************************
 */
_Service*
_DynamicServiceStateMapLookup(const char *service_name)
{
    LS_ASSERT(service_name != NULL);
    return g_hash_table_lookup(dynamic_service_states, service_name);
}

/** 
 *******************************************************************************
 * @brief Reap a spawned child process that was dynamically launched.
 * 
 * @param  pid      IN  pid of process that exited 
 * @param  status   IN  status of process that exited 
 * @param  service  IN  dynamic service 
 *******************************************************************************
 */
void
_DynamicServiceReap(GPid pid, gint status, _Service *service)
{
    LS_ASSERT(service != NULL);
    LS_ASSERT(service->is_dynamic == true);

    /* TODO: query exit status of process with WIFEXITED, WEXITSTATUS,
     * etc. See waitpid(2) */

    /* See comments in _LSHubHandleDisconnect */
    if (!service->uses_launch_helper)
    {
        service->state = _DynamicServiceStateStopped;
    }
    
    g_spawn_close_pid(pid);
    service->pid = 0;

    _ls_verbose("%s: Reaping dynamic service: service: %p, pid: %d, exit status: %d, state: %d", __func__, service, pid, status, service->state);
    //_ServicePrint(service);

    if (service->respawn_on_exit)
    {
        LSError lserror;
        LSErrorInit(&lserror);
        
        service->respawn_on_exit = false;

        if (!_DynamicServiceLaunch(service, &lserror))
        {
            LSErrorPrint(&lserror, stderr);
            LSErrorFree(&lserror);
        }
    }

    if (service->state == _DynamicServiceStateStopped)
    {
        /* Remove from state map since we're not running anymore */
        _DynamicServiceStateMapRemove(service);
    }
    
    _ServiceUnref(service);  /* ref from child_watch_add */
}

/** 
 *******************************************************************************
 * @brief Launch a dynamic service.
 * 
 * @param  service  IN  dynamic service to launch 
 * @param  lserror  OUT set on error 
 * 
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
_DynamicServiceLaunch(_Service *service, LSError *lserror)
{
    LS_ASSERT(service != NULL);
    LS_ASSERT(service->is_dynamic == true);

    GError *gerror = NULL;
    char **new_env = NULL;
    char *service_names_str = NULL;
    char *service_names_env = NULL;
    char *service_file_name_env = NULL;
    int argc = 0;
    char **argv = NULL;

    /* Debug */
    //_ServicePrint(service);

    if (service->state == _DynamicServiceStateSpawned)
    {
        /* someone else already spawned the service, so don't do anything
         * and wait for it to come up */
        return true;
    }
    else if (service->state == _DynamicServiceStateRunningDynamic)
    {
        /* service requested in the time frame between when it unregistered
         * from the bus and when we reaped the process. */
        service->respawn_on_exit = true;
        return true;
    }
    else if (service->state == _DynamicServiceStateRunning)
    {
        g_critical("Service is running, but _DynamicServiceLaunch was called");
        return false;
    }
    
    service->state = _DynamicServiceStateSpawned;

    /* parse the exec string into arguments */

    bool ret = g_shell_parse_argv(service->exec_path, &argc, &argv, &gerror);

    if (!ret)
    {
        _LSErrorSet(lserror, -1, "Error parsing arguments, string: \"%s\", message: \"%s\"\n", service->exec_path, gerror->message);
        goto error; 
    }

    int i = 1;
    char *tmp_service_names_str = g_strdup(service->service_names[0]);
    service_names_str = tmp_service_names_str;

    for (i = 1; i < service->num_services; i++)
    {
        service_names_str = g_strjoin(";", tmp_service_names_str, service->service_names[i], NULL);
        g_free(tmp_service_names_str);
        tmp_service_names_str = service_names_str;
    }
    
    service_names_env = g_strdup_printf("LS_SERVICE_NAMES=%s", service_names_str);
    service_file_name_env = g_strdup_printf("LS_SERVICE_FILE_NAME=%s", service->service_file_name);

    /* Append to the hub's environment. There could be an issue if you set
     * either of the above env variables in the hub itself (duplicate keys),
     * but that shouldn't happen  */
    int env_size = g_strv_length(environ);
    new_env = g_malloc(sizeof(char*) * (env_size + 3));
    memcpy(new_env, environ, sizeof(char*) * env_size);

    int offset = env_size;
    new_env[offset++] = service_names_env;
    new_env[offset++] = service_file_name_env;
    new_env[offset] = '\0';

    /* TODO: modify arguments, esp. stdin, stdout, stderr */
    ret = g_spawn_async_with_pipes(NULL,  /* inherit parent's working dir */
                             argv, /* argv */
                             new_env, /* environment -- NULL means inherit parent's env */
                             G_SPAWN_DO_NOT_REAP_CHILD, /* flags */
                             NULL, /* child_setup */
                             NULL, /* user_data */
                             &service->pid,    /* child_pid */
                             NULL, /* stdin */
                             NULL, /* stdout */
                             NULL, /* stderr */
                             &gerror);

    if (!ret)
    {
        _LSErrorSet(lserror, -1, "Error attemtping to launch service: \"%s\"\n", gerror->message);
        goto error;
    }

    /* set up child watch so we can reap the child */
    _ServiceRef(service);
    g_child_watch_add(service->pid, (GChildWatchFunc)_DynamicServiceReap, service);

error:
    if (gerror) g_error_free(gerror);
    if (new_env) g_free(new_env); 
    if (service_names_str) g_free(service_names_str);
    if (service_names_env) g_free(service_names_env);
    if (service_file_name_env) g_free(service_file_name_env);
    if (argv) g_strfreev(argv);
    return ret;
}

/** 
 *******************************************************************************
 * @brief Find and launch a dynamic service given a service name.
 * 
 * @param  service_name     IN  name of service to launch
 * @param  client           IN  client requesting the dynamic service
 * @param  requester_app_id IN  app id that is requesting the launch (for
 *                              debugging bad requests from apps)
 * @param  lserror          OUT set on error 
 * 
 * @retval  true if dynamic service was found and successfully launched
 * @retval  false on failure
 *******************************************************************************
 */
bool
_DynamicServiceFindandLaunch(const char *service_name, const _LSTransportClient *client, const char *requester_app_id, LSError *lserror)
{
    /* Check to see if this dynamic service is in one of the service files */
    _Service *service = _ServiceMapLookup(service_name);

    if (service)
    {
        LS_ASSERT(service->is_dynamic == true);

        /* Check to see if the service state is already being tracked */
        _Service *service_state = _DynamicServiceStateMapLookup(service_name);

        if (!service_state)
        {
            /* Create a new service state */
            service_state = _ServiceNewRef(&service_name, 1, service->exec_path, true,
                                           service->service_file_dir, service->service_file_name);
            if (!_DynamicServiceStateMapAdd(service_state, lserror))
            {
                _ServiceUnref(service_state);
                return false;
            }
            _ServiceUnref(service_state);
        }

        return _DynamicServiceLaunch(service_state, lserror);
    }
  
    const _LSTransportCred *cred = _LSTransportClientGetCred(client);
    pid_t requester_pid = _LSTransportCredGetPid(cred);
    const char *requester_exe = _LSTransportCredGetExePath(cred);
 
    _LSErrorSet(lserror, -1, "service: \"%s\" not found in dynamic service set (requester pid: "LS_PID_PRINTF_FORMAT", requester exe: \"%s\", requester app id: \"%s\"\n",
                service_name,
                LS_PID_PRINTF_CAST(requester_pid), requester_exe ? requester_exe : "(null)",
                requester_app_id ? requester_app_id : "(null)"); 
    return false;
}

/** 
 *******************************************************************************
 * @brief Set the state of a dynamic service.
 * 
 * @param  service          IN  dynamic service 
 * @param  state            IN  state 
 * 
 * @retval true on success 
 * @retval false otherwise
 *******************************************************************************
 */
bool
_DynamicServiceSetState(_Service *service, _DynamicServiceState state)
{
    LS_ASSERT(service != NULL);
    LS_ASSERT(service->is_dynamic == true);

    service->state = state;
    //g_critical("Updating dynamic service state for: \"%s\", state: %d", service_name, state);
    return true;
}


/** 
 *******************************************************************************
 * @brief Get the state of a dynamic service.
 * 
 * @param  service  IN  dynamic service 
 * 
 * @retval  state
 *******************************************************************************
 */
_DynamicServiceState
_DynamicServiceGetState(_Service *service)
{
    LS_ASSERT(service != NULL);
    LS_ASSERT(service->is_dynamic == true);

    return service->state;
}

/** 
 *******************************************************************************
 * @brief Allocate and initialize a service map.
 * 
 * @param  service_map     IN  map 
 * @param  lserror                  OUT set on error 
 * 
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
_ServiceInitMap(GHashTable **service_map, LSError *lserror)
{
    LS_ASSERT(service_map != NULL);

    /* destroy the old service map -- any items in use are
     * ref-counted and will still exist after this call */
    if (*service_map) 
    {
        g_hash_table_destroy(*service_map);
    }

    /* create the new map */
    *service_map = g_hash_table_new_full(_LSServiceNameHash, _LSServiceNameEquals, NULL, (GDestroyNotify)_ServiceUnref);

    if (!*service_map)
    {
        _LSErrorSetOOM(lserror);
        return false;
    }

    return true;
}

/** 
 *******************************************************************************
 * @brief Initialize the service map that contains all services.
 * 
 * @param  lserror  OUT set on error 
 * 
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
ServiceInitMap(LSError *lserror)
{
    return _ServiceInitMap(&all_services, lserror);
}

/** 
 *******************************************************************************
 * @brief Initialize the dynamic service map that contains service states.
 * 
 * @param  lserror  OUT set on error 
 * 
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
DynamicServiceInitStateMap(LSError *lserror)
{
    return _ServiceInitMap(&dynamic_service_states, lserror);
}

/** 
 *******************************************************************************
 * @brief Parse (and validate) a service file.
 *
   @verbatim
   Example:

   [Luna Service]
   Name=com.palm.foo
   Exec=/path/to/executable
   @endverbatim
 * 
 * @param  path     IN  path to service file 
 * @param  lserror  OUT set on error 
 * 
 * @retval  service with ref count of 1 on success
 * @retval  NULL on failure
 *******************************************************************************
 */
_Service*
_ParseServiceFile(const char *service_file_dir, const char *service_file_name, LSError *lserror)
{
    GError *gerror = NULL;
    char *path = NULL;
    GKeyFile *key_file = NULL;
    char **provided_services = NULL;
    char **groups = NULL;
    char *exec_str = NULL;
    char *exec_str_with_prefix = NULL;
    char *type_str = NULL;
    bool is_dynamic = true;
    const char *service_group = NULL;
    _Service *new_service = NULL;

    path = g_strconcat(service_file_dir, "/", service_file_name, NULL);

    _ls_verbose("%s: parsing file: \"%s\"\n", __func__, path);

    key_file = g_key_file_new();

    if (!key_file)
    {
        _LSErrorSet(lserror, -1, "OOM: Could not create key file");
        goto error;
    }

    if (!g_key_file_load_from_file(key_file, path, G_KEY_FILE_NONE, &gerror))
    {
        _LSErrorSet(lserror, -1, "Error loading key file: \"%s\"\n", gerror->message);
        goto error;
    }

    gsize group_len = 0;
    groups = g_key_file_get_groups(key_file, &group_len);

    if (!groups)
    {
        _LSErrorSet(lserror, -1, "No service group in key file: \"%s\"\n", path);
        goto error;
    }

    int i = 0;
    int j = 0;

    for (i = 0; i < group_len && !service_group; i++)
    {
        for (j = 0; j < ARRAY_SIZE(service_group_names); j++)
        {
            if (strcmp(groups[i], service_group_names[j]) == 0)
            {
                service_group = service_group_names[j];
                break;
            }
        }

        if (j == ARRAY_SIZE(service_group_names))
        {
            g_warning("Found unknown group: \"%s\" in key file: \"%s\"\n", groups[i], path);
        }
    }

    if (!service_group)
    {
        _LSErrorSet(lserror, -1, "Could not find valid service group in key file: \"%s\"\n", path);
        goto error;
    }

    /* check for the keys */

    if (!g_key_file_has_key(key_file, service_group, SERVICE_NAME_KEY, &gerror))
    {
        _LSErrorSet(lserror, -1, "Error finding key: \"%s\" in key file: \"%s\"\n", SERVICE_NAME_KEY, path);
        goto error;
    } 
    
    if (!g_key_file_has_key(key_file, service_group, SERVICE_EXEC_KEY, &gerror))
    {
        _LSErrorSet(lserror, -1, "Error finding key: \"%s\" in key file: \"%s\"\n", SERVICE_EXEC_KEY, path);
        goto error;
    }

    /* provided services -- can be more than one */
    gsize provided_services_len = 0;
    provided_services = g_key_file_get_string_list(key_file, service_group, SERVICE_NAME_KEY, &provided_services_len, &gerror);

    if (!provided_services)
    {
        _LSErrorSet(lserror, -1, "No services found in key file: \"%s\", message: \"%s\"\n", path, gerror->message);
        goto error;
    }

    /* exec string */
    exec_str = g_key_file_get_value(key_file, service_group, SERVICE_EXEC_KEY, &gerror);
    
    if (!exec_str)
    {
        _LSErrorSet(lserror, -1, "No \"%s\" key found in key file: \"%s\", message: \"%s\"\n", SERVICE_EXEC_KEY, path, gerror->message);
        goto error;
    }

    /* check for static string -- default to dynamic if we don't find one */
    type_str = g_key_file_get_value(key_file, service_group, SERVICE_TYPE_KEY, &gerror);

    /* ignore it since it's not required */
    if (!type_str)
    {
        g_error_free(gerror);
        gerror = NULL;
    }
    else
    {
        if (strcmp(type_str, SERVICE_TYPE_DYNAMIC) == 0)
        {
            is_dynamic = true;
        }
        else if (strcmp(type_str, SERVICE_TYPE_STATIC) == 0)
        {
            is_dynamic = false;
        }
        else
        {
            _LSErrorSet(lserror, -1, "Unrecognized service type: \"%s\"", type_str);
            goto error;
        }
    }
   
    /* we've got everything we need */
    
    for (i = 0; i < provided_services_len; i++)
    {
        _ls_verbose("%s: service file: \"%s\", provided service: \"%s\"\n", __func__, path, provided_services[i]);
    }

    if (g_conf_dynamic_service_exec_prefix)
    {
        exec_str_with_prefix = g_strdup_printf("%s %s", g_conf_dynamic_service_exec_prefix, exec_str);
    }
    else
    {
        exec_str_with_prefix = g_strdup(exec_str);
    }

    _ls_verbose("%s: service file: \"%s\", exec string: \"%s\"\n", __func__, path, exec_str_with_prefix);

    new_service = _ServiceNewRef((const char**)provided_services, provided_services_len, exec_str_with_prefix, is_dynamic, (char*)service_file_dir, (char*)service_file_name);

    if (!new_service)
    {
        _LSErrorSet(lserror, -1, "OOM: Could not create new Service");
        goto error;
    }
    
error:
    /* free up memory */
    if (path) g_free(path);
    if (key_file) g_key_file_free(key_file);
    if (groups) g_strfreev(groups);
    if (provided_services) g_strfreev(provided_services);
    if (exec_str) g_free(exec_str);
    if (exec_str_with_prefix) g_free(exec_str_with_prefix);
    if (type_str) g_free(type_str);
    if (gerror) g_error_free(gerror);

    return new_service;
}

/** 
 *******************************************************************************
 * @brief Parse a service directory.
 * 
 * @param  path     IN  path to directory 
 * @param  lserror  OUT set on error 
 * 
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
ParseServiceDirectory(const char *path, LSError *lserror)
{
    GError *gerror = NULL;
    const char *filename = NULL;

    _ls_verbose("%s: parsing service directory: \"%s\"\n", __func__, path);

    GDir *dir = g_dir_open(path, 0, &gerror);

    if (!dir)
    {
        _LSErrorSetFromGError(lserror, gerror);
        return false;
    }

    while ((filename = g_dir_read_name(dir)) != NULL)
    {
        /* check file extension */
        if (g_str_has_suffix(filename, SERVICE_FILE_SUFFIX))
        {
            /* get newly created and ref'd service */
            _Service *new_service = _ParseServiceFile(path, filename, lserror);

            if (new_service)
            {
                /* hash up the new service */
                if (!_ServiceMapAdd(new_service, lserror))
                {
                    LSErrorPrint(lserror, stderr);
                    LSErrorFree(lserror);
                }
                _ServiceUnref(new_service);
            }
            else
            {
                LSErrorPrint(lserror, stderr);
                LSErrorFree(lserror);
            }
        }
        else
        {
            g_critical("WARNING: file \"%s/%s\" does not have correct service file extension: "
                       "\"%s\"; ignoring file", path, filename, SERVICE_FILE_SUFFIX);
        }
    }

    g_dir_close(dir);

    return true;
}


/** 
 *******************************************************************************
 * @brief Send a signal to all registered clients that the config file scanning
 * is complete
 *******************************************************************************
 */
bool
LSHubSendConfScanCompleteSignal(void)
{
    char *payload = "{\"returnValue\": true, \"status\": \"scan complete\"}";

    _LSTransportMessage *message = LSTransportMessageSignalNewRef(HUB_CONTROL_CATEGORY, HUB_CONF_SCAN_COMPLETE_METHOD, payload);

    if (message)
    {
        _LSHubHandleSignal(message, true);
        _LSTransportMessageUnref(message);
        return true;
    }
    else
    {
        g_critical("Unable to send config scan complete signal");
        return false;
    }
}


/** 
 *******************************************************************************
 * @brief Send a signal to all registered clients that a service is up or
 * down.
 *
 * Don't use this directly. Instead use @ref _LSHubSendServiceDownSignal and
 * @ref _LSHubSendServiceUpSignal.
 * 
 * @param  service_name     IN   common name of service changing state (e.g.,
 * com.palm.foo)
 * @param  unique_name      IN   unique name of service changing state 
 * @param  service_pid      IN   pid of executable that registered service (might be 0), only used if service is coming up
 * @param  all_names        IN   JSON fragment placed inside an array, listed all service names that might be used by executable, only used if service is coming up
 * @param  up               IN   true if service is coming up, false otherwise 
 *******************************************************************************
 */
static void
_LSHubSendServiceUpDownSignal(const char *service_name, const char *unique_name, pid_t service_pid, const char * all_names, bool up)
{
    LS_ASSERT(service_name != NULL);
    LS_ASSERT(unique_name != NULL);

    char *payload = NULL;

    if (up)
    {
        payload = g_strdup_printf(SERVICE_STATUS_UP_PAYLOAD, service_name, unique_name, service_pid, all_names ? all_names : "");
    }
    else
    {
        payload = g_strdup_printf(SERVICE_STATUS_DOWN_PAYLOAD, service_name, unique_name);
    }

    if (!payload)
    {
        g_critical("OOM: Unable to send client up/down signal");
        return;
    }

    _LSTransportMessage *message = LSTransportMessageSignalNewRef(SERVICE_STATUS_CATEGORY, service_name, payload);

    if (message)
    {
        /* send out this "special" status signal to registered clients */
        if (up)
        {
            _LSTransportMessageSetType(message, _LSTransportMessageTypeServiceUpSignal);
        }
        else
        {
            _LSTransportMessageSetType(message, _LSTransportMessageTypeServiceDownSignal);
        }

        //g_critical("%s: sending \"service %s\" signal for unique_name: \"%s\", service_name: \"%s\"", __func__, up ? "up" : "down", unique_name, service_name);
        _LSHubHandleSignal(message, true);
        _LSTransportMessageUnref(message);
    }
    else
    {
        g_critical("Unable to send client up/down signal");
    }

    g_free(payload);
}

/** 
 *******************************************************************************
 * @brief Send a signal to all registered clients that a service is down.
 * 
 * @param  service_name     IN   common name of service going down (e.g.,
 * com.palm.foo)
 * @param  unique_name      IN   unique name of service going down 
 *******************************************************************************
 */
static void
_LSHubSendServiceDownSignal(const char *service_name, const char *unique_name)
{
    _LSHubSendServiceUpDownSignal(service_name, unique_name, 0, NULL, false);
}

/** 
 *******************************************************************************
 * @brief Send a signal to all registered clients that a service is up.
 * 
 * @param  service_name     IN   common name of service coming up (e.g.,
 * com.palm.foo)
 * @param  unique_name      IN   unique name of service coming up 
 *******************************************************************************
 */
static void
_LSHubSendServiceUpSignal(const char *service_name, const char *unique_name, pid_t service_pid, const char * all_names)
{
    _LSHubSendServiceUpDownSignal(service_name, unique_name, service_pid, all_names, true);
}

/** 
 *******************************************************************************
 * @brief Handle a client that is disconnecting.
 * 
 * @param  client   IN  client that is going away 
 * @param  type     IN  type of disconnect (clean, dirty, etc.) 
 *******************************************************************************
 */
void
_LSHubHandleDisconnect(_LSTransportClient *client, _LSTransportDisconnectType type, void *context)
{
    LSError lserror;
    LSErrorInit(&lserror);

    /* look up _ClientId */
    _ClientId *id = g_hash_table_lookup(connected_clients.by_fd, GINT_TO_POINTER(client->channel.fd));

    if (!id)
    {
        /* 
         * This can happen if the name was already taken when attempting to
         * register in _LSHubHandleRequestNameLocal
         */
        g_warning("We received a disconnect message for client: %p, but couldn't find it in the client map", client);
        //LS_ASSERT(0);
        return;
    }

    /* remove from available_services and/or pending */
    if (id->service_name != NULL)
    {
        _Service *service = _ServiceMapLookup(id->service_name);
        bool is_dynamic = service && service->is_dynamic;

        _ls_verbose("%s: disconnecting: \"%s\"\n", __func__, id->service_name);
        
        /* send out a server status message to registered clients to let them know
         * that the client is down */
        _LSHubSendServiceDownSignal(id->service_name, id->local.name);

        if (g_conf_log_service_status)
        {
            const _LSTransportCred *cred = _LSTransportClientGetCred(client);
            pid_t pid = _LSTransportCredGetPid(cred);
            g_message("SERVICE: ServiceDown (name: \"%s\", dynamic: %s, pid: "LS_PID_PRINTF_FORMAT", "
                      "exe: \"%s\", cmdline: \"%s\")",
                       id->service_name, is_dynamic ? "true" : "false",
                       LS_PID_PRINTF_CAST(pid),
                       _LSTransportCredGetExePath(cred),
                       _LSTransportCredGetCmdLine(cred));
        }
        
        g_hash_table_remove(pending, id->service_name);
        g_hash_table_remove(available_services, id->service_name);

        /* Send a failure QueryNameReply to any service that is still
         * waiting for this service */
        if (!_LSHubSendServiceWaitListReply(id, false, is_dynamic, &lserror))
        {
            LSErrorPrint(&lserror, stderr);
            LSErrorFree(&lserror);
        }

        /* LEGACY: If we were launched via luna-helper, then we need to
         * make sure that we set our dynamic service state to not running.
         * What happens is that the helper process is reaped before the
         * service actually comes up. When the service comes up, it sets
         * it state to running, but we never set the state back to not
         * running.
         *
         * TODO:
         * We could set the dynamic service state to not running here for
         * all dynamic services, but then we run the risk of having two
         * instances of a service running (one that has just unregistered
         * but not died) and the other that is launched because the service
         * is requested. This is correct from a service perspective (i.e.,
         * the service is only actually registered for one), but the
         * processes may try to contend for other resources (or it may be
         * a daemon that only expects a single instance to be running).
         */
        _Service *dynamic = _DynamicServiceStateMapLookup(id->service_name);
        if (dynamic && dynamic->uses_launch_helper)
        {
            _DynamicServiceSetState(dynamic, _DynamicServiceStateStopped);
            _DynamicServiceStateMapRemove(dynamic);
        }
        else if (dynamic && dynamic->state == _DynamicServiceStateRunning)
        {
            /* The service was launched manually so we'll never get the
             * _DynamicServiceReap callback */
            _DynamicServiceSetState(dynamic, _DynamicServiceStateStopped);
            //_DynamicServiceUnref(dynamic);
            _DynamicServiceStateMapRemove(dynamic);
        }
    }
    
    /* NOV-93826: Send out status messages for non-services as well because
     * subscriptions use this to keep track of connected clients
     *
     * In this case we set the service name to the unique name 
     * for legacy compatiblity */
    _LSHubSendServiceDownSignal(id->local.name, id->local.name);
    
    /* Update state if the monitor is disconnecting */
    if (id->is_monitor)
    {
        _ls_verbose("%s: monitor disconnected\n", __func__);
        id->is_monitor = false;
        _LSHubClientIdLocalUnref(monitor);
        monitor = NULL;
    }
    
    /* remove the socket file; we do this in the hub so that we clean up
     * even if the client crashes */
    _LSHubCleanupSocketLocal(id->local.name);
    
    /* remove from connected list */
    g_hash_table_remove(connected_clients.by_fd, GINT_TO_POINTER(client->channel.fd));
    g_hash_table_remove(connected_clients.by_unique_name, id->local.name);

    /* SIGNAL: remove all instances of client from _SignalMap */
    _LSHubRemoveClientSignals(client);

    /* Remove the client from the active role map */
    if (!LSHubActiveRoleMapClientRemove(client, &lserror))
    {
        LSErrorPrint(&lserror, stderr);
        LSErrorFree(&lserror);
    }

    /* transport code will handle cleaning up the client and removing the watches */
}

/** 
 *******************************************************************************
 * @brief Allocate memory for a new client id.
 * 
 * @param  service_name     IN  name of service provided by client (or NULL) 
 * @param  unique_name      IN  unique name of client 
 * @param  client           IN  underlying transport client 
 * 
 * @retval  client on success
 * @retval  NULL on failure
 *******************************************************************************
 */
static _ClientId*
_LSHubClientIdLocalNew(const char *service_name, const char *unique_name, _LSTransportClient *client)
{
    _ClientId *id = g_new0(_ClientId, 1);

    if (!id)
    {
        return NULL;
    }

    /* TODO: handle errors */
    id->service_name = g_strdup(service_name);
    id->local.name = g_strdup(unique_name);
    _LSTransportClientRef(client);
    id->client = client;
    id->is_monitor = false;

    return id;
} 

/** 
 *******************************************************************************
 * @brief Free a client id.
 * 
 * @param  id   IN  client id to free 
 *******************************************************************************
 */
static void
_LSHubClientIdLocalFree(_ClientId *id)
{
    LS_ASSERT(id != NULL);
    LS_ASSERT(id->ref == 0);
    
    if (id->service_name) g_free(id->service_name);
    if (id->local.name) g_free(id->local.name);
    _LSTransportClientUnref(id->client);

#ifdef MEMCHECK
    memset(id, 0xFF, sizeof(_ClientId));
#endif

    g_free(id);
}

/** 
 *******************************************************************************
 * @brief Allocate memory for a new client id with ref count of 1.
 * 
 * @param  service_name     IN  name of service provided by client (or NULL) 
 * @param  unique_name      IN  unique name of client 
 * @param  client           IN  underlying transport client 
 * 
 * @retval  client on success
 * @retval  NULL on failure
 *******************************************************************************
 */
static _ClientId*
_LSHubClientIdLocalNewRef(const char *service_name, const char *unique_name, _LSTransportClient *client)
{
    _ClientId *id = _LSHubClientIdLocalNew(service_name, unique_name, client);

    if (id)
    {
        id->ref = 1;
    }

    return id;
}

/** 
 *******************************************************************************
 * @brief Increment ref count of client id.
 * 
 * @param  id   IN  client id 
 *******************************************************************************
 */
static void
_LSHubClientIdLocalRef(_ClientId *id)
{
    LS_ASSERT(id != NULL);
    LS_ASSERT(g_atomic_int_get(&id->ref) > 0);

    g_atomic_int_inc(&id->ref);
    
    _ls_verbose("%s: %d (%p)\n", __func__, id->ref, id);
}

/** 
 *******************************************************************************
 * @brief Decrement ref count of client id.
 * 
 * @param  id   IN  client id 
 *******************************************************************************
 */
static void
_LSHubClientIdLocalUnref(_ClientId *id)
{
    LS_ASSERT(id != NULL);
    LS_ASSERT(g_atomic_int_get(&id->ref) > 0);

    if (g_atomic_int_dec_and_test(&id->ref))
    {
        _ls_verbose("%s: %d (%p)\n", __func__, id->ref, id);
        _LSHubClientIdLocalFree(id);
    }
    else
    {
        _ls_verbose("%s: %d (%p)\n", __func__, id->ref, id);
    }
}

static void
_LSHubClientIdLocalUnrefVoid(void *id)
{
    _LSHubClientIdLocalUnref((_ClientId*) id);
}

/** 
 *******************************************************************************
 * @brief Construct a message as the reply to a request name message that has a
 * payload containing an error code, a boolean and a string.
 * 
 * @param  message     IN  message to which this error is a reply 
 * @param  type        IN  type of error 
 * @param  err_code    IN  numeric error code 
 * @param  ret_str     IN  error string
 * @param  privileged  IN true if the service is privileged
 * @param  lserror     OUT set on error 
 * 
 * @retval  message on success
 * @retval  NULL on failure 
 *******************************************************************************
 */
static _LSTransportMessage*
_LSHubConstructRequestNameReply(_LSTransportMessage *message, 
                                _LSTransportMessageType type, long err_code,
                                const char *ret_str, bool privileged, LSError *lserror)
{
    _LSTransportMessageIter iter;

    _LSTransportMessage *reply_message = _LSTransportMessageNewRef(LS_TRANSPORT_MESSAGE_DEFAULT_PAYLOAD_SIZE);

    if (!reply_message) goto error;

    _LSTransportMessageSetType(reply_message, type);

    _LSTransportMessageIterInit(reply_message, &iter);
    if (!_LSTransportMessageAppendInt32(&iter, err_code)) goto error;
    if (!_LSTransportMessageAppendBool(&iter, privileged)) goto error;
    if (!_LSTransportMessageAppendString(&iter, ret_str)) goto error;
    if (!_LSTransportMessageAppendInvalid(&iter)) goto error;

    return reply_message;

error:
    if (reply_message) _LSTransportMessageUnref(reply_message);
    _LSErrorSetOOM(lserror);
    return NULL;
}

/** 
 *******************************************************************************
 * @brief Send a reply to a request name message.
 * 
 * @param  message      IN  request name message 
 * @param  err_code     IN  numeric error code (0 means success) 
 * @param  ret_str      IN  return string 
 * @param  lserror      OUT set on error 
 * 
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
static bool
_LSHubSendRequestNameReply(_LSTransportMessage *message, _LSTransportType transport_type,
                           long err_code, char* ret_str, LSError *lserror)
{
    int fd = -1;

    _LSTransportClient *client = _LSTransportMessageGetClient(message);

    if (!client)
    {
        LS_ASSERT(0);
    }

    _LSTransportMessageType message_type;

    if (transport_type == _LSTransportTypeLocal)
    {
        message_type = _LSTransportMessageTypeRequestNameLocalReply;

        /* tdh -- if replying with success, then go ahead and set up socket for
         * listening */
        if (err_code == 0)
        {
            /* read and write only by hub user (root) */
            if (!_LSTransportListenLocal(ret_str, S_IRUSR | S_IWUSR, &fd, lserror))
            {
                return false;
            }
        }
    }
    else
    {
        message_type = _LSTransportMessageTypeRequestNameInetReply;
    }

    _LSTransportMessage *reply_message = _LSHubConstructRequestNameReply(message, message_type, err_code, ret_str, LSHubClientGetPrivileged(client), lserror);

    if (!reply_message)
    {
        return false;
    }

    if (transport_type == _LSTransportTypeLocal)
    {
        _LSTransportMessageSetConnectionFd(reply_message, fd);
    }

    if (!_LSTransportSendMessage(reply_message, client, NULL, lserror))
    {
        _LSTransportMessageUnref(reply_message);
        return false;
    }

    _LSTransportMessageUnref(reply_message);

    return true;
}

static void
_LSHubCleanupSocketLocal(const char *unique_name)
{
    int ret = unlink(unique_name);

    if (ret != 0)
    {
        g_warning("Error removing socket: \"%s\"", g_strerror(errno));
    }
}

/** 
 *******************************************************************************
 * @brief Returns true if the service_name is for the media service, which
 * behaves differently than all other static and dynamic services and does
 * not have a static service file.
 * 
 * @param  service_name 
 * 
 * @retval  media service_name pointer if a media service
 * @retval  null pointer otherwise
 *******************************************************************************
 */
inline const char*
IsMediaService(const char *service_name)
{
    if (NULL == service_name)
    {
        return NULL;
    }

    int i = 0;
    for (i = 0; i < ARRAY_SIZE(media_service_names); i++)
    {
        /* match just the part of the name that doesn't change 
         * ( i.e., same as com.palm.mediad.* and com.palm.umediapipeline* ) */
        if (strncmp(media_service_names[i], service_name, strlen(media_service_names[i])) == 0)
        {
            return media_service_names[i];
        }
    }

    return NULL;
}

/** 
 *******************************************************************************
 * @brief Handle a "RequestName" message for a local (unix domain socket)
 * connection or inet connection.
 * 
 * @param  message  IN  request name message
 *******************************************************************************
 */
static void
_LSHubHandleRequestName(_LSTransportMessage *message)
{
    /* TODO: we need to make sure that we can't accidentally create
     * or open these from another process... is there a way to use 
     * mkstemp() with a socket ? -- maybe use PID of requester */
    LSError lserror;
    LSErrorInit(&lserror);

    _LSTransportMessageIter iter;
    char *unique_name = NULL;
    
    _LSTransportClient *client = _LSTransportMessageGetClient(message);

    if (!client)
    {
        g_critical("Unable to get client from message");
        goto error;
    }

    _LSTransportType transport_type = _LSTransportGetTransportType(client->transport);
    _LSTransportMessageIterInit(message, &iter);

    /* Is the client's version compatible with ours? */
    int32_t protocol_version = 0;
    _LSTransportMessageGetInt32(&iter, &protocol_version);

    if (protocol_version != LS_TRANSPORT_PROTOCOL_VERSION)
    {
        g_critical("Transport protocol mismatch. Client version: %d. Hub version: %d",
                    protocol_version, LS_TRANSPORT_PROTOCOL_VERSION);

        if (!_LSHubSendRequestNameReply(message, transport_type, LS_TRANSPORT_REQUEST_NAME_INVALID_PROTOCOL_VERSION, NULL, &lserror))
        {
            LSErrorPrint(&lserror, stderr);
            LSErrorFree(&lserror);
        }
        return;
    }
    
    /* get service name */
    const char *service_name = NULL;
    _LSTransportMessageIterNext(&iter);
    _LSTransportMessageGetString(&iter, &service_name); 

    _ls_verbose("%s: service_name: \"%s\"\n", __func__, service_name);
    
    if (NULL == IsMediaService(service_name))
    {
        /* Check security permissions */
        if (!LSHubIsClientAllowedToRequestName(client, service_name))
        {
            if (!_LSHubSendRequestNameReply(message, transport_type, LS_TRANSPORT_REQUEST_NAME_PERMISSION_DENIED, NULL, &lserror))
            {
                LSErrorPrint(&lserror, stderr);
                LSErrorFree(&lserror);
            }
            return;
        }
    }
    else
    {
        _ls_verbose("%s: \"%s\" is a media service -- skipping client permissions check\n", __func__, service_name);
    }

    if (NULL != service_name)
    {
        /* look up requested name and make sure that it's not already in use */
        if (g_hash_table_lookup(pending, service_name) || g_hash_table_lookup(available_services, service_name))
        {
            /* construct and send error reply */
            if (!_LSHubSendRequestNameReply(message, transport_type, LS_TRANSPORT_REQUEST_NAME_NAME_ALREADY_REGISTERED, NULL, &lserror))
            {
                LSErrorPrint(&lserror, stderr);
                LSErrorFree(&lserror);
            }
            return;
        }
    }

    if (transport_type == _LSTransportTypeLocal)
    {
        /* generate a unique name */
        unique_name = g_strdup_printf("%s/XXXXXX", *local_socket_path);

        if (!unique_name)
        {
            g_critical("OOM: Unable to create unique name");
            goto error;
        }

        int temp_fd = mkstemp(unique_name);

        if (temp_fd < 0)
        {
            /* TODO: test that this is the right error condition */
            g_critical("Unable to create unique name");
            goto error;
        }
        close(temp_fd);
    }
    else
    {
        /* get the ip address */
        int fd = _LSTransportChannelGetFd(_LSTransportClientGetChannel(client));

        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(addr);
        
        if (getpeername(fd, (struct sockaddr*) &addr, &addrlen) != 0)
        {
            g_critical("getpeername failed");
            goto error;
        }

        /* inet -- port is sent by far side and is in the
         * message after the service name */
        _LSTransportMessageIterNext(&iter);
        int32_t port;
        
        if (!_LSTransportMessageGetInt32(&iter, &port))
        {
            goto error;
        }
        
        char inet_buf[INET_ADDRSTRLEN];
        unique_name = g_strdup_printf("%s:%"PRId32, inet_ntop(AF_INET, &addr.sin_addr, inet_buf, sizeof(inet_buf)), port);

        if (unique_name == NULL)
        {
            g_critical("OOM: Failed to duplicate unique name");
            goto error;
        }
    }
    
    _ls_verbose("%s: unique_name: \"%s\"\n", __func__, unique_name);
    

    /* add client id to client lookup (refs client) */
    _ClientId *id = _LSHubClientIdLocalNewRef(service_name, unique_name, client);

    if (!id)
    {
        g_critical("OOM: unable to create client id");
        goto error;
    }
    
    /* add unique name to pending hash if they are registering a service name */
    if (id->service_name)
    {
        _LSHubClientIdLocalRef(id);
        g_hash_table_replace(pending, (gpointer)id->service_name, id);
    }

    /* hash clientId with fd as key */
    _LSHubClientIdLocalRef(id);
    g_hash_table_replace(connected_clients.by_fd, GINT_TO_POINTER(client->channel.fd), id);
    
    /* hash clientId with unique name as key */
    _LSHubClientIdLocalRef(id);
    g_hash_table_replace(connected_clients.by_unique_name, id->local.name, id);
  
    _LSHubClientIdLocalUnref(id);

    /* send reply with name */
    if (!_LSHubSendRequestNameReply(message, transport_type, LS_TRANSPORT_REQUEST_NAME_SUCCESS, unique_name, &lserror))
    {
        LSErrorPrint(&lserror, stdout);
        LSErrorFree(&lserror);

        /* TODO: can we do anything else if there's an error ? */
    }

error:
    if (unique_name) g_free(unique_name);
}

static void
_LSHubQueryNameReplyReplaceErrorCode(_LSTransportMessage *reply_message, long err_code)
{
    /* FIXME: This is only safe because the error code is not a variable length type
     * We should come up with a better way to generalize this */
    _LSTransportMessageIter iter;
    _LSTransportMessageIterInit(reply_message, &iter);
    _LSTransportMessageAppendInt32(&iter, err_code);
}

static gboolean
_LSHubHandleConnectReady(GIOChannel *channel, GIOCondition cond, _LSTransportMessage *message)
{
    LSError lserror;
    LSErrorInit(&lserror);

    bool connected = false;
    int fd = g_io_channel_unix_get_fd(channel);
        
    _LSTransportMessageType type = _LSTransportMessageGetType(message);
    LS_ASSERT(type == _LSTransportMessageTypeQueryNameReply || type == _LSTransportMessageTypeMonitorConnected);

    switch (_LSTransportMessageGetConnectState(message))
    {
    case _LSTransportConnectStateEagain:
    {
        /* need to attempt to connect again now that socket is ready for
         * writing */
        const char *unique_name = NULL;

        if (type == _LSTransportMessageTypeQueryNameReply)
        {
            unique_name = _LSTransportQueryNameReplyGetUniqueName(message);
        }
        else
        {
            LS_ASSERT(type == _LSTransportMessageTypeMonitorConnected);
            unique_name = _LSTransportMessageGetBody(message);
        }
       
        /* attempt to connect() the existing socket */ 
        _LSTransportConnectState new_state = _LSTransportConnectLocal(unique_name, false, &fd, &lserror);
        switch (new_state)
        {
        case _LSTransportConnectStateEinprogress:
        case _LSTransportConnectStateEagain:
            return TRUE;    /* try again until we hit the timeout */
            break;
        case _LSTransportConnectStateOtherFailure:
            /* fatal error */
            break;
        case _LSTransportConnectStateNoError:
            connected = true;
            break;
        default:
            LS_ASSERT(0);
            break;
        }

        break;
    }

    case _LSTransportConnectStateEinprogress:
    {
        int ret = 0;
        socklen_t ret_size = sizeof(ret);
        
        /* check to see if we connect()'ed */
        int opt_ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &ret, &ret_size);
        if (opt_ret != 0)
        {
            g_warning("getsockopt failed for fd: %d, errno: %d, error: %s", fd, errno, g_strerror(errno));
            return FALSE;   /* don't call again */
        }

        if (ret != 0)
        {
            _LSTransportMessageType type = _LSTransportMessageGetType(message);
            /* connect failed, so send error return message */
            if (type == _LSTransportMessageTypeQueryNameReply)
            {
                _LSHubQueryNameReplyReplaceErrorCode(message, LS_TRANSPORT_QUERY_NAME_SERVICE_NOT_AVAILABLE);
            }
            /* else we have _LSTransportMessageTypeMonitorConnected, which has
             * no error code in its body */
        }
        else
        {
            connected = true;
        }

        break;
    }

    default:
        g_warning("%s: Invalid state: %d", __FUNCTION__, _LSTransportMessageGetConnectState(message));
        LS_ASSERT(0);
    }

    if (connected)
    {
        /* make sure message has connected fd set */
        _LSTransportMessageSetConnectionFd(message, fd);

        _LSTransportMessageSetConnectState(message, _LSTransportConnectStateNoError);

        /* FIXME: remove this */
        _LSTransportFdSetBlock(fd, NULL);
    }
    else
    {
        /* close the open fd */
        close(fd);

        /* not connected, so don't send a valid fd */
        _LSTransportMessageSetConnectionFd(message, -1);
    }
        
    _LSTransportClient *client = _LSTransportMessageGetClient(message);
    
    if (!_LSTransportSendMessage(message, client, NULL, &lserror))
    {
        LSErrorPrint(&lserror, stderr);
        LSErrorFree(&lserror);
    }

    /* remove timeout */
    _LSHubRemoveConnectMessageTimeout(message);

    /* ref associated with callback */
    _LSTransportMessageUnref(message);

    g_io_channel_unref(channel);

    return FALSE;
}

/** 
 *******************************************************************************
 * @brief Send a reply to a "QueryName" message.
 * 
 * @param  message       IN     query name message to which we are replying 
 * @param  err_code      IN     numeric error code (0 means success) 
 * @param  service_name  IN     requested service name 
 * @param  unique_name   IN     unique name of requested service 
 * @param  is_dynamic    IN     true if the service is dynamic
 * @param  lserror       OUT    set on error 
 * 
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
static bool
_LSHubSendQueryNameReply(const _LSTransportMessage *message, long err_code,
                         const char *service_name, const char *unique_name, bool is_dynamic, LSError *lserror)
{
    LS_ASSERT(message != NULL);
    LS_ASSERT(service_name != NULL);

    _LSTransportMessageIter iter;
    bool send = true;
    bool ret = true;

    _LSTransportClient *client = _LSTransportMessageGetClient(message);

    if (!client)
    {
        LS_ASSERT(0);
    }
    
    _LSTransportMessage *reply_message = _LSTransportMessageNewRef(LS_TRANSPORT_MESSAGE_DEFAULT_PAYLOAD_SIZE);

    if (!reply_message) goto error;
    
    _LSTransportMessageSetType(reply_message, _LSTransportMessageTypeQueryNameReply);

    _LSTransportMessageIterInit(reply_message, &iter);

    _LSTransportMessageAppendInt32(&iter, err_code);
    if (!_LSTransportMessageAppendString(&iter, service_name)) goto error;
    if (!_LSTransportMessageAppendString(&iter, unique_name)) goto error;
    if (!_LSTransportMessageAppendInt32(&iter, is_dynamic)) goto error;
    if (!_LSTransportMessageAppendInvalid(&iter)) goto error;

    int fd = -1;
    _LSTransportConnectState connect_state = _LSTransportConnectStateNoError;
    if (err_code >= 0 &&
        _LSTransportGetTransportType(_LSTransportClientGetTransport(client)) == _LSTransportTypeLocal)
    {
        connect_state = _LSTransportConnectLocal(unique_name, true, &fd, lserror);

        _LSTransportMessageSetConnectState(reply_message, connect_state);

        switch (connect_state)
        {
        case _LSTransportConnectStateNoError:
            /* success */
            break;
        case _LSTransportConnectStateEagain:
        case _LSTransportConnectStateEinprogress:
            _LSHubAddPendingConnect(reply_message, client, fd);

            /* We don't want to send the message since we haven't connect()'ed yet */
            send = false;
            break;
        case _LSTransportConnectStateOtherFailure:
            /* fatal connect() error */

            g_warning("%s: could not connect to %s service \"%s\"", __func__,
                is_dynamic ? "dynamic" : "static", service_name);

            ret = false;

            // Replace original passed-in error code with this error
            err_code = LS_TRANSPORT_QUERY_NAME_SERVICE_NOT_AVAILABLE;
            _LSHubQueryNameReplyReplaceErrorCode(reply_message, err_code);
            break;
        default:
            g_critical("%s: Invalid connect state: %d", __FUNCTION__, connect_state);
            LS_ASSERT(0);
        }
    }
    
    _ls_verbose("%s: err_code: %ld, service_name: \"%s\", unique_name: \"%s\", %s, fd %d\n", __func__,
        err_code, service_name, unique_name, is_dynamic ? "dynamic" : "static", fd);

    /* set the connection fd on the message, which indicates that the fd
     * should be sent */

    /* Go ahead and set the fd to -1 on error */
    _LSTransportMessageSetConnectionFd(reply_message, fd);

    if (send && !_LSTransportSendMessage(reply_message, client, NULL, lserror))
    {
        ret = false;
    }

    _LSTransportMessageUnref(reply_message);

    return ret;

error:
    if (reply_message) _LSTransportMessageUnref(reply_message);    
    _LSErrorSetOOM(lserror);
    return false;
}

/** 
 *******************************************************************************
 * @brief Send a query name reply to all clients waiting for this service.
 * The reply can be "success" or "failure".
 * 
 * @param  id           IN      id of service 
 * @param  success      IN      on true send success, otherwise send failure 
 * @param  is_dynamic   IN      true if service is dynamic
 * @param  lserror      OUT     set on error 
 * 
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
static bool
_LSHubSendServiceWaitListReply(_ClientId *id, bool success, bool is_dynamic, LSError *lserror)
{
    long ret_code;

    if (success)
    {
        ret_code = LS_TRANSPORT_QUERY_NAME_SUCCESS;
    }
    else
    {
        ret_code = LS_TRANSPORT_QUERY_NAME_SERVICE_NOT_AVAILABLE;
    }

    /* 
     * Multiple clients may be waiting for this service, so we iterate over
     * all of those waiting and send replies
     */

    GSList *iter = waiting_for_service;
    while (iter)
    {
        _LSTransportMessage *query_message = (_LSTransportMessage*)iter->data;
        const char *requested_service = _LSTransportMessageTypeQueryNameGetQueryName(query_message);
       
        if (strcmp(requested_service, id->service_name) == 0)
        {
            /* we found a client waiting for this service */

#ifdef DEBUG
            printf("Sending QueryNameReply for service: \"%s\" to client: \"%s\" (\"%s\")\n", id->service_name, query_message->client->service_name, query_message->client->unique_name);
#endif

            if (!_LSHubSendQueryNameReply(query_message, ret_code, requested_service, id->local.name, is_dynamic, lserror))
            {
                LSErrorPrint(lserror, stderr);
                LSErrorFree(lserror);
            }

            /* remove the timeout if there is one */
            _LSHubRemoveMessageTimeout(query_message);

            /* ref associated with waiting_for_service list */
            _LSTransportMessageUnref(query_message);

            GSList *remove_node = iter;
            iter = g_slist_next(iter);

            waiting_for_service = g_slist_delete_link(waiting_for_service, remove_node);
        }
        else
        {
            iter = g_slist_next(iter);
        }
    }

    return true;
}

void
DumpHashItem(gpointer key, gpointer value, gpointer user_data)
{
    printf("key: \"%s\", value: %p\n", (char*)key, value);
}

void
DumpHashTable(GHashTable *table)
{
    LS_ASSERT(table != NULL);

    g_hash_table_foreach(table, DumpHashItem, NULL);
    printf("\n");
    fflush(stdout);
}

/** 
 *******************************************************************************
 * @brief Process a "NodeUp" message.
 * 
 * @param  message  IN      node up message to process
 *******************************************************************************
 */
static void
_LSHubHandleNodeUp(_LSTransportMessage *message)
{
    _ls_verbose("%s\n", __func__);

    LSError lserror;
    LSErrorInit(&lserror);

#ifdef DEBUG
    printf("%s: pending hash table:\n", __func__);
    DumpHashTable(pending); 
    printf("%s: available_services hash table:\n", __func__);
    DumpHashTable(available_services);
#endif

    /* the node is up, so move it to the list of available services */
    _LSTransportClient *client = _LSTransportMessageGetClient(message);

    const char *exe_path = NULL;

    gchar * allowed_names = NULL;
    
    /* Use exe_path in client credentials to look up role file and allowed service names */
    const _LSTransportCred *cred = _LSTransportClientGetCred(client);

    pid_t pid = _LSTransportCredGetPid(cred);

    /* 
     * FIXME: this won't work if we want to mux multiple services in the same
     * process through the same connection
     */
    _ClientId *id = g_hash_table_lookup(connected_clients.by_fd, GINT_TO_POINTER(client->channel.fd));

    if (!id)
    {
        g_critical("Could not find client using fd");
        return;
    }

    if (!id->service_name)
    {
        /* A non-service came up. For legacy compatibility with subscriptions
         * we send a service status message, using the unique name as the
         * service name */
        gchar * allowed_name = g_strdup_printf("\"%s\"", id->local.name);
        _LSHubSendServiceUpSignal(id->local.name, id->local.name, pid, allowed_name);
        g_free(allowed_name);
        return;
    }

    LS_ASSERT(id->service_name != NULL);

    /* stealing doesn't call key and value destroy functions */
    if (!g_hash_table_steal(pending, id->service_name))
    {
        LS_ASSERT(0);
    }

    /* if it's a dynamic service, update its state to running */
    _Service *dynamic = _DynamicServiceStateMapLookup(id->service_name);
    if (dynamic)
    {
        _DynamicServiceState state = _DynamicServiceGetState(dynamic);

        if (state == _DynamicServiceStateSpawned)
        {
            /* launched dynamically */
            _DynamicServiceSetState(dynamic, _DynamicServiceStateRunningDynamic);
        }
        else if (state == _DynamicServiceStateStopped)
        {
            /* launched manually */
            _DynamicServiceSetState(dynamic, _DynamicServiceStateRunning);
        }
        else
        {
            g_critical("Unexpected dynamic service state: %d", state);
        }
    }

    /* move into the available hash */
    g_hash_table_replace(available_services, id->service_name, id);

    /* Go through list of clients waiting for a service to come up
     * and send them a message letting them know it is now up */
    if (!_LSHubSendServiceWaitListReply(id, true, dynamic ? dynamic->is_dynamic : false, &lserror))
    {
        LSErrorPrint(&lserror, stderr);
        LSErrorFree(&lserror);
    }

    if (cred)
        exe_path = _LSTransportCredGetExePath(cred);

    if (exe_path)
        allowed_names = LSHubRoleAllowedNamesForExe(exe_path);
   
    /* Let registered clients know that this service is up */ 
    _LSHubSendServiceUpSignal(id->service_name, id->local.name, pid, allowed_names);
    
    g_free(allowed_names);

    if (g_conf_log_service_status)
    {
        g_message("SERVICE: ServiceUp (name: \"%s\", dynamic: %s, pid: "LS_PID_PRINTF_FORMAT", "
                  "exe: \"%s\", cmdline: \"%s\")",
                   id->service_name, dynamic ? "true" : "false",
                   LS_PID_PRINTF_CAST(pid),
                   exe_path,
                   _LSTransportCredGetCmdLine(cred));
    }

#ifdef DEBUG
    printf("%s: pending hash table:\n", __func__);
    DumpHashTable(pending); 
    printf("%s: available_services hash table:\n", __func__);
    DumpHashTable(available_services); 

    printf("service is up: \"%s\"\n", id->service_name);
#endif
}

/** 
 *******************************************************************************
 * @brief Set the specified message to be sent when it can successfully
 * connect() to its destination (or timeout).
 * 
 * @param  message  IN  message that failed to connect() due to EINPROGRESS
 *                      (would block)
 * @param  client   IN  destination client for message
 * @param  fd       IN  fd used for connect() attempt
 *******************************************************************************
 */
static void
_LSHubAddPendingConnect(_LSTransportMessage *message, _LSTransportClient *client, int fd)
{
    /* TODO: use LSTransportChannel abstraction and consider moving
     * this function to the transport level if we want to use it on
     * the client side (e.g., for inet) */

    /* save the client so we know who to send the reply to */
    _LSTransportMessageSetClient(message, client);

    /* wait for writability on this socket -- see connect() man page */
    GIOChannel *channel = g_io_channel_unix_new(fd);
    g_io_channel_set_close_on_unref(channel, FALSE);
    _LSTransportMessageRef(message);
    g_io_add_watch(channel, G_IO_OUT, (GIOFunc) _LSHubHandleConnectReady, message);
            
    _LSHubAddConnectMessageTimeout(message);
}

/** 
 *******************************************************************************
 * @brief Send a failure response to a query name message that timed out.
 * 
 * @param  message  IN  query name message that timed out 
 * 
 * @retval FALSE always so the timer does not fire again
 *******************************************************************************
 */
gboolean
_LSHubHandleQueryNameTimeout(_LSTransportMessage *message)
{
    LSError lserror;
    LSErrorInit(&lserror);

    /* remove the message from the waiting list */
    waiting_for_service = g_slist_remove(waiting_for_service, message);

    const char *requested_service = _LSTransportMessageTypeQueryNameGetQueryName(message);

    if (!requested_service)
    {
        g_critical("Failed to get service name for timeout message");
        goto exit;
    }

    /* the service didn't come up in time, so send a failure message */
    if (!_LSHubSendQueryNameReply(message, LS_TRANSPORT_QUERY_NAME_TIMEOUT, requested_service, NULL, false, &lserror))
    {
        LSErrorPrint(&lserror, stderr);
        LSErrorFree(&lserror);
    }

exit:
    /* refcount associated with the list */ 
    _LSTransportMessageUnref(message);
    
    _LSHubRemoveMessageTimeout(message);

    return FALSE;   /* don't fire the timer again */
}

/** 
 *******************************************************************************
 * @brief Send a failure response for a query name connect() that has timed out
 * 
 * @param  message  IN  the reply to the original query name message
 * 
 * @retval FALSE always so the timer does not fire again
 *******************************************************************************
 */
gboolean
_LSHubHandleConnectTimeout(_LSTransportMessage *message)
{
    LSError lserror;
    LSErrorInit(&lserror);

    int fd = _LSTransportMessageGetConnectionFd(message);
    close(fd);

    _LSTransportMessageSetConnectionFd(message, -1);

    _LSTransportMessageType type = _LSTransportMessageGetType(message);

    if (type == _LSTransportMessageTypeQueryNameReply)
    {
        /* update the error code -- even though the other fields may have
         * valid values for a QueryNameReply we always check the error code to
         * determine whether the message is valid */
        _LSHubQueryNameReplyReplaceErrorCode(message, LS_TRANSPORT_QUERY_NAME_CONNECT_TIMEOUT);
    }
    else
    {
        /* the only other valid message type that should be here */
        LS_ASSERT(type == _LSTransportMessageTypeMonitorConnected);
    }

    _LSTransportClient *client = _LSTransportMessageGetClient(message);

    /* send the failure! */
    _LSTransportSendMessage(message, client, NULL, NULL);

    /* remove the watch (_LSHubHandleConnectReady callback) */
    bool removed = g_source_remove_by_user_data(message);
    LS_ASSERT(removed);

    _LSHubRemoveConnectMessageTimeout(message);
    
    /* refcount associated with the list */ 
    _LSTransportMessageUnref(message);
    

    return FALSE;   /* don't fire the timer again */
}

/** 
 *******************************************************************************
 * @brief Add a timeout to message.
 * 
 * @param  message      IN  message
 * @param  timeout_ms   IN  timeout in milliseconds
 * @param  callback     IN  callback to call after timeout 
 *******************************************************************************
 */
static void
_LSHubAddMessageTimeout(_LSTransportMessage *message, int timeout_ms, GSourceFunc callback)
{
    _LSTransportMessageRef(message);
    
    GTimerSource *source = g_timer_source_new (timeout_ms, MESSAGE_TIMEOUT_GRANULARITY_MS);

    g_source_set_callback ((GSource*)source, callback, message, NULL);
    guint timeout_id = g_source_attach ((GSource*)source, NULL);

    _LSTransportMessageSetTimeoutId(message, timeout_id);
}

/** 
 *******************************************************************************
 * @brief Remove a timeout from a message.
 * 
 * @param  message  IN  query name message 
 *******************************************************************************
 */
static void
_LSHubRemoveMessageTimeout(_LSTransportMessage *message)
{
    /* remove timeout source from mainloop */
    GSource *timeout_source = g_main_context_find_source_by_id(NULL, _LSTransportMessageGetTimeoutId(message));

    if (timeout_source)
    {
        g_source_destroy(timeout_source);
    }

    /* clear timeout id */
    _LSTransportMessageSetTimeoutId(message, 0);

    _LSTransportMessageUnref(message);
}

/** 
 *******************************************************************************
 * @brief Add a timeout for a message that is waiting for connect() to
 * complete.
 * 
 * @param  message  IN  message
 *******************************************************************************
 */
static void
_LSHubAddConnectMessageTimeout(_LSTransportMessage *message)
{
    _LSTransportMessageRef(message);
    waiting_for_connect = g_slist_prepend(waiting_for_service, message);
    _LSHubAddMessageTimeout(message, g_conf_connect_timeout_ms, (GSourceFunc)_LSHubHandleConnectTimeout);
}

/** 
 *******************************************************************************
 * @brief Remove timeout for message that is waiting for connect() to complete
 * 
 * @param  message  IN  message
 *******************************************************************************
 */
static void
_LSHubRemoveConnectMessageTimeout(_LSTransportMessage *message)
{
    _LSHubRemoveMessageTimeout(message);
    waiting_for_connect = g_slist_remove(waiting_for_connect, message); 
    _LSTransportMessageUnref(message);
}

/** 
 *******************************************************************************
 * @brief Add a timeout to a "QueryName" message.
 * 
 * @param  message  IN  message
 *******************************************************************************
 */
static void
_LSHubAddQueryNameMessageTimeout(_LSTransportMessage *message)
{
    _LSTransportMessageRef(message);
    waiting_for_service = g_slist_prepend(waiting_for_service, message);
    _LSHubAddMessageTimeout(message, g_conf_query_name_timeout_ms, (GSourceFunc)_LSHubHandleQueryNameTimeout);
}

/** 
 *******************************************************************************
 * @brief Process a "QueryName" message.
 * 
 * @param  message  IN  query name message 
 *******************************************************************************
 */
static void
_LSHubHandleQueryName(_LSTransportMessage *message)
{
    _ls_verbose("%s\n", __func__);

    LSError lserror;
    LSErrorInit(&lserror);

#ifdef DEBUG
    printf("%s: available_services hash table:\n", __func__);
    DumpHashTable(available_services);
#endif

    const char *service_name = _LSTransportMessageTypeQueryNameGetQueryName(message);

    LS_ASSERT(service_name != NULL);

    /* If the message originated from a mojo app, we will get a non-NULL appId
     * from this call. */
    const char *app_id = _LSTransportMessageTypeQueryNameGetAppId(message);
    
    /* Check to see if the service exists */
    _Service *service = _ServiceMapLookup(service_name);
    if (!service && !IsMediaService(service_name))
    {
        const _LSTransportCred *cred = _LSTransportClientGetCred(_LSTransportMessageGetClient(message));
        g_critical("Service not listed in service files: \"%s\" "
                   "(requester pid: "LS_PID_PRINTF_FORMAT", "
                   "requester_exe: \"%s\", "
                   "requester_cmdline: \"%s\", "
                   "requester app id: \"%s\")",
                   service_name,
                   LS_PID_PRINTF_CAST(_LSTransportCredGetPid(cred)),
                   _LSTransportCredGetExePath(cred),
                   _LSTransportCredGetCmdLine(cred),
                   app_id);

        /* The service is not in a service file, so it doesn't exist
         * in the system and we should return error */
        if (!_LSHubSendQueryNameReply(message, LS_TRANSPORT_QUERY_NAME_SERVICE_NOT_EXIST, service_name, NULL, false, &lserror))
        {
            LSErrorPrint(&lserror, stderr);
            LSErrorFree(&lserror);
        }
        return;
    }
    
    bool service_is_dynamic = service ? service->is_dynamic : false;

    /* We know the service exists, so now we check to see if we have
     * appropriate permissions to talk to the service */
    if (!LSHubIsClientAllowedToQueryName(_LSTransportMessageGetClient(message), service_name, app_id))
    {
        if (!_LSHubSendQueryNameReply(message, LS_TRANSPORT_QUERY_NAME_PERMISSION_DENIED, service_name, NULL, false, &lserror))
        {
            LSErrorPrint(&lserror, stderr);
            LSErrorFree(&lserror);
        }
        return;
    }

    _ClientId *id = g_hash_table_lookup(available_services, service_name);

    if (!id)
    {
        id = g_hash_table_lookup(pending, service_name);

        if (!id)
        {
            /* Not available or pending. We know that the service *should*
             * exist because we checked the service files earlier and
             * found it. */
            if (service_is_dynamic)
            {
                bool launched = _DynamicServiceFindandLaunch(service_name, _LSTransportMessageGetClient(message), app_id, &lserror);

                if (!launched)
                {
                    LSErrorPrint(&lserror, stderr);
                    LSErrorFree(&lserror);

                    /* If we failed to launch, return error */
                    if (!_LSHubSendQueryNameReply(message, LS_TRANSPORT_QUERY_NAME_SERVICE_NOT_AVAILABLE, service_name, NULL, false, &lserror))
                    {
                        LSErrorPrint(&lserror, stderr);
                        LSErrorFree(&lserror);
                    }
                    return;
                }
            }
            /* !service->is_dynamic */
        }

        /* 
         * It's either pending, we just dynamically launched the process that
         * will provide the service, or it's a static service that currently
         * isn't up.
         *
         * In any of these cases, save the client info so we can send a
         * response when it actually comes up
         */
        _LSHubAddQueryNameMessageTimeout(message);

        return;
    }

    const char *unique_name = id->local.name;

    LS_ASSERT(unique_name != NULL);

#if 0
    /* MONITOR -- send a message to client  */
    if (monitor)
    {
        _LSHubSendMonitorMessage(-1, id, monitor->local.name);
    }
#endif

    /* found name; create response and send it off */
    if (!_LSHubSendQueryNameReply(message, LS_TRANSPORT_QUERY_NAME_SUCCESS, service_name, unique_name, service_is_dynamic, &lserror))
    {
        LSErrorPrint(&lserror, stderr);
        LSErrorFree(&lserror);

        if (service_is_dynamic && ECONNREFUSED == lserror.error_code)
        {
            /*
                We caught the dynamic service going down. Retry connecting and sending the reply later when the service comes back up.
            */
            service->respawn_on_exit = true;

            _LSHubAddQueryNameMessageTimeout(message);
        }
    }
}

/** 
 *******************************************************************************
 * @brief Allocate a new _LSTransportClientMap, which has a key of
 * _LSTransportClient* and value of a ref count (stored in ptr).
 * 
 * @retval map on success
 * @retal  NULL on failure
 *******************************************************************************
 */
static _LSTransportClientMap*
_LSTransportClientMapNew(void)
{
    _LSTransportClientMap *ret = g_new0(_LSTransportClientMap, 1);

    if (ret)
    {
        ret->map = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
        if (!ret->map)
        {
            g_free(ret);
            return NULL;
        }
    }
    return ret;
}

/** 
 *******************************************************************************
 * @brief Free a LSTransportClientMap.
 * 
 * @param  map  IN  map to free 
 *******************************************************************************
 */
static void
_LSTransportClientMapFree(_LSTransportClientMap *map)
{
    g_hash_table_unref(map->map);

#ifdef MEMCHECK
    memset(map, 0xFF, sizeof(_LSTransportClientMap));
#endif

    g_free(map);
}

/** 
 *******************************************************************************
 * @brief Add a client to the map with ref count of 1 if it's not in the map.
 * Otherwise, if it is already in the map, increment the ref count.
 * 
 * @param  map      IN  map 
 * @param  client   IN  client 
 *******************************************************************************
 */
static void 
_LSTransportClientMapAddRefClient(_LSTransportClientMap *map, _LSTransportClient *client)
{
    gpointer value = g_hash_table_lookup(map->map, client);

    if (value == NULL)
    {
        _LSTransportClientRef(client);

        /* add with ref count of 1 */
        g_hash_table_replace(map->map, client, GINT_TO_POINTER(1));
    }
    else
    {
        /* increment ref count */
        gint new_value = GPOINTER_TO_INT(value) + 1;
        g_hash_table_replace(map->map, client, GINT_TO_POINTER(new_value));
    }
}

/** 
 *******************************************************************************
 * @brief Decrement the client ref count in the map. Remove the client from
 * the map if the ref count goes to 0.
 * 
 * @param  map      IN  map 
 * @param  client   IN  client 
 * 
 * @retval  true if client was found in map
 * @retval  false if client was not found in map
 *******************************************************************************
 */
static bool
_LSTransportClientMapUnrefClient(_LSTransportClientMap *map, _LSTransportClient *client)
{
    gpointer value = g_hash_table_lookup(map->map, client);

    if (value)
    {
        gint new_value = GPOINTER_TO_INT(value) - 1;

        if (new_value == 0)
        {
            g_hash_table_remove(map->map, client);
            _LSTransportClientUnref(client);
        }
        else
        {
            g_hash_table_replace(map->map, client, GINT_TO_POINTER(new_value));
        }
        return true;
    }
    return false;
}

/** 
 *******************************************************************************
 * @brief Remove a client from the map irrespective of the ref count in the
 * map.
 * 
 * @param  map      IN  map 
 * @param  client   IN  client 
 * 
 * @retval  true if client was found in map
 * @retval  false if client was not found in map
 *******************************************************************************
 */
static bool
_LSTransportClientMapRemove(_LSTransportClientMap *map, _LSTransportClient *client)
{
    gpointer value = g_hash_table_lookup(map->map, client);

    if (value)
    {
        g_hash_table_remove(map->map, client);
        _LSTransportClientUnref(client);
        return true;
    }
    return false;
}

/** 
 *******************************************************************************
 * @brief Check to see if client map is empty.
 * 
 * @param  map  IN  map 
 * 
 * @retval  true if map is empty
 * @retval  false otherwise
 *******************************************************************************
 */
static bool
_LSTransportClientMapIsEmpty(_LSTransportClientMap *map)
{
    LS_ASSERT(map != NULL);
    
    if (g_hash_table_size(map->map) == 0)
    {
        return true;
    }
    return false;
}

/** 
 *******************************************************************************
 * @brief Call the specified function for each item in the map.
 * 
 * @param  map      IN  map 
 * @param  func     IN  callback
 * @param  message  IN  message to pass as data to callback 
 *******************************************************************************
 */
static void
_LSTransportClientMapForEach(_LSTransportClientMap *map, GHFunc func, _LSTransportMessage *message)
{
    g_hash_table_foreach(map->map, func, message);
}

/** 
 *******************************************************************************
 * @brief Send a signal message to a client.
 * 
 * @param  client   IN  client to which signal should be sent 
 * @param  dummy    IN  unused 
 * @param  message  IN  message to forward as the signal 
 *******************************************************************************
 */
static void
_LSHubSendSignal(_LSTransportClient *client, void *dummy, _LSTransportMessage *message)
{
    LSError lserror;
    LSErrorInit(&lserror);
    LSMessageToken token;

    /* Need to make a copy of the message, since this function gets called
     * multiple times with the same message.
     *
     * TODO: It would be nice to avoid the message copies for performance,
     * but we need to have independent message transmit counts since the
     * message is sent to different clients
     */

    _LSTransportMessage *msg_copy = _LSTransportMessageCopyNewRef(message);

    if (msg_copy)
    {
        if (!_LSTransportSendMessage(msg_copy, client, &token, &lserror))
        {
            LSErrorPrint(&lserror, stderr);
            LSErrorFree(&lserror);
        }
        //g_critical("%s: sent signal to client: %p (unique_name: \"%s\", service_name: \"%s\") with token: %d, category: \"%s\", method: \"%s\", payload: \"%s\"", __func__, client, client->unique_name, client->service_name, (int)token, _LSTransportMessageGetCategory(message), _LSTransportMessageGetMethod(message), _LSTransportMessageGetPayload(message));

#if 0
        _LSTransportMessageType type = _LSTransportMessageGetType(message);
        if (type == _LSTransportMessageTypeServiceUpSignal ||
            type == _LSTransportMessageTypeServiceDownSignal)
        {
            g_critical("%s: sent \"service %s\" signal to client: %p (unique_name: \"%s\", service_name: \"%s\") with token: %d, category: \"%s\", method: \"%s\", payload: \"%s\"", __func__, type == _LSTransportMessageTypeServiceUpSignal  ? "up" : "down", client, client->unique_name, client->service_name, (int)token, _LSTransportMessageGetCategory(message), _LSTransportMessageGetMethod(message), _LSTransportMessageGetPayload(message));
        }
#endif
    
        _LSTransportMessageUnref(msg_copy);
    }
    else
    {
        g_critical("%s: unable to allocate message", __func__);
    }
}

/** 
 *******************************************************************************
 * @brief Allocate a new signal map, which has a hash of category strings to
 * @ref _LSTransportClientMap and hash of method strings to @ref
 * _LSTransportClientMap.
 * 
 * @retval map on success
 * @retval NULL on failure
 *******************************************************************************
 */
static _SignalMap*
_SignalMapNew(void)
{
    _SignalMap *ret = g_new0(_SignalMap, 1);

    if (ret)
    {
        ret->category_map = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, (GDestroyNotify)_LSTransportClientMapFree);
        ret->method_map = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, (GDestroyNotify)_LSTransportClientMapFree);
    }
    return ret;
}

/** 
 *******************************************************************************
 * @brief Free a signal map.
 * 
 * @param  signal_map   IN  map to free 
 *******************************************************************************
 */
static void
_SignalMapFree(_SignalMap *signal_map)
{
    g_hash_table_unref(signal_map->category_map);
    g_hash_table_unref(signal_map->method_map);

#ifdef MEMCHECK
    memset(signal_map, 0xFF, sizeof(_SignalMap));
#endif

    g_free(signal_map);
}

/** 
 *******************************************************************************
 * @brief Remove a @ref LSTransportClient from the @ref _LSTransportClientMap
 * regardless of the ref count in the @ref _LSTransportClientMap.
 * 
 * @param  key          IN  unused
 * @param  value        IN  @ref _LSTransportClientMap 
 * @param  user_data    IN  @ref _LSTransportClient 
 * 
 * @retval  TRUE if the @ref _LSTransportClientMap is empty and should be
 * free'd
 * @retval  FALSE otherwise
 *******************************************************************************
 */
static gboolean
_LSTransportClientMapRemoveCallback(gpointer key, gpointer value, gpointer user_data)
{
    _LSTransportClient *client = (_LSTransportClient*)user_data;
    _LSTransportClientMap *client_map = (_LSTransportClientMap*)value;

    /* remove regardless of ref_count because the client is going down */
    _LSTransportClientMapRemove(client_map, client);

    if (_LSTransportClientMapIsEmpty(client_map))
    {
        return TRUE;    /* client map is free'd by destroy func */
    }
    return FALSE;
}

/** 
 *******************************************************************************
 * @brief Remove all references to the client in the signal map (all the
 * signals that it registered for).
 * 
 * @param  client   client 
 * 
 * @retval true always
 *******************************************************************************
 */
static bool
_LSHubRemoveClientSignals(_LSTransportClient *client)
{
    /* 
     * FIXME: this is quite inefficient: O(num_registered_signals * num_clients)
     */
    g_hash_table_foreach_remove(signal_map->category_map, _LSTransportClientMapRemoveCallback, client);
    g_hash_table_foreach_remove(signal_map->method_map, _LSTransportClientMapRemoveCallback, client);
    return true;
}

/** 
 *******************************************************************************
 * @brief Remove a client's registration for the given signal.
 * 
 * @param  map      IN  signal's "method_map" or "category_map" 
 * @param  path     IN  signal to unregister for 
 * @param  client   In  client 
 * 
 * @retval  true if signal registration was removed
 * @retval  false otherwise
 *******************************************************************************
 */
static bool
_LSHubRemoveSignal(GHashTable *map, const char *path, _LSTransportClient *client)
{
    bool ret = false;

    _LSTransportClientMap *client_map = g_hash_table_lookup(map, path);

    if (client_map)
    {
        ret = _LSTransportClientMapUnrefClient(client_map, client);

        if (_LSTransportClientMapIsEmpty(client_map))
        {
            /* if client_map is empty, we should remove "path" from
             * the hash table */
            bool remove_ret = g_hash_table_remove(map, path);
            LS_ASSERT(remove_ret == true);

            /* client_map is free'd by destroy func when remove is called */
        }
    }
    
    return ret;
}

/** 
 *******************************************************************************
 * @brief Process a signal unregistration message.
 * 
 * @param  message  IN  signal unregister message 
 *******************************************************************************
 */
static void
_LSHubHandleSignalUnregister(_LSTransportMessage *message)
{
    const char *category = _LSTransportMessageGetCategory(message);
    const char *method = _LSTransportMessageGetMethod(message);
    _LSTransportClient *client = _LSTransportMessageGetClient(message);

    _ls_verbose("%s: category: \"%s\", method: \"%s\", client: %p\n", __func__, category, method, client);
    //g_critical("%s: category: \"%s\", method: \"%s\", client: %p\n", __func__, category, method, client);

    LS_ASSERT(category != NULL);

    /* if method, remove from category/method hash */
    if (strlen(method) > 0)
    {
        char *full_path = g_strdup_printf("%s/%s", category, method);

        if (full_path)
        {
            //g_critical("%s: removing from category/method: category: \"%s\", method: \"%s\", client: %p\n", __func__, category, method, client);
#if 0
            /* SIGNAL debug */
            if (strcmp(category, SERVICE_STATUS_CATEGORY) == 0)
            {
                const _LSTransportCred *cred = _LSTransportClientGetCred(client);
                g_critical("Unregistering server status of [\"%s\"] by client: %p "
                           "(service_name: \"%s\", unique_name: \"%s\", pid: "LS_PID_PRINTF_FORMAT
                           ", exe: \"%s\")", 
                           method, client, client->service_name, client->unique_name,
                           LS_PID_PRINTF_CAST(_LSTransportCredGetPid(cred)),
                           _LSTransportCredGetExePath(cred));
            }
#endif

            if (!_LSHubRemoveSignal(signal_map->method_map, full_path, client))
            {
                const _LSTransportCred *cred = _LSTransportClientGetCred(client);
                g_critical("Unable to remove signal: \"%s\" (requester pid: "LS_PID_PRINTF_FORMAT", "
                           "requester exe: \"%s\", "
                           "requester cmdline: \"%s\")",
                           full_path,
                           LS_PID_PRINTF_CAST(_LSTransportCredGetPid(cred)),
                           _LSTransportCredGetExePath(cred),
                           _LSTransportCredGetCmdLine(cred));
            }
            g_free(full_path);
        }
        else
        {
            g_critical("OOM: Unable to remove signal: %s/%s", category, method);
        }
    }
    else
    {
        //g_critical("%s: removing from category: category: \"%s\", method: \"%s\", client: %p\n", __func__, category, method, client);
        
        /* remove from category hash */
        if (!_LSHubRemoveSignal(signal_map->category_map, category, client))
        {
            const _LSTransportCred *cred = _LSTransportClientGetCred(client);
            g_critical("Unable to remove signal: \"%s\" (requester pid: "LS_PID_PRINTF_FORMAT", "
                       "requester exe: \"%s\", " 
                       "requester cmdline: \"%s\")",
                       category,
                       LS_PID_PRINTF_CAST(_LSTransportCredGetPid(cred)),
                       _LSTransportCredGetExePath(cred),
                       _LSTransportCredGetCmdLine(cred));
        }
    }

    /* TODO: remove from reverse lookup */
}

/** 
 *******************************************************************************
 * @brief Add a client's registration for a given signal.
 * 
 * @param  map      IN  signal's "method_map" or "category_map" 
 * @param  path     IN  signal to register for
 * @param  client   In  client 
 * 
 * @retval  true if signal registration was added
 * @retval  false otherwise
 *******************************************************************************
 */
static bool
_LSHubAddSignal(GHashTable *map, const char *path, _LSTransportClient *client)
{
    _LSTransportClientMap *client_map = g_hash_table_lookup(map, path);

    if (!client_map)
    {
        client_map = _LSTransportClientMapNew();

        if (!client_map)
        {
            g_critical("OOM: Unable to allocate client_map");
            return false;
        }

        char *path_copy = g_strdup(path);
        if (path_copy)
        {
            g_hash_table_replace(map, (gpointer)path_copy, client_map);
        }
        else
        {
            _LSTransportClientMapFree(client_map);
            g_critical("OOM: Unable to allocate path_copy");
            return false;
        }
    }
    
    _LSTransportClientMapAddRefClient(client_map, client); 

    return true;
}

/** 
 *******************************************************************************
 * @brief Utility routine used by _LSHubSignalRegisterAllServices, for iteration.
 * 
 * @param  key    IN  service name
 * @param  value  IN  _ClientId pointer 
 * @param  user_data IN  GString * where results will be accumulated
 *******************************************************************************
 */
static void
_LSHubSignalRegisterAllServicesItem(gpointer key, gpointer value, gpointer user_data)
{
    GString * str = (GString*)user_data;
    _ClientId * client = (_ClientId*)value;
    
    const char *exe_path = NULL;

    gchar * allowed_names = NULL;
    
    /* Use exe_path in client credentials to look up role file and allowed service names */
    const _LSTransportCred *cred = NULL;
    
    if (client && client->client)
        cred = _LSTransportClientGetCred(client->client);

    pid_t pid = 0;
    
    if (cred)
        pid = _LSTransportCredGetPid(cred);

    if (cred)
        exe_path = _LSTransportCredGetExePath(cred);

    if (exe_path)
        allowed_names = LSHubRoleAllowedNamesForExe(exe_path);

    g_string_append_printf(str, "{\"serviceName\":\"%s\",\"pid\":%d,\"allNames\":[%s]},",
      client->service_name ? client->service_name : "",
      pid,
      allowed_names ? allowed_names : "");
}
    

/** 
 *******************************************************************************
 * @brief Generate payload for service subscription response listing all available services and their pids.
 * 
 * @param  table  IN  available_services table
 * @retval            allocated gchar* 
 *******************************************************************************
 */
static gchar *
_LSHubSignalRegisterAllServices(GHashTable *table)
{
    LS_ASSERT(table != NULL);
    GString * str = g_string_new("{\"returnValue\":true,\"services\":[");

    g_hash_table_foreach(table, _LSHubSignalRegisterAllServicesItem, str);
    
    // trim off last comma
    g_string_truncate(str, str->len-1);
    
    g_string_append_printf(str, "]}");
    
    return g_string_free(str, FALSE);
}
                

/** 
 *******************************************************************************
 * @brief Process a signal register message.
 * 
 * @param  message  IN  signal register message 
 *******************************************************************************
 */
static void
_LSHubHandleSignalRegister(_LSTransportMessage* message)
{
    LSError lserror;
    LSErrorInit(&lserror);

    const char *category = _LSTransportMessageGetCategory(message);
    const char *method = _LSTransportMessageGetMethod(message);
    _LSTransportClient *client = _LSTransportMessageGetClient(message);

    _ls_verbose("%s: category: \"%s\", method: \"%s\", client: %p\n", __func__, category, method, client);
    //g_critical("%s: category: \"%s\", method: \"%s\", client: %p\n", __func__, category, method, client);

    LS_ASSERT(category != NULL);
    
    /* add to our category/method hash if registering category/method */
    if (strlen(method) > 0)
    {
        /* method is optional for registration */
        char *full_path = g_strdup_printf("%s/%s", category, method);
        
        if (full_path)
        {
#if 0
            /* SIGNAL DEBUG */
            if (strcmp(category, SERVICE_STATUS_CATEGORY) == 0)
            {
                const _LSTransportCred *cred = _LSTransportClientGetCred(client);
                g_critical("Registering server status of [\"%s\"] by client: %p "
                           "(service_name: \"%s\", unique_name: \"%s\", pid: "LS_PID_PRINTF_FORMAT
                           ", exe: \"%s\")",
                           method, client, client->service_name, client->unique_name,
                           LS_PID_PRINTF_CAST(_LSTransportCredGetPid(cred)),
                           _LSTransportCredGetExePath(cred));
            }
#endif

            _LSHubAddSignal(signal_map->method_map, full_path, client);
            g_free(full_path);
        }
        else
        {
            g_critical("OOM: Unable to add signal: %s/%s", category, method);
        }
    }
    else
    {
        char *path = g_strdup(category);

        if (path)
        {
#if 0
            if (strcmp(category, SERVICE_STATUS_CATEGORY) == 0)
            {
                g_critical("Registering server status of \"%s\" for client: %p (service_name: \"%s\", unique_name: \"%s\")", method, client, client->service_name, client->unique_name);
            }
#endif
            _LSHubAddSignal(signal_map->category_map, path, client);
            g_free(path);
        }
        else
        {
            g_critical("OOM: Unable to add signal: \"%s\"", category);
        }
    }

    /* FIXME: we need to create a new "signal reply" function, so that we can
     * differentiate between method call replies and signal registration replies
     * for the shutdown logic */
     
    /* ACK the signal registration -- eventually we'll probably want to avoid
     * doing the extra translation in _LSMessageTranslateFromCall and send 
     * all of the relevant info here including the category and path */
     
    if (strcmp(category, SERVICE_STATUS_CATEGORY) == 0 &&
        strlen(method) == 0)
    {
        /* ACK signal registration for methodless serviceStatus with current
         * status of all services */
        gchar * payload = _LSHubSignalRegisterAllServices(available_services);
        
        if (!_LSTransportSendReply(message, payload, &lserror))
        {
            g_critical("error sending signal registration reply");
            LSErrorPrint(&lserror, stderr);
            LSErrorFree(&lserror);
        }
        g_free(payload);
        return;
    }         
     
    if (!_LSTransportSendReply(message, "{\"returnValue\":true}", &lserror))
    {
        g_critical("error sending signal registration reply");
        LSErrorPrint(&lserror, stderr);
        LSErrorFree(&lserror);
    }

    /* TODO: add reverse lookup */
}

/** 
 *******************************************************************************
 * @brief Process a signal message (i.e., forward to all interested clients).
 * 
 * @param  message  IN  signal message 
 * @param  generated_by_hub  IN  true if signal was generated internally by hub
 *******************************************************************************
 */
static void
_LSHubHandleSignal(_LSTransportMessage *message, bool generated_by_hub)
{
    const char *category = _LSTransportMessageGetCategory(message);
    const char *method = _LSTransportMessageGetMethod(message);

    LS_ASSERT(category != NULL);
    LS_ASSERT(method != NULL);

    if (!generated_by_hub && !LSHubIsClientAllowedToSendSignal(_LSTransportMessageGetClient(message)))
    {
        return;
    }

    /* look up all clients that handle this category */
    _LSTransportClientMap *client_map = g_hash_table_lookup(signal_map->category_map, category);

    if (client_map)
    {
        _LSTransportClientMapForEach(client_map, (GHFunc)_LSHubSendSignal, message);
    }

    /* look up all clients that handle this category/method */
    char *category_method = g_strdup_printf("%s/%s", category, method);

    if (category_method)
    {
        _LSTransportClientMap *client_map = g_hash_table_lookup(signal_map->method_map, category_method);

        if (client_map)
        {
            _LSTransportClientMapForEach(client_map, (GHFunc)_LSHubSendSignal, message);
        }

        g_free(category_method);
    }
    else
    {
        g_critical("OOM: Unable to send signal");
    }
}

/** 
 *******************************************************************************
 * @brief Send a message to client telling it to connect to the monitor.
 * 
 * @param  ignored_fd   IN  don't use this
 * @param  id           IN  client id 
 * @param  unique_name  IN  monitor's unique name 
 *******************************************************************************
 */
static void
_LSHubSendMonitorMessage(int ignored_fd, _ClientId *id, const char *unique_name)
{
    LSError lserror;
    LSErrorInit(&lserror);

    /* Skip sending the message to the monitor itself */
    if (id->is_monitor)
    {
        return;
    }

    _ls_verbose("%s: client: %p\n", __func__, id->client);

    bool send = true;
    bool monitor_is_connected = true;
    _LSTransportMessageIter iter;

    if (unique_name == NULL)
    {
        monitor_is_connected = false;
    }

    /* get the unique name for the client and add send it as part of the message */
    _LSTransportMessage *monitor_message = _LSTransportMessageNewRef(LS_TRANSPORT_MESSAGE_DEFAULT_PAYLOAD_SIZE);
    
    if (!monitor_message) goto error;

    if (monitor_is_connected)
    {
        _LSTransportMessageSetType(monitor_message, _LSTransportMessageTypeMonitorConnected);
    }
    else
    {
        _LSTransportMessageSetType(monitor_message, _LSTransportMessageTypeMonitorNotConnected);
    }

    _LSTransportMessageIterInit(monitor_message, &iter);
    if (!_LSTransportMessageAppendString(&iter, unique_name)) goto error;
    if (!_LSTransportMessageAppendInvalid(&iter)) goto error;

    /* set up the connection to the monitor if it exists and we're local */
    if (monitor_is_connected &&
        _LSTransportGetTransportType(_LSTransportClientGetTransport(id->client)) == _LSTransportTypeLocal)
    {
        int fd = -1;
        _LSTransportConnectState connect_state = _LSTransportConnectLocal(unique_name, true, &fd, &lserror);

        _LSTransportMessageSetConnectState(monitor_message, connect_state);

        switch (connect_state)
        {
        case _LSTransportConnectStateNoError:
            /* success */
            break;
        case _LSTransportConnectStateEagain:
        case _LSTransportConnectStateEinprogress:
            /* connect() would have blocked */
            _LSHubAddPendingConnect(monitor_message, id->client, fd);
            send = false;
            break;
        case _LSTransportConnectStateOtherFailure:
            /* fatal connect() error */
            LSErrorPrint(&lserror, stderr);
            LSErrorFree(&lserror);
            break;
        default:
            g_critical("%s: Invalid connect state: %d", __FUNCTION__, connect_state);
            LS_ASSERT(0);
        }

        /* go ahead and set the fd, even if it's -1 */
        _LSTransportMessageSetConnectionFd(monitor_message, fd);
    }
    
    if (send && !_LSTransportSendMessage(monitor_message, id->client, NULL, &lserror))
    {
        LSErrorPrint(&lserror, stderr);
        LSErrorFree(&lserror);
    }

error:
    if (monitor_message) _LSTransportMessageUnref(monitor_message);
}

/** 
 *******************************************************************************
 * @brief Process a monitor request message by sending out messages to each
 * client telling them to connect.
 * 
 * @param  message  IN  monitor request message 
 *******************************************************************************
 */
static void
_LSHubHandleMonitorRequest(_LSTransportMessage *message)
{
    /* get the unique name for the monitor */
    _LSTransportClient *monitor_client = _LSTransportMessageGetClient(message);;
   
    if (!monitor_client)
    {
        g_critical("Unable to get monitor client");
        return;
    }

    if (g_conf_security_enabled && !LSHubIsClientMonitor(monitor_client))
    {
        const _LSTransportCred *cred = _LSTransportClientGetCred(monitor_client);
        g_critical("Monitor message not sent by monitor ("
                   "requester pid: \""LS_PID_PRINTF_FORMAT"\", "
                   "requester exe: \"%s\", "
                   "requester cmdline: \"%s\")",
                   LS_PID_PRINTF_CAST(_LSTransportCredGetPid(cred)),
                   _LSTransportCredGetExePath(cred),
                   _LSTransportCredGetCmdLine(cred));

        return;
    }


    /* mark this client as the monitor */
    _ClientId *id = g_hash_table_lookup(connected_clients.by_fd, GINT_TO_POINTER(monitor_client->channel.fd));

    if (!id)
    {
        g_warning("Unable to find monitor in connected client map");
        return;
    }
    
    /* mark this client as the monitor */
    id->is_monitor = true;
    _LSHubClientIdLocalRef(id);
    monitor = id;
    
    if (monitor_client->unique_name)
    {
        char *unique_name = monitor_client->unique_name;

        _ls_verbose("\"%s\": monitor unique name: \"%s\"\n", __func__, unique_name);

        /* forward the message to all connected clients */
        g_hash_table_foreach(connected_clients.by_fd, (GHFunc)_LSHubSendMonitorMessage, unique_name);
    }
    else
    {
        g_critical("We were expecting the monitor to have the monitor's unique_name, monitor_client: %p", monitor_client);
    } 
}

/** 
 *******************************************************************************
 * @brief Send the status of the monitor (used when a client first comes up).
 * 
 * @param  message  IN  message with client info  
 *******************************************************************************
 */
static void
_LSHubSendMonitorStatus(_LSTransportMessage *message)
{
    _LSTransportClient *client = message->client;
   
    _ClientId *id = g_hash_table_lookup(connected_clients.by_fd, GINT_TO_POINTER(client->channel.fd));

    if (!id)
    {
        /* This can happen if the RequestName fails */
        g_critical("Unable to find fd: %d in connected_clients hash, client: %p, service_name: \"%s\", unique_name: \"%s\"",
                   client->channel.fd, client,
                   client->service_name ? client->service_name : "(null)",
                   client->unique_name ? client->unique_name : "(null)");
        //LS_ASSERT(id != NULL);
        return;
    }

    if (monitor)
    {
        _LSHubSendMonitorMessage(-1, id, monitor->local.name);
    }
    else
    {
        /* no monitor, so we send an empty name message */
        _LSHubSendMonitorMessage(-1, id, NULL);
    }
}

/** 
 *******************************************************************************
 * @brief Process a "QueryServiceStatus" message and send a reply with the
 * state of the service.
 * 
 * @param  message  IN  query service status message 
 *******************************************************************************
 */
static void
_LSHubHandleQueryServiceStatus(const _LSTransportMessage *message)
{
    LS_ASSERT(_LSTransportMessageGetType(message) == _LSTransportMessageTypeQueryServiceStatus);

    LSError lserror;
    LSErrorInit(&lserror);

    _LSTransportMessageIter iter;

    _LSTransportClient *reply_client = _LSTransportMessageGetClient(message);
    int available = 0;
    const char *service_name = NULL;

    _LSTransportMessageIterInit((_LSTransportMessage*)message, &iter);

    _LSTransportMessageGetString(&iter, &service_name);

    /* look up service name in available list */
    if (g_hash_table_lookup(available_services, service_name))
    {
        available = 1;
    }

    /* for legacy support for subscriptions, we allow asking for service
     * status with a unique name as the "service name" */
    if (g_hash_table_lookup(connected_clients.by_unique_name, service_name))
    {
        available = 1;
    }

    //g_critical("\"%s\": Sending service status for: \"%s\", available: %d", __func__, service_name, available);

    /* construct the reply -- reply_serial + available val */
    _LSTransportMessage *reply = _LSTransportMessageNewRef(sizeof(LSMessageToken) + sizeof(available));

    if (!reply)
    {
        g_critical("OOM: Unable to allocate message");
        return;
    }

    _LSTransportMessageSetType(reply, _LSTransportMessageTypeQueryServiceStatusReply);

    LSMessageToken msg_serial = _LSTransportMessageGetToken(message);
    char *body = _LSTransportMessageGetBody(reply);

    memcpy(body, &msg_serial, sizeof(msg_serial));
    body += sizeof(msg_serial);
    memcpy(body, &available, sizeof(available));

    if (!_LSTransportSendMessage(reply, reply_client, NULL, &lserror))
    {
        LSErrorPrint(&lserror, stderr);
        LSErrorFree(&lserror);
    }

    _LSTransportMessageUnref(reply);
}


/** 
 *******************************************************************************
 * @brief Replies with a message of all connected clients.
 * 
 * @param  message  IN  list clients message 
 *******************************************************************************
 */
static void
_LSHubHandleListClients(const _LSTransportMessage *message)
{
    LS_ASSERT(_LSTransportMessageGetType(message) == _LSTransportMessageTypeListClients);
    
    char *unique_name = NULL;
    _ClientId *id = NULL;
    gpointer key = NULL;
    gpointer value = NULL;

    LSError lserror;
    LSErrorInit(&lserror);

    _LSTransportMessageIter iter;
    GHashTableIter hash_iter;

    _LSTransportClient *reply_client = _LSTransportMessageGetClient(message);

    _LSTransportMessage *reply = _LSTransportMessageNewRef(LS_TRANSPORT_MESSAGE_DEFAULT_PAYLOAD_SIZE);

    if (!reply) goto error;

    _LSTransportMessageSetType(reply, _LSTransportMessageTypeListClientsReply);

    _LSTransportMessageIterInit(reply, &iter);
    g_hash_table_iter_init(&hash_iter, connected_clients.by_unique_name);

    /* TODO: set reply serial? */

    /* iterate over entire hash table of connected clients */
    while (g_hash_table_iter_next(&hash_iter, &key, &value))
    {
        const _LSTransportCred *cred = NULL;
        _Service *service = NULL;
        
        unique_name = key;
        id = value;

        if (!_LSTransportMessageAppendString(&iter, unique_name)) goto error;
        if (!_LSTransportMessageAppendString(&iter, id->service_name)) goto error;

        cred = _LSTransportClientGetCred(id->client);

        if (!_LSTransportMessageAppendInt32(&iter, _LSTransportCredGetPid(cred))) goto error;
        if (!_LSTransportMessageAppendString(&iter, _LSTransportCredGetExePath(cred))) goto error;

        if (id->service_name)
        {
            service = _ServiceMapLookup(id->service_name);
        }

        if (service)
        {
            if (!_LSTransportMessageAppendString(&iter, service->is_dynamic ? "dynamic" : "static")) goto error;
        }
        else
        {
            if (!_LSTransportMessageAppendString(&iter, "unknown/client only")) goto error;
        } 
    }
    
    if (!_LSTransportMessageAppendInvalid(&iter)) goto error;

    if (!_LSTransportSendMessage(reply, reply_client, NULL, &lserror))
    {
        LSErrorPrint(&lserror, stderr);
        LSErrorFree(&lserror);
    }

error:
    if (reply) _LSTransportMessageUnref(reply);
}

static void
_LSHubHandlePushRole(_LSTransportMessage *message)
{
    LS_ASSERT(_LSTransportMessageGetType(message) == _LSTransportMessageTypePushRole);

    LSError lserror;
    LSErrorInit(&lserror);

    _LSTransportMessageIter iter;
    const char *role_path = NULL;
    int32_t ret_code = LS_TRANSPORT_PUSH_ROLE_SUCCESS;

    /* If security is not enabled, then we just return success */
    if (g_conf_security_enabled)
    {
        _LSTransportClient *sender_client = _LSTransportMessageGetClient(message);

        /* Get the path to the role file */
        _LSTransportMessageIterInit(message, &iter);

        LS_ASSERT(_LSTransportMessageIterHasNext(&iter));

        bool role_ret = _LSTransportMessageGetString(&iter, &role_path);

        if (!role_ret || !role_path)
        {
            g_critical("Unable to get role path (sender service name: \"%s\", unique_name: \"%s\")",
                       _LSTransportMessageGetSenderServiceName(message),
                       _LSTransportMessageGetSenderUniqueName(message));
            return;
        }

        if (!LSHubPushRole(sender_client, role_path, &lserror))
        {
           const  _LSTransportCred *cred = _LSTransportClientGetCred(sender_client);

            ret_code = lserror.error_code;
            g_critical("Unable to push role ("
                       "requester pid: \""LS_PID_PRINTF_FORMAT"\", "
                       "requester exe: \"%s\", "
                       "requester cmdline: \"%s\")",
                       LS_PID_PRINTF_CAST(_LSTransportCredGetPid(cred)),
                       _LSTransportCredGetExePath(cred),
                       _LSTransportCredGetCmdLine(cred));
            LSErrorPrint(&lserror, stderr);
        }
    }

    _LSTransportClient *reply_client = _LSTransportMessageGetClient(message);

    _LSTransportMessage *reply = _LSTransportMessageNewRef(LS_TRANSPORT_MESSAGE_DEFAULT_PAYLOAD_SIZE);

    if (!reply) goto error;

    _LSTransportMessageSetType(reply, _LSTransportMessageTypePushRoleReply);

    _LSTransportMessageIterInit(reply, &iter);

    /* TODO: set reply serial ? */

    if (!_LSTransportMessageAppendInt32(&iter, ret_code)) goto error;

    if (ret_code != LS_TRANSPORT_PUSH_ROLE_SUCCESS)
    {
        /* We didn't free the lserror above when printed */
        if (!_LSTransportMessageAppendString(&iter, lserror.message)) goto error;
    }

    if (!_LSTransportMessageAppendInvalid(&iter)) goto error;

    if (LSErrorIsSet(&lserror))
    {
        LSErrorFree(&lserror);
    }

    if (!_LSTransportSendMessage(reply, reply_client, NULL, &lserror))
    {
        LSErrorPrint(&lserror, stderr);
        LSErrorFree(&lserror);
    }

error:
    if (reply) _LSTransportMessageUnref(reply);
}

/** 
 *******************************************************************************
 * @brief Process incoming messages from underlying transport.
 * 
 * @param  message  IN  incoming message 
 * @param  context  IN  unused  
 * 
 * @retval LSMessageHandlerResultHandled
 *******************************************************************************
 */
static LSMessageHandlerResult
_LSHubHandleMessage(_LSTransportMessage* message, void *context)
{
    switch (_LSTransportMessageGetType(message))
    {
    case _LSTransportMessageTypeRequestNameLocal:
    case _LSTransportMessageTypeRequestNameInet:
        _LSHubHandleRequestName(message);

        /* tell the connecting client whether we have a monitor */
        _LSHubSendMonitorStatus(message);
        break;

    case _LSTransportMessageTypeNodeUp:
        _LSHubHandleNodeUp(message);
        break;

    case _LSTransportMessageTypeListClients:
        _LSHubHandleListClients(message);
        break;

    case _LSTransportMessageTypeQueryName:
        _LSHubHandleQueryName(message);
        break;

    case _LSTransportMessageTypeSignalRegister:
        _LSHubHandleSignalRegister(message);
        break;
    
    case _LSTransportMessageTypeSignalUnregister:
        _LSHubHandleSignalUnregister(message);
        break;

    case _LSTransportMessageTypeSignal:
        _LSHubHandleSignal(message, false);
        break;

    case _LSTransportMessageTypeMonitorRequest:
        _LSHubHandleMonitorRequest(message);
        break;

    case _LSTransportMessageTypeQueryServiceStatus:
        _LSHubHandleQueryServiceStatus(message);
        break;

    case _LSTransportMessageTypePushRole:
        _LSHubHandlePushRole(message);
        break;

    case _LSTransportMessageTypeMethodCall:
    case _LSTransportMessageTypeReply:
    default:
        g_critical("Received unhandled message type: %d", _LSTransportMessageGetType(message));
        break;
    }

    return LSMessageHandlerResultHandled;
}

/** 
 *******************************************************************************
 * @brief Checks to see if the hub is already running. It saves the PID
 * in a file and locks it. It may call exit() if it encounters an error.
 * 
 * @param  public   public or private bus (one of each allowed to run)
 * 
 * @retval  true, if the hub is running
 * @retval  false, if the hub isn't running
 *******************************************************************************
 */
static bool
_HubIsRunning(bool public)
{
    if (public)
    {
        return LSIsRunning(*pid_dir, HUB_PUBLIC_LOCK_FILENAME);
    }
    else
    {
        return LSIsRunning(*pid_dir, HUB_PRIVATE_LOCK_FILENAME);
    }
}

/** 
 *******************************************************************************
 * @brief Callback to handle SIGINT and SIGTERM. Quits the mainloop so we can
 * do cleanup before exiting.
 * 
 * @param  signal 
 *******************************************************************************
 */
static void
_HandleShutdown(int signal)
{
    g_main_loop_quit(mainloop);
}

/** 
 *******************************************************************************
* @brief Use the options from the conf file unless we have overriden then
* on the command line.
 * 
 * @param  cmdline_local_socket_path  IN   ptr to socket path from command line
 *******************************************************************************
 */
static void
_ProcessConfFileOptions(char **cmdline_local_socket_path, char **cmdline_pid_dir)
{
    if (cmdline_local_socket_path && *cmdline_local_socket_path)
    {
        local_socket_path = cmdline_local_socket_path;
    }
    else
    {
        local_socket_path = &g_conf_local_socket_path;
    }

    if (g_mkdir_with_parents(*local_socket_path, 0755) == -1)
    {
        g_critical("Unable to create directory: \"%s\" (%d: \"%s\")",
                    *local_socket_path, errno, g_strerror(errno));
    }

    if (cmdline_pid_dir && *cmdline_pid_dir)
    {
        pid_dir = cmdline_pid_dir;
    }
    else
    {
        pid_dir = &g_conf_pid_dir;
    }
    
    if (g_mkdir_with_parents(*pid_dir, 0755) == -1)
    {
        g_critical("Unable to create directory: \"%s\" (%d: \"%s\")",
                    *pid_dir, errno, g_strerror(errno));
    }
}


static LSTransportHandlers _LSHubHandler;

int
main(int argc, char *argv[])
{
    GError *gerror = NULL;
    LSError lserror;
    LSErrorInit(&lserror);

    static gboolean public = FALSE;
    static gboolean daemonize = FALSE;
    static char *boot_file_name = NULL;
    static char *cmdline_local_socket_path = NULL;
    static char *cmdline_pid_dir = NULL;

    static GOptionEntry opt_entries[] =
    {
        {"debug-level", 'd', 0, G_OPTION_ARG_INT, &_ls_debug_tracing, "debug level; max is 2", "N"},
        {"local-socket-path", 'l', 0, G_OPTION_ARG_FILENAME, &cmdline_local_socket_path, "Directory where local socket files will be created", "/some/path"},
        {"service-dir", 's', 0, G_OPTION_ARG_FILENAME, &service_dir, "Directory where service files are stored", "/some/path"},
        {"pid-dir", 'i', 0, G_OPTION_ARG_FILENAME, &cmdline_pid_dir, "Directory where the pid file is stored (default /var/run)", "/some/path"},
        {"public", 'p', 0, G_OPTION_ARG_NONE, &public, "Provide public hub (default is private)", NULL},
        {"inet", 'n', 0, G_OPTION_ARG_NONE, &enable_inet, "Use inet connections (default is unix domain socket)", NULL},
        {"conf", 'c', 0, G_OPTION_ARG_FILENAME, &conf_file, "MANDATORY: Path to config file", "/some/path/ls.conf"},
        {"syslog", 'g', 0, G_OPTION_ARG_NONE, &use_syslog, "Log to syslog (default stdout/stderr)", NULL},
        {"boot-file", 'b', 0, G_OPTION_ARG_FILENAME, &boot_file_name, "Create specified file when done booting", "/some/path/file"},
        {"pmloglib", 'm', 0, G_OPTION_ARG_NONE, &use_pmloglib, "Log using pmloglib (default stdout/stderr)", NULL},
        {"daemon", 'a', 0, G_OPTION_ARG_NONE, &daemonize, "Run as daemon (fork and run in background)", NULL},
        { NULL }
    };

    GOptionContext *opt_context = NULL;
    _ls_debug_tracing = 0;

    opt_context = g_option_context_new("- Luna Service Hub");
    g_option_context_add_main_entries(opt_context, opt_entries, NULL);

    if (!g_option_context_parse(opt_context, &argc, &argv, &gerror))
    {
        g_critical("Error processing commandline args: \"%s\"", gerror->message);
        g_error_free(gerror);
        exit(EXIT_FAILURE);
    }

    g_option_context_free(opt_context);

    if (NULL == conf_file)
    {
        g_critical("Mandatory configuration file (-c/--conf) not provided!");
        exit(EXIT_FAILURE);
    }

    if (daemonize)
    {
        if (daemon(1, 1) < 0)
        {
            g_critical("Unable to become a daemon: %s", g_strerror(errno));
        }
    }
    
    if (use_syslog)
    {
        SetLoggingSyslog();
    }
    else if (use_pmloglib)
    {
        SetLoggingPmLogLib(public);
    }

    /* ignore SIGPIPE -- we'll handle the synchronous return val (EPIPE) */
    _LSTransportSetupSignalHandler(SIGPIPE, SIG_IGN);
    _LSTransportSetupSignalHandler(SIGTERM, _HandleShutdown);
    _LSTransportSetupSignalHandler(SIGINT, _HandleShutdown);

    _ls_verbose("hub starting\n");

    mainloop = g_main_loop_new(NULL, FALSE);

    if (!mainloop)
    {
        g_critical("Unable to create mainloop!");
    }

    /* TODO: turn into a daemon */

    /* config file
     *     - inits and fills the dynamic service map
     *     - inits and fills the role map and permission map */
    ConfigParseFile(conf_file, &lserror);

    /* config file */
    if (!ConfigSetupInotify(conf_file, &lserror))
    {
        LSErrorPrint(&lserror, stderr);
        LSErrorFree(&lserror);
    }
    
    /* Command-line options override the settings from the conf file */
    _ProcessConfFileOptions(&cmdline_local_socket_path, &cmdline_pid_dir);
    
    /* Don't allow multiple instances to run */
    if (_HubIsRunning(public))
    {
        g_critical("An instance of the %s hub is already running\n", public ? "public" : "private");
        exit(EXIT_FAILURE);
    }

    /* dynamic service state map */
    if (!DynamicServiceInitStateMap(&lserror))
    {
        LSErrorPrint(&lserror, stderr);
        LSErrorFree(&lserror);
    }

    /* init data structures */
    pending = g_hash_table_new_full(_LSServiceNameHash, _LSServiceNameEquals, NULL, _LSHubClientIdLocalUnrefVoid);

    if (!pending)
    {
        g_critical("Unable to create hash table");
    }

    available_services = g_hash_table_new_full(_LSServiceNameHash, _LSServiceNameEquals, NULL, _LSHubClientIdLocalUnrefVoid);
    
    if (!available_services)
    {
        g_critical("Unable to create hash table");
    }

    connected_clients.by_fd = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, _LSHubClientIdLocalUnrefVoid);

    if (!connected_clients.by_fd)
    {
        g_critical("Unable to create hash table");
    }
    
    connected_clients.by_unique_name = g_hash_table_new_full(_LSServiceNameHash, _LSServiceNameEquals, NULL, _LSHubClientIdLocalUnrefVoid);

    if (!connected_clients.by_unique_name)
    {
        g_critical("Unable to create hash table");
    }

    signal_map = _SignalMapNew();

    if (!signal_map)
    {
        g_critical("Unable to allocate signal map");
    }

    _LSHubHandler.msg_handler = _LSHubHandleMessage;
    _LSHubHandler.msg_context = NULL;
    _LSHubHandler.disconnect_handler = _LSHubHandleDisconnect;
    _LSHubHandler.disconnect_context = NULL;
    _LSHubHandler.message_failure_handler = NULL;
    _LSHubHandler.message_failure_context = NULL;

    /* set up socket for listening */
    if (!_LSTransportInit(&hub_transport, HUB_NAME, &_LSHubHandler, &lserror))
    {
        LSErrorPrint(&lserror, stderr);
        LSErrorFree(&lserror);
        g_critical("Unable to initialize transport");
    }

    if (enable_inet)
    {
        uint16_t hub_inet_port = 0;

        if (public)
        {
            hub_inet_port = DEFAULT_INET_PORT_PUBLIC;
        }
        else
        {
            hub_inet_port = DEFAULT_INET_PORT_PRIVATE;
        }

        /* inet */
        if (!_LSTransportSetupListenerInet(hub_transport, hub_inet_port, &lserror))
        {
            LSErrorPrint(&lserror, stderr);
            LSErrorFree(&lserror);
            g_critical("Unable to set up inet listener");
        }
    }
    else
    {
        const char *hub_local_addr = NULL;
        
        if (public)
        {
            hub_local_addr = HUB_LOCAL_ADDRESS_PUBLIC;
        }
        else
        {
            hub_local_addr = HUB_LOCAL_ADDRESS_PRIVATE;
        }

        /* everyone needs to be able to talk to the hub */
        if (!_LSTransportSetupListenerLocal(hub_transport, hub_local_addr, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH, &lserror))
        {
            LSErrorPrint(&lserror, stderr);
            LSErrorFree(&lserror);
            g_critical("Unable to set up local listener");
        }
    }

    _LSTransportGmainAttach(hub_transport, g_main_loop_get_context(mainloop));

#if !defined(TARGET_DESKTOP)
    const char *upstart_job = getenv("UPSTART_JOB");

    if (upstart_job)
    {
        char *upstart_event = g_strdup_printf("/sbin/initctl emit --no-wait %s-ready", getenv("UPSTART_JOB"));

        if (upstart_event)
        {
            system(upstart_event);
            g_free(upstart_event);
        }
        else
        {
            g_critical("Unable to emit upstart event");
        }
    }
#endif
    
    if (boot_file_name)
    {
        char *tmp = g_strdup(boot_file_name);
        char *dir = dirname(tmp);   /* can modify its arg, so we pass a copy */

        if (g_mkdir_with_parents(dir, 0755) == -1)
        {
            g_critical("Unable to create directory: \"%s\" (%d: \"%s\")", dir, errno, g_strerror(errno));
        }
        else
        {
            FILE *boot_file = fopen(boot_file_name, "w");
            
            if (!boot_file)
            {
                g_critical("Unable to open boot file: \"%s\" (%d: \"%s\")", boot_file_name, errno, g_strerror(errno));    
            }
            else
            {
                fclose(boot_file);
            }
        }
        if (tmp) g_free(tmp);
    }

    if (!SetupWatchdog(&lserror))
    {
        LSErrorPrint(&lserror, stderr);
        LSErrorFree(&lserror);
    }

    /* run mainloop */
    g_main_loop_run(mainloop);
    g_main_loop_unref(mainloop);

    /* TODO: clean up other allocations */
    _SignalMapFree(signal_map);

    if (boot_file_name) unlink(boot_file_name);

    g_message("Exiting...");

    return 0;
}

/* @} END OF LunaServiceHub */
