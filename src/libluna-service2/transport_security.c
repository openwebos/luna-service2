/* @@@LICENSE
*
*      Copyright (c) 2010-2014 LG Electronics, Inc.
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


#define _GNU_SOURCE

#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <glib.h>

#include "transport.h"
#include "transport_security.h"

/**
 * @defgroup LunaServiceTransportSecurity
 * @ingroup LunaServiceTransport
 * @brief Transport security
 */

/**
 * @addtogroup LunaServiceTransportSecurity
 * @{
 */

/**
 * Represents credentials for a client
 */
struct _LSTransportCred {
    pid_t pid;              /**< process pid */
    uid_t uid;              /**< process uid */
    gid_t gid;              /**< process gid */
    const char *exe_path;   /**< full path to process' executable */
    const char *cmd_line;   /**< process' cmdline */
};

/**
 *******************************************************************************
 * @brief Allocate a new credentials object.
 *
 * @retval  credentials on success
 * @retval  NULL on failure
 *******************************************************************************
 */
_LSTransportCred*
_LSTransportCredNew(void)
{
    _LSTransportCred *ret = g_slice_new(_LSTransportCred);

    ret->pid = LS_PID_INVALID;
    ret->uid = LS_UID_INVALID;
    ret->gid = LS_GID_INVALID;
    ret->exe_path = NULL;
    ret->cmd_line = NULL;

    return ret;
}

/**
 *******************************************************************************
 * @brief Free a credentials object.
 *
 * @param  cred     IN  credentials
 *******************************************************************************
 */
void
_LSTransportCredFree(_LSTransportCred *cred)
{
    LS_ASSERT(cred != NULL);
    g_free((char*)cred->exe_path);
    g_free((char*)cred->cmd_line);

#ifdef MEMCHECK
    memset(cred, 0xFF, sizeof(_LSTransportCred));
#endif

    g_slice_free(_LSTransportCred, cred);
}

/**
 *******************************************************************************
 * @brief Get the PID.
 *
 * @param  cred     IN  credentials
 *
 * @retval  pid on success
 * @retval  LS_PID_INVALID on failure
 *******************************************************************************
 */
inline pid_t
_LSTransportCredGetPid(const _LSTransportCred *cred)
{
    LS_ASSERT(cred != NULL);
    return cred->pid;
}

/**
 *******************************************************************************
 * @brief Get the UID.
 *
 * @param  creda    IN  credentials
 *
 * @retval  uid on success
 * @retval  LS_UID_INVALID on failure
 *******************************************************************************
 */
inline uid_t
_LSTransportCredGetUid(const _LSTransportCred *cred)
{
    LS_ASSERT(cred != NULL);
    return cred->uid;
}

/**
 *******************************************************************************
 * @brief Get the GID.
 *
 * @param  cred     IN  credentials
 *
 * @retval  gid on success
 * @retval  LS_GID_INVALID on failure
 *******************************************************************************
 */
inline gid_t
_LSTransportCredGetGid(const _LSTransportCred *cred)
{
    LS_ASSERT(cred != NULL);
    return cred->gid;
}

/**
 *******************************************************************************
 * @brief Get the full path to executable.
 *
 * @param  cred     IN  credentials
 *
 * @retval  path on success
 * @retval  NULL on failure
 *******************************************************************************
 */
inline const char*
_LSTransportCredGetExePath(const _LSTransportCred *cred)
{
    LS_ASSERT(cred != NULL);
    return cred->exe_path;
}

/**
 *******************************************************************************
 * @brief Get the process' command line.
 *
 * @param  cred     IN  credentials
 *
 * @retval  cmdline on success
 * @retval  NULL on failure
 *******************************************************************************
 */
inline const char*
_LSTransportCredGetCmdLine(const _LSTransportCred *cred)
{
    LS_ASSERT(cred != NULL);
    return cred->cmd_line;
}

/**
 *******************************************************************************
 * @brief Get the executable path for a given pid.
 *
 * @param  pid          IN  pid
 * @param  lserror      OUT set on error
 *
 * @retval  executable path on success
 * @retval  NULL on failure
 *******************************************************************************
 */
static char*
_LSTransportPidToExe(pid_t pid, LSError *lserror)
{
    GError *error = NULL;

    char *ret = NULL;
    char *root = NULL;
    char *exe = NULL;
    char *proc_exe_path = g_strdup_printf("/proc/%d/exe", pid);
    char *proc_root_path = g_strdup_printf("/proc/%d/root",pid);

    exe =  g_file_read_link(proc_exe_path, &error);

    if (!exe)
    {
        _LSErrorSetFromGError(lserror, MSGID_LS_PID_PATH_ERR, error);
        goto cleanup;
    }

    root = g_file_read_link(proc_root_path, &error);
    if (!root)
    {
        _LSErrorSetFromGError(lserror, MSGID_LS_PID_PATH_ERR, error);
        goto cleanup;
    }

    int rootlen = strlen(root);
    if ((rootlen > 1) && (strncmp(exe, root, rootlen) == 0))
    {
        /* /proc/<pid>/root is not a link to "/" so subtract
         * it from the exe path (it's probably an app running in jail) */
        ret = g_strdup(exe + rootlen);
    }
    else
    {
        ret = g_strdup(exe);
    }


cleanup:
    g_free(proc_exe_path);
    g_free(proc_root_path);
    g_free(exe);
    g_free(root);

    return ret;
}

/**
 *******************************************************************************
 * @brief Get the command line for a given pid.
 *
 * @param  pid          IN  pid
 * @param  lserror      OUT set on error
 *
 * @retval  command line on success
 * @retval  NULL on failure
 *******************************************************************************
 */
static char*
_LSTransportPidToCmdLine(pid_t pid, LSError *lserror)
{
    GError *error = NULL;

    char *cmd_line = NULL;
    int i = 0;
    gsize len = 0;
    char *proc_cmd_line_path = g_strdup_printf("/proc/%d/cmdline", pid);

    bool ret = g_file_get_contents(proc_cmd_line_path, &cmd_line, &len, &error);

    if (!ret)
    {
        _LSErrorSetFromGError(lserror, MSGID_LS_PID_READ_ERR, error);
        goto cleanup;
    }

    /* /proc/PID/cmdline has ASCII NUL instead of spaces, so replace all of
     * them except for the last one */
    for (i = 0; i < ((int)len) - 1; i++)
    {
        if (cmd_line[i] == '\0')
        {
            /* If we get two NULs in a row, we're at the end.
             * g_file_get_contents() seems to return a larger size than
             * necessary (calls fstat to determine size) */
            if (cmd_line[i + 1] == '\0')
            {
                break;
            }
            else
            {
                cmd_line[i] = ' ';
            }
        }
    }

cleanup:
    g_free(proc_cmd_line_path);

    return cmd_line;
}

/**
 *******************************************************************************
 * @brief Get the credentials from a unix domain socket.
 *
 * @param  fd           IN       unix domain socket fd
 * @param  cred         IN/OUT   credentials
 * @param  lserror      OUT      set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
_LSTransportGetCredentials(int fd, _LSTransportCred *cred, LSError *lserror)
{
    LS_ASSERT(cred != NULL);

#ifdef SO_PEERCRED
    struct ucred tmp_cred;

    socklen_t len = sizeof(tmp_cred);

    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &tmp_cred, &len) != 0)
    {
        _LSErrorSetFromErrno(lserror, MSGID_LS_SOCK_ERROR, errno);
        return false;
    }

    cred->pid = tmp_cred.pid;
    cred->uid = tmp_cred.uid;
    cred->gid = tmp_cred.gid;

    /* NOV-101642: Only do the following check if we're the hub */
    if (_LSTransportIsHub())
    {
        if (tmp_cred.pid != LS_PID_INVALID)
        {
            cred->exe_path = _LSTransportPidToExe(tmp_cred.pid, lserror);

            if (!cred->exe_path)
            {
                return false;
            }

            cred->cmd_line = _LSTransportPidToCmdLine(tmp_cred.pid, lserror);

            if (!cred->cmd_line)
            {
                g_free((char*)cred->exe_path);
                cred->exe_path = NULL;
                return false;
            }
        }
    }

#else
    cred->pid = LS_PID_INVALID;
    cred->uid = LS_UID_INVALID;
    cred->gid = LS_GID_INVALID;
#endif

    return true;
}

void _LSTransportCredSetExePath(_LSTransportCred *cred, char const *exe_path)
{
    g_free((char *) cred->exe_path);
    cred->exe_path = g_strdup(exe_path);
}

void _LSTransportCredSetPid(_LSTransportCred *cred, pid_t pid)
{
    cred->pid = pid;
}

/*< @} END OF LunaServiceTransportSecurity */
