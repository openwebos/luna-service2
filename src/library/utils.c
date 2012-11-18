/* @@@LICENSE
*
*      Copyright (c) 2008-2012 Hewlett-Packard Development Company, L.P.
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


#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdbool.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <glib.h>

/**
 * @addtogroup LunaServiceUtils
 * @{
 */

/** 
 *******************************************************************************
 * @brief Set a lock on the specified file
 * 
 * @param  fd   file descriptor
 * 
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
LSLockFile(int fd)
{
    struct flock fileLock = 
    {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 0,
    };

    int retVal = 0;

    retVal = fcntl(fd, F_SETLK, &fileLock);

    if (-1 == retVal)
    {
        /* already locked */
        return false;
    }

    return true;
}

/** 
 *******************************************************************************
 * @brief Check to see if an instance of this executable is running.
 * 
 * @param  pid_dir          IN   directory where the pid file should reside
 * @param  pid_file_name    IN   name of the pid (lock) file
 * 
 * @retval true if the executable is running (matching pid file found)
 * @retval false if the executable is not running
 *******************************************************************************
 */
bool
LSIsRunning(const char *pid_dir, const char *pid_file_name)
{
    char buf[16];
    int fd = 0;
    int write_ret = 0;
    int len = 0;
    char *lock_file = NULL;

    lock_file = g_strconcat(pid_dir, "/", pid_file_name, NULL);

    if (!lock_file)
    {
        g_critical("OOM when constructing pid path");
        exit(EXIT_FAILURE);
    }

    fd = open(lock_file, O_RDWR | O_CREAT, 0644);

    if (fd == -1)
    {
        g_critical("Error opening lock file: \"%s\"", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (!LSLockFile(fd))
    {
        close(fd);
        g_free(lock_file);
        return true; 
    }

    snprintf(buf, sizeof(buf), "%ld\n", (long)getpid());
    len = strlen(buf);

    write_ret = write(fd, buf, len);

    if (write_ret != len)
    {
        /* continue, but display a warning */
        g_critical("Did not write complete buffer to lock file: \"%s\"", strerror(errno));
    }
    
    if (ftruncate(fd, len) == -1)
    {
        /* continue, but display a warning */
        g_critical("Error while truncating lock file: \"%s\"", strerror(errno));
    }
    
    g_free(lock_file);

    return false; 
}

/* @} END OF LunaServiceUtils */
