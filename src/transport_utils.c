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


#include <fcntl.h>
#include <string.h>
#include "transport.h"
#include "transport_utils.h"
#include "base.h"

int _ls_debug_tracing = 0;

#ifdef COMPILE_VERBOSE_MESSAGES
void
_ls_verbose(const char *format, ...)
{
    va_list vargs;

    if (DEBUG_VERBOSE)/*(DEBUG_VERBOSE)*/
    {
        fprintf(stderr, "%lx: ", pthread_self());
        va_start(vargs, format);
        vfprintf(stderr, format, vargs);
        va_end(vargs);

        fflush(stderr);
    } 
}
#endif

int
strlen_safe(const char *str)
{
    if (str)
    {
        return strlen(str);
    }
    else
    {
        return 0;
    }
}

void
DumpHashItem(gpointer key, gpointer value, gpointer user_data)
{
    printf("key: %s, value: %p\n", (char*)key, value);
}

void
DumpHashTable(GHashTable *table)
{
    LS_ASSERT(table != NULL);

    g_hash_table_foreach(table, DumpHashItem, NULL);
    printf("\n");
}

/** 
 *******************************************************************************
 * @brief Set a callback for the specified signal.
 * 
 * @param  signal           IN  signal number (e.g., SIGINT)
 * @param  handler          IN  callback 
 * 
 * @retval true on success
 * @retval false on failure
 *******************************************************************************
 */
bool
_LSTransportSetupSignalHandler(int signal, void (*handler)(int))
{
    int ret = 0;
    sigset_t all_sigs;
    ret = sigfillset(&all_sigs);

    if (ret == -1)
    {
        return false;
    }

    struct sigaction sig_action =
    {
        .sa_handler = handler,
        .sa_mask = all_sigs,
        .sa_flags = 0,
        /* sa_restorer intentionally left out
         * it will be initialized to 0 on platforms where it exists */
    };

    ret = sigaction(signal, &sig_action, NULL);

    if (ret == -1)
    {
        return false;
    }

    return true;
}

/** 
 *******************************************************************************
 * @brief Set the fd to blocking or non-blocking mode and return previous
 * state.
 * 
 * @param  fd                       IN  fd
 * @param  block                    IN  true means set to blocking, false
 *                                      non-blocking
 * @param  prev_state_blocking      OUT previous state of fd (true means
 *                                      blocking) 
 *******************************************************************************
 */
void
_LSTransportFdSetBlockingState(int fd, bool block, bool *prev_state_blocking)
{
    LS_ASSERT(fd >= 0);
    
    bool old_block_state;
    int ret;

    /* Get current file descriptor flags */
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
    {
        LS_ASSERT(0);
    }

    /* Save current blocking state before we modify it */
    if (flags & O_NONBLOCK)
    {
        old_block_state = false;
    }
    else
    {
        old_block_state = true;
    }

    if (!block)
    {
        ret = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
    else
    {
        ret = fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
    }

    if (ret < 0)
    {
        LS_ASSERT(0);
    }

    if (prev_state_blocking != NULL)
    {
        *prev_state_blocking = old_block_state;
    }
}

/** 
 *******************************************************************************
 * @brief Set the fd to blocking mode.
 * 
 * @param  fd                   IN  fd 
 * @param  prev_state_blocking  OUT previous state of the fd (true means
 *                                  blocking)
 *******************************************************************************
 */
void
_LSTransportFdSetBlock(int fd, bool *prev_state_blocking)
{
    LS_ASSERT(fd >= 0);
    _LSTransportFdSetBlockingState(fd, true, prev_state_blocking);
}

/** 
 *******************************************************************************
 * @brief Set the fd to non-blocking mode.
 * 
 * @param  fd                   IN  fd 
 * @param  prev_state_blocking  OUT previous state of the fd (true means
 *                                  blocking)
 *******************************************************************************
 */
void
_LSTransportFdSetNonBlock(int fd, bool *prev_state_blocking)
{
    LS_ASSERT(fd >= 0);
    _LSTransportFdSetBlockingState(fd, false, prev_state_blocking);
}
