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


#include <fcntl.h>
#include <string.h>
#include "transport.h"
#include "transport_utils.h"
#include "base.h"

/* Hub socket's data */
static char *hub_socket_dir = NULL;
static char *public_hub_addr = NULL;
static char *private_hub_addr = NULL;

int _ls_debug_tracing = 0;

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

static void init_socket_addresses()
{
    /*
     * LS_HUB_LOCAL_SOCKET_DIRECTORY - environmental variable, which points to custom
     * hubs' sockets directory, otherwise we try to find it in default, /tmp directory.
     */
    if (!(hub_socket_dir = getenv("LS_HUB_LOCAL_SOCKET_DIRECTORY")))
    {
        hub_socket_dir = HUB_LOCAL_SOCKET_DIRECTORY;
    }

    public_hub_addr = g_strconcat(hub_socket_dir, "/", HUB_LOCAL_ADDRESS_PUBLIC_NAME, NULL);
    private_hub_addr = g_strconcat(hub_socket_dir, "/", HUB_LOCAL_ADDRESS_PRIVATE_NAME, NULL);
}

static pthread_once_t socket_address_initialized = PTHREAD_ONCE_INIT;

/**
 *******************************************************************************
 * @brief Get hub's socket address.
 *
 * @param  is_public_bus     IN   if we are trying to connect to the public bus
 * (private otherwise)
 *
 * @retval socket address
 *******************************************************************************
 */
const char *_LSGetHubLocalSocketAddress(bool is_public_bus)
{
    (void) pthread_once(&socket_address_initialized, init_socket_addresses);

    return is_public_bus ? public_hub_addr : private_hub_addr;
}

/**
 *******************************************************************************
 * @brief Get hub's socket directory.
 *
 * @param  is_public_bus     IN   if we are trying to connect to the public bus
 * (private otherwise)
 *
 * @retval local socket directory
 *******************************************************************************
 */
const char *_LSGetHubLocalSocketDirectory(bool is_public_bus)
{
    (void) pthread_once(&socket_address_initialized, init_socket_addresses);

    return hub_socket_dir;
}
