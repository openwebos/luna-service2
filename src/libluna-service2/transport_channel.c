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


#include <unistd.h>
#include <fcntl.h>

#include "error.h"
#include "transport_utils.h"
#include "transport_channel.h"

void _LSTransportRemoveSendWatch(_LSTransportChannel *channel);
void _LSTransportRemoveReceiveWatch(_LSTransportChannel *channel);
void _LSTransportRemoveAcceptWatch(_LSTransportChannel *channel);

/**
 * @defgroup LunaServiceTransportChannel
 * @ingroup LunaServiceTransport
 * @brief Transport channel
 */

/**
 * @addtogroup LunaServiceTransportChannel
 * @{
 */

/**
 *******************************************************************************
 * @brief Initialize a channel.
 *
 * @param  transport    IN  transport
 * @param  channel      IN  channel to initialize
 * @param  fd           IN  fd
 * @param  priority     IN  priority
 *
 * @retval true on success
 * @retval false on failure
 *******************************************************************************
 */
bool
_LSTransportChannelInit(_LSTransport *transport, _LSTransportChannel *channel, int fd, int priority)
{
    LS_ASSERT(channel != NULL);

    channel->transport = transport;
    channel->fd = fd;
    channel->priority = priority;
    channel->channel = g_io_channel_unix_new(fd);
    channel->send_watch = NULL;
    channel->recv_watch = NULL;
    channel->accept_watch = NULL;

    return true;
}

/**
 *******************************************************************************
 * @brief Deinitialize a channel.
 *
 * @param  channel  IN channel
 *******************************************************************************
 */
void
_LSTransportChannelDeinit(_LSTransportChannel *channel)
{
    LS_ASSERT(channel != NULL);

    if (channel->send_watch)
    {
        _LSTransportRemoveSendWatch(channel);
    }

    if (channel->recv_watch)
    {
        _LSTransportRemoveReceiveWatch(channel);
    }

    if (channel->accept_watch)
    {
        _LSTransportRemoveAcceptWatch(channel);
    }

    if (channel->channel)
    {
        g_io_channel_unref(channel->channel);
        channel->channel = NULL;
    }

    channel->transport = NULL;
}

/**
 *******************************************************************************
 * @brief Get the underlying file descriptor for a channel (not ref counted).
 *
 * @param  channel  IN  channel
 *
 * @retval  fd
 *******************************************************************************
 */
inline int
_LSTransportChannelGetFd(const _LSTransportChannel *channel)
{
    return channel->fd;
}

/**
 *******************************************************************************
 * @brief Close a channel.
 *
 * @param  channel  IN  channel
 * @param  flush    IN  flush the channel before closing
 *******************************************************************************
 */
void
_LSTransportChannelClose(_LSTransportChannel *channel, bool flush)
{
    LS_ASSERT(channel != NULL);

    GIOStatus status;
    GError *err = NULL;

    if (channel->channel)
    {
        status = g_io_channel_shutdown(channel->channel, flush, &err);

        if (err != NULL)
        {
            LOG_LS_WARNING(MSGID_LS_CHANNEL_ERR, 2,
                           PMLOGKFV("ERROR_CODE", "%d", err->code),
                           PMLOGKS("ERROR", err->message),
                           "Error on channel close (status: %d): %s", status, err->message);
            g_error_free(err);
        }

        g_io_channel_unref(channel->channel);
        channel->channel = NULL;
    }
}

/**
 *******************************************************************************
 * @brief Set the priority on a channel.
 *
 * @param  channel  IN  channel
 * @param  priority IN  priority
 *******************************************************************************
 */
void
_LSTransportChannelSetPriority(_LSTransportChannel *channel, int priority)
{
    LS_ASSERT(channel != NULL);

    if (channel->send_watch)
    {
        g_source_set_priority(channel->send_watch, priority);
    }

    if (channel->recv_watch)
    {
        g_source_set_priority(channel->recv_watch, priority);
    }

    channel->priority = priority;
}

bool
_LSTransportChannelHasReceiveWatch(const _LSTransportChannel *channel)
{
    LS_ASSERT(channel != NULL);
    return (channel->recv_watch != NULL);
}

bool
_LSTransportChannelHasSendWatch(const _LSTransportChannel *channel)
{
    LS_ASSERT(channel != NULL);
    return (channel->send_watch != NULL);
}

/**
 *******************************************************************************
 * @brief Set the given channel to blocking read/write mode. If
 * prev_state_blocking is not NULL, the previous state will be saved in that
 * variable.
 *
 * @param  channel                  IN  channel
 * @param  prev_state_blocking      OUT true if channel was set to block
 *                                      before calling this function,
 *                                      otherwise false
 *******************************************************************************
 */
void
_LSTransportChannelSetBlock(_LSTransportChannel *channel, bool *prev_state_blocking)
{
    LS_ASSERT(channel != NULL);
    int fd = _LSTransportChannelGetFd(channel);
    _LSTransportFdSetBlock(fd, prev_state_blocking);
}

/**
 *******************************************************************************
 * @brief Set the given channel to non-blocking read/write mode. If
 * prev_state_blocking is not NULL, the previous state will be saved in that
 * variable.
 *
 * @param  channel                  IN  channel
 * @param  prev_state_blocking      OUT true if channel was set to block
 *                                      before calling this function,
 *                                      otherwise false
 *******************************************************************************
 */
void
_LSTransportChannelSetNonblock(_LSTransportChannel *channel, bool *prev_state_blocking)
{
    LS_ASSERT(channel != NULL);
    int fd = _LSTransportChannelGetFd(channel);
    _LSTransportFdSetNonBlock(fd, prev_state_blocking);
}

/**
 *******************************************************************************
 * @brief Restore the saved blocking state to a channel (from
 * _LSTransportChannelSetBlock or _LSTransportChannelSetNonblock).
 *
 * @param  channel              IN  channel
 * @param  prev_state_blocking  IN  true sets channel to blocking, otherwise
 *                                  channel is set to non-blocking
 *******************************************************************************
 */
void
_LSTransportChannelRestoreBlockState(_LSTransportChannel *channel, const bool *prev_state_blocking)
{
    LS_ASSERT(channel != NULL);
    LS_ASSERT(prev_state_blocking != NULL);

    if (*prev_state_blocking)
    {
        _LSTransportChannelSetBlock(channel, NULL);
    }
    else
    {
        _LSTransportChannelSetNonblock(channel, NULL);
    }
}

/* @} END OF LunaServiceTransportChannel */
