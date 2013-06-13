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


#ifndef _TRANSPORT_CHANNEL_H_
#define _TRANSPORT_CHANNEL_H_

#include <stdbool.h>
#include <glib.h>

/* FIXME -- this should be in a header file */
#ifndef _TRANSPORT_H_
typedef struct LSTransport _LSTransport;
#endif

struct LSTransportChannel {
    _LSTransport *transport;    /**< transport that owns this channel */
    int fd;
    int priority;               /**< glib priority for send/recv watch */
    GIOChannel *channel;
    GSource *send_watch;
    GSource *recv_watch;
    GSource *accept_watch;      /**< only used on listen channel (one per transport */
};

typedef struct LSTransportChannel _LSTransportChannel;

bool _LSTransportChannelInit(_LSTransport *transport, _LSTransportChannel *channel, int fd, int priority);
int _LSTransportChannelGetFd(const _LSTransportChannel *channel);
void _LSTransportChannelDeinit(_LSTransportChannel *channel);
void _LSTransportChannelClose(_LSTransportChannel *channel, bool flush);
void _LSTransportChannelSetPriority(_LSTransportChannel *channel, int priority);
bool _LSTransportChannelHasReceiveWatch(const _LSTransportChannel *channel);
bool _LSTransportChannelHasSendWatch(const _LSTransportChannel *channel);
void _LSTransportChannelSetBlock(_LSTransportChannel *channel, bool *prev_state_blocking);
void _LSTransportChannelSetNonblock(_LSTransportChannel *channel, bool *prev_state_blocking);
void _LSTransportChannelRestoreBlockState(_LSTransportChannel *channel, const bool *prev_state_blocking);

#endif      // _TRANSPORT_CHANNEL_H_
