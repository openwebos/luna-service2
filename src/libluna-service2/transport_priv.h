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


#ifndef _TRANSPORT_PRIV_H_
#define _TRANSPORT_PRIV_H_

#include <pthread.h>
#include <glib.h>

#include "transport.h"
#include "transport_message.h"
#include "transport_client.h"
#include "transport_serial.h"
#include "transport_outgoing.h"
#include "transport_incoming.h"
#include "transport_channel.h"
#include "transport_signal.h"
#include "transport_shm.h"

/**
 * "Global" in this case means that the token is unique for this transport to
 * all of its connected clients. It does not imply any system-wide uniqueness
 * or even uniqueness within a single process, since a process may create more
 * than one transport.
 *
 * For example, if this transport is registered as com.palm.foo and is
 * connected to clients com.palm.bar and com.palm.bar2, then there will be
 * no overlapping serial numbers used when sending to the two different clients:
 *
 * Example serial numbers used for com.palm.bar:  1, 2, 5
 * Example serial numbers used for com.palm.bar2: 3, 4
 */
typedef struct LSTransportGlobalToken {
    pthread_mutex_t lock;
    LSMessageToken value;
} _LSTransportGlobalToken;

struct LSTransport {
    _LSTransportType    type;                 /*<< local transport (domain socket) or inet transport */
    char                *service_name;        /*<< pretty name (e.g., com.palm.foo), NULL if there is no service name (e.g., anonymous client */
    char                *unique_name;         /*<< unique name (e.g., local socket address) */
    GMainContext        *mainloop_context;   /*<< glib mainloop context -- ref'd when added, so make sure to deref when done */

    int                  source_priority;    /*<< io watch priority (for glib mainloop) */

    _LSTransportChannel  listen_channel;     /*<< accept incoming connections */

    _LSTransportShm      *shm;               /*<< shared memory for ordering of monitor messages */

    /* TODO: just copy the vtable passed in, instead of individual ones */
    LSTransportMessageFailure    message_failure_handler;   /**< callback to handle when a message fails to be delivered to the other side */
    void* message_failure_context;

    LSTransportDisconnectHandler disconnect_handler;        /**< callback to handle when a client disconnects */
    void* disconnect_context;

    /* internal message handler */
    LSTransportMessageHandler msg_handler;          /**< callback to handle incoming messages */
    void *msg_context;                              /**< private context passed to message handling callback */

    _LSTransportClient      *hub;           /*<< client info for hub; should always be valid after connecting */
    _LSTransportClient      *monitor;       /*<< client info for monitor; NULL when there is no monitor */

    _LSTransportGlobalToken *global_token;  /*<< global token that provides unique identity for messages sent by this transport */

    pthread_mutex_t         lock;               /*<< lock for clients, all_connections, pending */
    GHashTable              *clients;           /*<< hash of _LSTransportClients by *service* name */
    GHashTable              *all_connections;   /*<< hash of fd to _LSTransportClient */
    GHashTable              *pending;           /*<< hash of _LSTransportOutgoing by service name */

    bool                    privileged;         /*<< true if we are a privileged service */
};

#endif      // _TRANSPORT_PRIV_H_
