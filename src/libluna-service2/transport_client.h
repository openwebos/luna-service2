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


#ifndef _TRANSPORT_CLIENT_H_
#define _TRANSPORT_CLIENT_H_

#include "transport_outgoing.h"
#include "transport_incoming.h"
#include "transport_channel.h"
#include "transport_serial.h"
#include "transport_security.h"

typedef enum LSTransportClientState {
    _LSTransportClientStateInvalid = -1,
    _LSTransportClientStateConnected,       /**< set when we connect */
    _LSTransportClientStateShutdown,        /**< set when we get shutdown message */
    _LSTransportClientStateDisconnected,    /**< disconnected */
} _LSTransportClientState;

/**
 * A "client" encapsulates a connection to someone that you want to
 * communicate with. In the Luna Service world, the name is a bit misleading
 * because a client can serve as a LS client or LS server (i.e., it can
 * make method calls, process them, or do both).
 *
 * A LSTransportClient is created for each connection, including the hub,
 * monitor, and anyone else that you might be connecting to. It contains
 * incoming and outgoing buffers that keep track of data that is being
 * sent and received to/from the client.
 */
struct LSTransportClient {
    int ref;                            /**< ref count */
    char *unique_name;                  /**< globally unique address */
    char *service_name;                 /**< well-known name (e.g., com.palm.foo) */
    _LSTransportClientState state;      /* TODO: locking? */
    _LSTransport *transport;            /**< ptr back to overall transport obj */
    _LSTransportChannel channel;
    _LSTransportCred *cred;             /**< security credentials */
    _LSTransportOutgoing *outgoing;
    _LSTransportIncoming *incoming;
    bool is_sysmgr_app_proxy;           /**< true if this client is a
                                          "special" sysmgr connection
                                          used by apps */
    bool is_dynamic;                    /**< true for a dynamic service */
    bool initiator;                     /**< true if this is side that initiated the connection (typically by a method call) */
};

_LSTransportClient* _LSTransportClientNew(_LSTransport* transport, int fd, const char *service_name, const char *unique_name, _LSTransportOutgoing *outgoing, bool initiator);
void _LSTransportClientFree(_LSTransportClient* client);
_LSTransportClient* _LSTransportClientNewRef(_LSTransport* transport, int fd, const char *service_name, const char *unique_name, _LSTransportOutgoing *outgoing, bool initiator);
void _LSTransportClientRef(_LSTransportClient *client);
void _LSTransportClientUnref(_LSTransportClient *client);
const char* _LSTransportClientGetUniqueName(const _LSTransportClient *client);
const char* _LSTransportClientGetServiceName(const _LSTransportClient *client);
_LSTransportChannel* _LSTransportClientGetChannel(_LSTransportClient *client);
_LSTransport* _LSTransportClientGetTransport(const _LSTransportClient *client);
const _LSTransportCred* _LSTransportClientGetCred(const _LSTransportClient *client);

#endif      // _TRANSPORT_CLIENT_H_
