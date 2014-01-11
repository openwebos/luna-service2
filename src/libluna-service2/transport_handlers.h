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


#ifndef _TRANSPORT_HANDLERS_H_
#define _TRANSPORT_HANDLERS_H_

#include <luna-service2/lunaservice.h>
#include "transport_message.h"
#include "transport_client.h"

typedef enum
{
    LSMessageHandlerResultHandled,          /**< message was handled */
    LSMessageHandlerResultNotHandled,       /**< message was not handled; error will be sent as reply */
    LSMessageHandlerResultUnknownMethod,    /**< method was not found; error will be sent as reply */
} LSMessageHandlerResult;

typedef LSMessageHandlerResult (*LSTransportMessageHandler)(_LSTransportMessage *message, void *context);

typedef enum {
    _LSTransportDisconnectTypeClean,
    _LSTransportDisconnectTypeDirty
} _LSTransportDisconnectType;

/* client -- client that went down */
typedef void (*LSTransportDisconnectHandler)(_LSTransportClient *client, _LSTransportDisconnectType type, void *context);

typedef enum {
    _LSTransportMessageFailureTypeInvalid = -1,
    _LSTransportMessageFailureTypeUnknown,              /**< service went down and message status is unknown */
    _LSTransportMessageFailureTypeNotProcessed,         /**< service went down and message was not processed */
    _LSTransportMessageFailureTypeServiceUnavailable,   /**< the service is not up */
    _LSTransportMessageFailureTypePermissionDenied,     /**< invalid permission to contact service */
    _LSTransportMessageFailureTypeServiceNotExist,      /**< service doesn't exists (not in service file) */
    _LSTransportMessageFailureTypeMessageContentError,  /**< badly formatted message (corrupt or fake) */
} _LSTransportMessageFailureType;

typedef void (*LSTransportMessageFailure)(LSMessageToken global_token, _LSTransportMessageFailureType failure_type, void *context);

typedef struct LSTransportHandlers {
    LSTransportMessageFailure    message_failure_handler;   /**< callback to handle when a message fails to be delivered to the other side */
    void *message_failure_context;

    LSTransportDisconnectHandler disconnect_handler;        /**< callback to handle when a client disconnects */
    void *disconnect_context;

    LSTransportMessageHandler msg_handler;                  /**< callback to handle incoming messages */
    void *msg_context;
} LSTransportHandlers;

#endif      // _TRANSPORT_HANDLERS_H_
