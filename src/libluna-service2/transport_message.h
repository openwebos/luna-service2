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


#ifndef _TRANSPORT_MESSAGE_H_
#define _TRANSPORT_MESSAGE_H_

#include <sys/uio.h>
#include <luna-service2/lunaservice.h>
//#include "transport_client.h"

#include "transport_shm.h"

#ifdef LUNA_SERVICE_UNIT_TEST
#define INLINE
#else
#define INLINE inline
#endif

/**
 * @addtogroup LunaServiceTransportMessage
 *
 * @{
 */

#define LS_TRANSPORT_MESSAGE_DEFAULT_PAYLOAD_SIZE    16 /**< good default payload
                                                             size when creating
                                                             variable-length messages */

typedef struct LSTransportClient _LSTransportClient;

typedef enum LSTransportMessageType
{
    _LSTransportMessageTypeMethodCall,               /**< standard method call */
    _LSTransportMessageTypeReply,                    /**< reply to method call */
    _LSTransportMessageTypeSignal,                   /**< signal, which is sent to hub and broadcast out to interested clients */
    _LSTransportMessageTypeNodeUp,                   /**< message from client to hub indicating we are up and ready to accept connections */
    _LSTransportMessageTypeRequestNameLocal,         /**< request a "unique name" from the hub; local means it's a local unix domain name */
    _LSTransportMessageTypeRequestNameInet,
    _LSTransportMessageTypeRequestNameLocalReply,    /**< the hub's reply to the request for a local name */
    _LSTransportMessageTypeRequestNameInetReply,
    _LSTransportMessageTypeQueryName,                /**< look up a service name from the hub */
    _LSTransportMessageTypeQueryNameReply,
    _LSTransportMessageTypeShutdown,                 /**< clean shutdown message */
    _LSTransportMessageTypeServiceDownSignal,         /**< signal sent to registered clients indicating that a client that they're interested in went down */
    _LSTransportMessageTypeServiceUpSignal,           /**< signal sent to registered clients indicating that a client that they're interested in has come up */
    _LSTransportMessageTypeSignalRegister,           /**< register a signal with the bus */
    _LSTransportMessageTypeSignalUnregister,         /**< unregister a signal with the bus */
    _LSTransportMessageTypeError,                    /**< generic error */
    _LSTransportMessageTypeErrorUnknownMethod,       /**< method was not found error */
    _LSTransportMessageTypeCancelMethodCall,         /**< sent to cancel a subscription, does not expect a reply */
    _LSTransportMessageTypeClientInfo,               /**< connected client's service name */
    _LSTransportMessageTypeMonitorRequest,           /**< message to *hub* that asks to start monitoring */
    _LSTransportMessageTypeMonitorConnected,         /**< message from hub to clients that indicates we should start monitoring */
    _LSTransportMessageTypeMonitorNotConnected,      /**< message from hub to clients that indicates a monitor is not connected */
    _LSTransportMessageTypeQueryServiceStatus,       /**< message from client to hub to see if a service is available */
    _LSTransportMessageTypeQueryServiceStatusReply,  /**< reply from hub to client with status of the service */
    _LSTransportMessageTypeListClients,              /**< message to hub to request list of connected clients */
    _LSTransportMessageTypeListClientsReply,         /**< reply from hub with list of connected clients */
    _LSTransportMessageTypePushRole,                 /**< push a role (security state) to the hub */
    _LSTransportMessageTypePushRoleReply,            /**< reply for a push role message */
    _LSTransportMessageTypeUnknown,                  /**< tag uninitialized types */
    _LSTransportMessageTypeAppendCategory,           /**< message to the hub to update category tables */
    _LSTransportMessageTypeQueryServiceCategory,     /**< message from client to hub to get list of registered categories */
    _LSTransportMessageTypeQueryServiceCategoryReply,/**< reply from hub to client with list of registered categories */
} _LSTransportMessageType;

/**
 * @defgroup LSTransportQueryNameReturnCodes LSTransportQueryNameReturnCodes
 *
 * @{
 */

#define LS_TRANSPORT_QUERY_NAME_SUCCESS                  0  /**< success */
#define LS_TRANSPORT_QUERY_NAME_SERVICE_NOT_AVAILABLE   -1  /**< service is not up, could be a dynamic one in the process of coming up */
#define LS_TRANSPORT_QUERY_NAME_PERMISSION_DENIED       -2  /**< requester does not have permission to talk to requested service */
#define LS_TRANSPORT_QUERY_NAME_TIMEOUT                 -3  /**< timed out waiting for the dynamic service to come up */
#define LS_TRANSPORT_QUERY_NAME_SERVICE_NOT_EXIST       -4  /**< service does not exist */
#define LS_TRANSPORT_QUERY_NAME_CONNECT_TIMEOUT         -5  /**< connect'ing to service timed out */
#define LS_TRANSPORT_QUERY_NAME_MESSAGE_CONTENT_ERROR   -6  /**< badly formatted message (corrupt or fake) */

/** @} LSTransportQueryNameReturnCodes */

/**
 * @defgroup LSTransportRequestNameReturnCodes LSTransportRequestNameReturnCodes
 *
 * @{
 */

#define LS_TRANSPORT_REQUEST_NAME_SUCCESS                     0  /**< success */
#define LS_TRANSPORT_REQUEST_NAME_PERMISSION_DENIED          -1  /**< requester does not have permission to request name */
#define LS_TRANSPORT_REQUEST_NAME_NAME_ALREADY_REGISTERED    -2  /**< the name has already been registered by someone else */
#define LS_TRANSPORT_REQUEST_NAME_INVALID_PROTOCOL_VERSION   -3  /**< protocol versions do not match */

/** @} LSTransportRequestNameReturnCodes */

/**
 * @defgroup LSTransportPushRoleReturnCodes LSTransportPushRoleReturnCodes
 *
 * @{
 */
#define LS_TRANSPORT_PUSH_ROLE_SUCCESS               0
#define LS_TRANSPORT_PUSH_ROLE_FILE_ERROR           -1
#define LS_TRANSPORT_PUSH_ROLE_PERMISSION_DENIED    -2
#define LS_TRANSPORT_PUSH_ROLE_DUPLICATE            -3
#define LS_TRANSPORT_PUSH_ROLE_UNKNOWN_ERROR        -4

#define LS_TRANSPORT_PUSH_ROLE_FILE_ERROR_TEXT          "File error (check JSON): %s"
#define LS_TRANSPORT_PUSH_ROLE_PERMISSION_DENIED_TEXT   "Invalid permissions"
#define LS_TRANSPORT_PUSH_ROLE_DUPLICATE_TEXT           "Attempting to push a role after registering more than once"
#define LS_TRANSPORT_PUSH_ROLE_UNKNOWN_ERROR_TEXT       "Unknown error"

/** @} LSTransportPushRoleReturnCodes */

typedef enum LSTransportConnectState {
    _LSTransportConnectStateNoError = 0,    /**< successful connect (or no connect) */
    _LSTransportConnectStateEagain,         /**< connect() returned EAGAIN */
    _LSTransportConnectStateEinprogress,    /**< connect() returned EINPROGRESS */
    _LSTransportConnectStateOtherFailure    /**< connect() returned other error, which is considered fatal */
} _LSTransportConnectState;

/**
 * Header for the raw message.
 */
struct LSTransportHeader {
    unsigned long len;            /**< len of the data portion of the message (doesn't include size of header itself) */
    LSMessageToken token;         /**< serial associated with message */
    _LSTransportMessageType type; /**< signal, method call, reply, etc. */
};

typedef struct LSTransportHeader _LSTransportHeader;

/**
 * Underlying message that is sent across the wire. You shouldn't use this
 * directly, but instead use the @LSTransportMessage that wraps this.
 */
struct LSTransportMessageRaw {
    _LSTransportHeader header;
    char data[];                /**< actual data; variable length */
};

typedef struct LSTransportMessageRaw _LSTransportMessageRaw;

/**
 * Encapsulates the raw message with ref counting and state tracking.
 */
struct LSTransportMessage {
    int ref;
    _LSTransportClient *client;         /**< only valid for received messages -- client from which a message came */
    unsigned long tx_bytes_remaining;   /**< bytes of raw message left to transmit */
    guint timeout_id;                   /**< timeout source id (currently only used by hub) */
    unsigned long alloc_body_size;      /**< size of allocated memory for the body of
                                             the message (not including header). This
                                             can be larger than the actual len of the
                                             message to allow for adding arguments to
                                             to messages */
    int connection_fd;                  /**< fd passed from the hub that is already
                                             connected to the far side. This is only
                                             set for certain messages (-1 otherwise) */
    const char *app_id;                 /**< cached app id -- points inside the raw message */
    _LSTransportMessageRaw *raw;        /**< raw bytes sent over the wire */
    int retries;                        /**< remaining send retries */
    _LSTransportConnectState connect_state;   /**< state of connect() -- e.g., if we fail to connect()
                                                   due to non-blocking sockets we save the state here */
};

typedef struct LSTransportMessage _LSTransportMessage;

/**
 * Message data for monitor message copies.
 */
typedef enum {
    _LSMonitorMessageTypeTx,
    _LSMonitorMessageTypeRx
} _LSMonitorMessageType;

struct LSMonitorMessageData {
    _LSTransportMonitorSerial serial;
    _LSMonitorMessageType type;
    struct timespec timestamp;
};

typedef struct LSMonitorMessageData _LSMonitorMessageData;

bool LSTransportMessageFilterMatch(_LSTransportMessage *message, const char *filter);
void LSTransportMessagePrint(_LSTransportMessage *message, FILE *file);
int LSTransportMessagePrintCompactHeader(_LSTransportMessage *message, FILE *file);
int LSTransportMessagePrintCompactPayload(_LSTransportMessage *message, FILE *file, int width);

INLINE _LSTransportMessage* _LSTransportMessageEmpty();
INLINE _LSTransportMessage* _LSTransportMessageNew(unsigned long payload_size);
INLINE _LSTransportMessage* _LSTransportMessageNewRef(unsigned long payload_size);
INLINE void _LSTransportMessageReset(_LSTransportMessage *message);
INLINE void _LSTransportMessageFree(_LSTransportMessage *message);
INLINE _LSTransportMessage* _LSTransportMessageRef(_LSTransportMessage *message);
INLINE void _LSTransportMessageUnref(_LSTransportMessage *message);
INLINE _LSTransportMessage* _LSTransportMessageCopyNewRef(_LSTransportMessage *message);
INLINE _LSTransportMessage* _LSTransportMessageCopy(_LSTransportMessage *dest, const _LSTransportMessage *src);

_LSTransportMessage* _LSTransportMessageFromVectorNewRef(const struct iovec *iov, int iovcnt, unsigned long total_len);

INLINE guint _LSTransportMessageGetTimeoutId(const _LSTransportMessage *message);
INLINE void _LSTransportMessageSetTimeoutId(_LSTransportMessage *message, guint timeout_id);
INLINE _LSTransportConnectState _LSTransportMessageGetConnectState(const _LSTransportMessage * message);
INLINE void _LSTransportMessageSetConnectState(_LSTransportMessage *message, _LSTransportConnectState state);
INLINE int _LSTransportMessageGetConnectionFd(const _LSTransportMessage *message);
INLINE void _LSTransportMessageSetConnectionFd(_LSTransportMessage *message, int fd);
INLINE _LSTransportClient* _LSTransportMessageGetClient(const _LSTransportMessage *message);
INLINE void _LSTransportMessageSetClient(_LSTransportMessage *message, _LSTransportClient *client);
INLINE _LSTransportHeader* _LSTransportMessageGetHeader(const _LSTransportMessage *message);
INLINE void _LSTransportMessageSetHeader(_LSTransportMessage *message, _LSTransportHeader *header);
INLINE _LSTransportMessageType _LSTransportMessageGetType(const _LSTransportMessage *message);
INLINE void _LSTransportMessageSetType(_LSTransportMessage *message, _LSTransportMessageType type);
INLINE void _LSTransportMessageSetToken(_LSTransportMessage *message, LSMessageToken token);
INLINE LSMessageToken _LSTransportMessageGetToken(const _LSTransportMessage *message);
INLINE LSMessageToken _LSTransportMessageGetReplyToken(const _LSTransportMessage *message);
INLINE char* _LSTransportMessageGetBody(const _LSTransportMessage *message);
INLINE char* _LSTransportMessageSetBody(_LSTransportMessage *message, const void *body, int body_len);
INLINE int _LSTransportMessageGetBodySize(const _LSTransportMessage *message);

INLINE bool _LSTransportMessageIsMonitorType(const _LSTransportMessage *message);
INLINE bool _LSTransportMessageIsErrorType(const _LSTransportMessage *message);
INLINE bool _LSTransportMessageIsReplyType(const _LSTransportMessage *message);
INLINE bool _LSTransportMessageTypeIsMonitorType(_LSTransportMessageType type);
INLINE bool _LSTransportMessageTypeIsErrorType(_LSTransportMessageType type);
INLINE bool _LSTransportMessageTypeIsReplyType(_LSTransportMessageType type);
bool _LSTransportMessageIsConnectionFdType(const _LSTransportMessage *message);

const char* _LSTransportMessageGetMethod(const _LSTransportMessage *message);
const char* _LSTransportMessageGetCategory(const _LSTransportMessage *message);
const char* _LSTransportMessageGetPayload(const _LSTransportMessage *message);
INLINE void _LSTransportMessageSetAppId(_LSTransportMessage *message, const char *app_id);
const char* _LSTransportMessageGetAppId(_LSTransportMessage *message);
const char* _LSTransportMessageGetSenderServiceName(const _LSTransportMessage *message);
const char* _LSTransportMessageGetSenderUniqueName(const _LSTransportMessage *message);
const char* _LSTransportMessageGetDestServiceName(_LSTransportMessage *message);
const char* _LSTransportMessageGetDestUniqueName(_LSTransportMessage *message);
const char* _LSTransportMessageGetError(const _LSTransportMessage *message);

const _LSMonitorMessageData *_LSTransportMessageGetMonitorMessageData(_LSTransportMessage *message);

const char* _LSTransportMessageTypeQueryNameGetQueryName(_LSTransportMessage *message);
const char* _LSTransportMessageTypeQueryNameGetAppId(_LSTransportMessage *message);

/**
 * @defgroup LunaServiceTransportMessageIterator
 *
 * @{
 */

/**
 * Transport Message Iterator
 */
typedef struct _LSTransportMessageIter
{
    _LSTransportMessage *message;         /**< message this iterator belongs to */
    char *actual_iter;                    /**< current position in message */
    char *iter_end;                       /**< end of message */
    bool valid;                           /**< true when valid */
} _LSTransportMessageIter;

void _LSTransportMessageIterInit(_LSTransportMessage *message, _LSTransportMessageIter *iter);
bool _LSTransportMessageIterHasNext(_LSTransportMessageIter *iter);
_LSTransportMessageIter* _LSTransportMessageIterNext(_LSTransportMessageIter *iter);
bool _LSTransportMessageAppendString(_LSTransportMessageIter *iter, const char *str);
bool _LSTransportMessageAppendInt32(_LSTransportMessageIter *iter, int32_t value);
bool _LSTransportMessageAppendInt64(_LSTransportMessageIter *iter, int64_t value);
bool _LSTransportMessageAppendBool(_LSTransportMessageIter *iter, bool value);
bool _LSTransportMessageAppendInvalid(_LSTransportMessageIter *iter);
bool _LSTransportMessageGetString(_LSTransportMessageIter *iter, const char **str);
bool _LSTransportMessageGetInt32(_LSTransportMessageIter *iter, int32_t *ret);
bool _LSTransportMessageGetInt64(_LSTransportMessageIter *iter, int64_t *ret);
bool _LSTransportMessageGetBool(_LSTransportMessageIter *iter, bool *ret);

/** @} LunaServiceTransportMessageIterator */

/** @} LunaServiceTransportMessage */

#endif      // _TRANSPORT_MESSAGE_H_
