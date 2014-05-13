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


#include <string.h>
#include <unistd.h>
#include "error.h"
#include "transport.h"
#include "transport_message.h"

/**
 * Returns true if it is safe to dereference the specificed type with the
 * given iterator
 */
#define ITER_SAFE_DEREFERENCE(iter, type) ((iter->iter_end - iter->actual_iter) >= sizeof(type))

void _LSTransportClientRef(_LSTransportClient *client);
void _LSTransportClientUnref(_LSTransportClient *client);
const char* _LSTransportClientGetUniqueName(const _LSTransportClient *client);
const char* _LSTransportClientGetServiceName(const _LSTransportClient *client);

/**
 * @defgroup LunaServiceTransportMessage
 * @ingroup LunaServiceTransport
 * @brief Transport message
 */

/**
 * @addtogroup LunaServiceTransportMessage
 * @{
 */

static _LSTransportClient EMPTY_CLIENT =
{
    .ref = 42,
    .unique_name = "",
    .service_name = LUNABUS_SERVICE_NAME,
    .state = _LSTransportClientStateInvalid,
};

static _LSTransportMessageRaw EMPTY_RAW_MESSAGE =
{
    .header =
        {
            .len = 0,
            .token = LSMESSAGE_TOKEN_INVALID,
            .type = _LSTransportMessageTypeUnknown,
        },
    .data = "",
};

static _LSTransportMessage EMPTY_MESSAGE =
{
    .ref = 42,
    .client = &EMPTY_CLIENT,
    .connection_fd = -1,
    .app_id = EMPTY_RAW_MESSAGE.data,
    .raw = &EMPTY_RAW_MESSAGE,
    .connect_state = _LSTransportConnectStateOtherFailure,
};

/**
 *******************************************************************************
 * @brief Empty transport message stub.
 *
 * @retval  empty message
 *******************************************************************************
 */
INLINE _LSTransportMessage*
_LSTransportMessageEmpty()
{
    return &EMPTY_MESSAGE;
}

 /**
 *******************************************************************************
 * @brief Allocate a new message.
 *
 * @param  payload_size     IN  size of payload (doesn't include header)
 *
 * @retval  message on success
 * @retval  NULL on failure
 *******************************************************************************
 */
INLINE _LSTransportMessage*
_LSTransportMessageNew(unsigned long payload_size)
{
    _LSTransportMessage *ret = g_slice_new0(_LSTransportMessage);

    ret->raw = g_malloc(sizeof(_LSTransportMessageRaw) + payload_size);

    ret->raw->header.len = payload_size;
    ret->raw->header.token = LSMESSAGE_TOKEN_INVALID;
    ret->raw->header.type = _LSTransportMessageTypeUnknown;
    ret->alloc_body_size = payload_size;
    ret->tx_bytes_remaining = payload_size + sizeof(_LSTransportHeader);
    ret->connection_fd = -1;
    ret->retries = MAX_SEND_RETRIES;
    ret->connect_state = _LSTransportConnectStateNoError;

    return ret;
}

/**
 *******************************************************************************
 * @brief Resets an existing message for retransmission.
 *
 * @param  message     IN  message to reset
 *******************************************************************************
 */
INLINE void
_LSTransportMessageReset(_LSTransportMessage *message)
{
    LS_ASSERT(message);

    message->tx_bytes_remaining = message->raw->header.len + sizeof(_LSTransportHeader);
    message->connection_fd = -1;
}

/**
 *******************************************************************************
 * @brief Allocate a new message with a ref count of 1.
 *
 * @param  payload_size     IN  size of payload (doesn't include header)
 *
 * @retval  message on success
 * @retval  NULL on failure
 *******************************************************************************
 */
INLINE _LSTransportMessage*
_LSTransportMessageNewRef(unsigned long payload_size)
{
    _LSTransportMessage *ret = _LSTransportMessageNew(payload_size);

    ret->ref = 1;

    return ret;
}

/**
 *******************************************************************************
 * @brief Free a message.
 *
 * @param  message  IN  message to free
 *******************************************************************************
 */
INLINE void
_LSTransportMessageFree(_LSTransportMessage *message)
{
    LS_ASSERT(message != NULL);
    LS_ASSERT(message->raw != NULL);

    if (message == &EMPTY_MESSAGE) return;

    if (message->client) _LSTransportClientUnref(message->client);

    int connection_fd = -1;
    if ((connection_fd = _LSTransportMessageGetConnectionFd(message)) != -1)
    {
        close(connection_fd);
    }

    message->app_id = NULL;    /* just for sanity; this points inside the raw message */

    g_free(message->raw);

#ifdef MEMCHECK
    memset(message, 0xFF, sizeof(_LSTransportMessage));
#endif

    g_slice_free(_LSTransportMessage, message);
}

/**
*******************************************************************************
* @brief Create a new message with ref count of 1 that is a copy of the passed
* in message. Only the type, token, and body are copied, NOT tx_bytes_remaining
* or the timeout source id.
*
* @param  message   IN  message to copy
*
* @retval copy on success
* @retval NULL on failure
*******************************************************************************
*/
INLINE _LSTransportMessage*
_LSTransportMessageCopyNewRef(_LSTransportMessage *message)
{
    int body_size = _LSTransportMessageGetBodySize(message);
    _LSTransportMessage *ret = _LSTransportMessageNewRef(body_size);

    /* NOTE: tx_bytes_remaining is set when we actually put the message
     * on the queue with _LSTransportSendMessage */

    if (message->app_id)
    {
        size_t offset = message->app_id - _LSTransportMessageGetBody(message);
        ret->app_id = _LSTransportMessageGetBody(ret) + offset;
    }
    else
    {
        ret->app_id = NULL;
    }

    /* NOTE: does not copy timeout source id */
    _LSTransportMessageSetType(ret, _LSTransportMessageGetType(message));
    _LSTransportMessageSetToken(ret, _LSTransportMessageGetToken(message));
    _LSTransportMessageSetBody(ret, _LSTransportMessageGetBody(message), body_size);

    return ret;
}

/**
 *******************************************************************************
 * @brief Copies the message type, token, and body from src to dest.
 *
 * @note assumes that dest has already been allocated and does not adjust any
 * ref count associated with dest. Also, does not copy timeout source or transmit
 * bytes remaining.
 *
 * @param  dest  IN/OUT   destination message (already allocated to correct size)
 * @param  src   IN       src message
 *
 * @retval dest
 *******************************************************************************
 */
INLINE _LSTransportMessage*
_LSTransportMessageCopy(_LSTransportMessage *dest, const _LSTransportMessage *src)
{
    LS_ASSERT(dest != NULL);
    LS_ASSERT(src != NULL);

    size_t dest_body_size = _LSTransportMessageGetBodySize(dest);
    size_t src_body_size = _LSTransportMessageGetBodySize(src);

    LS_ASSERT(dest_body_size >= src_body_size);

    if (src->app_id)
    {
        size_t offset = src->app_id - _LSTransportMessageGetBody(src);
        dest->app_id = _LSTransportMessageGetBody(dest) + offset;
    }
    else
    {
        dest->app_id = NULL;
    }

    _LSTransportMessageSetType(dest, _LSTransportMessageGetType(src));
    _LSTransportMessageSetToken(dest, _LSTransportMessageGetToken(src));
    _LSTransportMessageSetBody(dest, _LSTransportMessageGetBody(src), src_body_size);

    return dest;
}

/**
 *******************************************************************************
 * @brief Increment the ref count of a message.
 *
 * @param  message  IN  message
 *
 * @retval message
 *******************************************************************************
 */
INLINE _LSTransportMessage*
_LSTransportMessageRef(_LSTransportMessage *message)
{
    LS_ASSERT(message != NULL);
    LS_ASSERT(g_atomic_int_get(&message->ref) > 0);

    g_atomic_int_inc(&message->ref);

    return message;
}

/**
 *******************************************************************************
 * @brief Decrement the ref count of a message.
 *
 * @param  message
 *******************************************************************************
 */
INLINE void
_LSTransportMessageUnref(_LSTransportMessage *message)
{
    LS_ASSERT(message != NULL);

    if (g_atomic_int_dec_and_test(&message->ref))
    {
        _LSTransportMessageFree(message);
    }
}

/**
 *******************************************************************************
 * @brief Create a new message with ref count of 1 from an array of io vectors.
 *
 * @param  iov          IN  array of io vectors
 * @param  iovcnt       IN  number of items in @ref iov array
 * @param  total_len    IN  total size of @ref io array
 *
 * @retval  message on success
 * @retval  NULL on failure
 *******************************************************************************
 */
_LSTransportMessage*
_LSTransportMessageFromVectorNewRef(const struct iovec *iov, int iovcnt, unsigned long total_len)
{
    _LSTransportMessage *message = _LSTransportMessageNewRef(total_len - sizeof(_LSTransportHeader));

    int i;
    int offset = 0;

    for (i = 0; i < iovcnt; i++)
    {
        memcpy((char*)message->raw + offset, iov[i].iov_base, iov[i].iov_len);
        offset += iov[i].iov_len;
    }

    return message;
}

/**
 *******************************************************************************
 * @brief Returns true if the message type is one that we're interested in
 * seeing output by the monitor.
 *
 * @param  type     IN  message type
 *
 * @retval  true if we should output to monitor
 * @retval  false otherwise
 *******************************************************************************
 */
INLINE bool
_LSTransportMessageTypeIsMonitorType(_LSTransportMessageType type)
{
    switch (type)
    {
    case _LSTransportMessageTypeReply:
    case _LSTransportMessageTypeMethodCall:
    case _LSTransportMessageTypeCancelMethodCall:
    case _LSTransportMessageTypeSignal:
        return true;

    default:
        return false;
    }
}

/**
 *******************************************************************************
 * @brief Check to see if the message is a type that we want to monitor (i.e.,
 * if it is then we send it to the monitor, otherwise we don't).
 *
 * @param  message  IN  message
 *
 * @retval  true if we should send this message to the monitor
 * @retval  false otherwise
 *******************************************************************************
 */
INLINE bool
_LSTransportMessageIsMonitorType(const _LSTransportMessage *message)
{
    return _LSTransportMessageTypeIsMonitorType(_LSTransportMessageGetType(message));
}

/**
 *******************************************************************************
 * @brief Returns true if the message type is an error.
 *
 * @param  type IN  message type
 *
 * @retval  true if message is an error type
 * @retval  false otherwise
 *******************************************************************************
 */
INLINE bool
_LSTransportMessageTypeIsErrorType(_LSTransportMessageType type)
{
    switch (type)
    {
    case _LSTransportMessageTypeError:
    case _LSTransportMessageTypeErrorUnknownMethod:
        return true;

    default:
        return false;
    }
}

/**
 *******************************************************************************
 * @brief   Returns true if the message is an error.
 *
 * @param  message  IN  message
 *
 * @retval  true if message is an error
 * @retval  false otherwise
 *******************************************************************************
 */
INLINE bool
_LSTransportMessageIsErrorType(const _LSTransportMessage *message)
{
    return _LSTransportMessageTypeIsErrorType(_LSTransportMessageGetType(message));
}

/**
 *******************************************************************************
 * @brief Returns true if the message is a "reply" type message (i.e., it has
 * a reply serial.
 *
 * @param  type     IN  message type
 *
 * @retval  true if reply type
 * @retval  false otherwise
 *******************************************************************************
 */
INLINE bool
_LSTransportMessageTypeIsReplyType(_LSTransportMessageType type)
{
    if (_LSTransportMessageTypeIsErrorType(type))
    {
        return true;
    }

    switch (type)
    {
    case _LSTransportMessageTypeReply:
    case _LSTransportMessageTypeQueryServiceStatusReply:
        return true;

    default:
        return false;
    }
}

/**
 *******************************************************************************
 * @brief Returns true if the message is a "reply" type (i.e., it has a reply
 * serial)
 *
 * @param  message  IN  message
 *
 * @retval true if reply type
 * @retval false otherwise
 *******************************************************************************
 */
INLINE bool
_LSTransportMessageIsReplyType(const _LSTransportMessage *message)
{
    return _LSTransportMessageTypeIsReplyType(_LSTransportMessageGetType(message));
}

INLINE bool
_LSTransportMessageIsConnectionFdType(const _LSTransportMessage *message)
{
    switch (_LSTransportMessageGetType(message))
    {
    case _LSTransportMessageTypeQueryNameReply:
    case _LSTransportMessageTypeRequestNameLocalReply:
    case _LSTransportMessageTypeMonitorConnected:
        return true;

    default:
        return false;
    }
}

/**
 *******************************************************************************
 * @brief Get an error string from an error message
 *
 * @param  message  IN  error message
 *
 * @retval error string
 *******************************************************************************
 */
const char*
_LSTransportMessageGetError(const _LSTransportMessage *message)
{
    LS_ASSERT(_LSTransportMessageIsErrorType(message));

    /* error message is just a string after the reply token */
    return _LSTransportMessageGetPayload(message);
}

/**
 *******************************************************************************
 * @brief Gets the timeout source id associated with the message.
 *
 * @param  message  IN  message
 *
 * @retval  id (0 means no timeout source id)
 *******************************************************************************
 */
INLINE guint
_LSTransportMessageGetTimeoutId(const _LSTransportMessage *message)
{
    LS_ASSERT(message != NULL);
    return message->timeout_id;
}

/**
 *******************************************************************************
 * @brief Set the timeout source id associated with the message.
 *
 * @param  message      IN  message
 * @param  timeout_id   IN  timeout source id (ret val from g_timeout_add())
 *******************************************************************************
 */
INLINE void
_LSTransportMessageSetTimeoutId(_LSTransportMessage *message, guint timeout_id)
{
    LS_ASSERT(message != NULL);
    message->timeout_id = timeout_id;
}

/**
 *******************************************************************************
 * @brief Get the "connect" state from a message (used for non-blocking
 * connect())
 *
 * @param  message  IN message to set state on
 *
 * @retval  state
 *******************************************************************************
 */
INLINE _LSTransportConnectState
_LSTransportMessageGetConnectState(const _LSTransportMessage * message)
{
    LS_ASSERT(message != NULL);
    return message->connect_state;
}

/**
 *******************************************************************************
 * @brief Set the "connect" state on a message (used for non-blocking
 * connect()).
 *
 * @param  message  IN message to set state on
 * @param  state    IN new state
 *******************************************************************************
 */
INLINE void
_LSTransportMessageSetConnectState(_LSTransportMessage *message, _LSTransportConnectState state)
{
    LS_ASSERT(message != NULL);
    message->connect_state = state;
}


INLINE int
_LSTransportMessageGetConnectionFd(const _LSTransportMessage *message)
{
    LS_ASSERT(message != NULL);
    return message->connection_fd;
}

INLINE void
_LSTransportMessageSetConnectionFd(_LSTransportMessage *message, int fd)
{
    LS_ASSERT(message != NULL);
    message->connection_fd = fd;
}


/**
 *******************************************************************************
 * @brief Get the client associated with the message (only valid for
 * received messages). This does not increment the client's ref count.
 *
 * @param  message  IN  message from which to get associated client
 *
 * @retval  client on success
 * @retval  NULL on failure
 *******************************************************************************
 */
INLINE _LSTransportClient*
_LSTransportMessageGetClient(const _LSTransportMessage *message)
{
    LS_ASSERT(message != NULL);
    return message->client;
}

/**
 *******************************************************************************
 * @brief Set the client associated with the message. This increments the
 * client's refcount.
 *
 * @param  message  IN  message
 * @param  client   IN  client
 *******************************************************************************
 */
INLINE void
_LSTransportMessageSetClient(_LSTransportMessage *message, _LSTransportClient *client)
{
    LS_ASSERT(message != NULL);
    LS_ASSERT(client != NULL);

    _LSTransportClientRef(client);
    message->client = client;
}

/**
 *******************************************************************************
 * @brief Get header for the message.
 *
 * @param  message  IN  message
 *
 * @retval header
 *******************************************************************************
 */
INLINE _LSTransportHeader*
_LSTransportMessageGetHeader(const _LSTransportMessage *message)
{
    LS_ASSERT(message != NULL);
    return &message->raw->header;
}

/**
 *******************************************************************************
 * @brief Set the message header
 *
 * @param  message  IN  message
 * @param  header   IN  header
 *******************************************************************************
 */
INLINE void
_LSTransportMessageSetHeader(_LSTransportMessage *message, _LSTransportHeader *header)
{
    LS_ASSERT(message != NULL);
    LS_ASSERT(header != NULL);

    memcpy(&message->raw->header, header, sizeof(_LSTransportHeader));
}

/**
 *******************************************************************************
 * @brief Get the type of a message
 *
 * @param  message  IN   message
 *
 * @retval  type
 *******************************************************************************
 */
INLINE _LSTransportMessageType
_LSTransportMessageGetType(const _LSTransportMessage *message)
{
    return message->raw->header.type;
}

/**
 *******************************************************************************
 * @brief Set the type of a message.
 *
 * @param  message  IN  message
 * @param  type     IN  type
 *******************************************************************************
 */
INLINE void
_LSTransportMessageSetType(_LSTransportMessage *message, _LSTransportMessageType type)
{
    message->raw->header.type = type;
}

/**
 *******************************************************************************
 * @brief Set the token (serial) for a message.
 *
 * @param  message  IN  message
 * @param  token    IN  token
 *******************************************************************************
 */
INLINE void
_LSTransportMessageSetToken(_LSTransportMessage *message, LSMessageToken token)
{
    message->raw->header.token = token;
}

/**
 *******************************************************************************
 * @brief Get the token (serial) for a message.
 *
 * @param  message  IN  message
 *
 * @retval  token
 *******************************************************************************
 */
INLINE LSMessageToken
_LSTransportMessageGetToken(const _LSTransportMessage *message)
{
    return message->raw->header.token;
}

/**
 *******************************************************************************
 * @brief Get the reply token (serial) for a message.
 *
 * @param  message  IN  message
 *
 * @retval  token on success
 * @retval  0 if message is incorrect type
 *******************************************************************************
 */
INLINE LSMessageToken
_LSTransportMessageGetReplyToken(const _LSTransportMessage *message)
{
    LS_ASSERT(message != NULL);

    if (!_LSTransportMessageIsReplyType(message))
    {
        /* match legacy behavior when attempting to get reply tokens
         * on method calls... */
        LOG_LS_WARNING(MSGID_LS_REPLY_TOK, 1,
                       PMLOGKFV("MSG_TYPE", "%d", _LSTransportMessageGetType(message)),
                       "Getting reply token for message type: %d", _LSTransportMessageGetType(message));
        return 0;
    }

    int token_size = sizeof(LSMessageToken);
    char *body = _LSTransportMessageGetBody(message);
    if (body && _LSTransportMessageGetBodySize(message) >= token_size)
    {
        return *((LSMessageToken*)(body));
    }

    return LSMESSAGE_TOKEN_INVALID;
}


/**
 *******************************************************************************
 * @brief Get the body of a message.
 *
 * @param  message  IN  message
 *
 * @retval  body
 *******************************************************************************
 */
INLINE char*
_LSTransportMessageGetBody(const _LSTransportMessage *message)
{
    /* TODO: differentiate between GetRawBody and GetBody -- this will be the
     * raw version but the other version will get the body based on the
     * message type */
    if (_LSTransportMessageGetBodySize(message) > 0)
    {
        return message->raw->data;
    }
    return NULL;
}

/**
 *******************************************************************************
 * @brief Set the message body by copying the passed data.
 *
 * @param  message  IN  message
 * @param  body     IN  body data
 * @param  body_len IN  len of @ref body data
 *
 * @retval body
 *******************************************************************************
 */
INLINE char*
_LSTransportMessageSetBody(_LSTransportMessage *message, const void *body, int body_len)
{
    LS_ASSERT(message != NULL);
    LS_ASSERT(body != NULL);

    return memcpy(message->raw->data, body, body_len);
}

/**
 *******************************************************************************
 * @brief Get the "raw" message for the message. The raw message is what is
 * actually sent over the wire.
 *
 * @param  message  IN  message
 *
 * @retval  raw message
 *******************************************************************************
 */
INLINE _LSTransportMessageRaw*
_LSTransportMessageGetRawMessage(_LSTransportMessage *message)
{
    LS_ASSERT(message != NULL);

    return message->raw;
}

/**
 *******************************************************************************
 * @brief Set the "raw" message for the message. The raw message is what is
 * actually sent over the wire.
 *
 * @param  message  IN  message
 * @param  raw      IN  raw message
 *
 * @retval  raw message
 *******************************************************************************
 */
INLINE _LSTransportMessageRaw*
_LSTransportMessageSetRawMessage(_LSTransportMessage *message, _LSTransportMessageRaw *raw)
{
    LS_ASSERT(message != NULL);
    LS_ASSERT(raw != NULL);

    message->raw = raw;
    return raw;
}

/**
 *******************************************************************************
 * @brief Get the size of the message body. (More memory may have be allocated behind
 * for the body behind the scenes. See _LSTransportMessageSetAllocBodySize()).
 *
 * @param  message  IN  message
 *
 * @retval size in bytes
 *******************************************************************************
 */
INLINE int
_LSTransportMessageGetBodySize(const _LSTransportMessage *message)
{
    LS_ASSERT(message != NULL);
    return _LSTransportMessageGetHeader(message)->len;
}

/**
 *******************************************************************************
 * @brief Set the currently set size of the message body (do not include the
 * size of the header).
 *
 * @param  message  IN  message
 * @param  size     IN  size (bytes)
 *******************************************************************************
 */
static INLINE void
_LSTransportMessageSetBodySize(const _LSTransportMessage *message, unsigned long size)
{
    LS_ASSERT(message != NULL);
    _LSTransportMessageGetHeader(message)->len = size;
}

/**
 *******************************************************************************
 * @brief Checks to see if the specified pointer falls within the message body.
 *
 * @param  message  IN  message
 * @param  ptr      IN  pointer to check
 *
 * @retval true if pointer points inside message body
 * @retval false otherwise
 *******************************************************************************
 */
static INLINE bool
_LSTransportMessageIsValidMessageBodyPtr(const _LSTransportMessage *message, const char *ptr)
{
    if (ptr < message->raw->data + _LSTransportMessageGetBodySize(message))
    {
        return true;
    }
    LOG_LS_WARNING(MSGID_LS_ACCESS_ERR, 0,
                   "Message access out of bounds: requested: %p, end: %p",
                   ptr, message->raw->data + _LSTransportMessageGetBodySize(message));
    return false;
}

/**
 *******************************************************************************
 * @brief Get the number of bytes allocated for the body of the message. (Does
 * not include the message header, which is implicitly allocated).
 *
 * @param  message  IN  message
 *
 * @retval  size (bytes)
 *******************************************************************************
 */
static INLINE int
_LSTransportMessageGetAllocBodySize(const _LSTransportMessage *message)
{
    LS_ASSERT(message != NULL);
    return message->alloc_body_size;
}

/**
 *******************************************************************************
 * @brief Set number of bytes allocated for the body of the message. (Do not
 * include the message header, which is implicitly allocated).
 *
 * @param  message  IN  message
 * @param  size     IN  size (bytes)
 *******************************************************************************
 */
static INLINE void
_LSTransportMessageSetAllocBodySize(_LSTransportMessage *message, unsigned long size)
{
    LS_ASSERT(message != NULL);
    message->alloc_body_size = size;
}

/**
 *******************************************************************************
 * @brief Expand the message body by @bytes_needed bytes. The message may be
 * moved in memory, but its contents will not change. The additional bytes are
 * not initialized.
 *
 * @param  message          IN  message
 * @param  bytes_needed     IN  number of bytes to add to message
 *
 * @retval  message on success (may have been moved)
 * @retval  NULL on failure
 *******************************************************************************
 */
_LSTransportMessage*
_LSTransportMessageBodyExpand(_LSTransportMessage *message, unsigned long bytes_needed)
{
    bool need_realloc = false;
    unsigned long alloc_body_size = _LSTransportMessageGetAllocBodySize(message);
    unsigned long body_size = _LSTransportMessageGetBodySize(message);

    _LSTransportMessageRaw *raw = _LSTransportMessageGetRawMessage(message);

    LS_ASSERT(alloc_body_size >= body_size);

    unsigned long new_body_size = body_size + bytes_needed;

    while (alloc_body_size < new_body_size)
    {
        alloc_body_size *= 2;
        need_realloc = true;
    }

    if (need_realloc)
    {
        raw = g_try_realloc(raw, sizeof(_LSTransportMessageRaw) + alloc_body_size);

        if (!raw)
        {
            new_body_size = 0;
            alloc_body_size = 0;
            LOG_LS_CRITICAL(MSGID_LS_OOM_ERR, 0, "Unable to re-allocate message body, OOM");
        }

        _LSTransportMessageSetRawMessage(message, raw);
        _LSTransportMessageSetAllocBodySize(message, alloc_body_size);
    }

    _LSTransportMessageSetBodySize(message, new_body_size);

    return message;
}

/**
 *******************************************************************************
 * @brief Get the payload for a message.
 *
 * @param  message  IN  message
 *
 * @retval  payload
 *******************************************************************************
 */
const char*
_LSTransportMessageGetPayload(const _LSTransportMessage *message)
{
    //LS_ASSERT(message->raw->header.type == _LSTransportMessageTypeReply);
    const char *ret = NULL;

    /* TODO: make this less expensive */
    switch (_LSTransportMessageGetType(message))
    {
    case _LSTransportMessageTypeReply:
    case _LSTransportMessageTypeError:
    case _LSTransportMessageTypeErrorUnknownMethod:
        /* skip over the reply serial */
        ret = _LSTransportMessageGetBody(message) + sizeof(LSMessageToken);
        if (!_LSTransportMessageIsValidMessageBodyPtr(message, ret))
        {
            return NULL;
        }
        return ret;

    case _LSTransportMessageTypeMethodCall:
    case _LSTransportMessageTypeCancelMethodCall:
    case _LSTransportMessageTypeSignal:
    case _LSTransportMessageTypeServiceUpSignal:
    case _LSTransportMessageTypeServiceDownSignal:
        /* skip over category */
        ret = _LSTransportMessageGetBody(message) + strlen(_LSTransportMessageGetBody(message)) + 1;

        if (!_LSTransportMessageIsValidMessageBodyPtr(message, ret))
        {
            return NULL;
        }

        /* skip over method */
        ret = ret + strlen(ret) + 1;

        if (!_LSTransportMessageIsValidMessageBodyPtr(message, ret))
        {
            return NULL;
        }
        return ret;

    default:
        /* When DEBUG_VERBOSE is enabled we expect to call this function on
         * all types of messages; otherwise we don't */
        if (!DEBUG_VERBOSE)
        {
            LOG_LS_DEBUG("No payload for message type: %d\n", _LSTransportMessageGetType(message));
        }
        return NULL;
    }

    return NULL;
}

/**
 *******************************************************************************
 * @brief Save a reference to the appId. This will *NOT* copy an memory; the
 * appId should point inside the message.
 *
 * @param  message  IN  message
 * @param  app_id   IN  application id
 *******************************************************************************
 */
INLINE void
_LSTransportMessageSetAppId(_LSTransportMessage *message, const char *app_id)
{
    LS_ASSERT(message != NULL);
    message->app_id = app_id;
}

/**
 *******************************************************************************
 * @brief Get a pointer to the application id in a message.
 *
 * @param  message  IN  message
 *
 * @retval  application id
 *******************************************************************************
 */
static const char*
_LSTransportMessageGetAppIdPtr(_LSTransportMessage *message)
{
    _LSTransportMessageType msg_type = _LSTransportMessageGetType(message);

    /* Check if value is cached */
    if (!message->app_id)
    {
        if (msg_type == _LSTransportMessageTypeMethodCall)
        {
            /* TODO: very inefficient */

            const char *payload = _LSTransportMessageGetPayload(message);

            /* skip over payload */
            const char *ret = (payload + strlen(payload) + 1);
            LS_ASSERT(ret);

            /* cache the value */
            message->app_id = ret;
        }
        else
        {
            LOG_LS_DEBUG("AppId msg type: %d", msg_type);
            return NULL;
        }
    }

    return message->app_id;
}

/**
 *******************************************************************************
 * @brief Get the application id for a message.
 *
 * @param  message  IN  message
 *
 * @retval  application id
 *******************************************************************************
 */
const char*
_LSTransportMessageGetAppId(_LSTransportMessage *message)
{
    const char *ret = _LSTransportMessageGetAppIdPtr(message);

    /* "NULL" is represented in the payload as an empty string
     * (i.e., just a '\0') */
    if (ret && *ret == '\0')
    {
        return NULL;
    }

    return ret;
}

/**
 *******************************************************************************
 * @brief Get the method for a message.
 *
 * @param  message  IN  message
 *
 * @retval  method
 *******************************************************************************
 */
const char*
_LSTransportMessageGetMethod(const _LSTransportMessage *message)
{
    /* TODO: make this less expensive */
    /* skip over category and the method is after the NUL */
    switch (_LSTransportMessageGetType(message))
    {
    case _LSTransportMessageTypeMethodCall:
    case _LSTransportMessageTypeCancelMethodCall:
    case _LSTransportMessageTypeSignal:
    case _LSTransportMessageTypeSignalRegister:
    case _LSTransportMessageTypeSignalUnregister:
    case _LSTransportMessageTypeServiceUpSignal:
    case _LSTransportMessageTypeServiceDownSignal:
    {
        const char *ret = message->raw->data + strlen(message->raw->data) + 1;
        if (!_LSTransportMessageIsValidMessageBodyPtr(message, ret))
        {
            return NULL;
        }
        return ret;
    }
    default:
        LOG_LS_DEBUG("Unrecognized type (%d) to call %s on", (int)_LSTransportMessageGetType(message), __func__);
        return NULL;
    }
}

/**
 *******************************************************************************
 * @brief Get category for a message.
 *
 * @param  message  IN  message
 *
 * @retval  category
 *******************************************************************************
 */
const char*
_LSTransportMessageGetCategory(const _LSTransportMessage *message)
{
    switch (_LSTransportMessageGetType(message))
    {
    case _LSTransportMessageTypeMethodCall:
    case _LSTransportMessageTypeCancelMethodCall:
    case _LSTransportMessageTypeSignal:
    case _LSTransportMessageTypeSignalRegister:
    case _LSTransportMessageTypeSignalUnregister:
    case _LSTransportMessageTypeServiceUpSignal:
    case _LSTransportMessageTypeServiceDownSignal:
        return message->raw->data;
    default:
        LOG_LS_DEBUG("Unrecognized type (%d) to call %s on", (int)_LSTransportMessageGetType(message), __func__);
        return NULL;
    }
}

/**
 *******************************************************************************
 * @brief Get the service name of the sender.
 *
 * @param  message  IN  message
 *
 * @retval  name
 *******************************************************************************
 */
const char*
_LSTransportMessageGetSenderServiceName(const _LSTransportMessage *message)
{
    LS_ASSERT(message != NULL);

    return _LSTransportClientGetServiceName(_LSTransportMessageGetClient(message));
}

/**
 *******************************************************************************
 * @brief Get the unique sender name.
 *
 * @param  message  IN  message
 *
 * @retval name (unique)
 *******************************************************************************
 */
const char*
_LSTransportMessageGetSenderUniqueName(const _LSTransportMessage *message)
{
    LS_ASSERT(message != NULL);

    return _LSTransportClientGetUniqueName(_LSTransportMessageGetClient(message));
}

/**
 *******************************************************************************
 * @brief Get the destination service name from the message. This only applies
 * messages sent to the monitor. The returned value points inside the message,
 * so you should copy it if you need it beyond the life of the message.
 *
 * @param  message  IN  message
 *
 * @retval service name (empty string if no name)
 *******************************************************************************
 */
const char*
_LSTransportMessageGetDestServiceName(_LSTransportMessage *message)
{
    switch (_LSTransportMessageGetType(message))
    {
    case _LSTransportMessageTypeMethodCall:
    {
        /* move past the appid to get the destination service name */
        const char *app_id = _LSTransportMessageGetAppIdPtr(message);

        /*
            In theory app_id can't be NULL as we are in the case for _LSTransportMessageTypeMethodCall and
            _LSTransportMessageGetAppIdPtr will only return a NULL when passed a message whose type is *not*
            _LSTransportMessageTypeMethodCall.
        */
        LS_ASSERT(app_id);

        const char *ret = app_id + strlen(app_id) + 1;

        /* make sure we're not trying to access data outside of the message */
        LS_ASSERT((ret - _LSTransportMessageGetBody(message) + 1) < _LSTransportMessageGetBodySize(message));

        return ret;
    }
    case _LSTransportMessageTypeCancelMethodCall:
    case _LSTransportMessageTypeSignal:
    case _LSTransportMessageTypeReply:
    {
        /* move past the payload to get the destination service name */
        const char *payload = _LSTransportMessageGetPayload(message);
        const char *ret = payload + strlen(payload) + 1;

        /* make sure we're not trying to access data outside of the message */
        LS_ASSERT((ret - _LSTransportMessageGetBody(message) + 1) < _LSTransportMessageGetBodySize(message));

        return ret;
    }
    default:
        LOG_LS_DEBUG("Unrecognized type (%d) to call %s on", (int)_LSTransportMessageGetType(message), __func__);
        return NULL;
    }
}

/**
 *******************************************************************************
 * @brief Get the destination unique name from the message. This only applies to
 * messages sent to the monitor. The returned value points inside the message,
 * so you should copy it if you need it beyond the life of the message.
 *
 * @param  message  IN  message
 *
 * @retval unique name string
 *******************************************************************************
 */
const char*
_LSTransportMessageGetDestUniqueName(_LSTransportMessage *message)
{
    switch (_LSTransportMessageGetType(message))
    {
    case _LSTransportMessageTypeMethodCall:
    case _LSTransportMessageTypeCancelMethodCall:
    case _LSTransportMessageTypeSignal:
    case _LSTransportMessageTypeReply:
    {
        /* move past the destination service name to get the destination unique name */
        const char *dest_service_name = _LSTransportMessageGetDestServiceName(message);
        const char *ret = dest_service_name + strlen(dest_service_name) + 1;

        /* make sure we're not trying to access data outside of the message */
        LS_ASSERT((ret - _LSTransportMessageGetBody(message) + 1) < _LSTransportMessageGetBodySize(message));

        return ret;
    }
    default:
        LOG_LS_DEBUG("Unrecognized type (%d) to call %s on", (int)_LSTransportMessageGetType(message), __func__);
        return NULL;
    }
}

/**
 *******************************************************************************
 * @brief Get the monitor serial number from the message. This only applies to
 * messages sent to the monitor.
 *
 * @param  message  IN  message
 *
 * @retval  serial
 *******************************************************************************
 */
const _LSMonitorMessageData*
_LSTransportMessageGetMonitorMessageData(_LSTransportMessage *message)
{
    switch (_LSTransportMessageGetType(message))
    {
    case _LSTransportMessageTypeMethodCall:
    case _LSTransportMessageTypeCancelMethodCall:
    case _LSTransportMessageTypeSignal:
    case _LSTransportMessageTypeReply:
    {
        /* move past the destination unique name to get the monitor serial */
        const char *dest_unique_name = _LSTransportMessageGetDestUniqueName(message);
        const char *ret = dest_unique_name + strlen(dest_unique_name) + 1;

        unsigned long offset = ret - _LSTransportMessageGetBody(message) + sizeof(_LSTransportHeader);

        /* move past padding */
        unsigned long padding = PADDING_BYTES_TYPE(void *, offset);

        ret += padding;

        /* make sure we're not trying to access data outside of the message */
        LS_ASSERT((ret - _LSTransportMessageGetBody(message) + 1) < _LSTransportMessageGetBodySize(message));

        return (_LSMonitorMessageData*)ret;
    }
    default:
        LOG_LS_DEBUG("Unrecognized type (%d) to call %s on", (int)_LSTransportMessageGetType(message), __func__);
        return NULL;
    }
}

/**
 *******************************************************************************
 * @brief Check if message matches the filter.
 *
 * @param  message      IN message
 * @param  filter       IN filter string
 * @param  check_sender IN  compare @ref filter against sender
 * @param  check_dest   IN  compare @ref filter against destination
 *
 * @retval  true if match found
 * @retval  false otherwise
 *******************************************************************************
 */
static bool
_LSTransportMessagePrintFilterMatch(_LSTransportMessage *message, const char *filter, bool check_sender, bool check_dest)
{
    /* treat no filter as matching */
    if (filter == NULL) return true;

    if (check_sender)
    {
        const char *sender_service_name = _LSTransportMessageGetSenderServiceName(message);
        const char *sender_unique_name = _LSTransportMessageGetSenderUniqueName(message);

        if ((sender_service_name && strstr(sender_service_name, filter)) ||
            (sender_unique_name && strstr(sender_unique_name, filter)))
        {
            return true;
        }
    }

    if (check_dest)
    {
        const char *dest_service_name =  _LSTransportMessageGetDestServiceName(message);
        const char *dest_unique_name = _LSTransportMessageGetDestUniqueName(message);

        if ((dest_service_name && strstr(dest_service_name, filter)) ||
            (dest_unique_name && strstr(dest_unique_name, filter)))
        {
            return true;
        }
    }

    return false;
}

/**
 *******************************************************************************
 * @brief Print out a message payload.
 *
 * @param  message  IN  message
 * @param  file     OUT file to print message to
 *******************************************************************************
 */
static void
_LSTransportMessagePrintPayload(const _LSTransportMessage *message, FILE *file)
{
    /* Raw UTF-8 encoding for 'Left-Pointing double angle quotation mark */
    fprintf(file, "\xc2\xab");
    fprintf(file, "%s", _LSTransportMessageGetPayload(message));
    /* Raw UTF-8 encoding for 'Right-Pointing double angle quotation mark' */
    fprintf(file, "\xc2\xbb");
}

/**
 *******************************************************************************
 * @brief Print a signal message.
 *
 * @param  message  IN  message
 * @param  file     IN  file to print message to
 *******************************************************************************
 */
static void
_LSTransportMessagePrintSignal(const _LSTransportMessage *message, FILE *file)
{
    LS_ASSERT(_LSTransportMessageGetType(message) == _LSTransportMessageTypeSignal);

    /* note that signals don't have a destination since they are broadcast */
    fprintf(file, "signal\t");
    fprintf(file, "%d\t", (int)_LSTransportMessageGetToken(message));
    fprintf(file, "\t");
    fprintf(file, "%s ", _LSTransportMessageGetSenderServiceName(message));
    fprintf(file, "(%s)\t", _LSTransportMessageGetSenderUniqueName(message));
    fprintf(file, "\t\t");
    fprintf(file, "%s/%s\t", _LSTransportMessageGetCategory(message), _LSTransportMessageGetMethod(message));
    _LSTransportMessagePrintPayload(message, file);
    fprintf(file, "\n");
}

/**
 *******************************************************************************
 * @brief Print "cancel method call" message.
 *
 * @param  message  IN  message
 * @param  file     IN  file to print message to
 *******************************************************************************
 */
static void
_LSTransportMessagePrintCancelMethodCall(_LSTransportMessage *message, FILE *file)
{
    LS_ASSERT(_LSTransportMessageGetType(message) == _LSTransportMessageTypeCancelMethodCall);

    fprintf(file, "call\t");
    fprintf(file, "%d\t", (int)_LSTransportMessageGetToken(message));
    fprintf(file, "\t");
    fprintf(file, "%s ", _LSTransportMessageGetSenderServiceName(message));
    fprintf(file, "(%s)\t", _LSTransportMessageGetSenderUniqueName(message));
    fprintf(file, "\t");
    fprintf(file, "%s ", _LSTransportMessageGetDestServiceName(message));
    fprintf(file, "(%s)\t", _LSTransportMessageGetDestUniqueName(message));
    fprintf(file, "\t");
    fprintf(file, "%s/%s\t", _LSTransportMessageGetCategory(message), _LSTransportMessageGetMethod(message));
    _LSTransportMessagePrintPayload(message, file);
    fprintf(file, "\n");
}

/**
 *******************************************************************************
 * @brief Print method call message.
 *
 * @param  message  IN  message
 * @param  file     IN  file to print message to
 *******************************************************************************
 */
static void
_LSTransportMessagePrintMethodCall(_LSTransportMessage *message, FILE *file)
{
    LS_ASSERT(_LSTransportMessageGetType(message) == _LSTransportMessageTypeMethodCall);

    fprintf(file, "call\t");
    fprintf(file, "%d\t", (int)_LSTransportMessageGetToken(message));
    fprintf(file, "\t");
    fprintf(file, "%s ", _LSTransportMessageGetSenderServiceName(message));
    fprintf(file, "(%s)\t", _LSTransportMessageGetSenderUniqueName(message));
    fprintf(file, "%s ", _LSTransportMessageGetDestServiceName(message));
    fprintf(file, "(%s)\t", _LSTransportMessageGetDestUniqueName(message));
    fprintf(file, "\t");
    fprintf(file, "%s\t", _LSTransportMessageGetAppId(message));
    fprintf(file, "\t");
    fprintf(file, "%s/%s\t", _LSTransportMessageGetCategory(message), _LSTransportMessageGetMethod(message));
    _LSTransportMessagePrintPayload(message, file);
    fprintf(file, "\n");
}

/**
 *******************************************************************************
 * @brief Print reply message.
 *
 * @param  message  IN  message
 * @param  file     IN  file to print message to
 *******************************************************************************
 */
static void
_LSTransportMessagePrintReply(_LSTransportMessage *message, FILE *file)
{
    LS_ASSERT(_LSTransportMessageGetType(message) == _LSTransportMessageTypeReply);

    fprintf(file, "return\t");
    fprintf(file, "%d\t", (int)_LSTransportMessageGetReplyToken(message));
    fprintf(file, "\t");
    fprintf(file, "%s ", _LSTransportMessageGetSenderServiceName(message));
    fprintf(file, "(%s)\t", _LSTransportMessageGetSenderUniqueName(message));
    fprintf(file, "\t");
    fprintf(file, "%s ", _LSTransportMessageGetDestServiceName(message));
    fprintf(file, "(%s)\t", _LSTransportMessageGetDestUniqueName(message));
    _LSTransportMessagePrintPayload(message, file);
    fprintf(file, "\n");
}

/**
 *******************************************************************************
 * @brief   Check to see if a message matches the filter.
 *
 * @param  message  IN  message
 * @param  filter   IN  filter string
 *
 * @retval  true if match found
 * @retval  false otherwise
 *******************************************************************************
 */
bool
LSTransportMessageFilterMatch(_LSTransportMessage *message, const char *filter)
{
    switch (_LSTransportMessageGetType(message))
    {
    case _LSTransportMessageTypeSignal:
        return _LSTransportMessagePrintFilterMatch(message, filter, true, false);

    case _LSTransportMessageTypeCancelMethodCall:
        return _LSTransportMessagePrintFilterMatch(message, filter, true, true);

    case _LSTransportMessageTypeMethodCall:
        return _LSTransportMessagePrintFilterMatch(message, filter, true, true);

    case _LSTransportMessageTypeReply:
        return _LSTransportMessagePrintFilterMatch(message, filter, true, true);

    default:
        fprintf(stdout, "No filter match function for message type: %d\n", _LSTransportMessageGetType(message));
        return false;
    }

}

/**
 *******************************************************************************
 * @brief Print a message.
 *
 * @param  message  IN  message
 * @param  file     IN  file to print message to
 *******************************************************************************
 */
void
LSTransportMessagePrint(_LSTransportMessage *message, FILE *file)
{
    switch (_LSTransportMessageGetType(message))
    {
    case _LSTransportMessageTypeSignal:
        _LSTransportMessagePrintSignal(message, file);
        break;

    case _LSTransportMessageTypeCancelMethodCall:
        _LSTransportMessagePrintCancelMethodCall(message, file);
        break;

    case _LSTransportMessageTypeMethodCall:
        _LSTransportMessagePrintMethodCall(message, file);
        break;

    case _LSTransportMessageTypeReply:
        _LSTransportMessagePrintReply(message, file);
        break;

    default:
        fprintf(stdout, "No print function for message type: %d\n", _LSTransportMessageGetType(message));
        break;
    }
}

/**
 *******************************************************************************
 * @brief Create compact service name
 *
 * ex) com.webos.activitymanager.client -> c.w.activitymanager.client
 *
 * @param  message      IN  service name
 * @param  buffer       OUT compact service name
 *                          size of buffer must be bigger than service name
 * @param  buffer_size  IN size of buffer
 *
 * @retval buffer
 *******************************************************************************
 */
#define _SERVICE_NAME_DELIMITER     '.'
#define _SERVICE_NAME_COMPACT_KEEP  2           // keep last 2 node
char const*
ServiceNameCompactCopy(const char *service_name, char buffer[], size_t buffer_size )
{
    LS_ASSERT(service_name != NULL);
    LS_ASSERT(strlen(service_name) < buffer_size);

    const char *tmp_node = service_name;
    int node_count = 1;

    while ((tmp_node = strchr(tmp_node, _SERVICE_NAME_DELIMITER)) != NULL)
    {
        ++tmp_node;
        ++node_count;
    }

    /* make compact service name */
    char *compact_node = buffer;
    tmp_node = service_name;
    if (node_count > _SERVICE_NAME_COMPACT_KEEP)
    {
        /* first node */
        int node_index = 1;
        *compact_node++ = *tmp_node++;
        while ((node_index <= (node_count - _SERVICE_NAME_COMPACT_KEEP))
               && (tmp_node = strchr(tmp_node, _SERVICE_NAME_DELIMITER)) != NULL)
        {
            *compact_node++ = *tmp_node++; /* _SERVICE_NAME_DELIMITER */
            *compact_node++ = *tmp_node++;
            ++node_index;
        }
    }
    /* keep at least last two nodes as is include delimiter */
    strcpy(compact_node, tmp_node);

    return buffer;
}

/**
 *******************************************************************************
 * @brief Print out a message header shorter formatted way.
 *
 * @param  caller_service_name IN service name of the origin caller
 * @param  callee_service_name IN service name of the origin callee
 * @param  directions          IN 2 byte printable string
 * @param  appId               IN application id or NULL
 * @param  category            IN category or NULL
 * @param  method              IN method or NULL
 * @param  messageToken        IN token for origin caller message
 * @param  file                IN file to print message to
 *
 * @retval number of characters printed
 *******************************************************************************
 */
#define _LST_DIRECTION_ALIGN    25
#define _LST_DATA_ALIGN         49
int
LSTransportMessagePrintCompactHeaderCommon(const char *caller_service_name,
                                           const char *callee_service_name,
                                           const char *directions,
                                           const char *appId,
                                           const char *category,
                                           const char *method,
                                           LSMessageToken messageToken,
                                           FILE *file)
{
    LS_ASSERT(caller_service_name != NULL);
    LS_ASSERT(callee_service_name != NULL);
    LS_ASSERT(directions != NULL);
    LS_ASSERT(file != NULL);

    int nchar = 0;
    int nfill = 0;
    char caller_compact[strlen(caller_service_name) + 1];
    char callee_compact[strlen(callee_service_name) + 1];

    ServiceNameCompactCopy(caller_service_name, caller_compact, sizeof(caller_compact));
    ServiceNameCompactCopy(callee_service_name, callee_compact, sizeof(callee_compact));

    nchar += fprintf(file, "%s.%d", caller_compact, (int)messageToken);
    if (appId)
    {
        nchar += fprintf(file, "(%s)", appId);
    }

    nfill = _LST_DIRECTION_ALIGN - nchar;
    nchar += fprintf(file, " %*s ", (nfill > 0 ? nfill : 1), directions);

    nfill = _LST_DATA_ALIGN - nchar;
    nchar += fprintf(file, "%*s", (nfill > 0 ? nfill : 1), callee_compact);

    if (category)
    {
        nchar += fprintf(file, "%s", category);
    }

    if (method)
    {
        nchar += fprintf(file, "/%s", method);
    }

    return nchar;
}

/**
 *******************************************************************************
 * @brief Print a message header compactly
 *
 * @param  message  IN  message
 * @param  file     IN  file to print message to
 *
 * @retval number of characters printed
 *******************************************************************************
 */
int
LSTransportMessagePrintCompactHeader(_LSTransportMessage *message, FILE *file)
{
    const char *caller_service_name = NULL;
    const char *callee_service_name = NULL;
    const char *directions = NULL;
    const char *appId = NULL;
    const char *category = NULL;
    const char *method = NULL;
    LSMessageToken messageToken = 0;

    switch (_LSTransportMessageGetType(message))
    {
    case _LSTransportMessageTypeSignal:
        directions = ">*";
        caller_service_name = _LSTransportMessageGetSenderServiceName(message);
        callee_service_name = "";
        messageToken = (int)_LSTransportMessageGetToken(message);
        category = _LSTransportMessageGetCategory(message);
        method = _LSTransportMessageGetMethod(message);
        break;

    case _LSTransportMessageTypeCancelMethodCall:
        directions = ">|";
        caller_service_name = _LSTransportMessageGetSenderServiceName(message);
        callee_service_name = _LSTransportMessageGetDestServiceName(message);
        messageToken = (int)_LSTransportMessageGetToken(message);
        category = _LSTransportMessageGetCategory(message);
        method = _LSTransportMessageGetMethod(message);
        break;

    case _LSTransportMessageTypeMethodCall:
        directions = " >";
        caller_service_name = _LSTransportMessageGetSenderServiceName(message);
        callee_service_name = _LSTransportMessageGetDestServiceName(message);
        messageToken = (int)_LSTransportMessageGetToken(message);
        appId = _LSTransportMessageGetAppId(message);
        category = _LSTransportMessageGetCategory(message);
        method = _LSTransportMessageGetMethod(message);
        break;

    case _LSTransportMessageTypeReply:
        directions = "< ";
        caller_service_name = _LSTransportMessageGetDestServiceName(message);
        callee_service_name = _LSTransportMessageGetSenderServiceName(message);
        messageToken = (int)_LSTransportMessageGetReplyToken(message);
        break;

    default:
        fprintf(stdout, "No print function for message type: %d\n", _LSTransportMessageGetType(message));
        break;
    }

    if (!caller_service_name || strlen(caller_service_name) == 0)
    {
        caller_service_name = "(null)";
    }
    if (!callee_service_name || strlen(callee_service_name) == 0)
    {
        callee_service_name = "(null)";
    }
    return LSTransportMessagePrintCompactHeaderCommon(caller_service_name, callee_service_name,
                                                      directions, appId, category, method, messageToken,
                                                      file);
}

/**
 *******************************************************************************
 * @brief Print out a message payload compactly
 *
 * @param  message  IN  message
 * @param  file     IN  file to print message to
 * @param  width    IN  hard limit of payload output length
 *
 * @retval number of characters printed
 *******************************************************************************
 */
int
LSTransportMessagePrintCompactPayload(_LSTransportMessage *message, FILE *file, int width)
{
    return fprintf(file, "%.*s", width, _LSTransportMessageGetPayload(message));
}

/*
 * Message types
 *
 * QueryName:
 * service name we're looking up (com.palm.whatever)
 *
 * QueryNameReply
 * error code
 * unique name
 */

/**
 *******************************************************************************
 * @brief Get the name that is being queried out of the "QueryName" message.
 *
 * @param  message  IN  query name message
 *
 * @retval  name of service being looked up
 *******************************************************************************
 */
const char*
_LSTransportMessageTypeQueryNameGetQueryName(_LSTransportMessage *message)
{
    LS_ASSERT(_LSTransportMessageGetType(message) == _LSTransportMessageTypeQueryName);
    _LSTransportMessageIter iter;
    const char *ret = NULL;

    _LSTransportMessageIterInit(message, &iter);

    if (_LSTransportMessageGetString(&iter, &ret))
    {
        return ret;
    }
    return NULL;
}

const char*
_LSTransportMessageTypeQueryNameGetAppId(_LSTransportMessage *message)
{
    LS_ASSERT(_LSTransportMessageGetType(message) == _LSTransportMessageTypeQueryName);

    _LSTransportMessageIter iter;
    const char *ret = NULL;

    _LSTransportMessageIterInit(message, &iter);

    /* skip over the service name */
    _LSTransportMessageIterNext(&iter);

    if (_LSTransportMessageGetString(&iter, &ret))
    {
        return ret;
    }
    return NULL;
}


/**
 * Message argument len
 */
typedef uint32_t _LSTransportMessageArgLen;

/**
 * Message argument type
 */
typedef enum LSTransportMessageArgType
{
    _LSTransportMessageArgTypeInvalid,
    _LSTransportMessageArgTypeString,
    _LSTransportMessageArgTypeInt32,
    _LSTransportMessageArgTypeInt64,
} _LSTransportMessageArgType;

/**
 * Message argument header, which stores the type and length of
 * the argument
 */
typedef struct _LSTransportMessageArgHeader
{
    _LSTransportMessageArgType type;
    _LSTransportMessageArgLen len;
} _LSTransportMessageArgHeader;

/**
 * String argument header, which adds an additional length
 * parameter since the standard header includes the size of
 * the padding bytes
 */
typedef struct _LSTransportMessageArgStringHeader
{
    _LSTransportMessageArgHeader std_header;
    _LSTransportMessageArgLen str_len;
} _LSTransportMessageArgStringHeader;

/**
 * Represents an argument that is a 32-bit integer
 */
typedef struct _LSTransportMessageArgInt32
{
    _LSTransportMessageArgHeader header;    /**< header */
    int32_t value;                          /**< actual 32-bit value */
} _LSTransportMessageArgInt32;

/**
 * Represents an argument that is a 64-bit integer
 */
typedef struct _LSTransportMessageArgInt64
{
    _LSTransportMessageArgHeader header;    /**< header */
    int64_t value;                          /**< actual 64-bit value */
} _LSTransportMessageArgInt64;

/**
 * Represents an argument that is a NULL-terminated string
 */
typedef struct _LSTransportMessageArgString
{
    _LSTransportMessageArgStringHeader header;    /**< header */
    char value[];                           /**< beginning of string */
} _LSTransportMessageArgString;

/**
 * Sentinel that terminates a series of arguments
 */
typedef struct _LSTransportMessageArgInvalid
{
    _LSTransportMessageArgHeader header;    /**< header */
} _LSTransportMessageArgInvalid;


/**
*******************************************************************************
* @brief Returns true if the iterator is valid.
*
* @param  iter  IN  iterator
*
* @retval   true if iterator is valid
* @retval   false otherwise
*******************************************************************************
*/
static INLINE bool
_LSTransportMessageIterIsValid(_LSTransportMessageIter *iter)
{
    LS_ASSERT(iter != NULL);

    if ((iter->actual_iter < iter->iter_end) && iter->valid)
    {
        return true;
    }
    iter->valid = false;
    return false;
}

/**
*******************************************************************************
* @brief Invalidate an iterator so that it cannot be used anymore.
*
* @param  iter  IN  iterator
*******************************************************************************
*/
static INLINE void
_LSTransportMessageIterInvalidate(_LSTransportMessageIter *iter)
{
    LS_ASSERT(iter != NULL);
    iter->valid = false;
}

/**
 *******************************************************************************
 * @brief Returns the number of bytes remaining in the message from the
 * location of the iterator.
 *
 * @param  iter IN  iterator
 *
 * @retval number of bytes
 *******************************************************************************
 */
static INLINE int
_LSTransportMessageIterBytesRemaining(_LSTransportMessageIter *iter)
{
    LS_ASSERT(iter != NULL);

    if (!_LSTransportMessageIterIsValid(iter))
    {
        return 0;
    }

    return (iter->iter_end - iter->actual_iter);
}

/**
 *******************************************************************************
 * @brief Initialize an iterator for a given message. No memory is allocated for
 * the iterator (it lives entirely on the stack). It does not ref count the message
 * that it's associated with.
 *
 * @param  message  IN      message
 * @param  iter     IN/OUT  iterator
 *******************************************************************************
 */
void
_LSTransportMessageIterInit(_LSTransportMessage *message, _LSTransportMessageIter *iter)
{
    LS_ASSERT(message != NULL);
    LS_ASSERT(iter != NULL);

    iter->message = message;
    iter->actual_iter = _LSTransportMessageGetBody(message);
    iter->iter_end = iter->actual_iter + _LSTransportMessageGetBodySize(message);
    iter->valid = true;
}

/**
 *******************************************************************************
 * @brief Initialize an argument header.
 *
 * @param  header   IN/OUT  header
 * @param  type     IN      arg type
 * @param  len      IN      arg len
 *
 * @retval  header
 *******************************************************************************
 */
static _LSTransportMessageArgHeader*
_LSTransportMessageArgSetHeader(_LSTransportMessageArgHeader *header,
                                _LSTransportMessageArgType type, _LSTransportMessageArgLen len)
{
    header->type = type;
    header->len = len;
    return header;
}

/**
 *******************************************************************************
 * @brief Initialize a string argument header.
 *
 * @param  header   IN/OUT  header
 * @param  len      IN      arg len (counts padding)
 * @param  str_len  IN      string length (no padding, includes NUL)
 *
 * @retval  header
 *******************************************************************************
 */
static _LSTransportMessageArgStringHeader*
_LSTransportMessageArgStringSetHeader(_LSTransportMessageArgStringHeader *header,
                                      _LSTransportMessageArgLen total_len,
                                      _LSTransportMessageArgLen str_len)
{
    _LSTransportMessageArgSetHeader(&header->std_header, _LSTransportMessageArgTypeString, total_len);
    header->str_len = str_len;
    return header;
}

/**
 *******************************************************************************
 * @brief Get the argument type of the current argument.
 *
 * @param  iter     IN  iterator
 *
 * @retval  type
 *******************************************************************************
 */
static _LSTransportMessageArgType
_LSTransportMessageGetArgType(_LSTransportMessageIter *iter)
{
    if (!_LSTransportMessageIterIsValid(iter))
    {
        return _LSTransportMessageArgTypeInvalid;
    }

    if (!ITER_SAFE_DEREFERENCE(iter, _LSTransportMessageArgHeader))
    {
        return _LSTransportMessageArgTypeInvalid;
    }

    return ((_LSTransportMessageArgHeader*)(iter->actual_iter))->type;
}

/**
 *******************************************************************************
 * @brief Get the header size of the current argument.
 *
 * @param  iter     IN  iterator
 *
 * @retval  size in bytes on success
 * @retval  -1 on failure
 *******************************************************************************
 */
static int
_LSTransportMessageGetArgHeaderSize(_LSTransportMessageIter *iter)
{
    if (!_LSTransportMessageIterIsValid(iter))
    {
        return -1;
    }

    switch (_LSTransportMessageGetArgType(iter))
    {
    case _LSTransportMessageArgTypeString:
        return sizeof(_LSTransportMessageArgStringHeader);
    case _LSTransportMessageArgTypeInt32:
    case _LSTransportMessageArgTypeInt64:
    case _LSTransportMessageArgTypeInvalid:
        return sizeof(_LSTransportMessageArgHeader);
    }

    return -1;
}

/**
 *******************************************************************************
 * @brief Get a pointer to the current argument value.
 *
 * @param  iter     IN  iterator
 * @param  type     IN  arg type
 *
 * @retval  ptr to current arg value on success
 * @retval  NULL on failure
 *******************************************************************************
 */
static void*
_LSTransportMessageGetArgValue(_LSTransportMessageIter *iter, _LSTransportMessageArgType type)
{
    if (!_LSTransportMessageIterIsValid(iter))
    {
        return NULL;
    }

    switch (type)
    {
    case _LSTransportMessageArgTypeString:
        if (!ITER_SAFE_DEREFERENCE(iter, _LSTransportMessageArgString))
        {
            return NULL;
        }
        return ((_LSTransportMessageArgString*)(iter->actual_iter))->value;
    case _LSTransportMessageArgTypeInt32:
        if (!ITER_SAFE_DEREFERENCE(iter, _LSTransportMessageArgInt32))
        {
            return NULL;
        }
        return &(((_LSTransportMessageArgInt32*)(iter->actual_iter))->value);
    case _LSTransportMessageArgTypeInt64:
        if (!ITER_SAFE_DEREFERENCE(iter, _LSTransportMessageArgInt64))
        {
            return NULL;
        }
        return &(((_LSTransportMessageArgInt64*)(iter->actual_iter))->value);
    default:
        return NULL;
    }
}

/**
 *******************************************************************************
 * @brief Get the length of the current argument
 *
 * @param  iter     IN  iterator
 *
 * @retval  length on success
 * @reval   -1 on failure
 *******************************************************************************
 */
static int
_LSTransportMessageIterGetArgLen(_LSTransportMessageIter *iter)
{
    if (!_LSTransportMessageIterIsValid(iter))
    {
        return -1;
    }

    if (!ITER_SAFE_DEREFERENCE(iter, _LSTransportMessageArgHeader))
    {
        return -1;
    }

    int len = ((_LSTransportMessageArgHeader*)(iter->actual_iter))->len;

    if (len <= _LSTransportMessageIterBytesRemaining(iter))
    {
        return len;
    }
    else
    {
        return -1;
    }
}

/**
 *******************************************************************************
 * @brief Get the string length of the current argument (includes terminating
 * NUL). The argument must be of type _LSTransportMessageArgTypeString.
 *
 * @param  iter     IN  iterator
 *
 * @retval  length on success
 * @reval   -1 on failure
 *******************************************************************************
 */
static int
_LSTransportMessageIterGetArgStrLen(_LSTransportMessageIter *iter)
{
    if (!_LSTransportMessageIterIsValid(iter))
    {
        return -1;
    }

    if (_LSTransportMessageGetArgType(iter) != _LSTransportMessageArgTypeString)
    {
        return -1;
    }

    if (!ITER_SAFE_DEREFERENCE(iter, _LSTransportMessageArgStringHeader))
    {
        return -1;
    }

    int len = ((_LSTransportMessageArgStringHeader*)(iter->actual_iter))->str_len;

    if (len <= _LSTransportMessageIterBytesRemaining(iter))
    {
        return len;
    }
    else
    {
        return -1;
    }
}

/**
 *******************************************************************************
 * @brief Returns true if there are more arguments available to iterate over.
 *
 * @param  iter IN  iterator
 *
 * @retval  true if more arguments
 * @retval  false otherwise
 *******************************************************************************
 */
bool
_LSTransportMessageIterHasNext(_LSTransportMessageIter *iter)
{
    if (!_LSTransportMessageIterIsValid(iter))
    {
        return false;
    }

    _LSTransportMessageArgType type = _LSTransportMessageGetArgType(iter);

    if (type == _LSTransportMessageArgTypeInvalid)
    {
        return false;
    }

    return true;
}

/**
 *******************************************************************************
 * @brief Advance the iterator forward one argument.
 *
 * @param  iter     IN  iterator
 *
 * @retval  iterator
 *******************************************************************************
 */
_LSTransportMessageIter*
_LSTransportMessageIterNext(_LSTransportMessageIter *iter)
{
    if (!_LSTransportMessageIterIsValid(iter))
    {
        return NULL;
    }

    int offset =  _LSTransportMessageIterGetArgLen(iter);

    if (offset == -1)
    {
        return NULL;
    }

    int header_size = _LSTransportMessageGetArgHeaderSize(iter);

    if (header_size == -1)
    {
        return NULL;
    }

    offset += header_size;

    iter->actual_iter += offset;

    if (!_LSTransportMessageIterIsValid(iter))
    {
        return NULL;
    }

    return iter;
}

/**
 *******************************************************************************
 * @brief Expand the message by @len bytes. This will potentially change the
 * memory location of the message; the iterator will be updated appropriately.
 *
 * @param  iter     IN  message's iterator
 * @param  len      IN  bytes to add to message
 *
 * @retval true on success
 * @retval false on failure
 *******************************************************************************
 */
static bool
_LSTransportMessageIterExpandMessage(_LSTransportMessageIter *iter, unsigned int len)
{
    LS_ASSERT(iter != NULL);
    LS_ASSERT(iter->actual_iter <= iter->iter_end);

    int cur_len =  (iter->iter_end - iter->actual_iter);
    int bytes_needed = len - cur_len;
    int offset = iter->actual_iter - _LSTransportMessageGetBody(iter->message);

    if (bytes_needed > 0)
    {
        if (!_LSTransportMessageBodyExpand(iter->message, bytes_needed))
        {
            _LSTransportMessageIterInvalidate(iter);
            return false;
        }

        /* update the iterator -- the message body may have moved */
        _LSTransportMessageIterInit(iter->message, iter);
        iter->actual_iter += offset;
    }

    return true;
}

/**
 *******************************************************************************
 * @brief Append a string argument to the message. @str can be NULL in which case
 * a corresponding call to _LSTransoprtMessageGetString() would return NULL.
 *
 * @param  iter     IN  iterator
 * @param  str      IN  string to append
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
_LSTransportMessageAppendString(_LSTransportMessageIter *iter, const char *str)
{
    LS_ASSERT(iter != NULL);

    int str_len = 0;

    if (str != NULL)
    {
        str_len = strlen(str) + 1;
    }

    _LSTransportMessageArgString arg;

    /* We're mixing strings and 32-bit ints, so we add padding to account for
     * 32-bit ints. If we add new types, we need to make this larger (or do
     * the padding when adding the type that must be aligned */
    unsigned int str_pad_bytes = PADDING_BYTES_TYPE(int32_t, str_len);
    unsigned int arg_len = sizeof(arg) + str_len + str_pad_bytes;

    if (!_LSTransportMessageIterExpandMessage(iter, arg_len))
    {
        return false;
    }

    _LSTransportMessageArgStringSetHeader(&arg.header, str_len + str_pad_bytes, str_len);

    char *pos = iter->actual_iter;

    /* copy header */
    memcpy(pos, &arg, sizeof(arg));
    pos += sizeof(arg);

    /* copy actual string */
    if (str_len > 0)
    {
        memcpy(pos, str, str_len);
        pos += str_len;

        /* set padding bytes to NUL */
        if (str_pad_bytes > 0)
        {
            memset(pos, '\0', str_pad_bytes);
        }
    }

    /* move iterator */
    _LSTransportMessageIterNext(iter);

    return true;
}

/**
 *******************************************************************************
 * @brief Append a 32-bit integer argument to the message.
 *
 * @param  iter     IN  iterator
 * @param  value    IN  argument
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
_LSTransportMessageAppendInt32(_LSTransportMessageIter *iter, int32_t value)
{
    LS_ASSERT(iter != NULL);

    _LSTransportMessageArgInt32 arg;

    _LSTransportMessageArgSetHeader(&arg.header, _LSTransportMessageArgTypeInt32, sizeof(arg.value));

    arg.value = value;

    int arg_len = sizeof(arg);

    if (!_LSTransportMessageIterExpandMessage(iter, arg_len))
    {
        return false;
    }

    memcpy(iter->actual_iter, &arg, arg_len);

    /* move iterator */
    _LSTransportMessageIterNext(iter);

    return true;
}

/**
 *******************************************************************************
 * @brief Append a 64-bit integer argument to the message.
 *
 * @param  iter     IN  iterator
 * @param  value    IN  argument
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
_LSTransportMessageAppendInt64(_LSTransportMessageIter *iter, int64_t value)
{
    LS_ASSERT(iter != NULL);

    _LSTransportMessageArgInt64 arg;

    _LSTransportMessageArgSetHeader(&arg.header, _LSTransportMessageArgTypeInt64, sizeof(arg.value));

    arg.value = value;

    int arg_len = sizeof(arg);

    if (!_LSTransportMessageIterExpandMessage(iter, arg_len))
    {
        return false;
    }

    memcpy(iter->actual_iter, &arg, arg_len);

    /* move iterator */
    _LSTransportMessageIterNext(iter);

    return true;
}

/**
 *******************************************************************************
 * @brief Append a boolean argument to the message.
 *
 * @param  iter     IN  iterator
 * @param  value    IN  argument
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
_LSTransportMessageAppendBool(_LSTransportMessageIter *iter, bool value)
{
    LS_ASSERT(iter != NULL);

    return _LSTransportMessageAppendInt32(iter, value ? 1 : 0);
}

/**
 *******************************************************************************
 * @brief Append an invalid argument to the message (sentinel). This should be
 * the last argument for the message.
 *
 * @param  iter     IN  iterator
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
_LSTransportMessageAppendInvalid(_LSTransportMessageIter *iter)
{
    LS_ASSERT(iter != NULL);

    _LSTransportMessageArgInvalid arg;
    int arg_len = sizeof(arg);

    _LSTransportMessageArgSetHeader(&arg.header, _LSTransportMessageArgTypeInvalid, 0);

    if (!_LSTransportMessageIterExpandMessage(iter, arg_len))
    {
        return false;
    }

    memcpy(iter->actual_iter, &arg, arg_len);

    /* move iterator */
    _LSTransportMessageIterNext(iter);

    /* make sure the message header is set to the final size of the message
     * (e.g., if we allocated a large message, but only filled part of it, we want
     * to make sure we only send the actual message size, not the extra */
    _LSTransportMessageSetBodySize(iter->message, iter->actual_iter - _LSTransportMessageGetBody(iter->message));

    /* mark as invalid so they don't attempt to use it again */
    _LSTransportMessageIterInvalidate(iter);

    return true;
}

/**
 *******************************************************************************
 * @brief Get a string argument from the message. The returned value points
 * inside the message, so make a copy if you need it to persist longer than
 * the message (or ref the message).
 *
 * @param  iter     IN  iterator
 * @param  ret      OUT result string
 *
 * @retval  true on success
 * @retval  false on failure (ret is meaningless)
 *******************************************************************************
 */
bool
_LSTransportMessageGetString(_LSTransportMessageIter *iter, const char **ret)
{
    LS_ASSERT(iter != NULL);
    LS_ASSERT(ret != NULL);

    if (_LSTransportMessageGetArgType(iter) != _LSTransportMessageArgTypeString)
    {
        *ret = NULL;
        return false;
    }

    int len = _LSTransportMessageIterGetArgStrLen(iter);

    if (len == -1)
    {
        *ret = NULL;
        return false;
    }
    else if (len == 0)
    {
        *ret = NULL;
        return true;
    }
    else
    {
        *ret = _LSTransportMessageGetArgValue(iter, _LSTransportMessageArgTypeString);
        if (*ret == NULL)
        {
            return false;
        }
        /* validate terminating NUL
         * if any padding bytes were added, they were set to NUL*/
        if ((*ret)[len - 1] != '\0')
        {
            *ret = NULL;
            return false;
        }
        return true;
    }
}

/**
 *******************************************************************************
 * @brief Get a 32-bit integer argument from a message.
 *
 * @param  iter     IN  iterator
 * @param  iter     OUT result int
 *
 * @retval  true on success
 * @retval  false on failure (ret is meaningless)
 *******************************************************************************
 */
bool
_LSTransportMessageGetInt32(_LSTransportMessageIter *iter, int32_t *ret)
{
    LS_ASSERT(iter != NULL);
    LS_ASSERT(ret != NULL);

    if (_LSTransportMessageGetArgType(iter) != _LSTransportMessageArgTypeInt32)
    {
        *ret = 0;
        return false;
    }

    *ret = *((int32_t*)_LSTransportMessageGetArgValue(iter, _LSTransportMessageArgTypeInt32));
    return true;
}

/**
 *******************************************************************************
 * @brief Get a 64-bit integer argument from a message.
 *
 * @param  iter     IN  iterator
 * @param  iter     OUT result int
 *
 * @retval  true on success
 * @retval  false on failure (ret is meaningless)
 *******************************************************************************
 */
bool
_LSTransportMessageGetInt64(_LSTransportMessageIter *iter, int64_t *ret)
{
    LS_ASSERT(iter != NULL);
    LS_ASSERT(ret != NULL);

    if (_LSTransportMessageGetArgType(iter) != _LSTransportMessageArgTypeInt64)
    {
        *ret = 0;
        return false;
    }

    *ret = *((int64_t*)_LSTransportMessageGetArgValue(iter, _LSTransportMessageArgTypeInt64));
    return true;
}

/**
 *******************************************************************************
 * @brief Get a boolean argument from a message.
 *
 * @param  iter     IN  iterator
 * @param  iter     OUT result int
 *
 * @retval  true on success
 * @retval  false on failure (ret is meaningless)
 *******************************************************************************
 */
bool
_LSTransportMessageGetBool(_LSTransportMessageIter *iter, bool *ret)
{
    LS_ASSERT(iter != NULL);
    LS_ASSERT(ret != NULL);

    int32_t int_ret;

    if (_LSTransportMessageGetInt32(iter, &int_ret))
    {
        *ret = int_ret ? true : false;
        return true;
    }

    *ret = false;
    return false;
}

/* @} END OF LunaServiceTransportMessage */
