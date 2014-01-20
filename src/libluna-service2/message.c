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


#include <glib.h>

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <pbnjson.h>
#include <luna-service2/lunaservice.h>

#include "base.h"
#include "message.h"

/**
 * @addtogroup LunaServiceInternals
 * @{
 */

/**
* @brief Allocate LSMessage from _LSTransportMessage with a refcount of 1.
*
* @param  transport_msg
*
* @retval
*/
LSMessage *
_LSMessageNewRef(_LSTransportMessage *transport_msg, LSHandle *sh)
{
    LSMessage *message = g_new0(LSMessage, 1);

    if (transport_msg)
        message->transport_msg = _LSTransportMessageRef(transport_msg);

    message->sh  = sh;
    message->ref = 1;

    return message;
}

void
_LSMessageFree(LSMessage *message)
{
    if (message->transport_msg)
        _LSTransportMessageUnref(message->transport_msg);

    g_free(message->uniqueTokenAllocated);
    g_free(message->kindAllocated);

    g_free(message->methodAllocated);
    g_free(message->payloadAllocated);

#ifdef MEMCHECK
    memset(message, 0xFF, sizeof(LSMessage));
#endif

    g_free(message);
}

/* @} END OF LunaServiceInternals */

/**
 * @addtogroup LunaServiceMessage
 *
 * @{
 */

/**
* @brief Return a handle to the connection-to-bus
*        through which message was sent.
*
* @param  message
*
* @retval
*/
LSHandle *
LSMessageGetConnection(LSMessage *message)
{
    if (!message) return NULL;
    return message->sh;
}

/**
* @brief Returns if message is received from public connection
*        to the bus.
*
* @param  psh
* @param  message
*
* @retval
*/
bool
LSMessageIsPublic(LSPalmService *psh, LSMessage *message)
{
    return (message->sh == psh->public_sh);
}

/**
* @brief Increment ref count on message object.  You MUST call this if you wish to store
*        LSMessage yourself.  A LSMessageRef() MUST be paired with a LSMessageUnref()
*        lest you leak memory.
*
* @param  message
*/
void
LSMessageRef(LSMessage *message)
{
    LS_ASSERT(message != NULL);
    LS_ASSERT(g_atomic_int_get (&message->ref) > 0);

    g_atomic_int_inc(&message->ref);
}

/**
* @brief Decrement ref count on message object.  Object is freed if ref goes to zero.
*
* @param  message
*/
void
LSMessageUnref(LSMessage *message)
{
    LS_ASSERT(message != NULL);
    LS_ASSERT(g_atomic_int_get (&message->ref) > 0);

    if (g_atomic_int_dec_and_test(&message->ref))
    {
        _LSMessageFree(message);
    }
}

/**
* @brief Convenience function to pretty print a message.
*
* @param  lmsg
* @param  out
*
* @retval
*/
bool
LSMessagePrint(LSMessage *message, FILE *out)
{
    _LSErrorIfFail(NULL != message, NULL, MSGID_LS_MSG_ERR);

    fprintf(out, "%s/%s <%s>\n",
        LSMessageGetCategory(message),
        LSMessageGetMethod(message),
        LSMessageGetPayload(message));

    return true;
}

/**
 * @brief Returns true if the message is an error message from the hub.
 *
 * @param  message
 *
 * @retval true, if message is error message from hub
 * @retval false, otherwise
 */
bool
LSMessageIsHubErrorMessage(LSMessage *message)
{
    if (!message) return false;

    const char *category = LSMessageGetCategory(message);

    if (!category) return false;

    return (strcmp(category, LUNABUS_ERROR_CATEGORY) == 0);
}

/**
* @brief Get the method name of the message.
*
* @param  message
*
* @retval
*/
const char *
LSMessageGetMethod(LSMessage *message)
{
    _LSErrorIfFail(NULL != message, NULL, MSGID_LS_MSG_ERR);

    if (message->method) return message->method;

    message->method = _LSTransportMessageGetMethod(message->transport_msg);

    return message->method;
}

/**
* @brief Obtain the application's ID.
*
* This only applies to JS Applications' LSCallFromApplication().
*
* @param  message
*
* @retval
*/
const char *
LSMessageGetApplicationID(LSMessage *message)
{
    const char *ret = _LSTransportMessageGetAppId(message->transport_msg);

    /* match previous semantics */
    if (ret != NULL && *ret == '\0')
    {
        return NULL;
    }
    else
    {
        return ret;
    }
}

/**
* @brief Obtain a unique token identifying the sender.
*
* @param  message
*
* @retval
*/
const char *
LSMessageGetSender(LSMessage *message)
{
    _LSErrorIfFail(NULL != message, NULL, MSGID_LS_MSG_ERR);

    const char *sender = _LSTransportMessageGetSenderUniqueName(message->transport_msg);

    return sender;
}

/**
* @brief Get the name of the service that sent the message. (NULL if the
* sender didn't register a service name)
*
* @param  message
*
* @retval   service_name if service sending the message has a name
* @retval   NULL otherwise
*/
const char *
LSMessageGetSenderServiceName(LSMessage *message)
{
    _LSErrorIfFail(NULL != message, NULL, MSGID_LS_MSG_ERR);

    const char *service_name = _LSTransportMessageGetSenderServiceName(message->transport_msg);

    return service_name;
}

/**
* @brief Get the unique serial of this message.  Do not confuse with
* LSMessageGetResponseToken().
*
* @param  message
*
* @retval
*/
LSMessageToken
LSMessageGetToken(LSMessage *message)
{
    _LSErrorIfFail(NULL != message, NULL, MSGID_LS_MSG_ERR);

    LSMessageToken serial = _LSTransportMessageGetToken(message->transport_msg);
    return serial;
}

/**
* @brief Get the response token associated with this message this will match
* with the LSMessageGetToken() of the original call.
*
* For signals, the response token is supplanted with the original token
* returned from LSSignalCall().
*
* @param  reply
*
* @retval
*/
LSMessageToken
LSMessageGetResponseToken(LSMessage *reply)
{
    _LSErrorIfFail(NULL != reply, NULL, MSGID_LS_MSG_ERR);

    if (reply->responseToken)
        return reply->responseToken;

    reply->responseToken = _LSTransportMessageGetReplyToken(reply->transport_msg);

    return reply->responseToken;
}

/**
* @brief Get the category of this message.
*
* @param  message
*
* @retval
*/
const char *
LSMessageGetCategory(LSMessage *message)
{
    _LSErrorIfFail(NULL != message, NULL, MSGID_LS_MSG_ERR);

    if (message->category)
        return message->category;

    message->category = _LSTransportMessageGetCategory(message->transport_msg);

    return message->category;
}

/**
* @brief Get the payload of this message.
*
* @param  message
*
* @retval
*/
const char *
LSMessageGetPayload(LSMessage *message)
{
    _LSErrorIfFail(message != NULL, NULL, MSGID_LS_MSG_ERR);

    if (message->payload)
    {
        return message->payload;
    }

    message->payload = _LSTransportMessageGetPayload(message->transport_msg);

    return message->payload;
}

/**
* @brief Get the payload of the message as a JSON object.
*
* @deprecated Do NOT use this function anymore. It now returns NULL always.
* Use LSMessageGetPayload() and use pbnjson (https://wiki.palm.com/display/CoreOS/pbnjson)
* to parse the JSON.
*
* @param  message
*
* @retval NULL always
*/
LS_DEPRECATED void*
LSMessageGetPayloadJSON(LSMessage  *message)
{
    _LSErrorIfFailMsg(NULL, NULL, MSGID_LS_DEPRECATED, LS_ERROR_CODE_DEPRECATED,
                      LS_ERROR_TEXT_DEPRECATED);
    return NULL;
}

/**
 * @brief Checks if the message has subscription field with
 * subscribe=true
 *
 * @param message
 *
 * @retval true if has subscribe=true, false otherwise
 */
bool
LSMessageIsSubscription(LSMessage *message)
{
    JSchemaInfo schemaInfo;
    jschema_info_init(&schemaInfo, jschema_all(), NULL, NULL);

    bool ret = false;
    jvalue_ref sub_object = NULL;
    const char *payload = LSMessageGetPayload(message);

    jvalue_ref object = jdom_parse(j_cstr_to_buffer(payload), DOMOPT_NOOPT,
                                   &schemaInfo);
    if (jis_null(object))
        goto exit;

    if (!jobject_get_exists(object, J_CSTR_TO_BUF("subscribe"),
                            &sub_object) || sub_object == NULL)
        goto exit;

    _LSErrorGotoIfFail(exit, jis_boolean(sub_object), NULL, MSGID_LS_INVALID_JSON, -1);

    (void)jboolean_get(sub_object, &ret); /* TODO: handle appropriately */

exit:
    j_release(&object);
    return ret;
}

/**
* @brief Send a reply to message using the same bus that
*        message came from.
*
* @param  lsmsg
* @param  reply_payload
* @param  lserror
*
* @retval
*/
bool
LSMessageRespond(LSMessage *message, const char *reply_payload,
                LSError *lserror)
{
    return LSMessageReply(LSMessageGetConnection(message),
        message, reply_payload, lserror);
}

/**
* @brief Send a reply to a message using the bus identified by LSHandle.
*
*        To use the same bus upon which the message arrived, it is
*        recommended to use LSMessageRespond().
*
* @param  sh
* @param  lsmsg
* @param  replyPayload
* @param  lserror
*
* @retval
*/
bool
LSMessageReply(LSHandle *sh, LSMessage *lsmsg, const char *replyPayload,
                LSError *lserror)
{
    _LSErrorIfFail (sh != NULL, lserror, MSGID_LS_INVALID_HANDLE);
    _LSErrorIfFail (lsmsg != NULL, lserror, MSGID_LS_MSG_ERR);
    _LSErrorIfFail (replyPayload != NULL, lserror, MSGID_LS_PARAMETER_IS_NULL);

    LSHANDLE_VALIDATE(sh);

    if (unlikely(_ls_enable_utf8_validation))
    {
        if (!g_utf8_validate (replyPayload, -1, NULL))
        {
            _LSErrorSet(lserror, MSGID_LS_INVALID_JSON, -EINVAL, "%s: payload is not utf-8",
                        __FUNCTION__);
            return false;
        }
    }

    if (unlikely(strcmp(replyPayload, "") == 0))
    {
        _LSErrorSet(lserror, MSGID_LS_INVALID_JSON, -EINVAL, "Empty payload is not valid JSON. Use {}");
        return false;
    }

    if (DEBUG_TRACING)
    {
        if (DEBUG_VERBOSE)
        {
                LOG_LS_DEBUG("TX: LSMessageReply token <<%ld>> %s",
                        LSMessageGetToken(lsmsg), replyPayload);
        }
        else
        {
                LOG_LS_DEBUG("TX: LSMessageReply token <<%ld>>",
                        LSMessageGetToken(lsmsg));
        }
    }

    if (_LSTransportMessageGetType(lsmsg->transport_msg) == _LSTransportMessageTypeReply)
    {
        LOG_LS_WARNING(MSGID_LS_MSG_ERR, 0,
                       "%s: \nYou are attempting to send a reply to a reply message.  \n"
                       "I'm going to allow this for now to more easily reproduce some bugs \n"
                       "we encountered with services using LSCustomWaitForMessage \n"
                       "receiving a reply-to-a-reply, but soon this will return an error.",
                       __FUNCTION__);
    }

    if (unlikely(LSMessageGetConnection(lsmsg) != sh))
    {
        _LSErrorSet(lserror, MSGID_LS_INVALID_BUS, -EINVAL,
                    "%s: You are replying to message on different bus.\n"
                    " If you can't identify which bus, "
                    "try LSMessageRespond() instead.",
                    __FUNCTION__);
        return false;
    }

    bool retVal = _LSTransportSendReply(lsmsg->transport_msg, replyPayload, lserror);

    return retVal;
}


/**
* @brief Send a reply.
*
* @param  sh
* @param  message
* @param  replyPayload
* @param  error
*
* @deprecated Use LSMessageReply() instead.
*
* @retval
*/
LS_DEPRECATED bool
LSMessageReturn(LSHandle *sh, LSMessage *lsmsg, const char *replyPayload,
                LSError *lserror)
{
    _LSErrorSet(lserror, MSGID_LS_DEPRECATED, LS_ERROR_CODE_DEPRECATED, LS_ERROR_TEXT_DEPRECATED);
    return false;
}

/**
* @brief Returns a string that uniquely represents this message.
*
* @param  message
*
* @retval
*/
const char *
LSMessageGetUniqueToken(LSMessage *message)
{
    if (!message)
        return NULL;

    if (message->uniqueTokenAllocated)
        return message->uniqueTokenAllocated;

    const char *sender = LSMessageGetSender(message);
    LSMessageToken token = LSMessageGetToken(message);

    message->uniqueTokenAllocated = g_strdup_printf("%s.%ld", sender, token);

    return message->uniqueTokenAllocated;
}

/**
* @brief Returns the kind of the message (i.e. category + method).
*
* @param  message
*
* @retval
*/
const char *
LSMessageGetKind(LSMessage *message)
{
    if (!message)
        return NULL;
    if (message->kindAllocated)
        return message->kindAllocated;

    const char *category = LSMessageGetCategory(message);
    const char *method = LSMessageGetMethod(message);

    message->kindAllocated = _LSMessageGetKindHelper(category,method);

    return message->kindAllocated;
}

char *
_LSMessageGetKindHelper(const char *category, const char *method)
{
    char *key = NULL;

    if (!category)
    {
        category = "";
    }

    key = g_build_filename(category, method, NULL);

    return key;
}

/* @} END OF LunaServiceMessage */
