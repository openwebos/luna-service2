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


#include <errno.h>
#include <string.h>
#include <pbnjson.h>
#include "transport_utils.h"
#include "transport_priv.h"
#include "transport_signal.h"

/**
 * @defgroup LunaServiceTransportSignal
 * @ingroup LunaServiceTransport
 * @brief Transport signal
 */

/**
 * @addtogroup LunaServiceTransportSignal
 * @{
 */

/**
 *******************************************************************************
 * @brief Send a signal registration message.
 *
 * @param  transport    IN  transport
 * @param  reg          IN  true to register, false to unregister
 * @param  category     IN  category (required)
 * @param  method       IN  method (optional, NULL means none)
 * @param  token        OUT message token
 * @param  lserror      OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
_LSTransportSignalRegistration(_LSTransport *transport, bool reg, const char *category,
                               const char *method, LSMessageToken *token, LSError *lserror)
{
    /*
     * format:
     *
     * category + NUL
     * method + NUL (if method is NULL, then we just have NUL)
     */
    bool ret = true;
    int category_len = strlen_safe(category) + 1;
    int method_len = strlen_safe(method) + 1;

    LOG_LS_TRACE("%s: category: %s, method: %s\n", __func__, category, method);

    _LSTransportMessage *message = _LSTransportMessageNewRef(category_len + method_len);

    if (reg)
    {
        _LSTransportMessageSetType(message, _LSTransportMessageTypeSignalRegister);
    }
    else
    {
        _LSTransportMessageSetType(message, _LSTransportMessageTypeSignalUnregister);
    }

    char *message_body = _LSTransportMessageGetBody(message);

    LS_ASSERT(message_body != NULL);

    memcpy(message_body, category, category_len);
    message_body += category_len;

    if (method_len == 1)
    {
        char nul = '\0';
        memcpy(message_body, &nul, sizeof(nul));
    }
    else
    {
        memcpy(message_body, method, method_len);
    }

    LS_ASSERT(transport->hub != NULL);

    if (!_LSTransportSendMessage(message, transport->hub, token, lserror))
    {
        ret = false;
    }

    _LSTransportMessageUnref(message);

    return ret;
}

/**
 *******************************************************************************
 * @brief Register a signal. It should only be called from users of the
 * transport (i.e., not from within this file).
 *
 * @param  transport    IN  transport
 * @param  category     IN  category
 * @param  method       IN  method (optional, NULL means none)
 * @param  token        OUT message token
 * @param  lserror      OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
LSTransportRegisterSignal(_LSTransport *transport, const char *category, const char *method,
                           LSMessageToken *token, LSError *lserror)
{
    return _LSTransportSignalRegistration(transport, true, category, method, token, lserror);
}

/**
 *******************************************************************************
 * @brief Unregister a signal. It should only be called from users of the
 * transport (i.e., not from within this file).
 *
 * @param  transport    IN  transport
 * @param  category     IN  category
 * @param  method       IN  method (optional, NULL means none)
 * @param  token        OUT message token
 * @param  lserror      OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
LSTransportUnregisterSignal(_LSTransport *transport, const char *category, const char *method,
                           LSMessageToken *token, LSError *lserror)
{
    return _LSTransportSignalRegistration(transport, false, category, method, token, lserror);
}

/**
 *******************************************************************************
 * @brief Register for server status signals.
 *
 * @param  transport        IN  transport
 * @param  service_name     IN  service name
 * @param  token            OUT message token
 * @param  lserror          OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
LSTransportRegisterSignalServiceStatus(_LSTransport *transport, const char *service_name,  LSMessageToken *token, LSError *lserror)
{
    return _LSTransportSignalRegistration(transport, true, SERVICE_STATUS_CATEGORY, service_name, token, lserror);
}

/**
 *******************************************************************************
 * @brief Unregister for server status signals.
 *
 * @param  transport        IN  transport
 * @param  service_name     IN  service name
 * @param  token            OUT message token
 * @param  lserror          OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
LSTransportUnregisterSignalServiceStatus(_LSTransport *transport, const char *service_name,  LSMessageToken *token, LSError *lserror)
{
    return _LSTransportSignalRegistration(transport, false, SERVICE_STATUS_CATEGORY, service_name, token, lserror);
}

/**
 *******************************************************************************
 * @brief Create a new signal message with ref count of 1.
 *
 * @param  category     IN  category
 * @param  method       IN  method (optional, NULL means none)
 * @param  payload      IN  payload
 *
 * @retval  message on success
 * @retval  NULL on failure
 *******************************************************************************
 */
_LSTransportMessage*
LSTransportMessageSignalNewRef(const char *category, const char *method, const char *payload)
{
    int category_len = strlen(category) + 1;
    int method_len = strlen(method) + 1;
    int payload_len = strlen(payload) + 1;

    LS_ASSERT(category_len > 1);
    LS_ASSERT(method_len > 1);

    _LSTransportMessage *message = _LSTransportMessageNewRef(category_len + method_len + payload_len);

    _LSTransportMessageSetType(message, _LSTransportMessageTypeSignal);

    char *message_body = _LSTransportMessageGetBody(message);

    memcpy(message_body, category, category_len);
    message_body += category_len;
    memcpy(message_body, method, method_len);
    message_body += method_len;
    memcpy(message_body, payload, payload_len);

    /* TODO: original code also appended the service_name of the sender (or "")
     * if there was no name (sh->name) */

    return message;
}

/**
 *******************************************************************************
 * @brief Send a signal.
 *
 * @param  transport    IN  transport
 * @param  category     IN  category
 * @param  method       IN  method (optional, NULL means none)
 * @param  payload      IN  payload
 * @param  lserror      OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
LSTransportSendSignal(_LSTransport *transport, const char *category, const char *method, const char *payload, LSError *lserror)
{
    bool ret = true;

    _LSTransportMessage *message = LSTransportMessageSignalNewRef(category, method, payload);

    LS_ASSERT(transport->hub != NULL);

    ret = _LSTransportSendMessage(message, transport->hub, NULL, lserror);

    _LSTransportMessageUnref(message);

    return ret;
}

/**
 *******************************************************************************
 * @brief Get the service name from a "ServceStatus" message. The name is
 * allocated and should be freed.
 *
 * @param  message  IN  message
 *
 * @retval name string on success
 * @retval NULL on error
 *******************************************************************************
 */
char*
LSTransportServiceStatusSignalGetServiceName(_LSTransportMessage *message)
{
    JSchemaInfo schemaInfo;
    jschema_info_init(&schemaInfo, jschema_all(), NULL, NULL);

    LS_ASSERT(_LSTransportMessageGetType(message) == _LSTransportMessageTypeServiceDownSignal
              || _LSTransportMessageGetType(message) == _LSTransportMessageTypeServiceUpSignal);

    char *service_name = NULL;
    jvalue_ref service_name_obj = NULL;
    const char *payload = _LSTransportMessageGetPayload(message);

    if (!payload)
    {
        LOG_LS_ERROR(MSGID_LS_INVALID_JSON, 0, "Unable to get payload from message");
        return NULL;
    }

    /* get the serviceName part of the JSON object */
    jvalue_ref payload_json = jdom_parse(j_cstr_to_buffer(payload),
                                         DOMOPT_NOOPT, &schemaInfo);

    bool ret = jobject_get_exists(payload_json,
                                  J_CSTR_TO_BUF(SERVICE_STATUS_SERVICE_NAME),
                                  &service_name_obj);

    if (ret)
    {
        raw_buffer service_name_buf = jstring_get_fast(service_name_obj);
        service_name = g_strndup(service_name_buf.m_str, service_name_buf.m_len);
    }
    else
    {
        LOG_LS_ERROR(MSGID_LS_INVALID_JSON, 0, "Unable to get service name string from payload: %s", payload);
    }

    j_release(&payload_json);

    return service_name;
}

/**
 *******************************************************************************
 * @brief Get the unique name from a "ServiceStatus" message.
 *
 * @param  message  IN  message
 *
 * @retval  name string on success
 * @retval  NULL on failure
 *******************************************************************************
 */
const char*
LSTransportServiceStatusSignalGetUniqueName(_LSTransportMessage *message)
{
    /* TODO: we may want this eventually, it's pretty much the same as GetServiceName */
    LOG_LS_ERROR(MSGID_LS_NOT_IMPLEMENTED, 0, "Not yet implemented!");
    LS_ASSERT(0);
    return NULL;
}

/* @} END OF LunaServiceTransportSignal */
