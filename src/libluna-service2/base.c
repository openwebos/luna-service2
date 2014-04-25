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
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>

#include <luna-service2/lunaservice.h>

#include "base.h"
#include "category.h"
#include "message.h"
#include "subscription.h"
#include "debug_methods.h"
#include "transport.h"
#include "clock.h"
#include "log.h"

#define __USE_GNU   /* for dladdr() in dlfcn.h */
#include <dlfcn.h>

/*
 * define LUNASERVICE_USE_SOCKETS to cause the same socket implementation
 * that's being used for Windows to be used on Linux.
 */
#ifdef LUNASERVICE_USE_SOCKETS
#include <sys/types.h>
#include <arpa/inet.h>
#endif

#include <pmtrace_ls2.h>

/* FIXME -- create a callmap.h header file (this function is in callmap.c */
void _LSHandleMessageFailure(LSMessageToken global_token, _LSTransportMessageFailureType failure_type, void *context);
void _LSDisconnectHandler(_LSTransportClient *client, _LSTransportDisconnectType type, void *context);
bool _LSHandleReply(LSHandle *sh, _LSTransportMessage *transport_msg);

/**
 * @defgroup LunaService
 * @ingroup Luna
 * @brief Luna Services API.
 */

/**
 * @defgroup LunaServiceExample
 * @ingroup LunaService
 * @brief Example of how to use Luna Service
 */

/**
 * @defgroup LunaServiceClient LunaServiceClient
 * @ingroup  LunaService
 *
 * @brief Luna Services Client-side API.
 *
 * @defgroup LunaServiceClientInternals
 * @ingroup  LunaServiceClient
 * @brief    The internals of LunaServiceClient.
 */

/**
 * @defgroup LunaServiceRegistration
 * @ingroup LunaService
 * @brief Luna Service registration functions
 */

/**
 * @defgroup LunaServiceSignals
 * @ingroup LunaService
 * @brief LunaService signals API.
 */

/**
 * @defgroup LunaServiceSubscription
 * @ingroup  LunaService
 * @brief    LunaService subscription APIs.
 */

/**
 *
 * @defgroup LunaServiceMessage
 * @ingroup LunaService
 * @brief Luna Service Messages
 */

/**
 * @defgroup LunaServiceMainloop
 * @ingroup LunaService
 * @brief Luna Service glib mainloop support.
 */

/**
 * @defgroup LunaServiceUtils
 * @ingroup LunaService
 * @brief Luna Service miscellaneous utilities.
 */

/**
 * @defgroup LunaServiceError
 * @ingroup LunaService
 * @brief Luna Service error handling
 */

/**
 * @defgroup LunaServiceCustom
 * @ingroup  LunaService
 * @brief    Custom mainloop support.
 *
 * @defgroup LunaServiceCustomInternals
 * @ingroup  LunaServiceCustom
 * @brief    Custom mainloop internals.
 */

/**
 * @defgroup LunaServiceInternals
 * @ingroup  LunaService
 * @brief    The internals of LunaService.
 */

/** Enable UTF8 validation on the payload */
bool _ls_enable_utf8_validation = false;

void
LSDebugLogIncoming(const char *where, _LSTransportMessage *message)
{
    if (DEBUG_TRACING)
    {
        LSMessageToken token = _LSTransportMessageGetReplyToken(message);
        const char *sender_service_name = _LSTransportMessageGetSenderServiceName(message);
        if (!sender_service_name) sender_service_name = "(null)";
        const char *sender_unique_name = _LSTransportMessageGetSenderUniqueName(message);
        if (!sender_unique_name) sender_unique_name = "(null)";

        if (DEBUG_VERBOSE)
        {
            const char *payload = _LSTransportMessageGetPayload(message);
            if (!payload) payload = "(null)";

            LOG_LS_DEBUG("RX: %s token <<%ld>> sender: %s sender_unique: %s payload: %s",
                    where, token, sender_service_name, sender_unique_name, payload);
        }
        else
        {
            LOG_LS_DEBUG("RX: %s token <<%ld>> sender: %s sender_unique: %s",
                    where, token, sender_service_name, sender_unique_name);
        }
    }
}

#ifdef LSHANDLE_CHECK
inline void
_lshandle_validate(LSHandle *sh)
{
    if (sh && sh->history.magic_state_num != LSHANDLE_MAGIC_STATE_VALID)
    {
        Dl_info create_info;
        Dl_info destroy_info;
        bool create_info_valid = false;
        bool destroy_info_valid = false;

        if (sh->history.creator_ret_addr)
        {
            create_info_valid = dladdr(sh->history.creator_ret_addr, &create_info);
        }

        if (sh->history.destroyer_ret_addr)
        {
            destroy_info_valid = dladdr(sh->history.destroyer_ret_addr, &destroy_info);
        }

        LOG_LS_ERROR(MSGID_LS_INVALID_HANDLE, 5,
                     PMLOGKFV("HANDLER", "%p", sh),
                     PMLOGKS("CREATE_DLI_FNAME", create_info_valid ? create_info.dli_fname : "(unknown)"),
                     PMLOGKS("CREATE_DLI_SNAME", create_info_valid ? create_info.dli_sname : "(unknown)"),
                     PMLOGKS("DESTR_DLI_FNAME", destroy_info_valid ? destroy_info.dli_fname : "(unknown)"),
                     PMLOGKS("DESTR_DLI_SNAME", destroy_info_valid ? destroy_info.dli_sname : "(unknown)"),
                     "%s: Invalid handle", __func__);
        LS_ASSERT(!"Invalid LSHandle");
    }
}
#endif

/**
 * @addtogroup LunaServiceInternals
 * @{
 */

struct GlobalState
{
    pthread_once_t  key_once;
    pthread_mutex_t lock;
};

static struct GlobalState state =
{
    .key_once = PTHREAD_ONCE_INIT,
    .lock     = PTHREAD_MUTEX_INITIALIZER,
};

/**
* @brief Global lock used exclusively for initialization.
*/
void
_LSGlobalLock()
{
    pthread_mutex_lock(&state.lock);
}

/**
* @brief Global unlock used exclusively for initialization.
*/
void
_LSGlobalUnlock()
{
    pthread_mutex_unlock(&state.lock);
}

/**
* @brief Called once to initialize the Luna Service world.
*
* @retval
*/
static void
_LSInit(void)
{
    if (!g_thread_supported())
    {
        g_thread_init(NULL);
    }

    char *ls_debug = getenv("LS_DEBUG");
    if (ls_debug)
    {
        _ls_debug_tracing = atoi(ls_debug);
        if (_ls_debug_tracing > 1)
        {
            PmLogSetContextLevel(PmLogGetLibContext(), kPmLogLevel_Debug);
            LOG_LS_DEBUG("Log mode enabled to level %d", _ls_debug_tracing);
        }
    }

    if (getenv("LS_ENABLE_UTF8"))
    {
        _ls_enable_utf8_validation = true;
        LOG_LS_DEBUG("Enable UTF8 validation on payloads");
    }
}

bool
_LSErrorSetFunc(LSError *lserror,
                const char *file, int line, const char *function,
                int error_code, const char *error_message, ...)
{
    if (!lserror) return true;

    // don't set an error that is already set.
    if (LSErrorIsSet(lserror))
    {
        return true;
    }

    lserror->file = file;
    lserror->line = line;
    lserror->func = function;
    lserror->error_code    =  error_code;

    va_list args;
    va_start (args, error_message);

    lserror->message = g_strdup_vprintf(error_message, args);

    va_end (args);

    return true;
}

/**
 *******************************************************************************
 * @brief Use when the error_message is not a printf-style string
 * (error_message could contain printf() escape sequences)
 *
 * @param  lserror
 * @param  file
 * @param  line
 * @param  function
 * @param  error_code
 * @param  error_message
 *
 * @retval
 *******************************************************************************
 */
bool
_LSErrorSetFuncLiteral(LSError *lserror,
                       const char *file, int line, const char *function,
                       int error_code, const char *error_message)
{
    if (!lserror) return true;

    // don't set an error that is already set.
    if (LSErrorIsSet(lserror))
    {
        return true;
    }

    lserror->file = file;
    lserror->line = line;
    lserror->func = function;
    lserror->error_code = error_code;

    lserror->message = g_strdup(error_message);

    return true;
}

bool
_LSErrorSetFromErrnoFunc(LSError *lserror,
                         const char *file, int line, const char *function,
                         int error_code)
{
    char err_buf[256];
    strerror_r(errno, err_buf, sizeof(err_buf));
    return _LSErrorSetFunc(lserror, file, line, function, error_code, "%s", err_buf);
}

#if 0
/**
* @brief Called on unregister of category.
*
* @warn This is NOT implemented!
*
* @param  connection
* @param  user_data
*/
static void
_LSCategoryUnregister(LSHandle *sh, void *user_data)
{
    /* FIXME -- implement this */
}
#endif

static LSMessageHandlerResult
_LSHandleMethodCall(LSHandle *sh, _LSTransportMessage *transport_msg)
{
    LSMessageHandlerResult retVal;

    LSMessage *message = _LSMessageNewRef(transport_msg, sh);

    /* look up the name in tableHandlers */
    GHashTable *categories = sh->tableHandlers;

    const char* category_name = LSMessageGetCategory(message);

    /* find the category in the tableHandlers (LSCategoryTable) */
    LSCategoryTable *category = g_hash_table_lookup(categories, category_name);
    if (!category)
    {
        LOG_LS_ERROR(MSGID_LS_NO_CATEGORY, 1,
                     PMLOGKS("CATEGORY", category_name),
                     "Couldn't find category: %s", category_name);
        retVal = LSMessageHandlerResultUnknownMethod;
    }
    else
    {
        retVal = LSCategoryMethodCall(sh, category, transport_msg->client->service_name, message);
    }

    LSMessageUnref(message);

    return retVal;
}


/* NOTE: only certain types are handled here -- those that aren't considered
 * "internal" */
static LSMessageHandlerResult
_LSMessageHandler(_LSTransportMessage *message, void *context)
{
    LSMessageHandlerResult retVal = LSMessageHandlerResultHandled;

    switch (_LSTransportMessageGetType(message))
    {
    case _LSTransportMessageTypeMethodCall:
    case _LSTransportMessageTypeCancelMethodCall:
        /* NOTE: the "cancel method call" is handled by the
         * _privateMethods -- _LSPrivateCancel, which is registered for
         * all services by default */
        retVal = _LSHandleMethodCall(context, message);
        break;

    case _LSTransportMessageTypeSignal:
    case _LSTransportMessageTypeReply:
    case _LSTransportMessageTypeQueryServiceStatusReply:
    case _LSTransportMessageTypeQueryServiceCategoryReply:
    case _LSTransportMessageTypeServiceDownSignal:
    case _LSTransportMessageTypeServiceUpSignal:
    case _LSTransportMessageTypeError:
    case _LSTransportMessageTypeErrorUnknownMethod:
        /* we're ignoring the return value; we don't really want to
         * send an error reply message to a reply */
        _LSHandleReply(context, message);
        break;

    default:
        LOG_LS_WARNING(MSGID_LS_UNKNOWN_MSG, 1,
                       PMLOGKFV("MSG_TYPE", "%d", _LSTransportMessageGetType(message)),
                       "Received message we don't understand: %d",
                       _LSTransportMessageGetType(message));
        break;
    }

    return retVal;
}

/* @} END OF LunaServiceInternals */

/**
 * @addtogroup LunaServiceError
 *
 * @{
 */

/**
* @brief Initializes a LSError.
*
* @param  lserror
*
* @retval
*/
bool
LSErrorInit(LSError *lserror)
{
    _LSErrorIfFail(lserror != NULL, NULL, MSGID_LS_ERROR_INIT_ERR);

    memset(lserror, 0, sizeof (LSError));

    LS_MAGIC_SET(lserror, LSError);

    return true;
}

/**
* @brief Find the status of a LSError
*
* @param  lserror
*
* @retval true if the LSError contains an error code/message.
*/
bool
LSErrorIsSet(LSError *lserror)
{
    LSERROR_CHECK_MAGIC(lserror);

    return (lserror && lserror->error_code != 0);
}

/**
* @brief Convenience function to print a LSError
*
* @param  lserror
* @param  out
*/
void
LSErrorPrint(LSError *lserror, FILE *out)
{
    LSERROR_CHECK_MAGIC(lserror);

    if (lserror)
    {
        fprintf(out, "LUNASERVICE ERROR %d: %s (%s @ %s:%d)\n",
            lserror->error_code, lserror->message,
            lserror->func, lserror->file, lserror->line);
    }
    else
    {
        fprintf(out, "LUNASERVICE ERROR: lserror is NULL. Did you pass in a LSError?");
    }
}

/**
* @brief Function to log a LSError with PmLogLib
*
* @param  log_context
* @param  lserror
*/
void
LSErrorLog(PmLogContext context, const char* message_id, LSError *lserror)
{
    LSERROR_CHECK_MAGIC(lserror);

    if (lserror)
    {
        PmLogError(context, message_id, 5,
                   PMLOGKFV("ERROR_CODE", "%d", lserror->error_code),
                   PMLOGKS("ERROR", lserror->message),
                   PMLOGKS("FUNC", lserror->func),
                   PMLOGKS("FILE", lserror->file),
                   PMLOGKFV("LINE", "%d", lserror->line),
                   "LUNASERVICE ERROR");
    }
    else
    {
        LOG_LS_ERROR(MSGID_LS_NULL_LS_ERROR, 0, "lserror is NULL. Did you pass in a LSError?");
    }
}

/**
* @brief Frees the internal structures of LSError if an error has been handled.
*        Must be called on an error if set.
*
* @param  lserror
*
* @retval
*/
void
LSErrorFree(LSError *lserror)
{
    if (lserror)
    {
        LSERROR_CHECK_MAGIC(lserror);
        g_free(lserror->message);

        LSErrorInit(lserror);
    }
}

/* @} END OF LunaServiceError */


/**
 * @addtogroup LunaServiceRegistration
 *
 * @{
 */


static bool
_LSPrivateCancel(LSHandle* sh, LSMessage *message, void *user_data)
{
    bool retVal;
    LSError lserror;
    LSErrorInit(&lserror);

    retVal = _CatalogHandleCancel(sh->catalog, message, &lserror);
    if (!retVal)
    {
        LOG_LSERROR(MSGID_LS_CANT_CANCEL_METH, &lserror);
        LSErrorFree(&lserror);
    }

    return true;
}

static bool
_LSPrivatePing(LSHandle* lshandle, LSMessage *message, void *user_data)
{
    bool retVal;
    LSError lserror;
    LSErrorInit(&lserror);

    const char *ping_string = "{\"returnValue\":true}";
    retVal = LSMessageReply(lshandle, message, ping_string, &lserror);
    if (!retVal)
    {
        LOG_LSERROR(MSGID_LS_CANT_PING, &lserror);
        LSErrorFree (&lserror);
    }

    return true;
}

static LSMethod _privateMethods[] = {
    { "cancel", _LSPrivateCancel},
    { "ping", _LSPrivatePing},
#ifdef SUBSCRIPTION_DEBUG
    { "subscriptions", _LSPrivateGetSubscriptions},
#endif
#ifdef MALLOC_DEBUG
    { "mallinfo", _LSPrivateGetMallinfo},
    { "malloc_trim", _LSPrivateDoMallocTrim},
#endif
#ifdef INTROSPECTION_DEBUG
    { "introspection", _LSPrivateInrospection},
#endif
    { },
};


/**
* @brief Set a function to be called if we are disconnected from the bus.
*
* @param  sh
* @param  disconnect_handler
* @param  lserror
*
* @retval
*/
bool
LSSetDisconnectHandler(LSHandle *sh, LSDisconnectHandler disconnect_handler,
                       void *user_data,
                       LSError *lserror)
{
    _LSErrorIfFail(sh != NULL, lserror, MSGID_LS_INVALID_HANDLE);
    LSHANDLE_VALIDATE(sh);
    sh->disconnect_handler = disconnect_handler;
    sh->disconnect_handler_data = user_data;
    return true;
}

/*
    We need a common routine one level down from all the public LSRegister* functions
*/
bool
_LSRegisterCommon(const char *name, LSHandle **ret_sh,
                  bool public_bus,
                  void *call_ret_addr,
                  LSError *lserror)
{
    _LSErrorIfFail(ret_sh != NULL, lserror, MSGID_LS_INVALID_HANDLE);

    pthread_once(&state.key_once, _LSInit);

    LSHandle *sh = g_new0(LSHandle, 1);

    /* For backward compatibility, convert empty string to NULL */
    if (name && name[0] == '\0')
    {
        name = NULL;
    }

    sh->name        = g_strdup(name);
    sh->transport   = NULL;

    LSHANDLE_SET_VALID(sh, call_ret_addr);

    /* custom message queue */
    sh->custom_message_queue = LSCustomMessageQueueNew();
    if (!sh->custom_message_queue)
    {
        LOG_LS_ERROR(MSGID_LS_QUEUE_ERROR, 0, "Failed to create new message queue");
        goto error;
    }

    LSTransportHandlers _LSTransportHandler =
    {
        .msg_handler = _LSMessageHandler,
        .msg_context = sh,
        .disconnect_handler = _LSDisconnectHandler,
        .disconnect_context = sh,
        .message_failure_handler = _LSHandleMessageFailure,
        .message_failure_context = sh
    };

    if (!_LSTransportInit(&sh->transport, name, &_LSTransportHandler, lserror))
    {
        goto error;
    }

    /* Connect to the hub and listen for incoming calls */
    if (!_LSTransportConnect(sh->transport, true, public_bus, lserror))
    {
        if (lserror->error_code == LS_ERROR_CODE_CONNECT_FAILURE)
        {
            LOG_LS_ERROR(MSGID_LS_CONN_ERROR, 0, "Failed to connect. Is the hub running?");
        }
        goto error;
    }

    if (!_CallMapInit(sh, &sh->callmap, lserror))
    {
        goto error;
    }

    sh->catalog = _CatalogNew(sh);
    if (!sh->catalog)
    {
        LOG_LS_ERROR(MSGID_LS_CATALOG_ERR, 0, "Failed to create new subscription catalog");
        goto error;
    }

    if (!LSRegisterCategory (sh, "/com/palm/luna/private", _privateMethods, NULL, NULL, lserror))
    {
        goto error;
    }

    *ret_sh = sh;

    return true;

error:

    if (sh)
    {
        _LSTransportDisconnect(sh->transport, true);
        _LSTransportDeinit(sh->transport);
        _CallMapDeinit(sh, sh->callmap);
        _CatalogFree(sh->catalog);

        if (sh->custom_message_queue) LSCustomMessageQueueFree(sh->custom_message_queue);

        g_free(sh->name);

        LSHANDLE_SET_DESTROYED(sh, call_ret_addr);

#ifdef MEMCHECK
        LSHANDLE_POISON(sh);
#endif

        g_free(sh);
    }

    *ret_sh = NULL;

    return false;
}

/**
* @brief Connect to bus by type.
*
* @param  name
* @param  *sh
* @param  public_bus
* @param  lserror
*
* @retval
*/
bool
LSRegisterPubPriv(const char *name, LSHandle **ret_sh,
                       bool public_bus,
                       LSError *lserror)
{
    return _LSRegisterCommon(name, ret_sh, public_bus, LSHANDLE_GET_RETURN_ADDR(), lserror);
}

const char *
LSHandleGetName(LSHandle *sh)
{
    if (!sh) return NULL;
    LSHANDLE_VALIDATE(sh);
    return sh->name;
}

/**
* @brief Register a service on the private bus.
* The old notion of clients and servers does not apply.  Everyone is a
* service.  Services may make outgoing service calls using LSCall()
* or handle incomming messages for handlers registered via
* LSRegisterCategory(), and send replies via LSMessageReply() or
* LSSubscriptionPost().  A traditional client may register with a NULL name if
* it never expects to be sent messages.
*
* @param  name
* @param  *serviceHandle
* @param  lserror
*
* @retval
*/
bool
LSRegister(const char *name, LSHandle **sh,
                  LSError *lserror)
{
    return _LSRegisterCommon(name, sh, false, LSHANDLE_GET_RETURN_ADDR(), lserror);
}

bool
LSUnregisterPalmService(LSPalmService *psh, LSError *lserror)
{
    _LSErrorIfFail(psh != NULL, lserror, MSGID_LS_INVALID_HANDLE);

    bool retVal;

    if (psh->public_sh)
    {
        retVal = _LSUnregisterCommon(psh->public_sh, true, LSHANDLE_GET_RETURN_ADDR(), lserror );
        if (!retVal) goto error;
    }

    if (psh->private_sh)
    {
        retVal = _LSUnregisterCommon(psh->private_sh, true, LSHANDLE_GET_RETURN_ADDR(), lserror );
        if (!retVal) goto error;
    }

error:
    g_free(psh);
    return true;
}


/**
* @brief Register a service that may expose public methods on the public bus,
*        and internal methods on the private bus.
*
* @param  name
* @param  *ret_public_service
* @param  lserror
*
* @retval
*/
bool
LSRegisterPalmService(const char *name,
                  LSPalmService **ret_public_service,
                  LSError *lserror)
{
    _LSErrorIfFailMsg(ret_public_service != NULL, lserror, MSGID_LS_INVALID_HANDLE,
        -EINVAL, "Invalid parameter ret_public_service to %s", __FUNCTION__);

    bool retVal;

    LSPalmService *psh = g_new0(LSPalmService,1);

    retVal = _LSRegisterCommon(name, &psh->public_sh, true, LSHANDLE_GET_RETURN_ADDR(), lserror);
    if (!retVal) goto error;

    retVal = _LSRegisterCommon(name, &psh->private_sh, false, LSHANDLE_GET_RETURN_ADDR(), lserror);
    if (!retVal) goto error;

    *ret_public_service = psh;
    return retVal;

error:
    (void)LSUnregisterPalmService(psh, NULL);
    *ret_public_service = NULL;
    return retVal;
}

/**
* @brief Obtain the private service handle from a public
*        service.
*
* @param  psh
*
* @retval
*/
LSHandle *
LSPalmServiceGetPrivateConnection(LSPalmService *psh)
{
    if (!psh) return NULL;
    return psh->private_sh;
}

/**
* @brief Obtain the public service handle from a public
*        service.
*
* @param  psh
*
* @retval
*/
LSHandle *
LSPalmServiceGetPublicConnection(LSPalmService *psh)
{
    if (!psh) return NULL;
    return psh->public_sh;
}

bool
_LSUnregisterCommon(LSHandle *sh, bool flush_and_send_shutdown, void *call_ret_addr, LSError *lserror)
{
    _LSErrorIfFail(sh != NULL, lserror, MSGID_LS_INVALID_HANDLE);

    _LSGlobalLock();

    if (sh->tableHandlers)
    {
        g_hash_table_unref(sh->tableHandlers);
    }

    if (sh->custom_message_queue)
    {
        LSCustomMessageQueueFree(sh->custom_message_queue);
        sh->custom_message_queue = NULL;
    }

    _CatalogFree(sh->catalog);

    _CallMapDeinit(sh, sh->callmap);

    _LSTransportDisconnect(sh->transport, flush_and_send_shutdown);

    _LSTransportDeinit(sh->transport);

    /* Now we can cleanup the gmainloop connection. */
    if (sh->context)
    {
        g_main_context_unref(sh->context);
        sh->context = NULL;
    }

    g_free(sh->name);

    LSHANDLE_SET_DESTROYED(sh, call_ret_addr);

#ifdef MEMCHECK
    LSHANDLE_POISON(sh);
#endif

    g_free(sh);

    _LSGlobalUnlock();

    return true;
}


/**
* @brief Unregister a service.
*
* @param  service
* @param  lserror
*
* @retval
*/
bool
LSUnregister(LSHandle *sh, LSError *lserror)
{
    return _LSUnregisterCommon(sh, true, LSHANDLE_GET_RETURN_ADDR(), lserror );
}

/**
 * @brief Push a role file for this process. Once the role file has been
 * pushed with this function, the process will be restricted to the
 * constraints of the provided role file.
 *
 * @param  sh           IN  handle (already connected with LSRegister())
 * @param  role_path    IN  full path to role file
 * @param  lserror      OUT set on error
 *
 * @retval true on success
 * @retval false on failure
 */
bool
LSPushRole(LSHandle *sh, const char *role_path, LSError *lserror)
{
    _LSErrorIfFail(sh != NULL, lserror, MSGID_LS_INVALID_HANDLE);

    LSHANDLE_VALIDATE(sh);

    return LSTransportPushRole(sh->transport, role_path, lserror);
}

/**
 * @brief Same as LSPushRole(), but for a LSPalmService connection.
 *
 * @param  psh          IN  handle
 * @param  role_path    IN  full path to role file
 * @param  lserror      OUT set on error
 *
 * @retval true on success
 * @retval false on failure
 */
bool
LSPushRolePalmService(LSPalmService *psh, const char *role_path, LSError *lserror)
{
    _LSErrorIfFail(psh != NULL, lserror, MSGID_LS_INVALID_HANDLE);

    bool retVal = true;

    if (psh->public_sh)
    {
        retVal = LSPushRole(psh->public_sh, role_path, lserror);
        if (!retVal) goto error;
    }

    if (psh->private_sh)
    {
        retVal = LSPushRole(psh->private_sh, role_path, lserror);
        if (!retVal) goto error;
    }

error:
    return retVal;
}

/* @} END OF LunaServiceRegistration */
