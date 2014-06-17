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
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <stdlib.h>

#ifdef WIN32
#include <winerror.h>
#define ENOTCONN WSAENOTCONN
#endif

#include <pbnjson.h>

#include <luna-service2/lunaservice.h>
#include <luna-service2/lunaservice-errors.h>

#include "simple_pbnjson.h"
//#include "callmap.h"
#include "transport.h"
#include "message.h"
#include "base.h"
#include "category.h"
#include "transport_utils.h"
#include "clock.h"
#include "pmtrace_ls2.h"

/**
 * @addtogroup LunaServiceClientInternals
 * @{
 */

static bool _LSCallFromApplicationCommon(LSHandle *sh, const char *uri,
       const char *payload,
       const char *applicationID,
       LSFilterFunc callback, void *ctx,
       LSMessageToken *ret_token, bool single, LSError *lserror);

#define LUNA_OLD_PREFIX "luna://"
#define LUNA_PREFIX "palm://"

typedef struct _Uri
{
    char *serviceName;
    char *objectPath;
    char *interfaceName;
    char *methodName;
} _Uri;


void
_UriFree(_Uri *luri)
{
    if (NULL == luri) return;

    g_free(luri->serviceName);
    g_free(luri->objectPath);
    g_free(luri->interfaceName);
    g_free(luri->methodName);

#ifdef MEMCHECK
    memset(luri, 0xFF, sizeof(_Uri));
#endif

    g_free(luri);
}

#define MAX_NAME_LEN 255

static inline bool is_valid_initial_char(int c)
{
    switch (c)
    {
    case 'A'...'Z':
    case 'a'...'z':
    case '_':
        return true;
    default:
        return false;
    }
}

static inline bool is_valid_name_char(int c)
{
    switch (c)
    {
    case 'A'...'Z':
    case 'a'...'z':
    case '0'...'9':
    case '_':
        return true;
    default:
        return false;
    }
}

static inline bool is_valid_path_char(int c)
{
    switch (c)
    {
    case 'A'...'Z':
    case 'a'...'z':
    case '0'...'9':
    case '_':
    case '.':
        return true;
    default:
        return false;
    }
}

/**
* @brief Validate the service name.
*
* @param  service_name
*
* @retval
*/
static bool
_validate_service_name(const char *service_name)
{
    int len;
    const char *p;
    const char *end;
    const char *last_dot;

    len = strlen(service_name);
    p = service_name;
    end = service_name + len;
    last_dot = NULL;

    if (len > MAX_NAME_LEN) return false;
    if (0 == len) return false;

    // unique names are not allowed.
    if (':' == *p) return false;

    if ('.' == *p) return false;

    if (unlikely(!is_valid_initial_char(*p))) return false;

    p++;

    for ( ; p < end; p++)
    {
        if ('.' == *p)
        {
            last_dot = p;

            // skip past '.'
            p++;

            if (p == end) return false;

            // after '.' back to initial character
            if (unlikely(!is_valid_initial_char(*p)))
            {
                return false;
            }
        }
        else if (unlikely(!is_valid_name_char(*p)))
        {
            return false;
        }
    }

    // name must have at least one dot '.'
    if (unlikely(NULL == last_dot)) return false;

    return true;
}

/**
* @brief
*
* The path has already been validated with the
* correct characters.  We just need to validate the
* slash positions.
*
* @param  path
*
* @retval
*/
static bool
_validate_path(const char *path)
{
    int len;
    const char *p;
    const char *last_slash;
    const char *end;

    len = strlen(path);
    p   = path;
    end = path+len;

    if (0 == len)
    {
        return false;
    }

    if ('/' != *p)
    {
        return false;
    }

    last_slash = p;
    p++;

    for (; p < end; p++)
    {
        if ('/' == *p)
        {
            // two successive slashes is invalid.
            if ((p - last_slash) < 2)
                return false;
        }
        else if (unlikely(!is_valid_path_char(*p)))
        {
            return false;
        }
    }

    // trailing '/' is also not allowed.
    if (((end - last_slash) < 2) && len > 1)
    {
        return false;
    }

    return true;
}

/**
* @brief Validate method of URI.
*
* This assumes that the member has already been validated with the correct
* characters.
*
* @param  method
*
* @retval
*/
static bool
_validate_method(const char *method)
{
    int len;
    const char *p;
    const char *end;

    len = strlen(method);
    p = method;
    end = method+len;

    if (len > MAX_NAME_LEN) return false;
    if (0 == len) return false;

    // first character may not be a digit.
    if (unlikely(!is_valid_initial_char(*p)))
    {
        return false;
    }
    p++;

    for ( ; p < end; p++)
    {
        if (unlikely(!is_valid_name_char(*p)))
        {
            return false;
        }
    }

    return true;
}

/**
* @brief Parse a uri and return a _Uri object containing the individual parts.
*
* @param  uri
*
* @retval
*/
_Uri *
_UriParse(const char *uri, LSError *lserror)
{
    _Uri *luri = NULL;
    const char *uri_p;
    const char *first_slash;
    int service_name_len;

    uri_p = uri;

    if (g_str_has_prefix(uri, LUNA_PREFIX))
    {
        uri_p += strlen(LUNA_PREFIX);
    }
    else if (g_str_has_prefix(uri, LUNA_OLD_PREFIX))
    {
        uri_p += strlen(LUNA_OLD_PREFIX);
    }
    else
    {
        _LSErrorSet(lserror, MSGID_LS_INVALID_URI, -EINVAL,
            "%s: Not a valid uri %s - it doesn't begin with " LUNA_PREFIX,
                __FUNCTION__, uri);
        goto error;
    }

    first_slash = strchr(uri_p, '/');
    if (!first_slash)
    {
        _LSErrorSet(lserror, MSGID_LS_INVALID_URI, -EINVAL,
            "%s: Not a valid uri %s", __FUNCTION__, uri);
        goto error;
    }

    luri = g_new0(_Uri, 1);

    service_name_len = first_slash - uri_p;
    luri->serviceName = g_strndup(uri_p, service_name_len);
    uri_p += service_name_len;

    luri->objectPath = g_path_get_dirname(uri_p);
    luri->methodName = g_path_get_basename(uri_p);

    if (!_validate_service_name(luri->serviceName))
    {
        _LSErrorSet(lserror, MSGID_LS_INVALID_URI_SERVICE_NAME, -EINVAL,
                    "%s: Not a valid service name in uri %s (service name: %s)",
                    __FUNCTION__, uri, luri->serviceName);
        goto error;
    }

    if (!_validate_path(luri->objectPath))
    {
        _LSErrorSet(lserror, MSGID_LS_INVALID_URI_PATH, -EINVAL,
                    "%s: Not a valid path in uri %s (path: %s)",
                    __FUNCTION__, uri, luri->objectPath);
        goto error;
    }

    if (!_validate_method(luri->methodName))
    {
        _LSErrorSet(lserror, MSGID_LS_INVALID_URI_METHOD, -EINVAL,
                    "%s: Not a valid method name in uri %s (method: %s)",
                    __FUNCTION__, uri, luri->methodName);
        goto error;
    }

    return luri;
error:
    _UriFree(luri);

    return NULL;
}

typedef GArray _TokenList;

static _TokenList *
_TokenListNew()
{
    return g_array_new(false, false, sizeof(LSMessageToken));
}

static void
_TokenListFree(_TokenList *tokens)
{
    g_array_free(tokens, true);
}

static int
_TokenListLen(_TokenList *tokens)
{
    if (!tokens) return 0;
    return tokens->len;
}

static void
_TokenListAddList(_TokenList *tokens, _TokenList *data)
{
    if (tokens && data)
        g_array_append_vals(tokens, data->data, data->len);
}

static void
_TokenListAdd(_TokenList *tokens, LSMessageToken t)
{
    if (tokens) g_array_append_val(tokens, t);
}

static void
_TokenListRemove(_TokenList *tokens, LSMessageToken t)
{
    if (!tokens) return;

    int i;
    for (i = 0; i < tokens->len; i++)
    {
        LSMessageToken iter = g_array_index(tokens, LSMessageToken, i);
        if (iter == t)
        {
            g_array_remove_index_fast(tokens, i);
            break;
        }
    }
}

static void
_TokenListRemoveAll(_TokenList *tokens)
{
   tokens->len = 0;
}

typedef struct _ServerStatus
{
    LSServerStatusFunc callback;
    void              *ctx;
    LSMessageToken     token;
} _ServerStatus;

typedef struct _ServerInfo
{
    bool ServiceStatusChanged;
    char *serviceName;
    bool connected;
} _ServerInfo;

struct _CallMap {

    GHashTable *tokenMap;      //< Map from token to _Call
    GHashTable *signalMap;     //< Map from signal key to list of tokens
    GHashTable *serviceMap;    //< Map from serviceName to list of tokens

    //DBusHandleMessageFunction message_handler;

    pthread_mutex_t  lock;
};

void
_CallMapLock(_CallMap *map)
{
    int pthread_mutex_lock_ret = pthread_mutex_lock(&map->lock);
    LS_ASSERT(pthread_mutex_lock_ret == 0);
}

void
_CallMapUnlock(_CallMap *map)
{
    int pthread_mutex_unlock_ret = pthread_mutex_unlock(&map->lock);
    LS_ASSERT(pthread_mutex_unlock_ret == 0);
}

//static DBusHandlerResult _message_filter(DBusConnection *conn, DBusMessage *msg, void *ctx);

enum {
    CALL_TYPE_INVALID,
    CALL_TYPE_METHOD_CALL,
    CALL_TYPE_SIGNAL,
    CALL_TYPE_SIGNAL_SERVER_STATUS,
};

typedef struct _Call {

    int           ref;
    char         *serviceName;
#ifdef HAS_LTTNG
    char         *methodName;
#endif
    LSHandle     *sh;          //< back pointer to the service handle (non-owning)
    LSFilterFunc  callback;

    void         *ctx;         //< user context

    LSMessageToken token;      //< key used in callmap->tokenMap

    int            type;

    bool           single;

    /* Signal specific (we may want to break this
     * out into a separate struct) */
    //char          *rule;
    char          *signal_method;   //< registered signal method (could be NULL)
    char          *signal_category; //< registered signal category (required)
    char          *match_key;  //<key used in callmap->signalMap
    struct        timespec time;  //< time value for performance measurement
    GSource       *timer_source; //< source for timer expiration (non-NULL if set)

    int           timeout_ms;  //< milliseconds to timeout before next message reply.
} _Call;


_Call *
_CallNew(LSHandle *sh, int type, const char *serviceName,
         LSFilterFunc callback, void *ctx,
         LSMessageToken token, const char *methodName)
{
    _Call *call = g_new0(_Call, 1);

    call->sh = sh;
    call->serviceName = g_strdup(serviceName);
    call->callback = callback;
    call->ctx = ctx;
    call->token = token;
    call->type = type;
#ifdef HAS_LTTNG
    call->methodName = g_strdup(methodName);
#endif

    return call;
}

void
_CallFree(_Call *call)
{
    if (!call) return;

    if (call->timer_source != NULL)
    {
        g_source_destroy(call->timer_source);
        g_source_unref(call->timer_source);
    }
    g_free(call->serviceName);
    //g_free(call->rule);
    g_free(call->signal_method);
    g_free(call->signal_category);
    g_free(call->match_key);

#ifdef HAS_LTTNG
    g_free(call->methodName);
#endif

#ifdef MEMCHECK
    memset(call, 0xFF, sizeof(_Call));
#endif

    g_free(call);
}

static bool
_service_watch_enable(LSHandle *sh, _Call *call, LSError *lserror)
{
    bool retVal = true;

    if (CALL_TYPE_SIGNAL_SERVER_STATUS == call->type && call->serviceName)
    {
        retVal = LSTransportRegisterSignalServiceStatus(sh->transport, call->serviceName, NULL, lserror);

    }
    return retVal;
}

static bool
_service_watch_disable(LSHandle *sh, _Call *call)
{
    if (CALL_TYPE_SIGNAL_SERVER_STATUS == call->type && call->serviceName)
    {
        return LSTransportUnregisterSignalServiceStatus(sh->transport, call->serviceName, NULL, NULL);
    }
    return false;
}

static void ResetCallTimeout(_Call *call);

/**
* @brief Insert a call into the callmap.
*
* @param  map
* @param  call
*/
static bool
_CallInsert(LSHandle *sh, _CallMap *map, _Call *call, bool single,
            LSError *lserror)
{
    // TODO: Remove default branch and add parameter checking with assertion,
    // as far, as we have only one 'true' case.
    GHashTable *table = NULL;
    gpointer    key = NULL;

    switch (call->type)
    {
    case CALL_TYPE_METHOD_CALL:
    case CALL_TYPE_SIGNAL_SERVER_STATUS:
        table = map->serviceMap;
        key   = call->serviceName;
        break;
    case CALL_TYPE_SIGNAL:
        table = map->signalMap;
        key   = call->match_key;
        break;
    default:
        _LSErrorSet(lserror, MSGID_LS_INVALID_CALL, -1, "Unsupported call type.");
        return false;
    }

    call->single = single;

    // TODO: LS_ASSERT(call->ref == 0);
    call->ref = 1;

    _TokenList *token_list = g_hash_table_lookup(table, key);
    if (_TokenListLen(token_list) == 0)
    {
        if (!token_list)
        {
            token_list = _TokenListNew();

            g_hash_table_replace(table, g_strdup(key), token_list);
        }
    }

    _TokenListAdd(token_list, call->token);

    /* It's an error if the key is already in the map */
    LS_ASSERT(g_hash_table_lookup(map->tokenMap, (gpointer)call->token) == NULL);

    g_hash_table_replace(map->tokenMap, (gpointer)call->token, call);

    return true;
}

static void
_CallRemove(LSHandle *sh, _CallMap *map, _Call *call)
{
    _CallMapLock(map);

    _Call *orig_call = g_hash_table_lookup(map->tokenMap, (gpointer)call->token);
    if (orig_call == call)
    {
        if (call->timer_source != NULL)
        {
            call->timeout_ms = 0;
            ResetCallTimeout(call);
        }
        switch(call->type)
        {
        case CALL_TYPE_METHOD_CALL:
        case CALL_TYPE_SIGNAL_SERVER_STATUS:
            if (call->serviceName)
            {
                _TokenList *token_list =
                    g_hash_table_lookup(map->serviceMap, call->serviceName);

                _TokenListRemove(token_list, call->token);
            }
            break;
        case CALL_TYPE_SIGNAL:
            if (call->match_key)
            {
                _TokenList *token_list =
                    g_hash_table_lookup(map->signalMap, call->match_key);

                _TokenListRemove(token_list, call->token);
            }
            break;
        }

        g_hash_table_remove(map->tokenMap, (gpointer)call->token);
    }

    /* <eeh> TODO: what does the else case mean (i.e., orig_call != call) */

    _CallMapUnlock(map);
}

static void
_CallAddReference(_Call *call)
{
    LS_ASSERT(g_atomic_int_get (&call->ref) > 0);
    g_atomic_int_inc(&call->ref);
}

static _Call*
_CallAcquire(_CallMap *map, LSMessageToken token)
{
    _Call *call;

    _CallMapLock(map);

    call = g_hash_table_lookup(map->tokenMap, (gpointer)token);
    if (call)
        _CallAddReference(call);

    _CallMapUnlock(map);

    return call;
}

static void
_CallRelease(_Call *call)
{
    LS_ASSERT(g_atomic_int_get (&call->ref) > 0);

    if (g_atomic_int_dec_and_test(&call->ref))
    {
        _CallFree(call);
    }
}

/**
* @brief Initialize callmap.
*
* @param  sh
* @param  *ret_map
* @param  lserror
*
* @retval
*/
bool
_CallMapInit(LSHandle *sh, _CallMap **ret_map, LSError *lserror)
{
    _CallMap *map = g_new0(_CallMap, 1);

    map->tokenMap = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                    NULL, (GDestroyNotify)_CallRelease);
    map->signalMap = g_hash_table_new_full(g_str_hash, g_str_equal,
                    (GDestroyNotify)g_free, (GDestroyNotify)_TokenListFree);
    map->serviceMap = g_hash_table_new_full(g_str_hash, g_str_equal,
                    (GDestroyNotify)g_free, (GDestroyNotify)_TokenListFree);

    if (pthread_mutex_init(&map->lock, NULL))
    {
        _LSErrorSet(lserror, MSGID_LS_MUTEX_ERR, -1, "Could not initialize mutex.");
        goto error;
    }

    *ret_map = map;
    return true;

error:
    _CallMapDeinit(sh, map);
    return false;
}

/**
* @brief Deinitialize call map.
*
* @param  sh
* @param  map
*/
void
_CallMapDeinit(LSHandle *sh, _CallMap *map)
{
    if (map)
    {
        g_hash_table_destroy(map->signalMap);
        g_hash_table_destroy(map->serviceMap);

        //Destroy set timers for all remaining calls if any
        GHashTableIter iter;
        gpointer key, value;
        g_hash_table_iter_init(&iter, map->tokenMap);
        while (g_hash_table_iter_next(&iter, &key, &value))
        {
            _Call * call = (_Call *)value;
            if (call->timer_source != NULL)
            {
                call->timeout_ms = 0;
                ResetCallTimeout(call);
            }
        }
        g_hash_table_destroy(map->tokenMap);

        if (pthread_mutex_destroy(&map->lock))
        {
            LOG_LS_WARNING(MSGID_LS_MUTEX_ERR, 0, "Could not destroy mutex &map->lock");
        }

        g_free(map);
    }
}

static void
_LSMessageSetFromError(_LSTransportMessage *transport_msg, _Call *call, LSMessage *reply)
{
    const char *error_text = NULL;

    LS_ASSERT(_LSTransportMessageIsErrorType(transport_msg));

    reply->category = LUNABUS_ERROR_CATEGORY;

    /* TODO: equivalent for DBUS_ERROR_SERVICE_UNKNOWN */
    switch (_LSTransportMessageGetType(transport_msg))
    {
    /* generic error */
    case _LSTransportMessageTypeError:
    {
        reply->methodAllocated =
                 g_strdup_printf("%s", LUNABUS_ERROR_UNKNOWN_ERROR);
        reply->method = reply->methodAllocated;
        //error_text = g_strdup("Unknown error");
        error_text = _LSTransportMessageGetError(transport_msg);
        break;
    }

    case _LSTransportMessageTypeErrorUnknownMethod:
    {
        reply->method = LUNABUS_ERROR_UNKNOWN_METHOD;
        //error_text = g_strdup_printf("Method \"%s\" doesn't exist", _LSTransportMessageGetError(msg));
        error_text = _LSTransportMessageGetError(transport_msg);
        break;
    }

    default:
    {
        LOG_LS_ERROR(MSGID_LS_NOT_AN_ERROR, 0,
                     "%s: The message type %d is not an error type", __func__, _LSTransportMessageGetType(transport_msg));
        LS_ASSERT(0);
    }
    }

    /* Escape the string */
    if (!reply->payload)
    {
        char *escaped = g_strescape(error_text, NULL);
        if (!escaped) goto error;

        reply->payloadAllocated = g_strdup_printf(
            "{\"returnValue\":false,\"errorCode\":-1,\"errorText\":\"%s\"}",
            escaped);
        reply->payload = reply->payloadAllocated;

        g_free(escaped);
    }

    return;

error:
    g_free(reply->methodAllocated);
    g_free(reply->payloadAllocated);

    reply->category = LUNABUS_ERROR_CATEGORY;
    reply->method = LUNABUS_ERROR_OOM;

    reply->payloadAllocated = NULL;
    reply->payload =
        "{\"returnValue\":false,\"errorCode\":-1,\"errorText\":\"OOM\"}";
}

void
_LSMessageTranslateFromCall(_Call *call, LSMessage *reply,
                            _ServerInfo *server_info)
{

    _LSTransportMessage *msg = reply->transport_msg;
    _LSTransportMessageType type = _LSTransportMessageGetType(msg);

    reply->responseToken = call->token;

    switch (type)
    {
    case _LSTransportMessageTypeReply:
        {
        /* translate signal ack to lunabus ack */
        switch (call->type)
        {
            case CALL_TYPE_SIGNAL:
                if (g_strcmp0(_LSTransportMessageGetPayload(msg), "{\"returnValue\":true}") == 0)
                {
                    reply->category = LUNABUS_SIGNAL_CATEGORY;
                    reply->method = LUNABUS_SIGNAL_REGISTERED;
                    reply->payload = "{\"returnValue\":true}";
                }
                break;
        }
        break;
        }
    case _LSTransportMessageTypeSignal:
    case _LSTransportMessageTypeServiceDownSignal:
    case _LSTransportMessageTypeServiceUpSignal:
    {
        if (server_info && server_info->ServiceStatusChanged)
        {
            switch (call->type)
            {
            case CALL_TYPE_METHOD_CALL:
                if (!server_info->connected)
                {
                    reply->category = LUNABUS_ERROR_CATEGORY;
                    reply->method = LUNABUS_ERROR_SERVICE_DOWN;

                    reply->payloadAllocated = g_strdup_printf(
                        "{\"serviceName\":\"%s\","
                         "\"returnValue\":false,"
                         "\"errorCode\":-1,"
                         "\"errorText\":\"%s is not running.\"}",
                        server_info->serviceName,
                        server_info->serviceName);

                    reply->payload = reply->payloadAllocated;
                    reply->serviceDownMessage = true;
                }
                else
                {
                    reply->ignore = true;
                }
                break;
            case CALL_TYPE_SIGNAL_SERVER_STATUS:
                reply->category = LUNABUS_SIGNAL_CATEGORY;
                reply->method = LUNABUS_SIGNAL_SERVERSTATUS;

                reply->payloadAllocated = g_strdup_printf(
                    "{\"serviceName\":\"%s\",\"connected\":%s}",
                    server_info->serviceName,
                    server_info->connected ? "true" : "false");

                reply->payload = reply->payloadAllocated;
                break;
            }
        }
        break;
    }

    /* reply for service name lookup (registerServerStatus) */
    case _LSTransportMessageTypeQueryServiceStatusReply:
    {
        LS_ASSERT(call->type == CALL_TYPE_SIGNAL_SERVER_STATUS);

        /* FIXME -- need getter for this or make GetBody skip over the
         * reply serial */
        /* skip over reply serial to get available value */
        int available = *((int*)(_LSTransportMessageGetBody(msg) + sizeof(LSMessageToken)));

        if (available)
        {
            reply->category = LUNABUS_SIGNAL_CATEGORY;
            reply->method = LUNABUS_SIGNAL_SERVERSTATUS;
            reply->payloadAllocated = g_strdup_printf(
                "{\"serviceName\":\"%s\",\"connected\":true}",
                call->serviceName);
            reply->payload = reply->payloadAllocated;
        }
        else
        {
            reply->category = LUNABUS_SIGNAL_CATEGORY;
            reply->method = LUNABUS_SIGNAL_SERVERSTATUS;
            reply->payloadAllocated = g_strdup_printf(
                "{\"serviceName\":\"%s\",\"connected\":false}",
                call->serviceName);
            reply->payload = reply->payloadAllocated;
        }

        break;
    }

    /* reply for service category query (registerServerCategory) */
    case _LSTransportMessageTypeQueryServiceCategoryReply:
    {
        LS_ASSERT(call->type == CALL_TYPE_SIGNAL);

        _LSTransportMessageIter iter;
        _LSTransportMessageIterInit(msg, &iter);

        LS_ASSERT(_LSTransportMessageIterHasNext(&iter));
        _LSTransportMessageIterNext(&iter);

        const char *categories = NULL;
        _LSTransportMessageGetString(&iter, &categories);

        reply->category = LUNABUS_SIGNAL_CATEGORY;
        reply->method = LUNABUS_SIGNAL_SERVICE_CATEGORY;
        reply->payload = reply->payloadAllocated = g_strdup(categories);

        break;
    }

    /* translate all transport errors to lunabus errors. */
    case _LSTransportMessageTypeError:
    case _LSTransportMessageTypeErrorUnknownMethod:
    {
        _LSMessageSetFromError(msg, call, reply);
        break;
    }

    default:
    {
        LOG_LS_ERROR(MSGID_LS_UNKNOWN_MSG, 0, "Unknown message type: %d", type);
        break;
    }
    }
}

void
_LSMessageTranslate(LSHandle *sh, LSMessage *message,
                    _ServerInfo *server_info)
{
    _Call *call = _CallAcquire(sh->callmap,
                               LSMessageGetResponseToken(message));
    if (!call) return;

    _LSMessageTranslateFromCall(call, message, server_info);

    _CallRelease(call);
}

/**
* @brief Dispatch a message to each callback in tokens list.
*
* Messages can have multiple callbacks in the case of signals and
* one callback for a message response.
*
* @param  sh
* @param  tokens
* @param  msg
*
* @retval
*/
static bool
_handle_reply(LSHandle *sh, _TokenList *tokens, _LSTransportMessage *msg,
              _ServerInfo *server_info)
{
    //DBusHandlerResult result = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    bool ret = true;

    int i;
    int len = tokens->len;
    for (i = 0; i < len; i++)
    {
        LSMessageToken token =
            g_array_index(tokens, LSMessageToken, i);

        _Call *call = _CallAcquire(sh->callmap, token);

        if (!call)
        {
            continue;
        }

        ResetCallTimeout(call);

        if (call->callback)
        {
            LSMessage *reply = _LSMessageNewRef(msg, sh);

            // translate non-jsonized bus messages here...
            _LSMessageTranslateFromCall(call, reply, server_info);

            if (!reply->ignore)
            {
                PMTRACE_CLIENT_CALLBACK(sh->name, call->serviceName, call->methodName, token);

                struct timespec current_time, gap_time;
                if (DEBUG_TRACING)
                {
                    ClockGetTime(&current_time);
                    ClockDiff(&gap_time, &current_time, &call->time);
                    LOG_LS_DEBUG("TYPE=method call response time | TIME=%ld | FROM=%s | TO=%s",
                              ClockGetMs(&gap_time), sh->name, call->serviceName);
                }
                ret = call->callback(sh, reply, call->ctx);
                if (DEBUG_TRACING)
                {
                    ClockGetTime(&current_time);
                    ClockDiff(&gap_time, &current_time, &call->time);
                    LOG_LS_DEBUG("TYPE=client handler execution time | TIME=%ld", ClockGetMs(&gap_time));
                }

                if (!ret)
                {
                    // TODO handle false == DBUS_HANDLER_RESULT_NEED_MEMORY
                }
            }

            if (reply->serviceDownMessage)
            {
                _CallRemove(sh, sh->callmap, call);
            }
            else if (call->single && !reply->ignore /* NOV-88761 */)
            {
                _CallRemove(sh, sh->callmap, call);
            }

            LSMessageUnref(reply);
        }

        _CallRelease(call);
    }

    return ret;
}

/* TODO: we should try to integrate this with the non-dbus version of
 * _LSMessageTranslateFromCall */
void
_LSHandleMessageFailure(LSMessageToken global_token, _LSTransportMessageFailureType failure_type, void *context)
{
    LSHandle *sh = (LSHandle*) context;

    /* acquire call */
    _Call *call = _CallAcquire(sh->callmap, global_token);

    if (!call)
    {
        LOG_LS_DEBUG("_CallAcquire failed");
        return;
    }

    /* assert that call is a method call type */
    if (call->callback)
    {
        LSMessage *reply = _LSMessageNewRef(_LSTransportMessageEmpty(), sh);

        /* We will only be calling this on messages that are method calls */
        LS_ASSERT(call->type == CALL_TYPE_METHOD_CALL);

        reply->responseToken = call->token;

        /* construct the error message -- the allocated payload is freed
         * when the message ref count goes to 0 */
        switch (failure_type)
        {

        case _LSTransportMessageFailureTypeNotProcessed:
            reply->category = LUNABUS_ERROR_CATEGORY;
            reply->method = LUNABUS_ERROR_SERVICE_DOWN;
            reply->payloadAllocated = g_strdup_printf(
                "{\"returnValue\":false,"
                 "\"errorCode\":-1,"
                 "\"errorText\":\"Message not processed.\"}");
            reply->payload = reply->payloadAllocated;
            break;

        case _LSTransportMessageFailureTypeUnknown:
            reply->category = LUNABUS_ERROR_CATEGORY;
            reply->method = LUNABUS_ERROR_SERVICE_DOWN;
            reply->payloadAllocated = g_strdup_printf(
                "{\"returnValue\":false,"
                 "\"errorCode\":-1,"
                 "\"errorText\":\"Message status unknown.\"}");
            reply->payload = reply->payloadAllocated;
            break;

        case _LSTransportMessageFailureTypeServiceUnavailable:
            reply->category = LUNABUS_ERROR_CATEGORY;
            reply->method = LUNABUS_ERROR_SERVICE_DOWN;
            reply->payloadAllocated = g_strdup_printf(
                "{\"serviceName\":\"%s\","
                 "\"returnValue\":false,"
                 "\"errorCode\":-1,"
                 "\"errorText\":\"%s is not running.\"}",
                call->serviceName, call->serviceName);
            reply->payload = reply->payloadAllocated;

            /* probably not necessary, since this is just a flag to mark
             * that we should remove this call from the callmap and we
             * always do that here */
            reply->serviceDownMessage = true;

            break;

        case _LSTransportMessageFailureTypePermissionDenied:
            reply->category = LUNABUS_ERROR_CATEGORY;
            reply->method = LUNABUS_ERROR_PERMISSION_DENIED;
            reply->payloadAllocated = g_strdup_printf(
                "{\"returnValue\":false,"
                 "\"errorCode\":-1,"
                 "\"errorText\":\"Not permitted to send to %s.\"}",
                 call->serviceName);
            reply->payload = reply->payloadAllocated;
            break;

        case _LSTransportMessageFailureTypeServiceNotExist:
            reply->category = LUNABUS_ERROR_CATEGORY;
            reply->method = LUNABUS_ERROR_SERVICE_NOT_EXIST;
            reply->payloadAllocated = g_strdup_printf(
                "{\"returnValue\":false,"
                 "\"errorCode\":-1,"
                 "\"errorText\":\"Service does not exist: %s.\"}",
                 call->serviceName);
            reply->payload = reply->payloadAllocated;
            break;

        case _LSTransportMessageFailureTypeMessageContentError:
            reply->category = LUNABUS_ERROR_CATEGORY;
            reply->method = LUNABUS_ERROR_BAD_MESSAGE;
            reply->payloadAllocated = g_strdup_printf(
                "{\"returnValue\":false,"
                 "\"errorCode\":-1,"
                 "\"errorText\":\"Badly formatted message\"}");
            reply->payload = reply->payloadAllocated;
            break;

        default:
            LOG_LS_ERROR(MSGID_LS_UNKNOWN_FAILURE, 1,
                         PMLOGKFV("FLR_TYPE", "%d", failure_type),
                         "Unknown failure_type: %d", failure_type);
            LS_ASSERT(0);
        }

        bool ret = call->callback(sh, reply, call->ctx);
        if (!ret)
        {
            // TODO handle false
        }

        _CallRemove(sh, sh->callmap, call);

        LSMessageUnref(reply);
    }

    _CallRelease(call);
}

void _send_not_running(LSHandle *sh, _TokenList *tokens)
{
    int token_list_len = _TokenListLen(tokens);
    int i;

    for (i = 0; i < token_list_len; i++)
    {
        LSMessageToken token = g_array_index(tokens, LSMessageToken, i);

        _Call *call = _CallAcquire(sh->callmap, token);

        if (!call)
        {
            LOG_LS_ERROR(MSGID_LS_NO_TOKEN, 0,
                         "%s: Expected to find call with token: %lu in callmap", __func__, (unsigned long)token);
            continue;
        }

        if (call->type == CALL_TYPE_METHOD_CALL)
        {
            if (call->callback)
            {
                LSMessage *reply = _LSMessageNewRef(_LSTransportMessageEmpty(), sh);

                reply->responseToken = call->token;

                reply->category = LUNABUS_ERROR_CATEGORY;
                reply->method = LUNABUS_ERROR_SERVICE_DOWN;

                reply->payloadAllocated = g_strdup_printf(
                    "{\"serviceName\":\"%s\","
                     "\"returnValue\":false,"
                     "\"errorCode\":-1,"
                     "\"errorText\":\"%s is not running.\"}",
                    call->serviceName, call->serviceName);

                reply->payload = reply->payloadAllocated;

                // fprintf(stderr, "%s: doing callback\n", __func__);

                bool ret = call->callback(sh, reply, call->ctx);

                if (!ret)
                {
                    fprintf(stderr, "%s: callback failed\n", __func__);
                }

                LSMessageUnref(reply);
            }

            _CallRemove(sh, sh->callmap, call);

        }

       _CallRelease(call);

    } // for
}

void
_LSDisconnectHandler(_LSTransportClient *client, _LSTransportDisconnectType type, void *context)
{

    LSHandle *sh = (LSHandle *)context;
    _CallMap *map = sh->callmap;

    /* The peer has disconnected, so if there're calls waiting for replies,
     * they should be terminated. Note, that the disconnect handler may
     * be called for either connection initiator or the connection acceptor.
     * The callmap contains the INITIATED calls.
     */
    if (NULL != client->service_name && client->initiator)
    {

        _CallMapLock(map);

        _TokenList *tokens = g_hash_table_lookup(map->serviceMap, client->service_name);

        // copy the list of tokens so we can unlock ASAP
        _TokenList *tokens_copy = _TokenListNew();
        _TokenListAddList(tokens_copy, tokens);

        _CallMapUnlock(map);

        _send_not_running(sh, tokens_copy);
        _TokenListFree(tokens_copy);
    }
    else
    {
        if (NULL != client->unique_name)
        {
            /* Remove client subscriptions from the catalog
             */
            _LSCatalogRemoveClientSubscriptions(sh->catalog, client);
        }
        else
        {
            LOG_LS_WARNING(MSGID_LS_NULL_CLIENT, 0,
                           "Client disconnected before sending client info");
        }
    }
}

/* SERVER_STATUS */
static void
_parse_service_status_signal(_LSTransportMessage *msg, _ServerInfo *server_info)
{
    _LSTransportMessageType type = _LSTransportMessageGetType(msg);

    if (type == _LSTransportMessageTypeServiceDownSignal)
    {
        server_info->ServiceStatusChanged = true;
        server_info->serviceName = LSTransportServiceStatusSignalGetServiceName(msg);
        server_info->connected = false;
    }
    else if (type == _LSTransportMessageTypeServiceUpSignal)
    {
        LOG_LS_DEBUG("ServiceUpSignal");
        server_info->ServiceStatusChanged = true;
        server_info->serviceName = LSTransportServiceStatusSignalGetServiceName(msg);
        server_info->connected = true;
    }
    else
    {
        server_info->ServiceStatusChanged = false;
        server_info->serviceName = NULL;
        server_info->connected = false;
    }
}

/**
* @brief Find all tokens that handle this signal message.
*
* @param  map
* @param  msg
* @param  tokens
*/
static void
_get_signal_tokens(_CallMap *map, _LSTransportMessage *msg, _TokenList *tokens,
                   _ServerInfo *server_info)
{
    const char *category = _LSTransportMessageGetCategory(msg);
    const char *method = _LSTransportMessageGetMethod(msg);

    char *category_key = g_strdup_printf("%s", category);
    char *method_key = g_strdup_printf("%s/%s", category, method);

    _CallMapLock(map);

    _TokenList *category_matches = g_hash_table_lookup(
                    map->signalMap, category_key);
    _TokenList *method_matches = g_hash_table_lookup(
                    map->signalMap, method_key);

    if (server_info->ServiceStatusChanged)
    {
        _TokenList *service_matches =
            g_hash_table_lookup(map->serviceMap,
                                server_info->serviceName);
        _TokenListAddList(tokens, service_matches);
    }

    _TokenListAddList(tokens, category_matches);
    _TokenListAddList(tokens, method_matches);

    _CallMapUnlock(map);

    g_free(category_key);
    g_free(method_key);
}

static void
_get_reply_tokens(_CallMap *map, _LSTransportMessage *msg, _TokenList *tokens)
{
    LSMessageToken tok = _LSTransportMessageGetReplyToken(msg);
    _TokenListAdd(tokens, tok);
}

static void
_get_first_field_tokens(_CallMap *callmap, _LSTransportMessage *msg, _TokenList *tokens)
{
    _LSTransportMessageIter iter;
    _LSTransportMessageIterInit(msg, &iter);
    LSMessageToken tok;
    _Static_assert(sizeof(tok) <= sizeof(int64_t), "LSMessageToken should fit into int64_t");
    _LSTransportMessageGetInt64(&iter, (int64_t *) &tok);
    _TokenListAdd(tokens, tok);
}

void
_MessageFindTokens(_CallMap *callmap, _LSTransportMessage *msg,
                   _ServerInfo *server_info, _TokenList *tokens)
{
    _LSTransportMessageType message_type = _LSTransportMessageGetType(msg);

    /* SERVER_STATUS */
    _parse_service_status_signal(msg, server_info);

    switch (message_type)
    {
    case _LSTransportMessageTypeSignal:
    case _LSTransportMessageTypeServiceDownSignal:
    case _LSTransportMessageTypeServiceUpSignal:
        _get_signal_tokens(callmap, msg, tokens, server_info);
        break;
    case _LSTransportMessageTypeReply:
    case _LSTransportMessageTypeQueryServiceStatusReply:
    case _LSTransportMessageTypeError:
    case _LSTransportMessageTypeErrorUnknownMethod:
        _get_reply_tokens(callmap, msg, tokens);
        break;
    case _LSTransportMessageTypeQueryServiceCategoryReply:
        _get_first_field_tokens(callmap, msg, tokens);
        break;
    case _LSTransportMessageTypeMethodCall:
    case _LSTransportMessageTypeCancelMethodCall:
        /* FIXME <tdh> This is here for the java custom mainloop, which
         * calls this function for all types of messages */
        break;
    default:
        LOG_LS_ERROR(MSGID_LS_UNHANDLED_MSG, 1,
                     PMLOGKFV("MSG_TYPE", "%d", message_type),
                     "Unhandled message type: %d", message_type);
        break;
    }
}

/**
* @brief Incoming messages are filtered and dispatched to callbacks.
*
* @param  conn
* @param  msg
* @param  ctx
*
* @retval
*/
bool
_LSHandleReply(LSHandle *sh, _LSTransportMessage *transport_msg)
{
    LS_ASSERT(sh != NULL);
    LS_ASSERT(transport_msg != NULL);

    /* FIXME -- Need to call sh->disconnect_handler(sh, sh->disconnect_handler_data); if the service is disconnected */

    bool ret = true;
    _CallMap   *callmap = sh->callmap;
    _TokenList *tokens = _TokenListNew();

    /* Find tokens that handle this message. */

    _ServerInfo server_info;
    memset(&server_info, 0, sizeof(server_info));

    /* Parse the message and find all tokens. */
    _MessageFindTokens(callmap, transport_msg, &server_info, tokens);

    /* logging */
    LSDebugLogIncoming("", transport_msg);

    /* Dispatch message to callbacks referenced by tokens. */
    if (_TokenListLen(tokens) > 0)
    {
        ret = _handle_reply(sh, tokens, transport_msg, &server_info);
    }

    _TokenListFree(tokens);

    /* serviceName may have been allocated in _MessageFindTokens's call to
     * _parse_name_owner_changed */
    g_free(server_info.serviceName);

    return ret;
}

static char *
_json_get_string(jvalue_ref object, const char *label)
{
    raw_buffer string_buf = jstring_get_fast(
        jobject_get(object, j_cstr_to_buffer(label))
    );
    return g_strndup(string_buf.m_str, string_buf.m_len);
}

/*
 * TODO: rename this function. It kind of made sense in the dbus-based world,
 * but doesn't really anymore.
 */
static bool
_send_match(LSHandle        *sh,
             _Uri           *luri,
             const char     *payload,
             LSFilterFunc    callback,
             void           *ctx,
             _Call        **ret_call,
             LSError        *lserror)
{
    JSchemaInfo schemaInfo;
    jschema_info_init(&schemaInfo, jschema_all(), NULL, NULL);

    char *rule = NULL;
    jvalue_ref object = jdom_parse(j_cstr_to_buffer(payload), DOMOPT_NOOPT,
                                   &schemaInfo);
    LSMessageToken token;
    bool retVal = false;
    char *key = NULL;

    char *category = NULL;
    char *method = NULL;

    if (jis_null(object))
    {
        _LSErrorSet(lserror, MSGID_LS_INVALID_JSON, -EINVAL, "Invalid signal/addmatch payload");
        goto error;
    }

    category = _json_get_string(object, "category");
    method = _json_get_string(object, "method");

    retVal = LSTransportRegisterSignal(sh->transport, category, method, &token, lserror);
    if (!retVal) goto error;

    if (category && method)
    {
        key = g_strdup_printf("%s/%s", category, method);
    }
    else if (category)
    {
        key = g_strdup_printf("%s", category);
    }

    _Call *call = _CallNew(sh, CALL_TYPE_SIGNAL, luri->serviceName, callback, ctx, token, method);

    //call->rule = g_strdup(rule);
    call->signal_category = category;
    call->signal_method = method;
    call->match_key = g_strdup(key);

    /* release ownership over method and category (moved to call structure) */
    category = NULL;
    method = NULL;

    if (ret_call)
    {
        *ret_call = call;
    }

error:
    j_release(&object);

    g_free(key);
    g_free(rule);
    g_free(category);
    g_free(method);
    return retVal;
}

static bool
_send_reg_server_status(LSHandle *sh,
             _Uri           *luri,
             const char     *payload,
             LSFilterFunc    callback,
             void           *ctx,
             _Call        **ret_call,
             LSError *lserror)
{
    JSchemaInfo schemaInfo;
    jschema_info_init(&schemaInfo, jschema_all(), NULL, NULL);

    bool retVal = false;
    LSMessageToken token;

    jvalue_ref object = jdom_parse(j_cstr_to_buffer(payload), DOMOPT_NOOPT,
                                   &schemaInfo);
    do {
        if (jis_null(object))
        {
            _LSErrorSet(lserror, MSGID_LS_INVALID_JSON, -1, "Malformed json.");
            break;
        }

        jvalue_ref child = jobject_get(object, J_CSTR_TO_BUF("serviceName"));

        raw_buffer serviceNameBuf = jstring_get_fast(child);

        if (!serviceNameBuf.m_str)
        {
            _LSErrorSet(lserror, MSGID_LS_INVALID_PAYLOAD, -1, "Invalid payload.");
            break;
        }

        LOCAL_CSTR_FROM_BUF(serviceName, serviceNameBuf);

        retVal = LSTransportSendQueryServiceStatus(sh->transport, serviceName,
                                                   &token, lserror);
        if (!retVal)
        {
            _LSErrorSet(lserror, MSGID_LS_SEND_ERROR, -1, "Could not send QueryServiceStatus.");
            break;
        }

        _Call *call = _CallNew(sh, CALL_TYPE_SIGNAL_SERVER_STATUS,
            serviceName, callback, ctx, token, luri ? luri->methodName : NULL);
        if (!call)
        {
            _LSErrorSet(lserror, MSGID_LS_OOM_ERR, -ENOMEM, "Out of memory");
            break;
        }

        if (ret_call)
        {
            *ret_call = call;
        }

        retVal = true;

    } while(0);
    j_release(&object);

    return retVal;
}

static bool
_send_reg_service_category(LSHandle     *sh,
                           _Uri         *luri,
                           const char   *payload,
                           LSFilterFunc callback,
                           void         *ctx,
                           _Call        **ret_call,
                           LSError      *lserror)
{
    /* Register watch for service category changes.
     *
     * For a specific category: {"serviceName": "com.palm.A", "category": "/category1"}
     * For every category: {"serviceName": "com.palm.A"}
     */

    JSchemaInfo schemaInfo;
    jschema_info_init(&schemaInfo, jschema_all(), NULL, NULL);

    bool retVal = false;
    LSMessageToken token;
    char *signal_category = NULL;

    jvalue_ref object = jdom_parse(j_cstr_to_buffer(payload), DOMOPT_NOOPT,
                                   &schemaInfo);
    do {
        if (!jis_valid(object))
        {
            _LSErrorSet(lserror, MSGID_LS_INVALID_JSON, -1, "Malformed json.");
            break;
        }

        // "serviceName"
        jvalue_ref child = jobject_get(object, J_CSTR_TO_BUF("serviceName"));

        raw_buffer service_name_buf = jstring_get_fast(child);

        if (!service_name_buf.m_str)
        {
            _LSErrorSet(lserror, MSGID_LS_INVALID_PAYLOAD, -1, "Invalid payload. Missing \"serviceName\".");
            break;
        }

        LOCAL_CSTR_FROM_BUF(service_name, service_name_buf);

        // "category"
        jvalue_ref category_val = NULL;
        if (jobject_get_exists(object, J_CSTR_TO_BUF("category"), &category_val))
        {
            raw_buffer category_buf = jstring_get_fast(category_val);
            LOCAL_CSTR_FROM_BUF(category, category_buf);

            if (category[0] != '/')
            {
                _LSErrorSet(lserror, MSGID_LS_INVALID_PAYLOAD, -1,
                            "Invalid payload. \"category\" should begin with /.");
                break;
            }

            signal_category = g_strdup_printf(LUNABUS_WATCH_CATEGORY_CATEGORY "/%s%s",
                                              service_name, category);
            retVal = LSTransportSendQueryServiceCategory(sh->transport, service_name, category,
                                                         &token, lserror);
        }
        else
        {
            signal_category = g_strdup_printf(LUNABUS_WATCH_CATEGORY_CATEGORY "/%s", service_name);
            retVal = LSTransportSendQueryServiceCategory(sh->transport, service_name, NULL,
                                                         &token, lserror);
        }

        if (!retVal)
        {
            _LSErrorSet(lserror, MSGID_LS_SEND_ERROR, -1, "Could not send QueryServiceCategory.");
            break;
        }

        _Call *call = _CallNew(sh, CALL_TYPE_SIGNAL,
                               service_name, callback, ctx, token, NULL);

        call->match_key = g_strdup(signal_category);
        call->signal_category = signal_category; signal_category = NULL;

        if (ret_call)
        {
            *ret_call = call;
        }

        retVal = true;

    } while(0);

    g_free(signal_category);
    j_release(&object);

    return retVal;
}


static bool
_send_method_call(LSHandle *sh,
             _Uri       *luri,
             const char *payload,
             const char *applicationID,
             LSFilterFunc    callback,
             void           *ctx,
             _Call         **ret_call,
             LSError *lserror)
{
    bool retVal;
    LSMessageToken token;

    PMTRACE_CLIENT_PREPARE(sh->name, luri->serviceName, luri->methodName);

    retVal = LSTransportSend(sh->transport, luri->serviceName, luri->objectPath, luri->methodName, payload, applicationID, &token, lserror);
    if (!retVal)
    {
        goto error;
    }

    PMTRACE_CLIENT_CALL(sh->name, luri->serviceName, luri->methodName, token);

    if (callback)
    {
        _Call *call = _CallNew(sh, CALL_TYPE_METHOD_CALL, luri->serviceName, callback, ctx, token, luri->methodName);

        if (ret_call)
        {
            *ret_call = call;
        }
    }

error:
    return retVal;
}

static bool
_cancel_method_call(LSHandle *sh, _Call *call, LSError *lserror)
{
    if (DEBUG_TRACING)
    {
        LOG_LS_DEBUG("TX: %s \"%s\" token <<%ld>>", __FUNCTION__, call->serviceName, call->token);
    }

    // palm://com.hhahha.haha/com/palm/luna/private/cancel {"token":17}

    return LSTransportCancelMethodCall(sh->transport, call->serviceName, call->token, lserror);
}

static bool
_cancel_signal(LSHandle *sh, _Call *call, LSError *lserror)
{
    if (DEBUG_TRACING)
    {
        LOG_LS_DEBUG("TX: %s token <<%ld>>", __FUNCTION__, call->token);
    }

    /* SIGNAL */
    if ((call->signal_category != NULL) || (call->signal_method != NULL))
    {
        if (!LSTransportUnregisterSignal(sh->transport, call->signal_category, call->signal_method, NULL, lserror))
        {
            return false;
        }
    }
    return true;
}

static bool
_LSSignalSendCommon(LSHandle *sh, const char *uri, const char *payload,
             bool typecheck, LSError *lserror)
{
    _Uri *luri;

    LSHANDLE_VALIDATE(sh);

    luri = _UriParse(uri, lserror);
    if (!luri)
    {
        return false;
    }

    bool retVal = false;

    if (unlikely(_ls_enable_utf8_validation))
    {
        if (!g_utf8_validate (payload, -1, NULL))
        {
            _LSErrorSet(lserror, MSGID_LS_INVALID_PAYLOAD, -EINVAL, "%s: payload is not utf-8",
                        __FUNCTION__);
            return false;
        }
    }

    if (unlikely(!payload || (strcmp(payload, "") == 0)))
    {
        _LSErrorSet(lserror, MSGID_LS_INVALID_PAYLOAD, -EINVAL, "Empty payload is not valid JSON. Use {}");
        return false;
    }

    if (typecheck)
    {
        /* typecheck the signal, warn if we haven't done a
         * LSRegisterCategory() with the the same signal name.
         */
        LSCategoryTable *table;
        table = (LSCategoryTable*)
            g_hash_table_lookup(sh->tableHandlers, luri->objectPath);
        if (!table || !g_hash_table_lookup(table->signals, luri->methodName))
        {
            LOG_LS_WARNING(MSGID_LS_SIGNAL_NOT_REGISTERED, 1,
                           PMLOGKS("URI", uri),
                           "%s: Warning: you did not register signal %s via "
                           "LSRegisterCategory().", __FUNCTION__, uri);
        }
    }

    retVal = LSTransportSendSignal(sh->transport, luri->objectPath, luri->methodName, payload, lserror);

    _UriFree(luri);

    return retVal;
}
/* @} END OF LunaServiceClientInternals */

/**
 * @addtogroup LunaServiceClient
 * @{
 */

/**
* @brief Sends payload to service at the specified uri.
*
* @param  sh
* @param  uri      - e.g. "palm://com.domain.reverse/method_name"
* @param  payload  - some string, usually following json object semantics.
* @param  callback  - function callback to be called when responses arrive.
* @param  ctx        - user data to be passed to callback
* @param  ret_token  - token which identifies responses to this call
* @param  lserror
*
* Special signals usage:
*
* Register for any ServerStatus signals:
*
* LSCall(sh, "palm://com.palm.bus/signal/registerServerStatus",
*            "{\"serviceName\":\"com.palm.telephony\"}", callback, ctx, lserror);
*
* Register for any signals from (category, method):
*
* LSCall(sh, "palm://com.palm.bus/signal/addmatch",
*            "{\"category\": \"/com/palm/bluetooth/gap\","
*            " \"method\":\"radioon\"}", callback, ctx, lserror);
*
* Register for any signals from category:
*
* LSCall(sh, "palm://com.palm.bus/signal/addmatch",
*            "{\"category\": \"/com/palm/bluetooth/gap\"}",
*            callback, ctx, lserror);
*
* @retval true on success.
*/
bool
LSCall(LSHandle *sh, const char *uri, const char *payload,
       LSFilterFunc callback, void *ctx,
       LSMessageToken *ret_token, LSError *lserror)
{
    return _LSCallFromApplicationCommon(sh, uri, payload, NULL, /*AppID*/
                callback, ctx, ret_token, false, lserror);
}

/**
* @brief Sends a message to service like LSCall() except it only
*        expects one response and does not need to be cancelled
*        via LSCallCancel().
*
* @param  sh
* @param  uri
* @param  payload
* @param  callback
* @param  ctx
* @param  ret_token
* @param  lserror
*
* @retval
*/
bool
LSCallOneReply(LSHandle *sh, const char *uri, const char *payload,
       LSFilterFunc callback, void *ctx,
       LSMessageToken *ret_token, LSError *lserror)
{
    return _LSCallFromApplicationCommon(sh, uri, payload, NULL, /*AppID*/
                callback, ctx, ret_token, true, lserror);
}


/**
* @brief Special LSCall() that sends an applicationID.
*
* See LSCall().
*
* @param  sh
* @param  uri
* @param  payload
* @param  applicationID
* @param  callback
* @param  ctx
* @param  ret_token
* @param  lserror
*
* @retval
*/
bool
LSCallFromApplication(LSHandle *sh, const char *uri, const char *payload,
       const char *applicationID,
       LSFilterFunc callback, void *ctx,
       LSMessageToken *ret_token, LSError *lserror)
{
    return _LSCallFromApplicationCommon(sh, uri, payload, applicationID,
                callback, ctx, ret_token, false, lserror);
}

/**
 *******************************************************************************
 * @brief Special LSCallOneReply() that sends an applicationID.
 *
 * See LSCallOneReply().
 *
 * @param  sh
 * @param  uri
 * @param  payload
 * @param  applicationID
 * @param  callback
 * @param  ctx
 * @param  ret_token
 * @param  lserror
 *
 * @retval
 *******************************************************************************
 */
bool
LSCallFromApplicationOneReply(
       LSHandle *sh, const char *uri, const char *payload,
       const char *applicationID,
       LSFilterFunc callback, void *ctx,
       LSMessageToken *ret_token, LSError *lserror)
{
    return _LSCallFromApplicationCommon(sh, uri, payload, applicationID,
                callback, ctx, ret_token, true, lserror);
}

static bool
_LSCallFromApplicationCommon(LSHandle *sh, const char *uri,
       const char *payload,
       const char *applicationID,
       LSFilterFunc callback, void *ctx,
       LSMessageToken *ret_token, bool single, LSError *lserror)
{
    _LSErrorIfFail(sh != NULL, lserror, MSGID_LS_INVALID_HANDLE);
    _LSErrorIfFail(uri != NULL, lserror, MSGID_LS_INVALID_URI);
    _LSErrorIfFail(payload != NULL, lserror, MSGID_LS_INVALID_PAYLOAD);

    if (applicationID && !_LSTransportGetPrivileged(sh->transport))
    {
        _LSErrorSet(lserror, MSGID_LS_PRIVILEDGES_ERROR, LS_ERROR_CODE_NOT_PRIVILEGED, LS_ERROR_TEXT_NOT_PRIVILEGED, applicationID);
        return false;
    }

    LSHANDLE_VALIDATE(sh);

    _Call *call = NULL;
    _Uri *luri = NULL;
    bool retVal;

    if (!g_str_has_prefix(uri, LUNA_PREFIX) &&
        !g_str_has_prefix(uri, LUNA_OLD_PREFIX)) /* TODO: we need to get rid of this */
    {
        _LSErrorSet(lserror, MSGID_LS_INVALID_URI, -EINVAL,
                "%s: Invalid syntax for uri", __FUNCTION__);
        return false;
    }

    if (unlikely(_ls_enable_utf8_validation))
    {
        if (!g_utf8_validate (payload, -1, NULL))
        {
            _LSErrorSet(lserror, MSGID_LS_INVALID_PAYLOAD, -EINVAL, "%s: payload is not utf-8",
                        __FUNCTION__);
            return false;
        }
    }

    if (unlikely(!payload || (strcmp(payload, "") == 0)))
    {
        _LSErrorSet(lserror, MSGID_LS_INVALID_PAYLOAD, -EINVAL, "Empty payload is not valid JSON. Use {}");
        return false;
    }

    luri = _UriParse(uri, lserror);
    if (!luri)
    {
        return false;
    }

    _CallMap *map = sh->callmap;
    _CallMapLock(map);

    if (strcmp(luri->serviceName, LUNABUS_SERVICE_NAME) == 0 ||
        strcmp(luri->serviceName, LUNABUS_SERVICE_NAME_OLD) == 0)
    {
        if (!callback)
        {
            _LSErrorSet(lserror, MSGID_LS_NO_CALLBACK, -EINVAL,
                            "Invalid parameters to lunabus LSCall.  "
                            "No callback specified.");
            goto error;
        }

        if (strcmp(luri->objectPath, "/signal") == 0)
        {
            // uri == "palm://com.palm.bus/signal/addmatch"
            if (strcmp(luri->methodName, "addmatch") == 0)
            {
                bool ret = _send_match(sh, luri, payload,
                    callback, ctx, &call, lserror);
                if (!ret) goto error;
            }
            // uri == "palm://com.palm.bus/signal/registerServerStatus"
            else if (strcmp(luri->methodName, "registerServerStatus") == 0)
            {
                bool ret = _send_reg_server_status(sh, luri, payload,
                    callback, ctx, &call, lserror);
                if (!ret) goto error;

                ret =  _service_watch_enable(sh, call, lserror);
                if (!ret) goto error;
            }
            // uri == "palm://com.palm.bus/signal/registerServiceCategory"
            else if (strcmp(luri->methodName, "registerServiceCategory") == 0)
            {
                bool ret = _send_reg_service_category(sh, luri, payload,
                                                      callback, ctx, &call, lserror);
                if (!ret) goto error;
            }
            else
            {
                _LSErrorSet(lserror, MSGID_LS_INVALID_METHOD, -EINVAL,
                            "Invalid method %s to lunabus LSCall.",
                            luri->methodName);
                goto error;
            }
        }
        else
        {
            _LSErrorSet(lserror, MSGID_LS_INVALID_CALL, -EINVAL, "Invalid parameters to LSCall.");
            goto error;
        }
    }
    else
    {
        bool ret = _send_method_call(sh, luri, payload,
                            applicationID,
                            callback, ctx, &call, lserror);
        if (!ret) goto error;
    }

    if (ret_token)
    {
        if (call)
            *ret_token = call->token;
        else
            *ret_token = LSMESSAGE_TOKEN_INVALID;
    }

    if (callback)
    {
        if (!call)
        {
            _LSErrorSet(lserror, MSGID_LS_UNKNOWN_FAILURE, -1, "Call is null. we should not be here.");
            goto error;
        }

        retVal = _CallInsert(sh, sh->callmap, call, single, lserror);
        if (!retVal) goto error;

        if (DEBUG_TRACING)
        {
            if (DEBUG_VERBOSE)
            {
                LOG_LS_DEBUG("TX: LCall token <<%ld>> %s %s",
                        call->token, uri, payload);
            }
            else
            {
                ClockGetTime(&call->time);
                LOG_LS_DEBUG("TX: LSCall token <<%ld>> %s", call->token, uri);
            }
        }
    }
    else
    {
        /* LS_ASSERT(!call); */
        if (DEBUG_TRACING)
        {
            LOG_LS_DEBUG("TX: LSCall no token");
        }
    }

    _CallMapUnlock(map);
    _UriFree(luri);
    return true;

error:
    _CallMapUnlock(map);
    _UriFree(luri);
    return false;
}


static gboolean
OnCallTimedOut(_Call *call)
{
    LSError lserror;
    LSErrorInit(&lserror);

    if (!LSCallCancel(call->sh, call->token, &lserror))
    {
        LSErrorFree(&lserror);
    }
    call->timer_source = NULL;
    return FALSE;  /* One-shot timer */
}


static void
ResetCallTimeout(_Call *call)
{
    if (call->timer_source != NULL)
    {
        g_source_destroy(call->timer_source);
        g_source_unref(call->timer_source);
    }

    if (call->timeout_ms > 0)
    {
        _CallAddReference(call);
        call->timer_source = g_timeout_source_new(call->timeout_ms);
        g_source_set_callback(call->timer_source, (GSourceFunc) OnCallTimedOut, call, (GDestroyNotify) _CallRelease);
        (void)g_source_attach(call->timer_source, call->sh->context);
    }
    else
    {
        call->timer_source = NULL;
    }
}

/**
 * @brief Sets timeout for a method call. The call will be canceled if no reply
 *        is received after the timeout_ms milliseconds.
 *
 * @param  sh
 * @param  token
 * @param  timeout_ms
 * @param  lserror
 *
 * @retval
 */
bool
LSCallSetTimeout(LSHandle *sh, LSMessageToken token, int timeout_ms, LSError *lserror)
{
    _LSErrorIfFail(sh != NULL, lserror, MSGID_LS_INVALID_HANDLE);

    if (DEBUG_TRACING)
    {
        g_debug("TX: %s token <<%ld>>", __FUNCTION__, token);
    }

    LSHANDLE_VALIDATE(sh);

    _CallMap *callmap = sh->callmap;

    _Call *call = _CallAcquire(callmap, token);
    if (!call)
    {
        _LSErrorSetNoPrint(lserror, -1, "Could not find call %ld to set timeout.", token);
        return false;
    }

    if (call->type != CALL_TYPE_METHOD_CALL)
    {
        _CallRelease(call);
        _LSErrorSetNoPrint(lserror, -1, "Call %ld isn't a method call.", token);
        return false;
    }
    call->timeout_ms = timeout_ms;

    ResetCallTimeout(call);

    _CallRelease(call);
    return true;
}


/**
* @brief Sends a cancel message to service to end call session and also
*        unregisters any callback associated with call.
*
* @param  sh
* @param  token
* @param  lserror
*
* @retval
*/
bool
LSCallCancel(LSHandle *sh, LSMessageToken token, LSError *lserror)
{
    _LSErrorIfFail(sh != NULL, lserror, MSGID_LS_INVALID_HANDLE);

    if (DEBUG_TRACING)
    {
        LOG_LS_DEBUG("TX: %s token <<%ld>>", __FUNCTION__, token);
    }

    LSHANDLE_VALIDATE(sh);

    bool retVal = false;
    _CallMap *callmap = sh->callmap;

    _Call * call = _CallAcquire(callmap, token); // +1
    if (!call)
    {
        _LSErrorSetNoPrint(lserror, -1, "Could not find call %ld to cancel.", token);
        return false;
    }

    switch (call->type)
    {
    case CALL_TYPE_METHOD_CALL:
        retVal = _cancel_method_call(sh, call, lserror);
        break;
    case CALL_TYPE_SIGNAL:
        retVal = _cancel_signal(sh, call, lserror);
        break;
    case CALL_TYPE_SIGNAL_SERVER_STATUS:

        /* Multiple registrations for the same service are ref-counted on the hub
         * side, so if "registerServerStatus" is called on the same service
         * twice, this will need to be called twice before the watch is truly destroyed */
        retVal = _service_watch_disable(sh, call);
        break;
    }

    _CallRemove(sh, callmap, call);

    _CallRelease(call); // -0

    return retVal;
}

static bool
_ServerStatusHelper(LSHandle *sh, LSMessage *message, void *ctx)
{
    JSchemaInfo schemaInfo;
    jschema_info_init(&schemaInfo, jschema_all(), NULL, NULL);

    const char *payload = LSMessageGetPayload(message);

    jvalue_ref object = jdom_parse(j_cstr_to_buffer(payload), DOMOPT_NOOPT,
                                   &schemaInfo);

    _ServerStatus *server_status = (_ServerStatus*)ctx;
    if (!server_status) goto error;

    if (!jis_null(object))
    {
        bool connected;

        jvalue_ref serviceObj = NULL;
        jvalue_ref connectedObj = NULL;

        if (!jobject_get_exists(object, J_CSTR_TO_BUF("serviceName"),
                                &serviceObj)) goto error;
        if (!jobject_get_exists(object, J_CSTR_TO_BUF("connected"),
                                &connectedObj)) goto error;

        (void)jboolean_get(connectedObj, &connected);/* TODO: handle appropriately */

        if (server_status->callback)
        {
            LOCAL_CSTR_FROM_BUF(serviceName, jstring_get_fast(serviceObj));
            server_status->callback
                (sh, serviceName, connected, server_status->ctx);
        }
    }

error:
    j_release(&object);
    return true;
}

/**
* @brief Register a callback to be called when the server goes up or
*        comes down.  Callback may be called in this context if
*        the server is already up.
*
* @param  sh
* @param  serviceName    service name to monitor for connect/disconnect.
* @param  func
* @param  ctx
* @param  lserror
*
* @deprecated Use LSRegisterServerStatusEx() instead.
*
* @retval
*/
bool
LSRegisterServerStatus(LSHandle *sh, const char *serviceName,
              LSServerStatusFunc func, void *ctx, LSError *lserror)
{
    void *cookie = NULL;
    return LSRegisterServerStatusEx(sh, serviceName, func, ctx,
                                    &cookie, lserror);
}

/**
* @brief Register a callback to be called when the server goes up or
*        comes down.  Callback may be called in this context if
*        the server is already up.
*
* Performs LSCall(sh, "palm://com.palm.bus/signal/registerServerStatus").
*
* @param  sh
* @param  serviceName    service name to monitor for connect/disconnect.
* @param  func
* @param  ctx
* @param  cookie         token to use for to unregister the callback
* @param  lserror
*
* @retval
*/
bool LSRegisterServerStatusEx(LSHandle *sh, const char *serviceName,
                              LSServerStatusFunc func, void *ctx,
                              void **cookie, LSError *lserror)
{
    char    *payload;

    LSHANDLE_VALIDATE(sh);

    payload = g_strdup_printf("{\"serviceName\":\"%s\"}", serviceName);

    _ServerStatus *server_status;
    server_status = g_new0(_ServerStatus, 1);

    server_status->callback = func;
    server_status->ctx = ctx;
    server_status->token = LSMESSAGE_TOKEN_INVALID;

    if (!LSCall(sh,
                "palm://com.palm.bus/signal/registerServerStatus",
                payload, _ServerStatusHelper, server_status,
                &server_status->token, lserror))
    {
        g_free(payload);
        g_free(server_status);
        return false;
    }

    if (cookie)
        *cookie = server_status;

    g_free(payload);
    return true;
}

/**
* @brief Cancel receiving notifications about server status.
*
* If unlikely false is returned, the subscription hasn't been canceled,
* and the associated memory hasn't been freed yet. This can happen if
* the system suffers from low memory.
*
* The call can be repeated until true is returned. Once that happened,
* the value of cookie is invalid, and should not be used.
*
* @param  sh
* @param  cookie         token obtained during registration, can't be NULL
* @param  lserror
*
* @retval
*
* @sa LSRegisterServerStatusEx
*/
bool LSCancelServerStatus(LSHandle *sh, void *cookie, LSError *lserror)
{
    LSHANDLE_VALIDATE(sh);
    LS_ASSERT(cookie != NULL && "A valid cookie from LSRegisterServerStatus() should be passed");

    _ServerStatus *server_status = (_ServerStatus *) cookie;

    if (!LSCallCancel(sh, server_status->token, lserror))
    {
        return false;
    }

    g_free(server_status);
    return true;
}

/* @} END OF LunaServiceClient */

/**
 * @addtogroup LunaServiceSignals
 *
 * @{
 */

/**
* @brief Attach a callback to be called when signal is received.
*
* @param  sh
* @param  serviceName
* @param  category
* @param  method
* @param  filterFunc
* @param  ctx
* @param  lserror
*
* @deprecated Use LSCall() with uri "palm://com.palm.bus/signal/addmatch",
*             and payload "{\"category\": \"/category/name\",\"method\":\"methodName\"}",
*
* @retval
*/
bool
LSSignalCall(LSHandle *sh,
         const char *category, const char *method,
         LSFilterFunc filterFunc, void *ctx,
         LSMessageToken *responseToken,
         LSError *lserror)
{
    bool retVal;
    char *payload;

    LSHANDLE_VALIDATE(sh);

    if (category && method)
    {
        payload  = g_strdup_printf(
            "{\"category\":\"%s\",\"method\":\"%s\"}", category, method);
    }
    else if (category)
    {
        payload  = g_strdup_printf("{\"category\":\"%s\"}", category);
    }
    else
    {
        _LSErrorSet(lserror, MSGID_LS_INVALID_CALL, -EINVAL, "Invalid arguments to %s", __FUNCTION__);
        return false;
    }

    retVal = LSCall(sh, "palm://com.palm.bus/signal/addmatch", payload,
                    filterFunc, ctx, responseToken, lserror);

    g_free(payload);

    return retVal;
}

/**
* @brief Remove callback & match for specific signal.
*
* @param  sh
* @param  serviceName
* @param  category
* @param  methodName
*
* @deprecated Use LSCallCancel() instead.
*
* @retval
*/
bool
LSSignalCallCancel(LSHandle *sh, LSMessageToken token, LSError *lserror)
{
    return LSCallCancel(sh, token, lserror);
}

/**
* @brief Variant of LSSignalSend() that does not attempt to check if the
*        signal is registered via LSRegisterCategory() this should only
*        be used if you don't use LSRegisterCategory()
*        (i.e. JNI implementation)
*
* @param  sh
* @param  uri
* @param  payload
* @param  lserror
*
* @retval
*/
bool
LSSignalSendNoTypecheck(LSHandle *sh, const char *uri, const char *payload,
             LSError *lserror)
{
    return _LSSignalSendCommon(sh, uri, payload, false, lserror);
}

/**
* @brief Send a signal.
*
* @param  sh
* @param  uri
* @param  payload
* @param  lserror
*
* @retval
*/
bool
LSSignalSend(LSHandle *sh, const char *uri, const char *payload,
             LSError *lserror)
{
    return _LSSignalSendCommon(sh, uri, payload, true, lserror);
}

/* @} END OF LunaServiceSignals */


/**
 * @addtogroup LunaServiceClientInternals
 * @{
 */

_LSTransportMessage* LSCustomMessageQueuePop(LSCustomMessageQueue *q);

struct _FetchMessageQueue
{
    _LSTransportMessage *message;
    _TokenList  *tokens;

    _ServerInfo  server_info;

    pthread_mutex_t lock;
};

static void
_FetchMessageQueueFree(_FetchMessageQueue *queue)
{
    if (queue)
    {
        pthread_mutex_destroy(&queue->lock);
        _TokenListFree(queue->tokens);
#ifdef MEMCHECK
        memset(queue, 0xFF, sizeof(_FetchMessageQueue));
#endif
    }

    g_free(queue);
}

static _FetchMessageQueue*
_FetchMessageQueueAlloc()
{
    _FetchMessageQueue *queue = g_new0(_FetchMessageQueue, 1);

    if (pthread_mutex_init(&queue->lock, NULL))
    {
        LOG_LS_ERROR(MSGID_LS_MUTEX_ERR, 0, "Could not initialize mutex.");
        goto error;
    }

    queue->tokens = _TokenListNew();

    return queue;

error:
    _FetchMessageQueueFree(queue);
    return NULL;
}

static void
_FetchMessageQueueLock(_FetchMessageQueue *queue)
{
    LS_ASSERT(pthread_mutex_lock(&queue->lock) == 0);
}

static void
_FetchMessageQueueUnlock(_FetchMessageQueue *queue)
{
    LS_ASSERT(pthread_mutex_unlock(&queue->lock) == 0);
}

/**
* @brief Get the size of the fetch message queue.
*
* @param  sh
*
* @retval
*/
int
_FetchMessageQueueSize(LSHandle *sh)
{
    _FetchMessageQueue *queue = sh->fetch_message_queue;
    if (!queue) return 0;

    int size;

    _FetchMessageQueueLock(queue);
    size = queue->tokens->len;
    _FetchMessageQueueUnlock(queue);

    return size;
}

/**
* @brief Fetch a message.
*
* Checks the fetch message queue for last dispatched message.
*
* If last message has been handled, then query dbus for next message
* to process.
*
* @param  sh
* @param  ret_message
* @param  lserror
*
* @retval
*/
bool
_FetchMessageQueueGet(LSHandle *sh, LSMessage **ret_message, LSError *lserror)
{
    if (!sh->fetch_message_queue)
    {
        sh->fetch_message_queue = _FetchMessageQueueAlloc();
    }

    if (!sh->fetch_message_queue)
    {
        _LSErrorSet(lserror, MSGID_LS_QUEUE_ERROR, -1, "Could not create message queue.");
        return false;
    }

    bool retVal = false;
    _FetchMessageQueue *queue = sh->fetch_message_queue;

    _FetchMessageQueueLock(queue);

    if (!queue->message)
    {
        _TokenListRemoveAll(queue->tokens);

        /* TODO - tdh - double-check ref counting */
        queue->message = LSCustomMessageQueuePop(sh->custom_message_queue);
        if (!queue->message)
        {
            retVal = true;
            goto done_empty;
        }

        LSDebugLogIncoming("", queue->message);

        /* FIXME - tdh - need to call disconnect handler: sh->disconnect_handler(sh, sh->disconnect_handler_data); */

        _MessageFindTokens(sh->callmap, queue->message,
                           &queue->server_info, queue->tokens);
    }

    LSMessage *reply = _LSMessageNewRef(queue->message, sh);

    if (queue->tokens->len > 0)
    {
        LSMessageToken token = g_array_index(queue->tokens, LSMessageToken, 0);

        _Call *call = _CallAcquire(sh->callmap, token);
        if (call)
        {
            _LSMessageTranslateFromCall(call, reply, &queue->server_info);
            _CallRelease(call);
        }

        g_array_remove_index_fast(queue->tokens, 0);
    }

    if (reply->ignore)
    {
        LSMessageUnref(reply);
        *ret_message = NULL;
    }
    else
    {
        *ret_message = reply;
    }

    if (0 == queue->tokens->len)
    {
        if (queue->message)
        {
            _LSTransportMessageUnref(queue->message);
            queue->message = NULL;
        }
    }

    _FetchMessageQueueUnlock(queue);
    return true;

done_empty:
    *ret_message = NULL;

    if (queue->message)
    {
        _LSTransportMessageUnref(queue->message);
        queue->message = NULL;
    }

    _FetchMessageQueueUnlock(queue);
    return retVal;
}

/* @} END OF LunaServiceClientInternals */
