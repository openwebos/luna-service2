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
#include <luna-service2/lunaservice.h>
#include <base.h>
#include <message.h>

/* Test data ******************************************************************/

typedef struct TestData
{
    // for mocked LSTransport* functions
    _LSTransportMessageType transport_message_type;

    LSMessageToken transport_message_reply_token;
    LSMessageToken transport_next_serial;

    const char *transport_message_category;
    const char *transport_message_method;
    const char *transport_message_payload;

    int transport_send_called;
    int transport_send_signal_called;
    int transport_cancel_method_call_called;
    int transport_send_query_service_status_called;
    int transport_register_signal_called;
    int transport_unregister_signal_called;

    bool transport_is_privileged;

    // cached/mocked message for callmap implementation
    LSMessage message;

    // luna service (fake) object handle
    LSHandle sh;

    // call count of test_methodcall_callback
    int methodcall_callback_called;
    // test_methodcall_callback message
    LSMessage *methodcall_reply;

    // call count of test_signalcall_callback
    int signalcall_callback_called;
    // test_signalcall_callback message
    LSMessage *signalcall_reply;

    // call count of test_registerserverstatus_callback
    int register_server_status_callback_called;
    // service name of test_registerserverstatus_callback
    char *registerserverstatus_service_name;
    // service connected flag of test_registerserverstatus_callback
    bool registerserverstatus_connected;
} TestData;

static TestData *test_data = NULL;

static void
test_setup(TestData *fixture, gconstpointer user_data)
{
    test_data = fixture;

    fixture->transport_message_type = _LSTransportMessageTypeUnknown;

    LSError error;
    LSErrorInit(&error);
    _CallMapInit(&fixture->sh, &fixture->sh.callmap, &error);
}

static void
test_teardown(TestData *fixture, gconstpointer user_data)
{
    g_free(fixture->registerserverstatus_service_name);

    _CallMapDeinit(&fixture->sh, fixture->sh.callmap);
    test_data = NULL;
}

static bool
test_methodcall_callback(LSHandle *sh, LSMessage *reply, void *ctx)
{
    test_data->methodcall_reply = reply;
    LSMessageRef(test_data->methodcall_reply);

    ++test_data->methodcall_callback_called;

    return true;
}

static bool
test_signalcall_callback(LSHandle *sh, LSMessage *reply, void *ctx)
{
    test_data->signalcall_reply = reply;
    LSMessageRef(test_data->signalcall_reply);

    ++test_data->signalcall_callback_called;

    return true;
}

static bool
test_registerserverstatus_callback(LSHandle *sh, const char *serviceName, bool connected, void *ctx)
{
    g_free(test_data->registerserverstatus_service_name);

    test_data->registerserverstatus_service_name = g_strdup(serviceName);
    test_data->registerserverstatus_connected = connected;

    ++test_data->register_server_status_callback_called;
    return true;
}

/* Test cases *****************************************************************/

static void
test_CallMapInitAndDeinit(void)
{
    LSError error;
    LSErrorInit(&error);

    LSHandle *sh = GINT_TO_POINTER(1);
    _CallMap *map = NULL;

    if (g_test_trap_fork(0, 0))
    {
        g_assert(_CallMapInit(sh, &map, &error));
        g_assert(NULL != map);
        _CallMapDeinit(sh, map);
        exit(0);
    }
    g_test_trap_assert_passed();
}

// TODO: no _LSHandleMessageFailure declaration available
extern void
_LSHandleMessageFailure(LSMessageToken global_token, _LSTransportMessageFailureType failure_type, void *context);

static void
test_LSHandleMessageFailure(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    struct MessageFailureData
    {
        // failure type to handle
        _LSTransportMessageFailureType failure_type;

        // expected message data for current failure
        const char *category;
        const char *method;
        const char *payload;
    };
    const struct MessageFailureData failures[] = {
        { _LSTransportMessageFailureTypeNotProcessed,
          LUNABUS_ERROR_CATEGORY,
          LUNABUS_ERROR_SERVICE_DOWN,
          "{\"returnValue\":false,\"errorCode\":-1,\"errorText\":\"Message not processed.\"}" },

        { _LSTransportMessageFailureTypeUnknown,
          LUNABUS_ERROR_CATEGORY,
          LUNABUS_ERROR_SERVICE_DOWN,
          "{\"returnValue\":false,\"errorCode\":-1,\"errorText\":\"Message status unknown.\"}" },

        { _LSTransportMessageFailureTypeServiceUnavailable,
          LUNABUS_ERROR_CATEGORY,
          LUNABUS_ERROR_SERVICE_DOWN,
          "{\"serviceName\":\"com.name.service\",\"returnValue\":false,\"errorCode\":-1,\"errorText\":\"com.name.service is not running.\"}" },

        { _LSTransportMessageFailureTypePermissionDenied,
          LUNABUS_ERROR_CATEGORY,
          LUNABUS_ERROR_PERMISSION_DENIED,
          "{\"returnValue\":false,\"errorCode\":-1,\"errorText\":\"Not permitted to send to com.name.service.\"}" },

        { _LSTransportMessageFailureTypeServiceNotExist,
          LUNABUS_ERROR_CATEGORY,
          LUNABUS_ERROR_SERVICE_NOT_EXIST,
          "{\"returnValue\":false,\"errorCode\":-1,\"errorText\":\"Service does not exist: com.name.service.\"}" },

        { _LSTransportMessageFailureTypeMessageContentError,
          LUNABUS_ERROR_CATEGORY,
          LUNABUS_ERROR_BAD_MESSAGE,
          "{\"returnValue\":false,\"errorCode\":-1,\"errorText\":\"Badly formatted message\"}" }
    };

    int i;
    for (i=0; i < sizeof(failures)/sizeof(failures[0]); ++i)
    {
        // append call, receive token
        LSMessageToken token = LSMESSAGE_TOKEN_INVALID;
        g_assert(LSCall(&fixture->sh, "palm://com.name.service/method", "{}", test_methodcall_callback, NULL, &token, &error));
        g_assert_cmpint(token, !=, LSMESSAGE_TOKEN_INVALID);

        fixture->methodcall_callback_called = 0;

        _LSHandleMessageFailure(token, failures[i].failure_type, &fixture->sh);

        // make sure failure message sent once
        g_assert_cmpint(fixture->methodcall_callback_called, ==, 1);

        // and verify message content
        g_assert_cmpstr(fixture->methodcall_reply->category, ==, failures[i].category);
        g_assert_cmpstr(fixture->methodcall_reply->method, ==, failures[i].method);
        g_assert_cmpstr(fixture->methodcall_reply->payload, ==, failures[i].payload);

        g_assert(fixture->methodcall_reply->kindAllocated == NULL);
        g_assert(fixture->methodcall_reply->methodAllocated == NULL);
        g_assert(fixture->methodcall_reply->uniqueTokenAllocated == NULL);

        g_assert_cmpint(fixture->methodcall_reply->ref, ==, 1);
        LSMessageUnref(fixture->methodcall_reply);
    }
}

// TODO: no _LSDisconnectHandler declaration available
extern void
_LSDisconnectHandler(_LSTransportClient *client, _LSTransportDisconnectType type, void *context);

static void
test_LSDisconnectHandler(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    _LSTransportClient client =
    {
        .service_name = "com.name.service",
        .initiator = 1
    };
    _LSTransportDisconnectType type = _LSTransportDisconnectTypeClean;

    // Append method call
    LSMessageToken token = LSMESSAGE_TOKEN_INVALID;
    LSCall(&fixture->sh, "palm://com.name.service/method", "{}", test_methodcall_callback, NULL, &token, &error);

    // com.name.service down
    _LSDisconnectHandler(&client, type, &fixture->sh);

    // disconnect handler should call test_methodcall_callback, with proper disconnect information
    g_assert_cmpint(fixture->methodcall_callback_called, ==, 1);
    g_assert_cmpstr(fixture->methodcall_reply->category, ==, LUNABUS_ERROR_CATEGORY);
    g_assert_cmpstr(fixture->methodcall_reply->method, ==, LUNABUS_ERROR_SERVICE_DOWN);
    g_assert(g_str_has_prefix(fixture->methodcall_reply->payload, "{\"serviceName\":\"com.name.service\""));
    LSMessageUnref(fixture->methodcall_reply);
}

// TODO: no _LSHandleReply declaration available
extern bool
_LSHandleReply(LSHandle *sh, _LSTransportMessage *transport_msg);

static void
test_LSHandleReply(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    // handle signal call (attach callback for signal) reply
    LSMessageToken token = LSMESSAGE_TOKEN_INVALID;
    LSSignalCall(&fixture->sh, "/", "test", test_signalcall_callback, NULL, &token, &error);

    // signal received
    fixture->transport_message_type = _LSTransportMessageTypeSignal;
    fixture->transport_message_category = "/";
    fixture->transport_message_method = "test";
    _LSTransportMessage *msg = GINT_TO_POINTER(2);

    g_assert(_LSHandleReply(&fixture->sh, msg));
    g_assert_cmpint(fixture->signalcall_callback_called, ==, 1);
    LSMessageUnref(fixture->signalcall_reply);

    // reply received
    fixture->transport_message_type = _LSTransportMessageTypeReply;
    fixture->transport_message_reply_token = token;
    fixture->transport_message_payload = "{\"returnValue\":true}";

    g_assert(_LSHandleReply(&fixture->sh, msg));
    g_assert_cmpstr(fixture->signalcall_reply->category, ==, LUNABUS_SIGNAL_CATEGORY);
    g_assert_cmpstr(fixture->signalcall_reply->method, ==, LUNABUS_SIGNAL_REGISTERED);
    g_assert_cmpint(fixture->signalcall_callback_called, ==, 2);
    LSMessageUnref(fixture->signalcall_reply);

    // error received
    fixture->transport_message_type = _LSTransportMessageTypeError;
    fixture->transport_message_payload = "{}";

    g_assert(_LSHandleReply(&fixture->sh, msg));
    g_assert_cmpstr(fixture->signalcall_reply->category, ==, LUNABUS_ERROR_CATEGORY);
    g_assert_cmpstr(fixture->signalcall_reply->method, ==, LUNABUS_ERROR_UNKNOWN_ERROR);
    g_assert_cmpint(fixture->signalcall_callback_called, ==, 3);
    LSMessageUnref(fixture->signalcall_reply);

    // unknown method error received
    fixture->transport_message_type = _LSTransportMessageTypeErrorUnknownMethod;

    g_assert(_LSHandleReply(&fixture->sh, msg));
    g_assert_cmpstr(fixture->signalcall_reply->category, ==, LUNABUS_ERROR_CATEGORY);
    g_assert_cmpstr(fixture->signalcall_reply->method, ==, LUNABUS_ERROR_UNKNOWN_METHOD);
    g_assert_cmpint(fixture->signalcall_callback_called, ==, 4);
    LSMessageUnref(fixture->signalcall_reply);

    LSSignalCallCancel(&fixture->sh, token, &error);

    // handle method call reply

    token = LSMESSAGE_TOKEN_INVALID;
    LSCall(&fixture->sh, "palm://com.name.service/method", "{}", test_methodcall_callback, NULL, &token, &error);

    // service down signal received
    fixture->transport_message_type = _LSTransportMessageTypeServiceDownSignal;
    fixture->transport_message_category = "/";
    fixture->transport_message_method = "test";

    g_assert(_LSHandleReply(&fixture->sh, msg));
    g_assert_cmpstr(fixture->methodcall_reply->category, ==, LUNABUS_ERROR_CATEGORY);
    g_assert_cmpstr(fixture->methodcall_reply->method, ==, LUNABUS_ERROR_SERVICE_DOWN);
    g_assert_cmpint(fixture->methodcall_callback_called, ==, 1);
    LSMessageUnref(fixture->methodcall_reply);

    LSCallCancel(&fixture->sh, token, &error);

    // handle register server status reply

    void *cookie = NULL;
    LSRegisterServerStatusEx(&fixture->sh, "com.name.service", test_registerserverstatus_callback, NULL,
                             &cookie, &error);

    // service down signal received
    fixture->transport_message_type = _LSTransportMessageTypeServiceDownSignal;

    g_assert(_LSHandleReply(&fixture->sh, msg));
    g_assert_cmpint(fixture->register_server_status_callback_called, ==, 1);
    g_assert_cmpstr(fixture->registerserverstatus_service_name, ==, "com.name.service");
    g_assert(!fixture->registerserverstatus_connected);

    g_assert(LSCancelServerStatus(&fixture->sh, cookie, &error));
    LSErrorFree(&error);
}

static void
test_LSCallAndCancel(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    const char *uri = "palm://com.name.service/method";
    const char *payload = "{}";
    LSFilterFunc callback = test_methodcall_callback;
    LSMessageToken token = LSMESSAGE_TOKEN_INVALID;

    g_assert(LSCall(&fixture->sh, uri, payload, callback, GINT_TO_POINTER(1), &token, &error));
    g_assert_cmpint(token, ==, 1);
    g_assert_cmpint(fixture->transport_send_called, ==, 1);

    // cancel call
    g_assert(LSCallCancel(&fixture->sh, token, &error));
    g_assert_cmpint(fixture->transport_cancel_method_call_called, ==, 1);

    // registerServerStatus
    uri = "palm://com.palm.bus/signal/registerServerStatus";
    payload = "{ \"serviceName\": \"com.name.service\" }";
    g_assert_cmpint(fixture->transport_send_query_service_status_called, ==, 0);
    g_assert(LSCall(&fixture->sh, uri, payload, callback, GINT_TO_POINTER(1), &token, &error));
    g_assert_cmpint(token, ==, 2);
    g_assert_cmpint(fixture->transport_send_query_service_status_called, ==, 1);

    g_assert(LSCallCancel(&fixture->sh, token, &error));
    // no cancel method call for registerServerStatus
    g_assert_cmpint(fixture->transport_cancel_method_call_called, ==, 1);
}

static void
test_LSCallOneReply(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    const char *uri = "palm://com.name.service/method";
    const char *payload = "{}";
    LSFilterFunc callback = test_methodcall_callback;
    LSMessageToken token = LSMESSAGE_TOKEN_INVALID;

    g_assert(LSCallOneReply(&fixture->sh, uri, payload, callback, NULL, &token, &error));
    g_assert_cmpint(token, ==, 1);

    LSErrorFree(&error);
}

static void
test_LSCallFromApplication(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);
    const char *uri = "palm://com.name.service/method";
    const char *payload = "{}";
    const char *appid = "0";
    LSFilterFunc callback = test_methodcall_callback;
    LSMessageToken token = LSMESSAGE_TOKEN_INVALID;

    if (g_test_trap_fork(0, G_TEST_TRAP_SILENCE_STDERR))
    {
        // 'call from application; feature is only valid for privileged binaries
        fixture->transport_is_privileged = false;
        g_assert(!LSCallFromApplication(&fixture->sh, uri, payload, appid, callback, NULL, &token, &error));
        exit(0);
    }

    fixture->transport_is_privileged = true;
    g_assert(LSCallFromApplication(&fixture->sh, uri, payload, appid, callback, NULL, &token, &error));

    g_assert_cmpint(token, ==, 1);
    g_assert_cmpint(fixture->transport_send_called, ==, 1);

    g_assert(LSCallCancel(&fixture->sh, token, &error));
    g_assert_cmpint(fixture->transport_cancel_method_call_called, ==, 1);

    LSErrorFree(&error);
}

static void
test_LSCallFromApplicationOneReply(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    const char *uri = "palm://com.name.service/method";
    const char *payload = "{}";
    const char *appid = "com.name.application";
    LSFilterFunc callback = test_methodcall_callback;
    LSMessageToken token = LSMESSAGE_TOKEN_INVALID;

    if (g_test_trap_fork(0, G_TEST_TRAP_SILENCE_STDERR))
    {
        // 'call from application; feature is only valid for privileged binaries
        fixture->transport_is_privileged = false;
        g_assert(!LSCallFromApplicationOneReply(&fixture->sh, uri, payload, appid, callback, NULL, &token, &error));
        exit(0);
    }

    fixture->transport_is_privileged = true;
    g_assert(LSCallFromApplicationOneReply(&fixture->sh, uri, payload, appid, callback, NULL, &token, &error));
    g_assert_cmpint(fixture->transport_send_called, ==, 1);

    LSErrorFree(&error);
}

static void
test_LSRegisterServerStatusAndCancel(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    const char *service_name = "com.name.service";
    LSServerStatusFunc callback = test_registerserverstatus_callback;

    void *cookie = NULL;
    g_assert(LSRegisterServerStatusEx(&fixture->sh, service_name, callback, NULL, &cookie, &error));
    g_assert_cmpint(fixture->transport_send_query_service_status_called, ==, 1);

    g_assert(LSCancelServerStatus(&fixture->sh, cookie, &error));

    LSErrorFree(&error);
}

static void
test_LSSignalCallAndCancel(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    const char *category = "/test";
    const char *method = "activated";
    LSFilterFunc callback = test_signalcall_callback;
    LSMessageToken token = LSMESSAGE_TOKEN_INVALID;

    // Attach callback to signal
    g_assert(LSSignalCall(&fixture->sh, category, method, callback, NULL, &token, &error));
    g_assert_cmpint(token, ==, 1);
    g_assert_cmpint(fixture->transport_register_signal_called, ==, 1);

    // cancel call
    g_assert(LSSignalCallCancel(&fixture->sh, token, &error));
    g_assert_cmpint(fixture->transport_unregister_signal_called, ==, 1);

    LSErrorFree(&error);
}

static void
test_LSSignalSendNoTypecheck(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    const char *uri = "palm://com.name.service/activated";
    const char *payload = "{}";

    g_assert(LSSignalSendNoTypecheck(&fixture->sh, uri, payload, &error));
    g_assert_cmpint(fixture->transport_send_signal_called, ==, 1);

    LSErrorFree(&error);
}

static void
test_LSSignalSend(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    if (g_test_trap_fork(0, G_TEST_TRAP_SILENCE_STDERR))
    {
        const char *uri = "palm://com.name.service/activated";
        const char *payload = "{}";

        g_assert(LSSignalSend(&fixture->sh, uri, payload, &error));
        g_assert_cmpint(fixture->transport_send_signal_called, ==, 1);
        exit(0);
    }
    // no service registered, expecting warning
    g_test_trap_assert_stderr("*Warning: you did not register signal palm://com.name.service/activated via LSRegisterCategory*");
}


static void
IterateMainLoop(int ms)
{
    g_test_timer_start();
    while (true)
    {
        g_main_context_iteration(NULL, FALSE);
        if (g_test_timer_elapsed() * 1000 > ms)
            break;
        g_usleep(500);
    }
}

static void
test_LSCallSetTimeout(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    const char *uri = "palm://com.name.service/whatever";
    const char *payload = "{}";
    LSMessageToken token = LSMESSAGE_TOKEN_INVALID;
    int timeout_ms = 100;
    int delta_t_ms = 20;
    _LSTransportMessage *msg = GINT_TO_POINTER(2);

    // Send method call with timeout_ms
    g_assert(LSCall(&fixture->sh, uri, payload, test_methodcall_callback, NULL,
                    &token, &error));
    g_assert(LSCallSetTimeout(&fixture->sh, token, timeout_ms, &error));

    // Ensure the method isn't canceled after timeout_ms − 20 milliseconds
    IterateMainLoop(timeout_ms - delta_t_ms);
    g_assert_cmpint(fixture->transport_cancel_method_call_called, ==, 0);

    // Send method reply
    fixture->transport_message_type = _LSTransportMessageTypeReply;
    fixture->transport_message_reply_token = token;
    fixture->transport_message_payload = "{\"returnValue\":true}";
    g_assert(_LSHandleReply(&fixture->sh, msg));

    // Ensure the method isn't canceled after timeout_ms − 20 milliseconds
    IterateMainLoop(timeout_ms - delta_t_ms);
    g_assert_cmpint(fixture->transport_cancel_method_call_called, ==, 0);

    // Wait another 40–50 milliseconds
    IterateMainLoop(delta_t_ms * 2);

    // Ensure the call was canceled by the timer
    g_assert_cmpint(fixture->transport_cancel_method_call_called, ==, 1);
    LSMessageUnref(fixture->methodcall_reply);
}

/* Mocks **********************************************************************/

// base.c

void
LSDebugLogIncoming(const char *where, _LSTransportMessage *message)
{
}

void
_lshandle_validate(LSHandle *sh)
{
}

bool LSErrorInit(LSError *error)
{
    return true;
}

bool LSErrorIsSet(LSError *lserror)
{
    return false;
}

bool _LSErrorSetFunc(LSError *lserror,
    const char *file, int line, const char *function,
    int error_code, const char *error_message, ...)
{
    return true;
}

void LSErrorFree(LSError *error)
{
}

// transport.c

bool
LSTransportSend(_LSTransport *transport, const char *service_name,
                const char *category, const char *method,
                const char *payload, const char* applicationId,
                LSMessageToken *token, LSError *lserror)
{
    *token = ++test_data->transport_next_serial;
    ++test_data->transport_send_called;
    return true;
}

bool
LSTransportCancelMethodCall(_LSTransport *transport, const char *service_name, LSMessageToken serial, LSError *lserror)
{
    ++test_data->transport_cancel_method_call_called;
    return true;
}

bool
LSTransportSendQueryServiceStatus(_LSTransport *transport, const char *service_name,
                                  LSMessageToken *serial, LSError *lserror)
{
    *serial = ++test_data->transport_next_serial;
    ++test_data->transport_send_query_service_status_called;
    return true;
}

bool
_LSTransportGetPrivileged(const _LSTransport *transport)
{
    return test_data->transport_is_privileged;
}

// transport_message.c

_LSTransportMessageType
_LSTransportMessageGetType(const _LSTransportMessage *message)
{
    return test_data->transport_message_type;
}

const char *
_LSTransportMessageGetCategory(const _LSTransportMessage *message)
{
    return test_data->transport_message_category;
}

const char *
_LSTransportMessageGetMethod(const _LSTransportMessage *message)
{
    return test_data->transport_message_method;
}

const char *
_LSTransportMessageGetPayload(const _LSTransportMessage *message)
{
    return test_data->transport_message_payload;
}

LSMessageToken
_LSTransportMessageGetReplyToken(const _LSTransportMessage *message)
{
    return test_data->transport_message_reply_token;
}

bool
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

bool
_LSTransportMessageIsErrorType(const _LSTransportMessage *message)
{
    return _LSTransportMessageTypeIsErrorType(_LSTransportMessageGetType(message));
}

const char *
_LSTransportMessageGetError(const _LSTransportMessage *message)
{
    return _LSTransportMessageGetPayload(message);
}

// transport_signal.c

bool
LSTransportRegisterSignal(_LSTransport *transport, const char *category, const char *method,
                           LSMessageToken *token, LSError *lserror)
{
    *token = ++test_data->transport_next_serial;
    ++test_data->transport_register_signal_called;
    return true;
}

bool
LSTransportUnregisterSignal(_LSTransport *transport, const char *category, const char *method,
                           LSMessageToken *token, LSError *lserror)
{
    g_assert(NULL == token);
    ++test_data->transport_unregister_signal_called;
    return true;
}

bool
LSTransportSendSignal(_LSTransport *transport, const char *category, const char *method, const char *payload, LSError *lserror)
{
    ++test_data->transport_send_signal_called;
    return true;
}

bool
LSTransportRegisterSignalServiceStatus(_LSTransport *transport, const char *service_name,  LSMessageToken *token, LSError *lserror)
{
    g_assert(NULL == token);
    return true;
}

bool
LSTransportUnregisterSignalServiceStatus(_LSTransport *transport, const char *service_name,  LSMessageToken *token, LSError *lserror)
{
    g_assert(NULL == token);
    return true;
}

char *
LSTransportServiceStatusSignalGetServiceName(_LSTransportMessage *message)
{
    // caller responsible to free string returned
    return g_strdup("com.name.service");
}

// mainloop.c

_LSTransportMessage *
LSCustomMessageQueuePop(LSCustomMessageQueue *q)
{
    return GINT_TO_POINTER(1);
}

// message.c

LSMessage *
_LSMessageNewRef(_LSTransportMessage *transport_msg, LSHandle *sh)
{
    LSMessage *msg = g_new0(LSMessage, 1);
    msg->transport_msg = transport_msg;
    msg->sh = sh;
    msg->ref = 1;
    return msg;
}

void
LSMessageRef(LSMessage *message)
{
    g_assert(NULL != message);
    g_assert(message->ref > 0);
    ++message->ref;
}

void
LSMessageUnref(LSMessage *message)
{
    if (0 == --message->ref)
    {
        g_free(message->uniqueTokenAllocated);
        g_free(message->kindAllocated);
        g_free(message->methodAllocated);
        g_free(message->payloadAllocated);
        g_free(message);
    }
}

const char *
LSMessageGetPayload(LSMessage *message)
{
    return message->payload;
}


// PmLogLib.h
PmLogErr _PmLogMsgKV(PmLogContext context, PmLogLevel level, unsigned int flags,
                     const char *msgid, size_t kv_count, const char *check_keywords,
                     const char *check_formats, const char *fmt, ...)
{
    va_list args;
    va_start (args, fmt);
    vfprintf (stderr, fmt, args);
    va_end (args);

    putc('\n', stderr);

    return kPmLogErr_None;
}

/* Test suite *****************************************************************/

#define LSTEST_ADD(name, func) \
    g_test_add(name, TestData, NULL, test_setup, func, test_teardown)

int
main(int argc, char *argv[])
{
    g_test_init(&argc, &argv, NULL);

    g_log_set_always_fatal (G_LOG_LEVEL_ERROR);
    g_log_set_fatal_mask ("LunaService", G_LOG_LEVEL_ERROR);

    g_test_add_func("/luna-service2/CallMapInitAndDeinit", test_CallMapInitAndDeinit);

    LSTEST_ADD("/luna-service2/LSHandleMessageFailure", test_LSHandleMessageFailure);
    LSTEST_ADD("/luna-service2/LSDisconnectHandler", test_LSDisconnectHandler);
    LSTEST_ADD("/luna-service2/LSHandleReply", test_LSHandleReply);
    LSTEST_ADD("/luna-service2/LSCallAndCallCancel", test_LSCallAndCancel);
    LSTEST_ADD("/luna-service2/LSCallOneReply", test_LSCallOneReply);
    LSTEST_ADD("/luna-service2/LSCallFromApplication", test_LSCallFromApplication);
    LSTEST_ADD("/luna-service2/LSCallFromApplicationOneReply", test_LSCallFromApplicationOneReply);
    LSTEST_ADD("/luna-service2/LSRegisterServerStatusAndCancel", test_LSRegisterServerStatusAndCancel);
    LSTEST_ADD("/luna-service2/LSSignalCallAndCancel", test_LSSignalCallAndCancel);
    LSTEST_ADD("/luna-service2/LSSignalSendNoTypecheck", test_LSSignalSendNoTypecheck);
    LSTEST_ADD("/luna-service2/LSSignalSend", test_LSSignalSend);
    LSTEST_ADD("/luna-service2/LSCallSetTimeout", test_LSCallSetTimeout);

    return g_test_run();
}

