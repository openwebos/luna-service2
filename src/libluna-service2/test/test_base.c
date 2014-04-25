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


#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <base.h>
#include <category.h>

/* Test data ******************************************************************/

typedef struct TestData
{
    // payload from mocked LSMessageReply
    gchar *lsmessagereply_payload;

    // transport handlers copied in _LSTransportInit
    LSTransportHandlers transport_handlers;

    // for mocked LSTransport* functions
    _LSTransportMessageType transportmessage_type;
    int transportmessage_reply_token;
    const char *transportmessage_category;
    const char *transportmessage_method;
    const char *transportmessage_payload;
    const char *transportmessage_service_name;
    const char *transportmessage_sender_unique_name;

    // payload from mocked LSMessageGetCategory
    const char *message_category;
    // payload from mocked LSMessageGetMethod
    const char *message_method;

    // call count of mocked LSHandleReply
    int lshandlereply_called;

    // call count of mocked LSPrivateGetSubscriptions
    int lsprivategetsubscriptions_called;
    // call count of mocked LSPrivateGetMallocInfo
    int lsprivategetmallocinfo_called;
    // call count of mocked LSPrivateDoMallocTrim
    int lsprivatedomalloctrim_called;
} TestData;

static TestData *test_data = NULL;

static void
test_setup(TestData *fixture, gconstpointer user_data)
{
    test_data = fixture;

    fixture->transportmessage_reply_token = 0;
    fixture->transportmessage_service_name = "com.name.service";
    fixture->transportmessage_sender_unique_name = "com.name.service.0";
    fixture->transportmessage_payload = "{}";
}

static void
test_teardown(TestData *fixture, gconstpointer user_data)
{
    g_free(fixture->lsmessagereply_payload);
    fixture->lsmessagereply_payload = NULL;

    test_data = NULL;
}

// PmLogLib.h
PmLogErr _PmLogMsgKV(PmLogContext context, PmLogLevel level, unsigned int flags,
                     const char *msgid, size_t kv_count, const char *check_keywords,
                     const char *check_formats, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    putc('\n', stderr);

    return kPmLogErr_None;
}

/* Test cases *****************************************************************/

static void
test_LSErrorInit(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    g_assert(!LSErrorIsSet(&error));
}

static void
test_LSErrorSet(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);
    _LSErrorSetNoPrint(&error, LS_ERROR_CODE_UNKNOWN_ERROR, LS_ERROR_TEXT_UNKNOWN_ERROR);

    g_assert(LSErrorIsSet(&error));

    g_assert_cmpint(error.error_code, ==, LS_ERROR_CODE_UNKNOWN_ERROR);
    g_assert_cmpstr(error.message, ==, LS_ERROR_TEXT_UNKNOWN_ERROR);

    LSErrorFree(&error);
}

static void
test_LSErrorFree(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);
    _LSErrorSetNoPrint(&error, LS_ERROR_CODE_UNKNOWN_ERROR, LS_ERROR_TEXT_UNKNOWN_ERROR);
    LSErrorFree(&error);

    g_assert(!LSErrorIsSet(&error));
}

static void
test_LSErrorPrint(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);
    _LSErrorSetNoPrint(&error, LS_ERROR_CODE_UNKNOWN_ERROR, LS_ERROR_TEXT_UNKNOWN_ERROR);

    if (g_test_trap_fork(0, G_TEST_TRAP_SILENCE_STDERR))
    {
        LSErrorPrint(&error, stderr);
        exit(0);
    }
    gchar *expected_stderr = g_strdup_printf("LUNASERVICE ERROR %d: %s (%s @ %s:%d)\n",
             error.error_code, error.message, error.func, error.file, error.line);
    g_test_trap_assert_stderr(expected_stderr);
    g_free(expected_stderr);

    if (g_test_trap_fork(0, G_TEST_TRAP_SILENCE_STDERR))
    {
        LSErrorPrint(NULL, stderr);
        exit(0);
    }
    g_test_trap_assert_stderr("LUNASERVICE ERROR: lserror is NULL. Did you pass in a LSError?");

    LSErrorFree(&error);
}

static void
test_LSErrorLog(TestData *fixture, gconstpointer user_data)
{
    LSError lserror;
    LSErrorInit(&lserror);
    _LSErrorSetNoPrint(&lserror, LS_ERROR_CODE_UNKNOWN_ERROR, LS_ERROR_TEXT_UNKNOWN_ERROR);

    if (g_test_trap_fork(0, G_TEST_TRAP_SILENCE_STDERR))
    {
        LOG_LSERROR("LS_TEST_ERROR", &lserror);
        exit(0);
    }
    gchar *expected_stderr = g_strdup_printf("{\"ERROR_CODE\":%d,\"ERROR\":\"%s\",\"FUNC\":\"%s\",\"FILE\":\"%s\",\"LINE\":%d"
                                             "} LUNASERVICE ERROR\n",
                                             lserror.error_code, lserror.message, lserror.func, lserror.file, lserror.line);
    g_test_trap_assert_stderr(expected_stderr);
    g_free(expected_stderr);

    if (g_test_trap_fork(0, G_TEST_TRAP_SILENCE_STDERR))
    {
        LOG_LSERROR("LS_TEST_ERROR", NULL);
        exit(0);
    }
    g_test_trap_assert_stderr("lserror is NULL. Did you pass in a LSError?\n");

    LSErrorFree(&lserror);
}

static void
test_LSErrorSetFunc(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    const char *file = __FILE__;
    const int line = __LINE__;
    const char *func = __FUNCTION__;
    const int error_code = LS_ERROR_CODE_UNKNOWN_ERROR;

    g_assert(_LSErrorSetFunc(&error, file, line, func, error_code, LS_ERROR_TEXT_OOM));
    g_assert_cmpstr(error.file, ==, file);
    g_assert_cmpint(error.line, ==, line);
    g_assert_cmpstr(error.func, ==, func);
    g_assert_cmpint(error.error_code, ==, error_code);
    g_assert_cmpstr(error.message, ==, LS_ERROR_TEXT_OOM);

    // error already set, should not touch given error, but just return true
    g_assert(_LSErrorSetFunc(&error, "file", 0, "func", LS_ERROR_CODE_UNKNOWN_ERROR, "msg"));
    g_assert_cmpstr(error.file, ==, file);
    g_assert_cmpint(error.line, ==, line);
    g_assert_cmpstr(error.func, ==, func);
    g_assert_cmpint(error.error_code, ==, error_code);
    g_assert_cmpstr(error.message, ==, LS_ERROR_TEXT_OOM);

    LSErrorFree(&error);

    // NULL error case (should return true)
    g_assert(_LSErrorSetFunc(NULL, file, line, func, error_code, LS_ERROR_TEXT_OOM));
}

static void
test_LSErrorSetFromErrnoFunc(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    const char *file = __FILE__;
    const int line = __LINE__;
    const char *func = __FUNCTION__;
    const int error_code = LS_ERROR_CODE_UNKNOWN_ERROR;

    g_assert(_LSErrorSetFromErrnoFunc(&error, file, line, func, error_code));
    g_assert_cmpstr(error.file, ==, file);
    g_assert_cmpint(error.line, ==, line);
    g_assert_cmpstr(error.func, ==, func);
    g_assert_cmpint(error.error_code, ==, error_code);

    LSErrorFree(&error);
}

static void
test_LSDebugLogIncoming(TestData *fixture, gconstpointer user_data)
{
    const char *expected_stdout = "RX: where token <<0>> sender: com.name.service sender_unique: com.name.service.0\n";
    const char *expected_verbose_stdout = "RX: where token <<0>> sender: com.name.service sender_unique: com.name.service.0 payload: {}\n";

    setenv("G_MESSAGES_DEBUG", "all", 1);

    PmLogSetContextLevel(PmLogGetLibContext(), kPmLogLevel_Debug);

    if (g_test_trap_fork(0, G_TEST_TRAP_SILENCE_STDERR))
    {
        LSDebugLogIncoming("where", GINT_TO_POINTER(1));
        exit(0);
    }
    g_test_trap_assert_stderr_unmatched(expected_stdout);

    // enable DEBUG_TRACING
    _ls_debug_tracing = 1;

    if (g_test_trap_fork(0, G_TEST_TRAP_SILENCE_STDERR))
    {
        LSDebugLogIncoming("where", GINT_TO_POINTER(1));
        exit(0);
    }
    g_test_trap_assert_stderr(expected_stdout);

    // enable DEBUG_VERBOSE
    _ls_debug_tracing = 2;

    if (g_test_trap_fork(0, G_TEST_TRAP_SILENCE_STDERR))
    {
        LSDebugLogIncoming("where", GINT_TO_POINTER(1));
        exit(0);
    }
    g_test_trap_assert_stderr(expected_verbose_stdout);

    _ls_debug_tracing = 0;
}

static void
test_LSRegisterAndUnregister(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    LSHandle *sh = NULL;

    if (g_test_trap_fork(0, G_TEST_TRAP_SILENCE_STDERR))
    {
        setenv("LS_DEBUG", "2", 1);
        setenv("LS_ENABLE_UTF8", "2", 1);

        LSRegister("com.name.service", &sh, &error);
        g_assert_cmpint(_ls_debug_tracing, ==, 2);
        g_assert(_ls_enable_utf8_validation == true);
        LSUnregister(sh, &error);
        exit(0);
    }
    g_test_trap_assert_stderr("Log mode enabled to level 2\nEnable UTF8 validation on payloads\n");
    g_test_trap_assert_passed();

    g_assert(LSRegister("com.name.service", &sh, &error));
    g_assert(NULL != sh);
    g_assert(!LSErrorIsSet(&error));
    g_assert_cmpstr(LSHandleGetName(sh), ==, "com.name.service");
    g_assert(LSUnregister(sh, &error));
    g_assert(!LSErrorIsSet(&error));

    g_assert(LSRegisterPubPriv("com.name.service", &sh, true, &error));
    g_assert(NULL != sh);
    g_assert(!LSErrorIsSet(&error));
    g_assert(LSUnregister(sh, &error));
    g_assert(!LSErrorIsSet(&error));

    g_assert(LSRegisterPubPriv("com.name.service", &sh, false, &error));
    g_assert(NULL != sh);
    g_assert(!LSErrorIsSet(&error));

    if (g_test_trap_fork(0, G_TEST_TRAP_SILENCE_STDERR))
    {
        sh->history.magic_state_num = 0;
        _lshandle_validate(sh);
        exit(0);
    }
    // _lshandle_validate calls assert which aborts only in debug build
#ifdef NDEBUG
    g_test_trap_assert_passed();
#else
    g_test_trap_assert_failed();
#endif
    g_test_trap_assert_stderr("*Invalid LSHandle*");

    g_assert(LSUnregister(sh, &error));
    g_assert(!LSErrorIsSet(&error));
}

static void
test_FetchMessageQueueGet(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    LSHandle *sh = NULL;
    LSRegister("com.name.service", &sh, &error);

    LSMessage *msg = NULL;
    g_assert(_FetchMessageQueueGet(sh, &msg, &error));
    // no message in queue
    g_assert(NULL == msg);

    LSUnregister(sh, &error);
}

static void
test_LSSetDisconnectHandler(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    LSHandle *sh = NULL;

    LSRegister("com.name.service", &sh, &error);

    g_assert(LSSetDisconnectHandler(sh, GINT_TO_POINTER(1), GINT_TO_POINTER(2), &error));
    g_assert(sh->disconnect_handler == GINT_TO_POINTER(1));
    g_assert(sh->disconnect_handler_data == GINT_TO_POINTER(2));

    LSUnregister(sh, &error);

    if (g_test_trap_fork(0, G_TEST_TRAP_SILENCE_STDERR))
    {
        g_assert(!LSSetDisconnectHandler(NULL, GINT_TO_POINTER(1), GINT_TO_POINTER(2), &error));
        LSErrorFree(&error);
        exit(0);
    }
    g_test_trap_assert_passed();
}

static void
test_LSHandleGetName(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    LSHandle *sh = NULL;
    g_assert_cmpstr(LSHandleGetName(sh), ==, NULL);

    LSRegister("com.name.service", &sh, &error);
    g_assert_cmpstr(LSHandleGetName(sh), ==, "com.name.service");

    LSUnregister(sh, &error);
}

static void
test_LSRegisterAndUnregisterPalmService(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    LSPalmService *psh = NULL;

    g_assert(LSRegisterPalmService("com.name.service", &psh, &error));
    g_assert(NULL != psh);
    g_assert(NULL != psh->public_sh);
    g_assert(LSPalmServiceGetPublicConnection(psh) == psh->public_sh);
    g_assert(LSPalmServiceGetPrivateConnection(psh) == psh->private_sh);
    g_assert(NULL != psh->private_sh);
    g_assert(!LSErrorIsSet(&error));

    g_assert(LSUnregisterPalmService(psh, &error));
    g_assert(!LSErrorIsSet(&error));
}

static void
test_LSRegisterCategory(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    LSHandle *sh = NULL;
    LSRegister("com.service.name", &sh, &error);

    LSMethod methods[] =
    {
        { "test_method", GINT_TO_POINTER(1) },
        { }
    };
    LSSignal signals[] =
    {
        { "test_signal" },
        { }
    };

    g_assert(LSRegisterCategory(sh, "/", methods, signals, NULL, &error));

    LSCategoryTable *table = g_hash_table_lookup(sh->tableHandlers, "/");
    g_assert(NULL != table);
    g_assert(g_hash_table_lookup(table->methods, "test_method"));
    g_assert(g_hash_table_lookup(table->signals, "test_signal"));

    // registering same methods again should fail
    if (g_test_trap_fork(0, G_TEST_TRAP_SILENCE_STDERR))
    {
        g_assert(!LSRegisterCategory(sh, "/", methods, NULL, NULL, &error));
        g_assert(LSErrorIsSet(&error));
        exit(0);
    }
    g_test_trap_assert_passed();
    g_test_trap_assert_stderr("*Category / already registered.\n");

    LSUnregister(sh, &error);
}

static void
test_LSRegisterCategoryAppend(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    LSHandle *sh = NULL;
    LSRegister("com.service.name", &sh, &error);

    LSMethod methods[] =
    {
        { "test_method", GINT_TO_POINTER(1) },
        { }
    };
    LSSignal signals[] =
    {
        { "test_signal" },
        { }
    };

    // NULL category should be converted to "/"
    g_assert(LSRegisterCategoryAppend(sh, NULL, methods, NULL, &error));

    LSCategoryTable *table = g_hash_table_lookup(sh->tableHandlers, "/");
    g_assert(NULL != table);
    g_assert(g_hash_table_lookup(table->methods, "test_method"));

    // reregistering same category should not replace existing methods
    g_assert(LSRegisterCategoryAppend(sh, "/", NULL, signals, &error));

    table = g_hash_table_lookup(sh->tableHandlers, "/");
    g_assert(NULL != table);
    g_assert(g_hash_table_lookup(table->methods, "test_method"));
    g_assert(g_hash_table_lookup(table->signals, "test_signal"));

    LSUnregister(sh, &error);
}

static void
test_LSPalmServiceRegisterCategory(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    LSPalmService *psh = NULL;
    LSRegisterPalmService("com.name.service", &psh, &error);

    LSMethod methods[] =
    {
        { "test", GINT_TO_POINTER(1) },
        { }
    };
    g_assert(LSPalmServiceRegisterCategory(psh, "/", methods, methods, NULL, NULL, &error));

    LSUnregisterPalmService(psh, &error);
}

static void
test_LSCategorySetData(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    LSHandle *sh = NULL;
    LSRegister("com.service.name", &sh, &error);

    LSMethod methods[] =
    {
        { "test", GINT_TO_POINTER(1) },
        { }
    };
    LSRegisterCategory(sh, "/", methods, NULL, NULL, &error);

    g_assert(LSCategorySetData(sh, "/", NULL, &error));

    LSUnregister(sh, &error);
}

static void
test_LSPushRole(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    LSHandle *sh = NULL;
    LSRegister("com.name.service", &sh, &error);

    g_assert(LSPushRole(sh, "/path/to/role.json", &error));

    LSUnregister(sh, &error);
}

static void
test_LSPushRolePalmService(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    LSPalmService *psh = NULL;
    LSRegisterPalmService("com.name.service", &psh, &error);

    g_assert(LSPushRolePalmService(psh, "/path/to/role.json", &error));

    // pushing to NULL service should fail
    if (g_test_trap_fork(0, G_TEST_TRAP_SILENCE_STDERR))
    {
        g_assert(!LSPushRolePalmService(NULL, "/path/to/role.json", &error));
        g_assert(LSErrorIsSet(&error));
        exit(0);
    }
    g_test_trap_assert_passed();

    g_assert(LSUnregisterPalmService(psh, &error));
}

static void
test_serviceDefaultMethods(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    LSHandle *sh = NULL;
    LSRegister("com.name.service", &sh, &error);

    LSCategoryTable *table = g_hash_table_lookup(sh->tableHandlers, "/com/palm/luna/private");
    g_assert(NULL != table);
    g_assert(NULL != table->methods);
    g_assert_cmpint(g_hash_table_size(table->methods), ==, 6);
    LSMethodEntry *cancel = g_hash_table_lookup(table->methods, "cancel");
    LSMethodEntry *ping = g_hash_table_lookup(table->methods, "ping");
    LSMethodEntry *subscriptions = g_hash_table_lookup(table->methods, "subscriptions");
    LSMethodEntry *mallinfo = g_hash_table_lookup(table->methods, "mallinfo");
    LSMethodEntry *malloc_trim = g_hash_table_lookup(table->methods, "malloc_trim");
    LSMethodEntry *introspection = g_hash_table_lookup(table->methods, "introspection");
    g_assert(NULL != cancel);
    g_assert(NULL != ping);
    g_assert(NULL != subscriptions);
    g_assert(NULL != mallinfo);
    g_assert(NULL != malloc_trim);
    g_assert(NULL != introspection);

    LSMessage *msg = GINT_TO_POINTER(1);

    // test cancel
    g_assert(cancel->function(sh, msg, NULL));

    // test ping
    g_assert(ping->function(sh, msg, NULL));
    g_assert_cmpstr(fixture->lsmessagereply_payload, ==, "{\"returnValue\":true}");

    // test subscriptions, verify that _LSPrivateGetSubscriptions called (mocked)
    // NOTE: work only when requested from monitor
    fixture->transportmessage_service_name = MONITOR_NAME;
    g_assert(subscriptions->function(sh, msg, NULL));
    g_assert_cmpint(fixture->lsprivategetsubscriptions_called, ==, 1);

    // test mallinfo, verify that _LSPrivateGetMallinfo called (mocked)
    g_assert(mallinfo->function(sh, msg, NULL));
    g_assert_cmpint(fixture->lsprivategetmallocinfo_called, ==, 1);

    // test malloc_trim, verify that _LSPrivateDoMallocTrim called (mocked)
    g_assert(malloc_trim->function(sh, msg, NULL));
    g_assert_cmpint(fixture->lsprivatedomalloctrim_called, ==, 1);

    // test message handlers
    fixture->transportmessage_type = _LSTransportMessageTypeMethodCall;
    fixture->message_category = "/com/palm/luna/private";
    fixture->message_method = "ping";

    // build a semi-valid transport message
    _LSTransportClient dummy_client = {
        .service_name = "dummy",
    };
    _LSTransportMessage dummy_transport_msg = {
        .client = &dummy_client,
    };

    g_assert(NULL != fixture->transport_handlers.msg_handler);
    g_assert_cmpint(fixture->transport_handlers.msg_handler(&dummy_transport_msg, sh), ==, LSMessageHandlerResultHandled);
    g_assert_cmpstr(fixture->lsmessagereply_payload, ==, "{\"returnValue\":true}");
    g_assert_cmpint(fixture->lshandlereply_called, ==, 0);

    fixture->transportmessage_type = _LSTransportMessageTypeSignal;
    g_assert_cmpint(fixture->transport_handlers.msg_handler(&dummy_transport_msg, sh), ==, LSMessageHandlerResultHandled);
    g_assert_cmpint(fixture->lshandlereply_called, ==, 1);

    LSUnregister(sh, &error);
}

/* Mocks **********************************************************************/

// subscription.c

_Catalog *
_CatalogNew(LSHandle *sh)
{
    return GINT_TO_POINTER(1);
}

void
_CatalogFree(_Catalog *catalog)
{
}

bool
_CatalogHandleCancel(_Catalog *catalog, LSMessage *cancelMsg,
                     LSError *lserror)
{
    return true;
}

// callmap.c

bool
_CallMapInit(LSHandle *sh, _CallMap **ret_map, LSError *lserror)
{
    *ret_map = GINT_TO_POINTER(1);
    return true;
}

void
_CallMapDeinit(LSHandle *sh, _CallMap *map)
{
}

void
_CallMapLock(_CallMap *map)
{
}

bool
_FetchMessageQueueGet(LSHandle *sh, LSMessage **ret_message, LSError *lserror)
{
    *ret_message = NULL;
    return true;
}

// mainloop.c

LSCustomMessageQueue*
LSCustomMessageQueueNew(void)
{
    return GINT_TO_POINTER(1);
}

void
LSCustomMessageQueueFree(LSCustomMessageQueue *q)
{
}

// transport_message.c

LSMessageToken
_LSTransportMessageGetReplyToken(const _LSTransportMessage *message)
{
    return test_data->transportmessage_reply_token;
}

const char*
_LSTransportMessageGetSenderServiceName(const _LSTransportMessage *message)
{
    return test_data->transportmessage_service_name;
}

const char*
_LSTransportMessageGetSenderUniqueName(const _LSTransportMessage *message)
{
    return test_data->transportmessage_sender_unique_name;
}

const char*
_LSTransportMessageGetPayload(const _LSTransportMessage *message)
{
    return test_data->transportmessage_payload;
}

_LSTransportMessageType
_LSTransportMessageGetType(const _LSTransportMessage *message)
{
    return test_data->transportmessage_type;
}

// transport.c

bool
_LSTransportInit(_LSTransport **ret_transport, const char *service_name,
                 LSTransportHandlers *handlers, LSError *lserror)
{
    *ret_transport = GINT_TO_POINTER(1);
    // store handlers for testing
    memcpy(&test_data->transport_handlers, handlers, sizeof(LSTransportHandlers));
    return true;
}

void
_LSTransportDeinit(_LSTransport *transport)
{
}

bool
_LSTransportConnect(_LSTransport *transport, bool local, bool public_bus, LSError *lserror)
{
    return true;
}

bool
_LSTransportAppendCategory(_LSTransport *transport, const char *category, LSMethod *methods, LSError *lserror)
{
    return true;
}

bool
_LSTransportDisconnect(_LSTransport *transport, bool flush_and_send_shutdown)
{
    return true;
}

bool
LSTransportPushRole(_LSTransport *transport, const char *path, LSError *lserror)
{
    return true;
}

// message.c

LSMessage *
_LSMessageNewRef(_LSTransportMessage *transport_msg, LSHandle *sh)
{
    return GINT_TO_POINTER(1);
}

void
LSMessageUnref(LSMessage *message)
{
}

const char *
LSMessageGetCategory(LSMessage *message)
{
    return test_data->message_category;
}

const char *
LSMessageGetMethod(LSMessage *message)
{
    return test_data->message_method;
}

const char *
LSMessageGetSenderServiceName(LSMessage *message)
{
    return _LSTransportMessageGetSenderServiceName(NULL);
}

const char *
LSMessageGetSender(LSMessage *message)
{
    return _LSTransportMessageGetSenderUniqueName(NULL);
}

bool
LSMessageReply(LSHandle *sh, LSMessage *lsmsg, const char *replyPayload,
                LSError *lserror)
{
    g_free(test_data->lsmessagereply_payload);
    test_data->lsmessagereply_payload = g_strdup(replyPayload);
    return true;
}

bool
_LSHandleReply(LSHandle *sh, _LSTransportMessage *transport_msg)
{
    ++test_data->lshandlereply_called;
    return true;
}

// debug_methods.c

bool
_LSPrivateGetSubscriptions(LSHandle* sh, LSMessage *message, void *ctx)
{
    ++test_data->lsprivategetsubscriptions_called;
    return true;
}

bool
_LSPrivateGetMallinfo(LSHandle* sh, LSMessage *message, void *ctx)
{
    ++test_data->lsprivategetmallocinfo_called;
    return true;
}

bool
_LSPrivateDoMallocTrim(LSHandle* sh, LSMessage *message, void *ctx)
{
    ++test_data->lsprivatedomalloctrim_called;
    return true;
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

    LSTEST_ADD("/luna-service2/LSErrorInit", test_LSErrorInit);
    LSTEST_ADD("/luna-service2/LSErrorSet", test_LSErrorSet);
    LSTEST_ADD("/luna-service2/LSErrorFree", test_LSErrorFree);
    LSTEST_ADD("/luna-service2/LSErrorPrint", test_LSErrorPrint);
    LSTEST_ADD("/luna-service2/LSErrorLog", test_LSErrorLog);
    LSTEST_ADD("/luna-service2/LSErrorSetFunc", test_LSErrorSetFunc);
    LSTEST_ADD("/luna-service2/LSErrorSetFromErrnoFunc", test_LSErrorSetFromErrnoFunc);
    LSTEST_ADD("/luna-service2/LSDebugLogIncoming", test_LSDebugLogIncoming);
    LSTEST_ADD("/luna-service2/LSRegisterAndUnregister", test_LSRegisterAndUnregister);
    LSTEST_ADD("/luna-service2/FetchMessageQueueGet", test_FetchMessageQueueGet);
    LSTEST_ADD("/luna-service2/LSSetDisconnectHandler", test_LSSetDisconnectHandler);
    LSTEST_ADD("/luna-service2/LSHandleGetName", test_LSHandleGetName);
    LSTEST_ADD("/luna-service2/LSRegisterAndUnregisterPalmService", test_LSRegisterAndUnregisterPalmService);
    LSTEST_ADD("/luna-service2/LSRegisterCategory", test_LSRegisterCategory);
    LSTEST_ADD("/luna-service2/LSRegisterCategoryAppend", test_LSRegisterCategoryAppend);
    LSTEST_ADD("/luna-service2/LSPalmServiceRegisterCategory", test_LSPalmServiceRegisterCategory);
    LSTEST_ADD("/luna-service2/LSCategorySetData", test_LSCategorySetData);
    LSTEST_ADD("/luna-service2/LSPushRole", test_LSPushRole);
    LSTEST_ADD("/luna-service2/LSPushRolePalmService", test_LSPushRolePalmService);
    LSTEST_ADD("/luna-service2/serviceDefaultMethods", test_serviceDefaultMethods);

    return g_test_run();
}

