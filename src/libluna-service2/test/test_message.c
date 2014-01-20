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
#include <glib.h>
#include <message.h>
#include <base.h>

/* Test data ******************************************************************/

typedef struct TestData
{
    // LSTransportMessage mock data

    _LSTransportMessage *transport_msg;
    int transport_msg_ref_call_count;
    const char *transport_msg_method;
    const char *transport_msg_category;
    const char *transport_msg_appid;
    const char *transport_msg_sender;
    const char *transport_msg_sender_service_name;
    LSMessageToken transport_msg_token;
    LSMessageToken transport_msg_response_token;
    _LSTransportMessageType transport_msg_type;
    const char *transport_msg_payload;

    // connection handle for message
    LSHandle *sh;

    // message used for tests
    LSMessage *msg;
} TestData;

static TestData *test_data = NULL;

static void
test_setup(TestData *fixture, gconstpointer user_data)
{
    test_data = fixture;

    fixture->transport_msg = GINT_TO_POINTER(1);
    fixture->transport_msg_ref_call_count = 0;
    fixture->transport_msg_method = NULL;
    fixture->transport_msg_category = NULL;
    fixture->transport_msg_appid = NULL;
    fixture->transport_msg_sender = NULL;
    fixture->transport_msg_sender_service_name = NULL;
    fixture->transport_msg_token = 0;
    fixture->transport_msg_response_token = 0;
    fixture->transport_msg_type = _LSTransportMessageTypeUnknown;
    fixture->transport_msg_payload = NULL;

    fixture->sh = GINT_TO_POINTER(2);

    fixture->msg = _LSMessageNewRef(fixture->transport_msg, fixture->sh);
}

static void
test_teardown(TestData *fixture, gconstpointer user_data)
{
    if (fixture->msg)
        LSMessageUnref(fixture->msg);

    test_data = NULL;
}

/* Test cases *****************************************************************/

static void
test_LSMessage(TestData *fixture, gconstpointer user_data)
{
    LSMessage *msg = fixture->msg;

    g_assert_cmpint(GPOINTER_TO_INT(msg->transport_msg), ==, GPOINTER_TO_INT(fixture->transport_msg));
    g_assert_cmpint(GPOINTER_TO_INT(msg->sh), ==, GPOINTER_TO_INT(fixture->sh));
    g_assert_cmpint(msg->ref, ==, 1);
    g_assert_cmpint(fixture->transport_msg_ref_call_count, ==, 1);

    // test LSMessageGetConnection
    g_assert_cmpint(GPOINTER_TO_INT(LSMessageGetConnection(msg)), ==, 2);

    // test LSMessageRef,LSMessageUnref
    LSMessageRef(msg);
    g_assert_cmpint(msg->ref, ==, 2);
    LSMessageUnref(msg);
    g_assert_cmpint(msg->ref, ==, 1);
    // transport message should exist (message ref count == 1)
    g_assert_cmpint(fixture->transport_msg_ref_call_count, ==, 1);

    LSMessageUnref(msg);

    // _LSTransportMessageUnref through _LSMessageFree (message ref count == 0)
    g_assert_cmpint(fixture->transport_msg_ref_call_count, ==, 0);

    // msg released by unref. Set NULL to prevent double free in test_teardown.
    fixture->msg = NULL;
}

static void
test_LSMessageIsPublic(TestData *fixture, gconstpointer user_data)
{
    LSPalmService palm_service =
    {
        .public_sh = fixture->sh
    };
    // public connection
    g_assert(LSMessageIsPublic(&palm_service, fixture->msg));

    // 'non public' connection
    palm_service.public_sh = GINT_TO_POINTER(GPOINTER_TO_INT(fixture->sh) + 1);
    g_assert(!LSMessageIsPublic(&palm_service, fixture->msg));
}

static void
test_LSMessagePrint(TestData *fixture, gconstpointer user_data)
{
    if (g_test_trap_fork(0, G_TEST_TRAP_SILENCE_STDOUT))
    {
        fixture->msg->category = "a";
        fixture->msg->method = "b";
        fixture->msg->payload = "c";
        LSMessagePrint(fixture->msg, stdout);
        exit(0);
    }
    g_test_trap_assert_stdout("a/b <c>\n");
}

static void
test_LSMessageIsHubErrorMessage(TestData *fixture, gconstpointer user_data)
{
    // NULL category
    g_assert(!LSMessageIsHubErrorMessage(fixture->msg));

    // "random" category
    fixture->msg->category = "a";
    g_assert(!LSMessageIsHubErrorMessage(fixture->msg));

    // "bus error" category
    fixture->msg->category = LUNABUS_ERROR_CATEGORY;
    g_assert(LSMessageIsHubErrorMessage(fixture->msg));
}

static void
test_LSMessageGetMethod(TestData *fixture, gconstpointer user_data)
{
    // NULL method
    g_assert_cmpstr(LSMessageGetMethod(fixture->msg), ==, NULL);
    // valid method
    fixture->msg->method = "a";
    g_assert_cmpstr(LSMessageGetMethod(fixture->msg), ==, "a");
}

static void
test_LSMessageGetApplicationID(TestData *fixture, gconstpointer user_data)
{
    g_assert_cmpstr(NULL, ==, LSMessageGetApplicationID(fixture->msg));

    fixture->transport_msg_appid = "a";
    g_assert_cmpstr(LSMessageGetApplicationID(fixture->msg), ==, "a");

    fixture->transport_msg_appid = "\0";
    g_assert_cmpstr(LSMessageGetApplicationID(fixture->msg), ==, NULL);
}

static void
test_LSMessageGetSender(TestData *fixture, gconstpointer user_data)
{
    g_assert_cmpstr(NULL, ==, LSMessageGetSender(fixture->msg));

    fixture->transport_msg_sender = "a";
    g_assert_cmpstr(LSMessageGetSender(fixture->msg), ==, "a");
}

static void
test_LSMessageGetSenderServiceName(TestData *fixture, gconstpointer user_data)
{
    g_assert_cmpstr(NULL, ==, LSMessageGetSenderServiceName(fixture->msg));

    fixture->transport_msg_sender_service_name = "a";
    g_assert_cmpstr(LSMessageGetSenderServiceName(fixture->msg), ==, "a");
}

static void
test_LSMessageGetToken(TestData *fixture, gconstpointer user_data)
{
    g_assert_cmpint(0, ==, LSMessageGetToken(fixture->msg));

    fixture->transport_msg_token = 1;
    g_assert_cmpint(LSMessageGetToken(fixture->msg), ==, 1);
}

static void
test_LSMessageGetResponseToken(TestData *fixture, gconstpointer user_data)
{
    g_assert_cmpint(0, ==, LSMessageGetResponseToken(fixture->msg));

    fixture->transport_msg_response_token = 1;
    g_assert_cmpint(LSMessageGetResponseToken(fixture->msg), ==, 1);
}

static void
test_LSMessageGetCategory(TestData *fixture, gconstpointer user_data)
{
    g_assert_cmpstr(NULL, ==, LSMessageGetCategory(fixture->msg));

    fixture->transport_msg_category = "a";
    g_assert_cmpstr(LSMessageGetCategory(fixture->msg), ==, "a");
}

static void
test_LSMessageGetPayload(TestData *fixture, gconstpointer user_data)
{
    g_assert_cmpstr(NULL, ==, LSMessageGetPayload(fixture->msg));

    fixture->transport_msg_payload = "a";
    g_assert_cmpstr(LSMessageGetPayload(fixture->msg), ==, "a");
}

static void
test_LSMessageIsSubscription(TestData *fixture, gconstpointer user_data)
{
    fixture->msg->payload = "{\"a\":b}";
    g_assert(!LSMessageIsSubscription(fixture->msg));

    fixture->msg->payload = "{\"subscribe\":true}";
    g_assert(LSMessageIsSubscription(fixture->msg));

    fixture->msg->payload = "{\"subscribe\":false}";
    g_assert(!LSMessageIsSubscription(fixture->msg));

    fixture->msg->payload = "{\"subscribe\":null}";
    g_assert(!LSMessageIsSubscription(fixture->msg));

    fixture->msg->payload = "{\"subscribe\":666}";
    g_assert(!LSMessageIsSubscription(fixture->msg));

    fixture->msg->payload = "{\"subscribe\":\"bad\"}";
    g_assert(!LSMessageIsSubscription(fixture->msg));
}

static void
test_LSMessageRespond(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    g_assert(LSMessageRespond(fixture->msg, "{}", &error));
}

static void
test_LSMessageReply(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    g_assert(LSMessageReply(fixture->sh, fixture->msg, "{}", &error));
}

static void
test_LSMessageGetUniqueToken(TestData *fixture, gconstpointer user_data)
{
    g_assert_cmpstr("(null).0", ==, LSMessageGetUniqueToken(fixture->msg));

    // LSMessageGetKind caches returned string to kindAllocated. free/reset.
    g_free(fixture->msg->uniqueTokenAllocated);
    fixture->msg->uniqueTokenAllocated = NULL;

    fixture->transport_msg_sender = "a";
    fixture->transport_msg_token = 1;
    g_assert_cmpstr(LSMessageGetUniqueToken(fixture->msg), ==, "a.1");
}

static void
test_LSMessageGetKind(TestData *fixture, gconstpointer user_data)
{
    g_assert_cmpstr("", ==, LSMessageGetKind(fixture->msg));

    // LSMessageGetKind caches returned string to kindAllocated. free/reset.
    g_free(fixture->msg->kindAllocated);
    fixture->msg->kindAllocated = NULL;

    fixture->msg->category = "a";
    fixture->msg->method = "b";
    g_assert_cmpstr(LSMessageGetKind(fixture->msg), ==, "a/b");
}

/* Mocks **********************************************************************/

_LSTransportMessage *
_LSTransportMessageRef(_LSTransportMessage *message)
{
    ++test_data->transport_msg_ref_call_count;
    return message;
}

void
_LSTransportMessageUnref(_LSTransportMessage *message)
{
    --test_data->transport_msg_ref_call_count;
}

const char *
_LSTransportMessageGetMethod(const _LSTransportMessage *message)
{
    return test_data->transport_msg_method;
}

const char *
_LSTransportMessageGetCategory(const _LSTransportMessage *message)
{
    return test_data->transport_msg_category;
}

const char *
_LSTransportMessageGetAppId(_LSTransportMessage *message)
{
    return test_data->transport_msg_appid;
}

const char *
_LSTransportMessageGetSenderUniqueName(const _LSTransportMessage *message)
{
    return test_data->transport_msg_sender;
}

const char *
_LSTransportMessageGetPayload(const _LSTransportMessage *message)
{
    return test_data->transport_msg_payload;
}

const char *
_LSTransportMessageGetSenderServiceName(const _LSTransportMessage *message)
{
    return test_data->transport_msg_sender_service_name;
}

LSMessageToken
_LSTransportMessageGetToken(const _LSTransportMessage *message)
{
    return test_data->transport_msg_token;
}

LSMessageToken
_LSTransportMessageGetReplyToken(const _LSTransportMessage *message)
{
    return test_data->transport_msg_response_token;
}

void
_lshandle_validate(LSHandle *sh)
{
}

_LSTransportMessageType
_LSTransportMessageGetType(const _LSTransportMessage *message)
{
    return test_data->transport_msg_type;
}

bool
_LSTransportSendReply(const _LSTransportMessage *message, const char *payload, LSError *lserror)
{
    return true;
}

/* Test suite *****************************************************************/

#define LSTEST_ADD(name, func) \
    g_test_add(name, TestData, NULL, test_setup, func, test_teardown)

int
main(int argc, char *argv[])
{
    g_test_init(&argc, &argv, NULL);

    // do not trap on LSError
    g_log_set_always_fatal(0);

    LSTEST_ADD("/luna-service2/LSMessage", test_LSMessage);
    LSTEST_ADD("/luna-service2/LSMessageIsPublic", test_LSMessageIsPublic);
    LSTEST_ADD("/luna-service2/LSMessagePrint", test_LSMessagePrint);
    LSTEST_ADD("/luna-service2/LSMessageIsHubErrorMessage", test_LSMessageIsHubErrorMessage);
    LSTEST_ADD("/luna-service2/LSMessageGetMethod", test_LSMessageGetMethod);
    LSTEST_ADD("/luna-service2/LSMessageGetApplicationID", test_LSMessageGetApplicationID);
    LSTEST_ADD("/luna-service2/LSMessageGetSender", test_LSMessageGetSender);
    LSTEST_ADD("/luna-service2/LSMessageGetSenderServiceName", test_LSMessageGetSenderServiceName);
    LSTEST_ADD("/luna-service2/LSMessageGetToken", test_LSMessageGetToken);
    LSTEST_ADD("/luna-service2/LSMessageGetResponseToken", test_LSMessageGetResponseToken);
    LSTEST_ADD("/luna-service2/LSMessageGetCategory", test_LSMessageGetCategory);
    LSTEST_ADD("/luna-service2/LSMessageGetPayload", test_LSMessageGetPayload);
    LSTEST_ADD("/luna-service2/LSMessageIsSubscription", test_LSMessageIsSubscription);
    LSTEST_ADD("/luna-service2/LSMessageRespond", test_LSMessageRespond);
    LSTEST_ADD("/luna-service2/LSMessageReply", test_LSMessageReply);
    LSTEST_ADD("/luna-service2/LSMessageGetKind", test_LSMessageGetKind);
    LSTEST_ADD("/luna-service2/LSMessageGetUniqueToken", test_LSMessageGetUniqueToken);

    return g_test_run();
}

