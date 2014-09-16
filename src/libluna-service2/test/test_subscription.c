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
#include <errno.h>
#include <string.h>
#include <pbnjson.h>
#include <luna-service2/lunaservice.h>
#include <subscription.h>
#include <base.h>

/* Test data ******************************************************************/

typedef struct TestData
{
    LSHandle sh;
    LSMessage *message;
    int message_ref_count;
    const char *message_payload;
    const char *message_sender;
    const char *message_service_name;
    const char *message_unique_token;
    LSMessageToken message_token;

    int lscall_call_count;
    char *lscall_uri;
    char *lscall_payload;

    int lsmessagereply_call_count;
    char *lsmessagereply_payload;

    _Catalog *catalog;
} TestData;

static TestData *test_data = NULL;

static void
test_setup(TestData *fixture, gconstpointer user_data)
{
    test_data = fixture;

    memset(&fixture->sh, 0, sizeof(fixture->sh));

    fixture->message = GINT_TO_POINTER(2);
    fixture->message_ref_count = 1;
    fixture->message_payload = NULL;
    fixture->message_sender = "com.name.server.unique";
    fixture->message_payload = NULL;
    fixture->lsmessagereply_payload = NULL;

    fixture->lscall_call_count = 0;
    fixture->lscall_uri = 0;
    fixture->lscall_payload = 0;

    fixture->lsmessagereply_call_count = 0;
    fixture->message_token = 0;

    fixture->message_unique_token = "a.1";
    fixture->message_service_name = "com.name.server";

    fixture->catalog = _CatalogNew(&fixture->sh);
    fixture->sh.catalog = fixture->catalog;

    LSError error;
    LSErrorInit(&error);

    _CallMapInit(&fixture->sh, &fixture->sh.callmap, &error);
}

static void
test_teardown(TestData *fixture, gconstpointer user_data)
{
    g_free(fixture->lscall_uri);
    g_free(fixture->lscall_payload);
    g_free(fixture->lsmessagereply_payload);

    fixture->lscall_uri = NULL;
    fixture->lscall_payload = NULL;
    fixture->lsmessagereply_payload = NULL;

    _CallMapDeinit(&fixture->sh, fixture->sh.callmap);

    _CatalogFree(fixture->catalog);

    test_data = NULL;
}

/* Test cases *****************************************************************/

static void
test_CatalogNewAndFree(void)
{
    LSHandle sh = {0};
    _Catalog *c = _CatalogNew(&sh);
    g_assert(NULL != c);
    _CatalogFree(c);
}

static void
test_LSSubscriptionSetCancelFunction(TestData *fixture, gconstpointer user_data)
{
    g_assert(LSSubscriptionSetCancelFunction(&fixture->sh, GINT_TO_POINTER(1), GINT_TO_POINTER(2), NULL));
}

static void
test_LSSubscriptionAddAndRemove(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    const char *key = "a/b";

    g_assert(LSSubscriptionAdd(&fixture->sh, key, fixture->message, &error));

    LSSubscriptionIter *sub_iter = NULL;
    g_assert(LSSubscriptionAcquire(&fixture->sh, key, &sub_iter, &error));
    g_assert(LSSubscriptionHasNext(sub_iter));

    LSMessage *msg = LSSubscriptionNext(sub_iter);
    g_assert_cmpint(fixture->message_ref_count, ==, 3);
    g_assert(msg == fixture->message);
    LSMessageUnref(msg);
    g_assert(!LSSubscriptionHasNext(sub_iter));

    LSSubscriptionRemove(sub_iter);
    g_assert_cmpint(fixture->message_ref_count, ==, 1);

    LSSubscriptionRelease(sub_iter);
}

static void
test_CatalogHandleCancel(TestData *fixture, gconstpointer user_data)
{
    if (g_test_trap_fork(0, G_TEST_TRAP_SILENCE_STDERR))
    {
        LSError error;
        LSErrorInit(&error);
        fixture->message_payload = "";

        g_assert(!_CatalogHandleCancel(fixture->catalog, fixture->message, &error));
        g_assert(LSErrorIsSet(&error));
        g_assert_cmpstr(error.message, ==, "Invalid json");
        g_assert_cmpint(error.error_code, ==, -EINVAL);
        LSErrorFree(&error);
        exit(0);
    }
    g_test_trap_assert_passed();

    if (g_test_trap_fork(0, G_TEST_TRAP_SILENCE_STDERR))
    {
        LSError error;
        LSErrorInit(&error);
        fixture->message_payload = "{}";

        g_assert(!_CatalogHandleCancel(fixture->catalog, fixture->message, &error));
        g_assert(LSErrorIsSet(&error));
        g_assert_cmpstr(error.message, ==, "Invalid json");
        g_assert_cmpint(error.error_code, ==, -EINVAL);
        LSErrorFree(&error);
        exit(0);
    }
    g_test_trap_assert_passed();

    if (g_test_trap_fork(0, G_TEST_TRAP_SILENCE_STDERR))
    {
        LSError error;
        LSErrorInit(&error);
        fixture->message_payload = "{\"token\":null}";

        g_assert(!_CatalogHandleCancel(fixture->catalog, fixture->message, &error));
        g_assert(LSErrorIsSet(&error));
        g_assert_cmpstr(error.message, ==, "Invalid json");
        g_assert_cmpint(error.error_code, ==, -EINVAL);
        LSErrorFree(&error);
        exit(0);
    }
    g_test_trap_assert_passed();

    if (g_test_trap_fork(0, G_TEST_TRAP_SILENCE_STDERR))
    {
        LSError error;
        LSErrorInit(&error);
        fixture->message_payload = "{\"token\":\"hello\"}";

        g_assert(!_CatalogHandleCancel(fixture->catalog, fixture->message, &error));
        g_assert(LSErrorIsSet(&error));
        g_assert_cmpstr(error.message, ==, "Invalid json");
        g_assert_cmpint(error.error_code, ==, -EINVAL);
        LSErrorFree(&error);
        exit(0);
    }
    g_test_trap_assert_passed();

    LSError error;
    LSErrorInit(&error);
    fixture->message_payload = "{\"token\":1}";

    g_assert(_CatalogHandleCancel(fixture->catalog, fixture->message, &error));
    g_assert(!LSErrorIsSet(&error));
}

static void
test_LSSubscriptionGetJson(TestData *fixture, gconstpointer user_data)
{
    jvalue_ref result = NULL;

    LSError error;
    LSErrorInit(&error);

    const char *key = "a/b";

    LSSubscriptionAdd(&fixture->sh, key, fixture->message, &error);

    g_assert(_LSSubscriptionGetJson(&fixture->sh, &result, &error));

    LSSubscriptionIter *sub_iter = NULL;
    g_assert(LSSubscriptionAcquire(&fixture->sh, key, &sub_iter, &error));
    LSMessage *msg = LSSubscriptionNext(sub_iter);
    LSMessageUnref(msg);
    LSSubscriptionRemove(sub_iter);
    LSSubscriptionRelease(sub_iter);

    const char *result_json = jvalue_tostring_simple(result);
    const char *expected_json =
            "{\"returnValue\":true," \
            "\"subscriptions\":[{\"key\":\"a/b\"," \
            "\"subscribers\":[{\"service_name\":\"com.name.server\",\"unique_name\":\"com.name.server.unique\",\"subscription_message\":\"\"}]" \
            "}]" \
            "}";

    g_assert_cmpstr(result_json, ==, expected_json);

    j_release(&result);
}

static void
test_LSSubscriptionReply(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    const char *key = "a/b";

    LSSubscriptionAdd(&fixture->sh, key, fixture->message, &error);

    const char *payload = "{ \"key\": \"value\" }";

    g_assert(LSSubscriptionReply(&fixture->sh, key, payload, &error));
    g_assert_cmpstr(fixture->lsmessagereply_payload, ==, payload);
    g_assert_cmpint(fixture->lsmessagereply_call_count, ==, 1);

    LSSubscriptionIter *sub_iter = NULL;
    g_assert(LSSubscriptionAcquire(&fixture->sh, key, &sub_iter, &error));
    LSMessage *msg = LSSubscriptionNext(sub_iter);
    LSMessageUnref(msg);
    LSSubscriptionRemove(sub_iter);
    LSSubscriptionRelease(sub_iter);
}

static void
test_LSSubscriptionRespond(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    LSPalmService psh =
    {
        .public_sh = &fixture->sh,
        .private_sh = &fixture->sh
    };

    const char *key = "a/b";

    LSSubscriptionAdd(&fixture->sh, key, fixture->message, &error);

    const char *payload = "{ \"key\": \"value\" }";

    g_assert(LSSubscriptionRespond(&psh, key, payload, &error));
    g_assert_cmpstr(fixture->lsmessagereply_payload, ==, payload);
    g_assert_cmpint(fixture->lsmessagereply_call_count, ==, 2);

    LSSubscriptionIter *sub_iter = NULL;
    g_assert(LSSubscriptionAcquire(&fixture->sh, key, &sub_iter, &error));
    LSMessage *msg = LSSubscriptionNext(sub_iter);
    LSMessageUnref(msg);
    LSSubscriptionRemove(sub_iter);
    LSSubscriptionRelease(sub_iter);
}

static void
test_LSSubscriptionProcess(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    bool subscribed = false;

    // dont subscribe
    fixture->message_payload = "{}";

    g_assert(LSSubscriptionProcess(&fixture->sh, fixture->message, &subscribed, &error));
    g_assert(!subscribed);
    g_assert_cmpint(fixture->lscall_call_count, ==, 0);

    // dont subscribe
    fixture->message_payload = "{\"subscribe\": null}";

    g_assert(LSSubscriptionProcess(&fixture->sh, fixture->message, &subscribed, &error));
    g_assert(!subscribed);
    g_assert_cmpint(fixture->lscall_call_count, ==, 0);

    // dont subscribe
    fixture->message_payload = "{\"subscribe\": 1}";

    g_assert(LSSubscriptionProcess(&fixture->sh, fixture->message, &subscribed, &error));
    g_assert(!subscribed);
    g_assert_cmpint(fixture->lscall_call_count, ==, 0);

    // dont subscribe
    fixture->message_payload = "{\"subscribe\": false}";

    g_assert(LSSubscriptionProcess(&fixture->sh, fixture->message, &subscribed, &error));
    g_assert(!subscribed);
    g_assert_cmpint(fixture->lscall_call_count, ==, 0);

    // subscribe
    fixture->message_payload = "{\"subscribe\": true}";

    g_assert(LSSubscriptionProcess(&fixture->sh, fixture->message, &subscribed, &error));
    g_assert(subscribed);
}

static void
test_LSSubscriptionPost(TestData *fixture, gconstpointer user_data)
{
    const char *category = "a";
    const char *method = "b";
    const char *payload = "{}";
    LSError error;
    LSErrorInit(&error);

    // post with no subscriptions
    g_assert(LSSubscriptionPost(&fixture->sh, category, method, payload, &error));
    g_assert_cmpint(fixture->lsmessagereply_call_count, ==, 0);

    // post with valid subscription
    const char *key = "a/b";
    g_assert(LSSubscriptionAdd(&fixture->sh, key, fixture->message, &error));
    g_assert(LSSubscriptionPost(&fixture->sh, category, method, payload, &error));
    g_assert_cmpint(fixture->lsmessagereply_call_count, ==, 1);
    g_assert_cmpstr(fixture->lsmessagereply_payload, ==, "{}");

    LSSubscriptionIter *sub_iter = NULL;
    g_assert(LSSubscriptionAcquire(&fixture->sh, key, &sub_iter, &error));
    LSMessage *msg = LSSubscriptionNext(sub_iter);
    LSMessageUnref(msg);
    LSSubscriptionRemove(sub_iter);
    LSSubscriptionRelease(sub_iter);
}

/* Mocks **********************************************************************/

const char *
LSMessageGetPayload(LSMessage *message)
{
    return test_data->message_payload;
}

const char *
LSMessageGetSender(LSMessage *message)
{
    return test_data->message_sender;
}

const char *
LSMessageGetSenderServiceName(LSMessage *message)
{
    return test_data->message_service_name;
}

const char *
LSMessageGetUniqueToken(LSMessage *message)
{
    return test_data->message_unique_token;
}

const char *
LSMessageGetKind(LSMessage *message)
{
    return "a/b";
}

void
LSMessageRef(LSMessage *message)
{
    ++test_data->message_ref_count;
}

void
LSMessageUnref(LSMessage *message)
{
    --test_data->message_ref_count;
}

LSMessageToken
LSMessageGetToken(LSMessage *message)
{
    return test_data->message_token;
}

bool
LSCall(LSHandle *sh, const char *uri, const char *payload,
       LSFilterFunc callback, void *ctx,
       LSMessageToken *ret_token, LSError *lserror)
{
    ++test_data->lscall_call_count;
    g_free(test_data->lscall_uri);
    g_free(test_data->lscall_payload);
    test_data->lscall_uri = g_strdup(uri);
    test_data->lscall_payload = g_strdup(payload);
    return true;
}

bool
LSMessageReply(LSHandle *sh, LSMessage *lsmsg, const char *replyPayload,
                LSError *lserror)
{
    ++test_data->lsmessagereply_call_count;
    g_free(test_data->lsmessagereply_payload);
    test_data->lsmessagereply_payload = g_strdup(replyPayload);
    return true;
}

void
_lshandle_validate(LSHandle *sh)
{
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

    g_test_add_func("/luna-service2/CatalogNewAndFree", test_CatalogNewAndFree);

    LSTEST_ADD("/luna-service2/LSSubscriptionSetCancelFunction", test_LSSubscriptionSetCancelFunction);
    LSTEST_ADD("/luna-service2/LSSubscriptionAddAndRemove", test_LSSubscriptionAddAndRemove);
    LSTEST_ADD("/luna-service2/LSSubscriptionGetJson", test_LSSubscriptionGetJson);
    LSTEST_ADD("/luna-service2/LSSubscriptionReply", test_LSSubscriptionReply);
    LSTEST_ADD("/luna-service2/LSSubscriptionRespond", test_LSSubscriptionRespond);
    LSTEST_ADD("/luna-service2/CatalogHandleCancel", test_CatalogHandleCancel);
    LSTEST_ADD("/luna-service2/LSSubscriptionProcess", test_LSSubscriptionProcess);
    LSTEST_ADD("/luna-service2/LSSubscriptionPost", test_LSSubscriptionPost);

    return g_test_run();
}

