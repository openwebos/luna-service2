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
#include <debug_methods.h>

/* Test data ******************************************************************/

typedef struct TestData
{
    // payload from mocked LSMessageReply
    gchar *lsmessagereply_payload;

    // for mocked LSMessageGetSenderServiceName
    const char *message_sender_service_name;

    // for mocked LSMessageGetSender
    const char *message_sender;
} TestData;

static TestData *test_data = NULL;

static void
test_setup(TestData *fixture, gconstpointer user_data)
{
    test_data = fixture;
}

static void
test_teardown(TestData *fixture, gconstpointer user_data)
{
    g_free(fixture->lsmessagereply_payload);
    fixture->lsmessagereply_payload = NULL;

    test_data = NULL;
}

/* Test cases *****************************************************************/

static void
test_LSPrivateGetSubscriptions(TestData *fixture, gconstpointer user_data)
{
    LSHandle *sh = GINT_TO_POINTER(1);
    LSMessage *msg = GINT_TO_POINTER(2);
    void *ctx = NULL;

    // _LSPrivateGetSubscriptions works only if requested from monitor
    fixture->message_sender_service_name = MONITOR_NAME;

    g_assert(_LSPrivateGetSubscriptions(sh, msg, ctx));
    g_assert_cmpstr(fixture->lsmessagereply_payload, ==, "{\"returnValue\":true,\"subscriptions\":[]}");

    // verify that no reply sent to non-monitor client
    if (g_test_trap_fork(0, G_TEST_TRAP_SILENCE_STDERR))
    {
        g_free(fixture->lsmessagereply_payload);
        fixture->lsmessagereply_payload = NULL;

        fixture->message_sender_service_name = "com.name.service";

        g_assert(_LSPrivateGetSubscriptions(sh, msg, ctx));
        g_assert_cmpstr(fixture->lsmessagereply_payload, ==, NULL);

        exit(0);
    }
    g_test_trap_assert_passed();
}

static void
test_LSPrivateGetMallinfo(TestData *fixture, gconstpointer user_data)
{
    LSHandle *sh = GINT_TO_POINTER(1);
    LSMessage *msg = GINT_TO_POINTER(2);
    void *ctx = NULL;

    // _LSPrivateGetMallinfo works only if requested from monitor
    fixture->message_sender_service_name = MONITOR_NAME;

    g_assert(_LSPrivateGetMallinfo(sh, msg, ctx));
    g_assert(g_str_has_prefix(fixture->lsmessagereply_payload, "{\"returnValue\":true,\"mallinfo\":{"));

    // verify that no reply sent to non-monitor client
    if (g_test_trap_fork(0, G_TEST_TRAP_SILENCE_STDERR))
    {
        g_free(fixture->lsmessagereply_payload);
        fixture->lsmessagereply_payload = NULL;

        fixture->message_sender_service_name = "com.name.service";

        g_assert(_LSPrivateGetMallinfo(sh, msg, ctx));
        g_assert_cmpstr(fixture->lsmessagereply_payload, ==, NULL);

        exit(0);
    }
}

static void
test_LSPrivateDoMallocTrim(TestData *fixture, gconstpointer user_data)
{
    LSHandle *sh = GINT_TO_POINTER(1);
    LSMessage *msg = GINT_TO_POINTER(2);
    void *ctx = NULL;

    g_assert(_LSPrivateDoMallocTrim(sh, msg, ctx));
    g_assert(g_str_has_prefix(fixture->lsmessagereply_payload, "{\"malloc_trim\":1,\"returnValue\":true}") ||
             g_str_has_prefix(fixture->lsmessagereply_payload, "{\"malloc_trim\":0,\"returnValue\":true}"));
}

/* Mocks **********************************************************************/

bool
_LSSubscriptionGetJson(LSHandle *sh, jvalue_ref *ret_obj, LSError *lserror)
{
    *ret_obj = jobject_create();
    jvalue_ref return_value = jboolean_create(true);
    jvalue_ref subscriptions = jarray_create(NULL);
    jobject_put(*ret_obj,
                J_CSTR_TO_JVAL("returnValue"),
                return_value);
    jobject_put(*ret_obj,
                J_CSTR_TO_JVAL("subscriptions"),
                subscriptions);
    return true;
}

bool
LSMessageReply(LSHandle *sh, LSMessage *lsmsg, const char *replyPayload,
                LSError *lserror)
{
    g_free(test_data->lsmessagereply_payload);
    test_data->lsmessagereply_payload = g_strdup(replyPayload);
    return true;
}

const char *
LSMessageGetSenderServiceName(LSMessage *message)
{
    return test_data->message_sender_service_name;
}

const char *
LSMessageGetSender(LSMessage *message)
{
    return test_data->message_sender;
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

    LSTEST_ADD("/luna-service2/LSPrivateGetSubscriptions", test_LSPrivateGetSubscriptions);
    LSTEST_ADD("/luna-service2/LSPrivateGetMallinfo", test_LSPrivateGetMallinfo);
    LSTEST_ADD("/luna-service2/LSPrivateDoMallocTrim", test_LSPrivateDoMallocTrim);

    return g_test_run();
}

