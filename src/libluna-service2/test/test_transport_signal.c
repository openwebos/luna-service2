/* @@@LICENSE
*
*      Copyright (c) 2008-2013 LG Electronics, Inc.
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
#include <luna-service2/lunaservice.h>
#include <transport_signal.h>
#include <transport_priv.h>

/* Test data ******************************************************************/

typedef struct TestData
{
    int lstransportsendmessage_call_count;
} TestData;

static TestData *test_data = NULL;

static void
test_setup(TestData *fixture, gconstpointer user_data)
{
    test_data = fixture;

    fixture->lstransportsendmessage_call_count = 0;
}

static void
test_teardown(TestData *fixture, gconstpointer user_data)
{
    test_data = NULL;
}

/* Test cases *****************************************************************/

static void
test_LSTransportRegisterSignal(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    _LSTransport transport =
    {
        .hub = GINT_TO_POINTER(1)
    };

    LSMessageToken token = 0;
    const char *category = "a";
    const char *method = "b";

    g_assert(LSTransportRegisterSignal(&transport, category, method, &token, &error));

    g_assert_cmpint(fixture->lstransportsendmessage_call_count, ==, 1);

    g_assert(LSTransportRegisterSignal(&transport, category, NULL, &token, &error));

    g_assert_cmpint(fixture->lstransportsendmessage_call_count, ==, 2);
}

static void
test_LSTransportUnregisterSignal(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    _LSTransport transport =
    {
        .hub = GINT_TO_POINTER(1)
    };

    LSMessageToken token = 0;
    const char *category = "a";
    const char *method = "b";

    g_assert(LSTransportUnregisterSignal(&transport, category, method, &token, &error));

    g_assert_cmpint(fixture->lstransportsendmessage_call_count, ==, 1);
}

static void
test_LSTransportRegisterSignalServiceStatus(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    _LSTransport transport =
    {
        .hub = GINT_TO_POINTER(1)
    };

    LSMessageToken token = 0;
    const char *service_name = "com.name.service";

    g_assert(LSTransportRegisterSignalServiceStatus(&transport, service_name, &token, &error));

    g_assert_cmpint(fixture->lstransportsendmessage_call_count, ==, 1);
}

static void
test_LSTransportUnregisterSignalServiceStatus(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    _LSTransport transport =
    {
        .hub = GINT_TO_POINTER(1)
    };

    LSMessageToken token = 0;
    const char *service_name = "com.name.service";

    g_assert(LSTransportUnregisterSignalServiceStatus(&transport, service_name, &token, &error));

    g_assert_cmpint(fixture->lstransportsendmessage_call_count, ==, 1);
}

static void
test_LSTransportMessageSignalNewRef(TestData *fixture, gconstpointer user_data)
{
    const char *category = "a";
    const char *method = "b";
    const char *payload = "{}";

    _LSTransportMessage *msg = LSTransportMessageSignalNewRef(category, method, payload);
    g_assert(NULL != msg);
    g_assert_cmpint(_LSTransportMessageGetType(msg), ==, _LSTransportMessageTypeSignal);
    g_assert_cmpstr(_LSTransportMessageGetCategory(msg), ==, category);
    g_assert_cmpstr(_LSTransportMessageGetMethod(msg), ==, method);
    g_assert_cmpstr(_LSTransportMessageGetPayload(msg), ==, payload);

    _LSTransportMessageUnref(msg);
}

static void
test_LSTransportSendSignal(TestData *fixture, gconstpointer user_data)
{
    LSError error;
    LSErrorInit(&error);

    _LSTransport transport =
    {
        .hub = GINT_TO_POINTER(1)
    };
    const char *category = "a";
    const char *method = "b";
    const char *payload = "{}";
    g_assert(LSTransportSendSignal(&transport, category, method, payload, &error));

    g_assert_cmpint(fixture->lstransportsendmessage_call_count, ==, 1);
}

static void
test_LSTransportServiceStatusSignalGetServiceName(TestData *fixture, gconstpointer user_data)
{
    const char *category = "a";
    const char *method = "b";
    const char *payload = "{ \"serviceName\": \"com.name.service\" }";
    char *service_name = NULL;

    _LSTransportMessage *msg = LSTransportMessageSignalNewRef(category, method, payload);

    // LSTransportServiceStatusSignalGetServiceName is only valid for following message types:
    // - _LSTransportMessageTypeServiceDownSignal
    // - _LSTransportMessageTypeServiceUpSignal

    _LSTransportMessageSetType(msg, _LSTransportMessageTypeServiceDownSignal);
    service_name = LSTransportServiceStatusSignalGetServiceName(msg);
    g_assert_cmpstr(service_name, ==, "com.name.service");
    g_free(service_name);

    _LSTransportMessageSetType(msg, _LSTransportMessageTypeServiceUpSignal);
    service_name = LSTransportServiceStatusSignalGetServiceName(msg);
    g_assert_cmpstr(service_name, ==, "com.name.service");
    g_free(service_name);

    _LSTransportMessageUnref(msg);
}

/* Mocks *******************************************************************/

bool
_LSTransportSendMessage(_LSTransportMessage *message, _LSTransportClient *client,
                        LSMessageToken *token, LSError *lserror)
{
    ++test_data->lstransportsendmessage_call_count;
    return true;
}

/* Test suite **************************************************************/

#define LSTEST_ADD(name, func) \
    g_test_add(name, TestData, NULL, test_setup, func, test_teardown)

int
main(int argc, char *argv[])
{
    g_test_init(&argc, &argv, NULL);

    g_log_set_always_fatal (G_LOG_LEVEL_ERROR);
    g_log_set_fatal_mask ("LunaService", G_LOG_LEVEL_ERROR);

    LSTEST_ADD("/luna-service2/LSTransportRegisterSignal", test_LSTransportRegisterSignal);
    LSTEST_ADD("/luna-service2/LSTransportUnregisterSignal", test_LSTransportUnregisterSignal);
    LSTEST_ADD("/luna-service2/LSTransportRegisterSignalServiceStatus", test_LSTransportRegisterSignalServiceStatus);
    LSTEST_ADD("/luna-service2/LSTransportUnregisterSignalServiceStatus", test_LSTransportUnregisterSignalServiceStatus);
    LSTEST_ADD("/luna-service2/LSTransportMessageSignalNewRef", test_LSTransportMessageSignalNewRef);
    LSTEST_ADD("/luna-service2/LSTransportSendSignal", test_LSTransportSendSignal);
    LSTEST_ADD("/luna-service2/LSTransportServiceStatusSignalGetServiceName", test_LSTransportServiceStatusSignalGetServiceName);

    return g_test_run();
}

