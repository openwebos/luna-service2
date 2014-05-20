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
#include <locale.h>
#include <glib.h>
#include <transport_message.h>
#include <transport.h>
#include <clock.h>

/* Test data ******************************************************************/

/* Not in transport_message.h */
#define _LST_DIRECTION_ALIGN    25
#define _LST_DATA_ALIGN         49
char const* ServiceNameCompactCopy(const char *service_name, char buffer[], size_t buffer_size );
int LSTransportMessagePrintCompactHeaderCommon(const char *caller_service_name, const char *callee_service_name, const char *directions, const char *appId, const char *category, const char *method, LSMessageToken messageToken, FILE *file);

typedef struct TestData
{
    // transport client mock data
    const char *transport_client_service_name;
    const char *transport_client_unique_name;

    // Message used for tests
    _LSTransportMessage *msg;
} TestData;

static TestData *test_data = NULL;

static void
test_setup(TestData *fixture, gconstpointer user_data)
{
    test_data = fixture;

    fixture->transport_client_service_name = NULL;
    fixture->transport_client_unique_name = NULL;

    // default payload size big enough to pass most of test cases
    const int payload_size = 128;

    fixture->msg = _LSTransportMessageNewRef(payload_size);

    // initialize raw message buffer for valgrind
    // TODO: alloc message buffer using g_malloc0 instead of g_malloc
    memset(fixture->msg->raw->data, 0, payload_size);
}

static void
test_teardown(TestData *fixture, gconstpointer user_data)
{
    _LSTransportMessageFree(fixture->msg);

    test_data = NULL;
}

static int
formatTransportMessageReplyBuffer(char *dest, LSMessageToken token, const char *payload, const char *dest_servicename, const char *dest_uniquename)
{
    g_assert(NULL != dest);
    g_assert(NULL != payload);
    g_assert(NULL != dest_servicename);
    g_assert(NULL != dest_uniquename);

    char *dest_org = dest;
    const char *p[] = { payload, dest_servicename, dest_uniquename };
    int i;

    memcpy(dest, &token, sizeof(token));
    dest += sizeof(token);

    for (i = 0; i < sizeof(p)/sizeof(p[0]); ++i)
    {
        strcpy(dest, p[i]);
        dest += strlen(p[i]) + 1;
    }
    return dest - dest_org;
}

static int
formatTransportMessageMethodCallBuffer(char *dest, const char *category, const char *method, const char *payload, const char *appid, const char* dest_servicename, const char *dest_uniquename)
{
    g_assert(NULL != dest);

    char *dest_org = dest;
    const char *p[] = { category, method, payload, appid, dest_servicename, dest_uniquename };
    int i;
    for (i = 0; i < sizeof(p)/sizeof(p[0]); ++i)
    {
        if (p[i])
        {
            strcpy(dest, p[i]);
            dest += strlen(p[i]) + 1;
        }
    }
    return dest - dest_org;
}

/* Test cases *****************************************************************/

static void
test_LSTransportMessageNewRef(void)
{
    _LSTransportMessage *msg = _LSTransportMessageNewRef(10);
    g_assert_cmpint(msg->ref, ==, 1);

    g_assert(msg->raw != NULL);
    g_assert_cmpint(msg->raw->header.len, ==, 10);
    g_assert_cmpint(msg->raw->header.token, ==, LSMESSAGE_TOKEN_INVALID);
    g_assert_cmpint(msg->raw->header.type, ==, _LSTransportMessageTypeUnknown);

    g_assert_cmpint(msg->alloc_body_size, ==, 10);
    g_assert_cmpint(msg->tx_bytes_remaining, ==, 10 + sizeof(_LSTransportHeader));
    g_assert_cmpint(msg->retries, ==, MAX_SEND_RETRIES);
    g_assert_cmpint(msg->connection_fd, ==, -1);
    g_assert_cmpint(msg->connect_state, ==, _LSTransportConnectStateNoError);

    _LSTransportMessageUnref(msg);
}

static void
test_LSTransportMessageEmpty(void)
{
    _LSTransportMessage *msg = _LSTransportMessageEmpty();
    g_assert(msg);
    g_assert_cmpint(msg->ref, >, 1);

    g_assert(msg->raw);
    g_assert_cmpint(msg->raw->header.len, ==, 0);
    g_assert_cmpint(msg->raw->header.token, ==, LSMESSAGE_TOKEN_INVALID);
    g_assert_cmpint(msg->raw->header.type, ==, _LSTransportMessageTypeUnknown);

    g_assert_cmpint(msg->alloc_body_size, ==, 0);
    g_assert_cmpint(msg->tx_bytes_remaining, ==, 0);
    g_assert_cmpint(msg->retries, ==, 0);
    g_assert_cmpint(msg->connection_fd, ==, -1);
    g_assert_cmpint(msg->connect_state, ==, _LSTransportConnectStateOtherFailure);
}

static void
test_LSTransportMessageCopyNewRef(TestData *fixture, gconstpointer user_data)
{
    _LSTransportMessage *msg = _LSTransportMessageCopyNewRef(fixture->msg);
    g_assert(NULL != msg);
    g_assert_cmpint(msg->ref, ==, 1);

    g_assert_cmpint(_LSTransportMessageGetType(msg), ==, _LSTransportMessageGetType(fixture->msg));
    g_assert_cmpint(_LSTransportMessageGetToken(msg), ==, _LSTransportMessageGetToken(fixture->msg));
    g_assert_cmpstr(_LSTransportMessageGetBody(msg), ==, _LSTransportMessageGetBody(fixture->msg));

    _LSTransportMessageUnref(msg);
}

static void
test_LSTransportMessageCopy(TestData *fixture, gconstpointer user_data)
{
    _LSTransportMessage *dst = _LSTransportMessageNewRef(_LSTransportMessageGetBodySize(fixture->msg));

    g_assert(_LSTransportMessageCopy(dst, fixture->msg) == dst);

    g_assert_cmpint(_LSTransportMessageGetType(dst), ==, _LSTransportMessageGetType(fixture->msg));
    g_assert_cmpint(_LSTransportMessageGetToken(dst), ==, _LSTransportMessageGetToken(fixture->msg));
    g_assert(memcmp(_LSTransportMessageGetBody(dst), _LSTransportMessageGetBody(fixture->msg), _LSTransportMessageGetBodySize(fixture->msg)) == 0);

    _LSTransportMessageUnref(dst);
}

static void
test_LSTransportMessageFromVectorNewRef(TestData *fixture, gconstpointer user_data)
{
    char *category = "category";
    const int category_len = strlen(category) + 1;

    _LSTransportHeader header =
    {
        .len = category_len,
        .token = LSMESSAGE_TOKEN_INVALID,
        .type = _LSTransportMessageTypeMethodCall
    };

    const int total_len = sizeof(header) + category_len;
    struct iovec iov[2] =
    {
        {
            .iov_base = &header,
            .iov_len = sizeof(header)
        },
        {
            .iov_base = category,
            .iov_len = category_len
        }
    };

    _LSTransportMessage *msg = _LSTransportMessageFromVectorNewRef(iov, 2, total_len);
    g_assert(NULL != msg);
    g_assert_cmpint(msg->ref, ==, 1);

    g_assert_cmpint(msg->alloc_body_size, ==, category_len);
    g_assert_cmpstr(_LSTransportMessageGetCategory(msg), ==, category);

    _LSTransportMessageUnref(msg);
}

static void
test_LSTransportMessageReset(TestData *fixture, gconstpointer user_data)
{
    fixture->msg->tx_bytes_remaining = 0;
    fixture->msg->connection_fd = 0;

    _LSTransportMessageReset(fixture->msg);

    g_assert_cmpint(fixture->msg->tx_bytes_remaining, ==, _LSTransportMessageGetBodySize(fixture->msg) + sizeof(_LSTransportHeader));
    g_assert_cmpint(fixture->msg->connection_fd, ==, -1);
}

static void
test_LSTransportMessageRefAndUnref(TestData *fixture, gconstpointer user_data)
{
    _LSTransportMessageRef(fixture->msg);
    g_assert_cmpint(fixture->msg->ref, ==, 2);

    _LSTransportMessageUnref(fixture->msg);
    g_assert_cmpint(fixture->msg->ref, ==, 1);
}

static void
test_LSTransportMessageMiscGetSet(TestData *fixture, gconstpointer user_data)
{
    // get/set client
    _LSTransportMessageSetClient(fixture->msg, GINT_TO_POINTER(1));
    g_assert(GINT_TO_POINTER(1) == _LSTransportMessageGetClient(fixture->msg));

    // get/set token
    _LSTransportMessageSetToken(fixture->msg, 1);
    g_assert_cmpint(_LSTransportMessageGetToken(fixture->msg), ==, 1);

    // get/set connection fd
    _LSTransportMessageSetConnectionFd(fixture->msg, 1234);
    g_assert_cmpint(_LSTransportMessageGetConnectionFd(fixture->msg), ==, 1234);

    // set/get type
    _LSTransportMessageSetType(fixture->msg, _LSTransportMessageTypeError);
    g_assert_cmpint(_LSTransportMessageGetType(fixture->msg), ==, _LSTransportMessageTypeError);

    // get/set header
    _LSTransportHeader header;
    memset(&header, 1, sizeof(_LSTransportHeader));
    _LSTransportMessageSetHeader(fixture->msg, &header);
    g_assert(memcmp(_LSTransportMessageGetHeader(fixture->msg), &header, sizeof(_LSTransportHeader)) == 0);

    // get/set body
    const char *body = "new_body";
    _LSTransportMessageSetBody(fixture->msg, body, strlen(body)+1);
    g_assert_cmpstr(_LSTransportMessageGetBody(fixture->msg), ==, body);

    // get/set timeout id
    _LSTransportMessageSetTimeoutId(fixture->msg, 1);
    g_assert_cmpint(_LSTransportMessageGetTimeoutId(fixture->msg), ==, 1);

    // get/set connect state
    _LSTransportMessageSetConnectState(fixture->msg, _LSTransportConnectStateOtherFailure);
    g_assert_cmpint(_LSTransportMessageGetConnectState(fixture->msg), ==, _LSTransportConnectStateOtherFailure);

    // get/set app id
    _LSTransportMessageSetAppId(fixture->msg, "new_app_id");
    g_assert_cmpstr(_LSTransportMessageGetAppId(fixture->msg), ==, "new_app_id");
}

static void
test_LSTransportMessageGetError(TestData *fixture, gconstpointer user_data)
{
    _LSTransportMessageSetType(fixture->msg, _LSTransportMessageTypeError);
    strcpy(_LSTransportMessageGetBody(fixture->msg) + sizeof(LSMessageToken), "error");

    g_assert_cmpstr(_LSTransportMessageGetError(fixture->msg), ==, "error");
}

static void
test_LSTransportMessageGetReplyToken(TestData *fixture, gconstpointer user_data)
{
    _LSTransportMessageSetType(fixture->msg, _LSTransportMessageTypeReply);

    LSMessageToken token;
    memset(&token, 1, sizeof(token));

    memcpy(_LSTransportMessageGetBody(fixture->msg), &token, sizeof(token));

    g_assert_cmpint(_LSTransportMessageGetReplyToken(fixture->msg), ==, token);
}

static void
test_LSTransportMessageGetMethod(TestData *fixture, gconstpointer user_data)
{
    _LSTransportMessageSetType(fixture->msg, _LSTransportMessageTypeMethodCall);

    // create raw message (token + category + method)
    char raw_msg[10] = {0};
    const char *category = "a";
    const char *method = "b";
    strcpy(raw_msg, category);
    strcpy(raw_msg + strlen(category) + 1, method);
    memcpy(_LSTransportMessageGetBody(fixture->msg), raw_msg, sizeof(raw_msg));

    g_assert_cmpstr(_LSTransportMessageGetMethod(fixture->msg), ==, method);
}

static void
test_LSTransportMessageGetSenderServiceName(TestData *fixture, gconstpointer user_data)
{
    fixture->transport_client_service_name = "1";

    _LSTransportMessageSetClient(fixture->msg, GINT_TO_POINTER(1));

    g_assert_cmpstr(_LSTransportMessageGetSenderServiceName(fixture->msg), ==, "1");
}

static void
test_LSTransportMessageGetSenderUniqueName(TestData *fixture, gconstpointer user_data)
{
    fixture->transport_client_unique_name = "1";

    _LSTransportMessageSetClient(fixture->msg, GINT_TO_POINTER(1));

    g_assert_cmpstr(_LSTransportMessageGetSenderUniqueName(fixture->msg), ==, "1");
}

static void
test_LSTransportMessageGetDestServiceName(TestData *fixture, gconstpointer user_data)
{
    const char *category = "a";
    const char *method = "b";
    const char *payload = "{}";
    const char *appid = "c";
    const char *dest_servicename = "d";

    fixture->msg->raw->header.len = formatTransportMessageMethodCallBuffer(fixture->msg->raw->data, category, method, payload, appid, dest_servicename, NULL);
    fixture->msg->raw->header.type = _LSTransportMessageTypeMethodCall;

    g_assert_cmpstr(_LSTransportMessageGetDestServiceName(fixture->msg), ==, dest_servicename);
}

static void
test_LSTransportMessageGetDestUniqueName(TestData *fixture, gconstpointer user_data)
{
    const char *category = "a";
    const char *method = "b";
    const char *payload = "{}";
    const char *appid = "c";
    const char *dest_servicename = "d";
    const char *dest_uniquename = "e";

    fixture->msg->raw->header.len = formatTransportMessageMethodCallBuffer(fixture->msg->raw->data, category, method, payload, appid, dest_servicename, dest_uniquename);
    fixture->msg->raw->header.type = _LSTransportMessageTypeMethodCall;

    g_assert_cmpstr(_LSTransportMessageGetDestUniqueName(fixture->msg), ==, dest_uniquename);
}

static void
test_LSTransportMessageGetMonitorMessageData(TestData *fixture, gconstpointer user_data)
{
    // no valid data available
    g_assert(_LSTransportMessageGetMonitorMessageData(fixture->msg) == NULL);

    // valid data
    const char *category = "a";
    const char *method = "b";
    const char *payload = "{}";
    const char *appid = "c";
    const char *dest_servicename = "d";
    const char *dest_uniquename = "e";

    struct timespec now;
    ClockGetTime(&now);

    fixture->msg->raw->header.len = formatTransportMessageMethodCallBuffer(fixture->msg->raw->data, category, method, payload, appid, dest_servicename, dest_uniquename);
    fixture->msg->raw->header.type = _LSTransportMessageTypeMethodCall;

    _LSMonitorMessageData message_data;
    message_data.serial = 1;
    message_data.timestamp = now;
    message_data.type = _LSMonitorMessageTypeRx;

    const int orig_msg_size = sizeof(_LSTransportHeader) + _LSTransportMessageGetBodySize(fixture->msg);

    unsigned long padding_bytes = PADDING_BYTES_TYPE(void *, orig_msg_size);

    // new message containing enough memory for monitor_message_data + padding
    _LSTransportMessage *monitor_message = _LSTransportMessageNewRef(orig_msg_size + sizeof(message_data) + padding_bytes);
    _LSTransportMessageCopy(monitor_message, fixture->msg);

    char *body = monitor_message->raw->data + _LSTransportMessageGetBodySize(fixture->msg);
    memset(body, 0, padding_bytes);
    body += padding_bytes;
    memcpy(body, &message_data, sizeof(message_data));

    const _LSMonitorMessageData *result_data = _LSTransportMessageGetMonitorMessageData(monitor_message);

    g_assert(result_data != NULL);

    g_assert_cmpint(result_data->serial, ==, message_data.serial);
    g_assert_cmpint(result_data->type, ==, message_data.type);
    g_assert(result_data->timestamp.tv_nsec == message_data.timestamp.tv_nsec
            && result_data->timestamp.tv_sec == message_data.timestamp.tv_sec);

    _LSTransportMessageUnref(monitor_message);
}

static void
test_LSTransportMessageFilterMatch(TestData *fixture, gconstpointer user_data)
{
    fixture->transport_client_unique_name = "1";
    fixture->transport_client_service_name = "2";

    if (g_test_trap_fork(0, G_TEST_TRAP_SILENCE_STDOUT))
    {
        // should return false
        bool result = LSTransportMessageFilterMatch(fixture->msg, "");
        exit(result ? 1 : 0);
    }
    g_test_trap_assert_passed();
    gchar *expected_output = g_strdup_printf("No filter match function for message type: %d\n", _LSTransportMessageTypeUnknown);
    g_test_trap_assert_stdout(expected_output);
    g_free(expected_output);

    _LSTransportMessageSetType(fixture->msg, _LSTransportMessageTypeSignal);
    g_assert(LSTransportMessageFilterMatch(fixture->msg, "1"));
    g_assert(LSTransportMessageFilterMatch(fixture->msg, "2"));
    g_assert(!LSTransportMessageFilterMatch(fixture->msg, "3"));

    _LSTransportMessageSetType(fixture->msg, _LSTransportMessageTypeCancelMethodCall);
    g_assert(LSTransportMessageFilterMatch(fixture->msg, "1"));
    g_assert(LSTransportMessageFilterMatch(fixture->msg, "2"));
    g_assert(!LSTransportMessageFilterMatch(fixture->msg, "3"));

    _LSTransportMessageSetType(fixture->msg, _LSTransportMessageTypeMethodCall);
    g_assert(LSTransportMessageFilterMatch(fixture->msg, "1"));
    g_assert(LSTransportMessageFilterMatch(fixture->msg, "2"));
    g_assert(!LSTransportMessageFilterMatch(fixture->msg, "3"));

    _LSTransportMessageSetType(fixture->msg, _LSTransportMessageTypeReply);
    g_assert(LSTransportMessageFilterMatch(fixture->msg, "1"));
    g_assert(LSTransportMessageFilterMatch(fixture->msg, "2"));
    g_assert(!LSTransportMessageFilterMatch(fixture->msg, "3"));
}

static void
test_LSTransportMessagePrintUnknownMessage(TestData *fixture, gconstpointer user_data)
{
    if (g_test_trap_fork(0, G_TEST_TRAP_SILENCE_STDOUT))
    {
        LSTransportMessagePrint(fixture->msg, stdout);
        exit(0);
    }
    gchar *expected_output = g_strdup_printf("No print function for message type: %d\n", _LSTransportMessageTypeUnknown);
    g_test_trap_assert_stdout(expected_output);
    g_free(expected_output);
}

static void
test_LSTransportMessagePrintSignal(TestData *fixture, gconstpointer user_data)
{
    const char *category = "a";
    const char *method = "b";
    const char *payload = "{}";
    fixture->transport_client_service_name = "2";
    fixture->transport_client_unique_name = "3";

    fixture->msg->raw->header.len = formatTransportMessageMethodCallBuffer(fixture->msg->raw->data, category, method, payload, NULL, NULL, NULL);
    fixture->msg->raw->header.token = 1;
    fixture->msg->raw->header.type = _LSTransportMessageTypeSignal;

    FILE *output = tmpfile();
    g_assert(output);
    LSTransportMessagePrint(fixture->msg, output);
    rewind(output);

    const char *format = "signal\t%d\t\t%s (%s)\t\t\t%s/%s\t\xc2\xab%s\xc2\xbb\n";
    gchar *expected_output = g_strdup_printf(format,
            fixture->msg->raw->header.token,
            fixture->transport_client_service_name,
            fixture->transport_client_unique_name,
            category,
            method,
            payload);
    char buffer[strlen(expected_output)+10];
    g_assert_cmpstr(expected_output, ==, fgets(buffer, sizeof(buffer), output));
    g_free(expected_output);
    fclose(output);
}

static void
test_LSTransportMessagePrintCancelMethodCall(TestData *fixture, gconstpointer user_data)
{
    const char *category = "a";
    const char *method = "b";
    const char *payload = "{}";
    const char *dest_servicename = "d";
    const char *dest_uniquename = "f";
    fixture->transport_client_service_name = "2";
    fixture->transport_client_unique_name = "3";

    fixture->msg->raw->header.len = formatTransportMessageMethodCallBuffer(fixture->msg->raw->data, category, method, payload, NULL, dest_servicename, dest_uniquename);
    fixture->msg->raw->header.token = 1;
    fixture->msg->raw->header.type = _LSTransportMessageTypeCancelMethodCall;

    FILE *output = tmpfile();
    g_assert(output);
    LSTransportMessagePrint(fixture->msg, output);
    rewind(output);

    const char *format = "call\t%d\t\t%s (%s)\t\t%s (%s)\t\t%s/%s\t\xc2\xab%s\xc2\xbb\n";
    gchar *expected_output = g_strdup_printf(format,
            fixture->msg->raw->header.token,
            fixture->transport_client_service_name,
            fixture->transport_client_unique_name,
            dest_servicename,
            dest_uniquename,
            category,
            method,
            payload);
    char buffer[strlen(expected_output)+10];
    g_assert_cmpstr(expected_output, ==, fgets(buffer, sizeof(buffer), output));
    g_free(expected_output);
    fclose(output);
}

static void
test_LSTransportMessagePrintMethodCall(TestData *fixture, gconstpointer user_data)
{
    const char *category = "a";
    const char *method = "b";
    const char *payload = "{}";
    const char *appid = "c";
    const char *dest_servicename = "d";
    const char *dest_uniquename = "f";
    fixture->transport_client_service_name = "2";
    fixture->transport_client_unique_name = "3";

    fixture->msg->raw->header.len = formatTransportMessageMethodCallBuffer(fixture->msg->raw->data, category, method, payload, appid, dest_servicename, dest_uniquename);
    fixture->msg->raw->header.token = 1;
    fixture->msg->raw->header.type = _LSTransportMessageTypeMethodCall;

    FILE *output = tmpfile();
    g_assert(output);
    LSTransportMessagePrint(fixture->msg, output);
    rewind(output);

    const char *format = "call\t%d\t\t%s (%s)\t%s (%s)\t\t%s\t\t%s/%s\t\xc2\xab%s\xc2\xbb\n";
    gchar *expected_output = g_strdup_printf(format,
            fixture->msg->raw->header.token,
            fixture->transport_client_service_name,
            fixture->transport_client_unique_name,
            dest_servicename,
            dest_uniquename,
            appid,
            category,
            method,
            payload);
    char buffer[strlen(expected_output)+10];
    g_assert_cmpstr(expected_output, ==, fgets(buffer, sizeof(buffer), output));
    g_free(expected_output);
    fclose(output);
}

static void
test_LSTransportMessagePrintReply(TestData *fixture, gconstpointer user_data)
{
    LSMessageToken token = 1;
    const char *payload = "{}";
    const char *dest_servicename = "a";
    const char *dest_uniquename = "b";
    fixture->transport_client_service_name = "2";
    fixture->transport_client_unique_name = "3";

    fixture->msg->raw->header.type = _LSTransportMessageTypeReply;
    fixture->msg->raw->header.token = 1;
    fixture->msg->raw->header.len = formatTransportMessageReplyBuffer(fixture->msg->raw->data, token, payload, dest_servicename, dest_uniquename);

    FILE *output = tmpfile();
    g_assert(output);

    LSTransportMessagePrint(fixture->msg, output);
    rewind(output);

    const char *format = "return\t%d\t\t%s (%s)\t\t%s (%s)\t\xc2\xab%s\xc2\xbb\n";
    gchar *expected_output = g_strdup_printf(format,
            token,
            fixture->transport_client_service_name,
            fixture->transport_client_unique_name,
            dest_servicename,
            dest_uniquename,
            payload);
    char buffer[strlen(expected_output)+10];
    g_assert_cmpstr(expected_output, ==, fgets(buffer, sizeof(buffer), output));
    g_free(expected_output);
    fclose(output);
}

static void
test_ServiceNameCompactCopy(TestData *fixture, gconstpointer user_data)
{
    typedef struct ServiceNamePair
    {
        char *full_name;
        char *compact_name;
    } ServiceNamePair;
    ServiceNamePair service_pairs [] =
    {
        { "o",                                           "o"},
        { "onenode",                                     "onenode"},
        { "two.node",                                    "two.node"},
        { "com.webos.three",                             "c.webos.three"},
        { "com.webos.four.node",                         "c.w.four.node"},
        { "com.webos.very.long.node.sample.service.name","c.w.v.l.n.s.service.name"},
        { "c.w",                                         "c.w"},
        { "c.w.v.l.n.s.service.name",                    "c.w.v.l.n.s.service.name"},
    };

    int i;
    for (i=0; i < sizeof(service_pairs)/sizeof(service_pairs[0]); ++i)
    {
        char output_buffer[strlen(service_pairs[i].full_name)+1];
        g_assert_cmpstr(ServiceNameCompactCopy(service_pairs[i].full_name, output_buffer, sizeof(output_buffer)),
                        ==,
                        service_pairs[i].compact_name);
    }
}

static void
test_LSTransportMessagePrintCompactHeaderCommon(TestData *fixture, gconstpointer user_data)
{
    LSMessageToken token = 1;
    const char *category = "a";
    const char *method = "b";
    const char *appid = "c";
    const char *service_name = "d";
    const char *directions = "<>";

    FILE *output = tmpfile();
    g_assert(output);

    /* supply full param */
    LSTransportMessagePrintCompactHeaderCommon(service_name, service_name, directions,
                                               appid, category, method, token, output);
    rewind(output);

    const char *format = "%s.%d(%s) %*s %*s%s/%s";
    gchar *expected_output = g_strdup_printf(format,
                                             service_name, token, appid,
                                             (_LST_DIRECTION_ALIGN - 6), directions,
                                             (_LST_DATA_ALIGN - (_LST_DIRECTION_ALIGN + 2)), service_name,
                                             category, method);
    char buffer[strlen(expected_output)+10];
    g_assert_cmpstr(expected_output, ==, fgets(buffer, sizeof(buffer), output));
    g_free(expected_output);
    fclose(output);

    output = tmpfile();
    g_assert(output);
    /* supply null */
    LSTransportMessagePrintCompactHeaderCommon(service_name, service_name, directions,
                                               NULL, NULL, NULL, token, output);
    rewind(output);

    format = "%s.%d %*s %*s";
    expected_output = g_strdup_printf(format,
                                      service_name, token,
                                      (_LST_DIRECTION_ALIGN - 3), directions,
                                      (_LST_DATA_ALIGN - (_LST_DIRECTION_ALIGN + 2)), service_name);
    g_assert_cmpstr(expected_output, ==, fgets(buffer, sizeof(buffer), output));
    g_free(expected_output);
}

static void
test_LSTransportMessagePrintCompactSignalHeader(TestData *fixture, gconstpointer user_data)
{
    const char *category = "a";
    const char *method = "b";
    const char *payload = "{}";
    fixture->transport_client_service_name = "2";
    fixture->transport_client_unique_name = "3";

    fixture->msg->raw->header.len = formatTransportMessageMethodCallBuffer(fixture->msg->raw->data, category, method, payload, NULL, NULL, NULL);
    fixture->msg->raw->header.token = 1;
    fixture->msg->raw->header.type = _LSTransportMessageTypeSignal;

    FILE *output = tmpfile();
    g_assert(output);

    LSTransportMessagePrintCompactHeader(fixture->msg, output);
    rewind(output);

    const char *format = "%s.%d %*s %*s%s/%s";
    gchar *expected_output = g_strdup_printf(format,
                                             fixture->transport_client_service_name,
                                             fixture->msg->raw->header.token,
                                             (_LST_DIRECTION_ALIGN - 3), ">*",
                                             (_LST_DATA_ALIGN - (_LST_DIRECTION_ALIGN +2)), "(null)",
                                             category,
                                             method);
    char buffer[strlen(expected_output)+10];
    g_assert_cmpstr(expected_output, ==, fgets(buffer, sizeof(buffer), output));
    g_free(expected_output);
    fclose(output);
}

static void
test_LSTransportMessagePrintCompactCancelMethodCallHeader(TestData *fixture, gconstpointer user_data)
{
    const char *category = "a";
    const char *method = "b";
    const char *payload = "{}";
    const char *dest_servicename = "d";
    const char *dest_uniquename = "f";
    fixture->transport_client_service_name = "2";
    fixture->transport_client_unique_name = "3";

    fixture->msg->raw->header.len = formatTransportMessageMethodCallBuffer(fixture->msg->raw->data, category, method, payload, NULL, dest_servicename, dest_uniquename);
    fixture->msg->raw->header.token = 1;
    fixture->msg->raw->header.type = _LSTransportMessageTypeCancelMethodCall;

    FILE *output = tmpfile();
    g_assert(output);

    LSTransportMessagePrintCompactHeader(fixture->msg, output);
    rewind(output);

    const char *format = "%s.%d %*s %*s%s/%s";
    gchar *expected_output = g_strdup_printf(format,
                                             fixture->transport_client_service_name,
                                             fixture->msg->raw->header.token,
                                             (_LST_DIRECTION_ALIGN - 3), ">|",
                                             (_LST_DATA_ALIGN - (_LST_DIRECTION_ALIGN +2)), dest_servicename,
                                             category,
                                             method);
    char buffer[strlen(expected_output)+10];
    g_assert_cmpstr(expected_output, ==, fgets(buffer, sizeof(buffer), output));
    g_free(expected_output);
    fclose(output);
}

static void
test_LSTransportMessagePrintCompactMethodCallHeader(TestData *fixture, gconstpointer user_data)
{
    const char *category = "a";
    const char *method = "b";
    const char *payload = "{}";
    const char *appid = "c";
    const char *dest_servicename = "d";
    const char *dest_uniquename = "f";
    fixture->transport_client_service_name = "2";
    fixture->transport_client_unique_name = "3";

    fixture->msg->raw->header.len = formatTransportMessageMethodCallBuffer(fixture->msg->raw->data, category, method, payload, appid, dest_servicename, dest_uniquename);
    fixture->msg->raw->header.token = 1;
    fixture->msg->raw->header.type = _LSTransportMessageTypeMethodCall;

    FILE *output = tmpfile();
    g_assert(output);

    LSTransportMessagePrintCompactHeader(fixture->msg, output);
    rewind(output);

    const char *format = "%s.%d(%s) %*s %*s%s/%s";
    gchar *expected_output = g_strdup_printf(format,
                                             fixture->transport_client_service_name,
                                             fixture->msg->raw->header.token,
                                             appid,
                                             (_LST_DIRECTION_ALIGN - 6), " >",
                                             (_LST_DATA_ALIGN - (_LST_DIRECTION_ALIGN +2)), dest_servicename,
                                             category,
                                             method);
    char buffer[strlen(expected_output)+10];
    g_assert_cmpstr(expected_output, ==, fgets(buffer, sizeof(buffer), output));
    g_free(expected_output);
    fclose(output);
}

static void
test_LSTransportMessagePrintCompactReplyHeader(TestData *fixture, gconstpointer user_data)
{
    LSMessageToken token = 1;
    const char *payload = "{}";
    const char *dest_servicename = "a";
    const char *dest_uniquename = "b";
    fixture->transport_client_service_name = "2";
    fixture->transport_client_unique_name = "3";

    fixture->msg->raw->header.type = _LSTransportMessageTypeReply;
    fixture->msg->raw->header.token = 1;
    fixture->msg->raw->header.len = formatTransportMessageReplyBuffer(fixture->msg->raw->data, token, payload, dest_servicename, dest_uniquename);

    FILE *output = tmpfile();
    g_assert(output);

    LSTransportMessagePrintCompactHeader(fixture->msg, output);
    rewind(output);

    const char *format = "%s.%d %*s %*s";
    gchar *expected_output = g_strdup_printf(format,
                                             dest_servicename,
                                             fixture->msg->raw->header.token,
                                             (_LST_DIRECTION_ALIGN - 3), "< ",
                                             (_LST_DATA_ALIGN - (_LST_DIRECTION_ALIGN +2)),
                                             fixture->transport_client_service_name);
    char buffer[strlen(expected_output)+10];
    g_assert_cmpstr(expected_output, ==, fgets(buffer, sizeof(buffer), output));
    g_free(expected_output);
    fclose(output);
}


static bool
is_in_array(GArray *array, _LSTransportMessageType item)
{
    int i;
    for (i=0; i<array->len; ++i)
        if (g_array_index(array, _LSTransportMessageType, i) == item)
            return true;
    return false;
}

static void
test_LSTransportMessageTypes(TestData *fixture, gconstpointer user_data)
{
    GArray *types = g_array_new(FALSE, FALSE, sizeof(_LSTransportMessageType));
    int i;

    // test monitor types
    const _LSTransportMessageType monitor_types[] =
    {
        _LSTransportMessageTypeMethodCall,
        _LSTransportMessageTypeReply,
        _LSTransportMessageTypeSignal,
        _LSTransportMessageTypeCancelMethodCall
    };
    types = g_array_append_vals(types, monitor_types, G_N_ELEMENTS(monitor_types));

    for (i=0; i<_LSTransportMessageTypeUnknown+1; ++i)
    {
        _LSTransportMessageSetType(fixture->msg, i);

        if (is_in_array(types, i))
            g_assert(_LSTransportMessageIsMonitorType(fixture->msg));
        else
            g_assert(!_LSTransportMessageIsMonitorType(fixture->msg));
    }

    // cleanup
    g_array_remove_range(types, 0, types->len);

    // test error types
    const _LSTransportMessageType error_types[] =
    {
        _LSTransportMessageTypeError,
        _LSTransportMessageTypeErrorUnknownMethod
    };
    types = g_array_append_vals(types, error_types, G_N_ELEMENTS(error_types));

    for (i=0; i<_LSTransportMessageTypeUnknown+1; ++i)
    {
        _LSTransportMessageSetType(fixture->msg, i);

        if (is_in_array(types, i))
            g_assert(_LSTransportMessageIsErrorType(fixture->msg));
        else
            g_assert(!_LSTransportMessageIsErrorType(fixture->msg));
    }

    // cleanup
    g_array_remove_range(types, 0, types->len);

    // test reply types
    const _LSTransportMessageType reply_types[] =
    {
        _LSTransportMessageTypeReply,
        _LSTransportMessageTypeQueryServiceStatusReply
    };
    types = g_array_append_vals(types, error_types, G_N_ELEMENTS(error_types));
    types = g_array_append_vals(types, reply_types, G_N_ELEMENTS(reply_types));

    for (i=0; i<_LSTransportMessageTypeUnknown+1; ++i)
    {
        _LSTransportMessageSetType(fixture->msg, i);

        if (is_in_array(types, i))
            g_assert(_LSTransportMessageIsReplyType(fixture->msg));
        else
            g_assert(!_LSTransportMessageIsReplyType(fixture->msg));
    }

    // cleanup
    g_array_remove_range(types, 0, types->len);

    // test connectionfd types
    const _LSTransportMessageType connectionfd_types[] =
    {
        _LSTransportMessageTypeQueryNameReply,
        _LSTransportMessageTypeRequestNameLocalReply,
        _LSTransportMessageTypeMonitorConnected
    };
    types = g_array_append_vals(types, connectionfd_types, G_N_ELEMENTS(connectionfd_types));

    for (i=0; i<_LSTransportMessageTypeUnknown+1; ++i)
    {
        _LSTransportMessageSetType(fixture->msg, i);

        if (is_in_array(types, i))
            g_assert(_LSTransportMessageIsConnectionFdType(fixture->msg));
        else
            g_assert(!_LSTransportMessageIsConnectionFdType(fixture->msg));
    }

    g_array_free(types, TRUE);
}

static void
test_LSTransportMessageTypeQueryNameGetQueryName(TestData *fixture, gconstpointer user_data)
{
    fixture->msg->raw->header.type = _LSTransportMessageTypeQueryName;

    g_assert_cmpstr(_LSTransportMessageTypeQueryNameGetQueryName(fixture->msg), ==, NULL);

    const char *servicename = "a";
    struct _LSTransportMessageIter iter;
    _LSTransportMessageIterInit(fixture->msg, &iter);
    _LSTransportMessageAppendString(&iter, servicename);

    g_assert_cmpstr(_LSTransportMessageTypeQueryNameGetQueryName(fixture->msg), ==, servicename);
}

static void
test_LSTransportMessageTypeQueryNameGetAppId(TestData *fixture, gconstpointer user_data)
{
    fixture->msg->raw->header.type = _LSTransportMessageTypeQueryName;

    g_assert_cmpstr(_LSTransportMessageTypeQueryNameGetAppId(fixture->msg), ==, NULL);

    const char *servicename = "a";
    const char *appid = "b";
    struct _LSTransportMessageIter iter;
    _LSTransportMessageIterInit(fixture->msg, &iter);
    _LSTransportMessageAppendString(&iter, servicename);
    _LSTransportMessageAppendString(&iter, appid);

    g_assert_cmpstr(_LSTransportMessageTypeQueryNameGetAppId(fixture->msg), ==, appid);
}

static void
test_LSTransportMessageIter(TestData *fixture, gconstpointer user_data)
{
    _LSTransportMessageIter iter;

    // write data
    _LSTransportMessageIterInit(fixture->msg, &iter);

    g_assert(!_LSTransportMessageIterHasNext(&iter));

    g_assert(_LSTransportMessageAppendString(&iter, "a"));
    g_assert(!_LSTransportMessageIterHasNext(&iter));

    g_assert(_LSTransportMessageAppendInt32(&iter, 1));
    g_assert(!_LSTransportMessageIterHasNext(&iter));

    g_assert(_LSTransportMessageAppendBool(&iter, true));
    g_assert(!_LSTransportMessageIterHasNext(&iter));

    g_assert(_LSTransportMessageAppendInvalid(&iter));
    g_assert(!_LSTransportMessageIterHasNext(&iter));

    // read data
    _LSTransportMessageIterInit(fixture->msg, &iter);

    const char *a = NULL;
    g_assert(_LSTransportMessageGetString(&iter, &a));
    g_assert_cmpstr(a, ==, "a");
    g_assert(_LSTransportMessageIterHasNext(&iter));
    g_assert(_LSTransportMessageIterNext(&iter) == &iter);

    int32_t b;
    g_assert(_LSTransportMessageGetInt32(&iter, &b));
    g_assert_cmpint(b, ==, 1);
    g_assert(_LSTransportMessageIterHasNext(&iter));
    g_assert(_LSTransportMessageIterNext(&iter) == &iter);

    bool c;
    g_assert(_LSTransportMessageGetBool(&iter, &c));
    g_assert(c == true);
    g_assert(_LSTransportMessageIterHasNext(&iter));
    g_assert(_LSTransportMessageIterNext(&iter) == &iter);

    g_assert(!_LSTransportMessageIterHasNext(&iter));
    g_assert(_LSTransportMessageIterNext(&iter) == NULL);
}

static void
test_LSTransportMessageIterBodyExpand(TestData *fixture, gconstpointer user_data)
{
    // message with small buffer -> appending data need to expand message body
    _LSTransportMessage *msg = _LSTransportMessageNewRef(1);

    _LSTransportMessageIter iter;

    // write data
    _LSTransportMessageIterInit(msg, &iter);

    g_assert(_LSTransportMessageAppendString(&iter, "a"));
    g_assert(_LSTransportMessageAppendInt32(&iter, 1));
    g_assert(_LSTransportMessageAppendBool(&iter, true));
    g_assert(_LSTransportMessageAppendInvalid(&iter));

    // read data
    _LSTransportMessageIterInit(msg, &iter);

    const char *a = NULL;
    g_assert(_LSTransportMessageGetString(&iter, &a));
    g_assert_cmpstr(a, ==, "a");
    _LSTransportMessageIterNext(&iter);

    int32_t b;
    g_assert(_LSTransportMessageGetInt32(&iter, &b));
    g_assert_cmpint(b, ==, 1);
    _LSTransportMessageIterNext(&iter);

    bool c;
    g_assert(_LSTransportMessageGetBool(&iter, &c));
    g_assert(c == true);
    _LSTransportMessageIterNext(&iter);

    _LSTransportMessageUnref(msg);
}

/* Mocks **********************************************************************/

void
_LSTransportClientRef(_LSTransportClient *client)
{
}

void
_LSTransportClientUnref(_LSTransportClient *client)
{
}

const char*
_LSTransportClientGetServiceName(const _LSTransportClient *client)
{
    return test_data->transport_client_service_name;
}

const char*
_LSTransportClientGetUniqueName(const _LSTransportClient *client)
{
    return test_data->transport_client_unique_name;
}

/* Test suite *****************************************************************/

#define LSTEST_ADD(name, func) \
    g_test_add(name, TestData, NULL, test_setup, func, test_teardown)

int
main(int argc, char *argv[])
{
    // need to use utf8 locale for _LSTransportMessagePrint* cases,
    // because of payload 'angle quotation mark' characters
    setlocale(LC_ALL, "en_US.utf8");

    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/luna-service2/LSTransportMessageNewRef", test_LSTransportMessageNewRef);
    g_test_add_func("/luna-service2/LSTransportMessageEmpty", test_LSTransportMessageEmpty);

    LSTEST_ADD("/luna-service2/LSTransportMessageCopyNewRef", test_LSTransportMessageCopyNewRef);
    LSTEST_ADD("/luna-service2/LSTransportMessageCopy", test_LSTransportMessageCopy);
    LSTEST_ADD("/luna-service2/LSTransportMessageFromVectorNewRef", test_LSTransportMessageFromVectorNewRef);
    LSTEST_ADD("/luna-service2/LSTransportMessageReset", test_LSTransportMessageReset);
    LSTEST_ADD("/luna-service2/LSTransportMessageRefAndUnref", test_LSTransportMessageRefAndUnref);
    LSTEST_ADD("/luna-service2/LSTransportMessageMiscGetSet", test_LSTransportMessageMiscGetSet);
    LSTEST_ADD("/luna-service2/LSTransportMessageGetError", test_LSTransportMessageGetError);
    LSTEST_ADD("/luna-service2/LSTransportMessageGetReplyToken", test_LSTransportMessageGetReplyToken);
    LSTEST_ADD("/luna-service2/LSTransportMessageGetMethod", test_LSTransportMessageGetMethod);
    LSTEST_ADD("/luna-service2/LSTransportMessageGetSenderServiceName", test_LSTransportMessageGetSenderServiceName);
    LSTEST_ADD("/luna-service2/LSTransportMessageGetSenderUniqueName", test_LSTransportMessageGetSenderUniqueName);
    LSTEST_ADD("/luna-service2/LSTransportMessageGetDestServiceName", test_LSTransportMessageGetDestServiceName);
    LSTEST_ADD("/luna-service2/LSTransportMessageGetDestUniqueName", test_LSTransportMessageGetDestUniqueName);
    LSTEST_ADD("/luna-service2/LSTransportMessageGetMonitorMessageData", test_LSTransportMessageGetMonitorMessageData);
    LSTEST_ADD("/luna-service2/LSTransportMessageFilterMatch", test_LSTransportMessageFilterMatch);
    LSTEST_ADD("/luna-service2/LSTransportMessageTypes", test_LSTransportMessageTypes);
    LSTEST_ADD("/luna-service2/LSTransportMessagePrintUnknownMessage", test_LSTransportMessagePrintUnknownMessage);
    LSTEST_ADD("/luna-service2/LSTransportMessagePrintSignal", test_LSTransportMessagePrintSignal);
    LSTEST_ADD("/luna-service2/LSTransportMessagePrintCancelMethodCall", test_LSTransportMessagePrintCancelMethodCall);
    LSTEST_ADD("/luna-service2/LSTransportMessagePrintMethodCall", test_LSTransportMessagePrintMethodCall);
    LSTEST_ADD("/luna-service2/LSTransportMessagePrintReply", test_LSTransportMessagePrintReply);
    LSTEST_ADD("/luna-service2/ServiceNameCompactCopy", test_ServiceNameCompactCopy);
    LSTEST_ADD("/luna-service2/LSTransportMessagePrintCompactHeaderCommon", test_LSTransportMessagePrintCompactHeaderCommon);
    LSTEST_ADD("/luna-service2/LSTransportMessagePrintCompactSignalHeader", test_LSTransportMessagePrintCompactSignalHeader);
    LSTEST_ADD("/luna-service2/LSTransportMessagePrintCompactCancelMethodCallHeader", test_LSTransportMessagePrintCompactCancelMethodCallHeader);
    LSTEST_ADD("/luna-service2/LSTransportMessagePrintCompactMethodCallHeader", test_LSTransportMessagePrintCompactMethodCallHeader);
    LSTEST_ADD("/luna-service2/LSTransportMessagePrintCompactReplyHeader", test_LSTransportMessagePrintCompactReplyHeader);
    LSTEST_ADD("/luna-service2/LSTransportMessageTypeQueryNameGetQueryName", test_LSTransportMessageTypeQueryNameGetQueryName);
    LSTEST_ADD("/luna-service2/LSTransportMessageTypeQueryNameGetAppId", test_LSTransportMessageTypeQueryNameGetAppId);
    LSTEST_ADD("/luna-service2/LSTransportMessageIter", test_LSTransportMessageIter);
    LSTEST_ADD("/luna-service2/LSTransportMessageIterBodyExpand", test_LSTransportMessageIterBodyExpand);

    return g_test_run();
}

