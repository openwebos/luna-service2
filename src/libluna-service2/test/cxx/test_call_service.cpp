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
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pbnjson.h>
#include <luna-service2/lunaservice.h>

#include <iostream>
#include <string>
#include <chrono>
#include <thread>

#define SIMPLE_CALL_NAME     "simpleCall"
#define TIMEOUT_CALL_NAME    "timeoutCall"
#define SUBSCRIBE_CALL_NAME  "subscribeCall"


static GMainLoop *g_mainloop = NULL;
static JSchemaInfo g_schemaInfo;
static bool g_subscribe = false;
static guint g_timeout = 100;
static guint g_timer_id = 0;

struct CallData
{
    LSHandle * sh;
    LSMessage * message;
};

static CallData g_callData = {NULL, NULL};

static void term_handler( int signal )
{
    g_main_loop_quit(g_mainloop);
}

static void justReply(LSHandle* lsh, LSMessage* message, const std::string & methodName = "")
{
    std::string answerStr = "{\"returnValue\": true, \"timestamp\": \"";
    std::string timeStr = "";
    time_t rawtime;
    struct tm * timeinfo = NULL;
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    if (timeinfo)
    {
        timeStr = std::string(asctime(timeinfo));
        timeStr.erase(timeStr.length() - 1);
    }

    answerStr += timeStr;
    answerStr += "\"";
    if (methodName.length())
    {
        answerStr += ", \"method\":\"";
        answerStr += methodName;
        answerStr += "\"";
    }
    answerStr += "}";

    LSError lserror;
    LSErrorInit(&lserror);
    if (!LSMessageReply(lsh, message, answerStr.c_str(), &lserror))
    {
        LSErrorPrint(&lserror, stderr);
    }

    if (LSErrorIsSet(&lserror))
    {
        LSErrorFree(&lserror);
    }
}

static void errorReply(LSHandle* lsh, LSMessage* message, const std::string & methodName = "")
{
    std::string answerStr = "{\"returnValue\": false";
    if (methodName.length())
    {
        answerStr += ", \"method\":\"";
        answerStr += methodName;
        answerStr += "\"";
    }
    answerStr += "}";

    LSError lserror;
    LSErrorInit(&lserror);
    if (!LSMessageReply(lsh, message, answerStr.c_str(), &lserror))
    {
        LSErrorPrint(&lserror, stderr);
    }

    if (LSErrorIsSet(&lserror))
    {
        LSErrorFree(&lserror);
    }
}

static gboolean onSubscribeCall(gpointer data)
{
    if (!data)
        return FALSE;
    CallData * callData = (CallData *)data;
    if (!callData->sh || !callData->message)
        return FALSE;

    justReply(callData->sh, callData->message, SUBSCRIBE_CALL_NAME);
    return TRUE;
}

static void makeSubscription(LSHandle* lsh, LSMessage* message)
{
    if (!g_subscribe)
    {
        return;
    }

    bool subscribed = false;
    LSError lserror;
    LSErrorInit(&lserror);
    // Add subscription to catalog
    if (!LSSubscriptionProcess(lsh, message, &subscribed, &lserror))
    {
        LSErrorPrint(&lserror, stderr);
        LSErrorFree(&lserror);
        return errorReply(lsh, message, SUBSCRIBE_CALL_NAME);
    }

    if (g_timer_id > 0)
    {
        // Should not be here but anyway
        g_source_remove(g_timer_id);
        g_timer_id = 0;
    }

    // Send reply
    justReply(lsh, message, SUBSCRIBE_CALL_NAME);
    // Set timer for subscription
    g_callData.sh = lsh;
    LSMessageRef(message);
    g_callData.message = message;
    g_timer_id = g_timeout_add(g_timeout, onSubscribeCall, &g_callData);
}

static void cancelSubscription()
{
    if (!g_subscribe)
    {
        return;
    }
    g_subscribe = false;

    if (g_timer_id > 0)
    {
        g_source_remove(g_timer_id);
        g_timer_id = 0;
    }

    g_callData.sh = NULL;
    LSMessageUnref(g_callData.message);
    g_callData.message = NULL;
}

static bool subscribeCancelHandler(LSHandle *sh, LSMessage *reply, void *ctx)
{
    cancelSubscription();
    return true;
}

int32_t getTimeoutFromMessage(LSMessage * message)
{
    if (!message)
        return -1;

    const char* payload = LSMessageGetPayload(message);
    jvalue_ref timeoutValue = NULL;
    jvalue_ref msgJSON = jdom_parse(j_cstr_to_buffer(payload),
                                    DOMOPT_NOOPT,
                                    &g_schemaInfo);
    if (!msgJSON)
    {
        return -1;
    }

    if (!jobject_get_exists(msgJSON, J_CSTR_TO_BUF("timeout"),
                            &timeoutValue))
    {
        j_release(&msgJSON);
        return -1;
    }

    if (!jis_number(timeoutValue))
    {
        j_release(&msgJSON);
        return -1;
    }

    int32_t timeout(0);
    if (jnumber_get_i32(timeoutValue, &timeout))
    {
        j_release(&msgJSON);
        return -1;
    }

    j_release(&msgJSON);
    return timeout;
}

static void timeoutReply(LSHandle* lsh, LSMessage* message)
{

    uint32_t timeout = getTimeoutFromMessage(message);
    if (timeout <= 0)
    {
        return errorReply(lsh, message, TIMEOUT_CALL_NAME);
    }

    usleep(timeout * 1000);
    return justReply(lsh, message, TIMEOUT_CALL_NAME);
}

static void subscribeReply(LSHandle* lsh, LSMessage* message)
{

    if (g_subscribe)
    {
        //We already have subscription -reply error
        return errorReply(lsh, message, SUBSCRIBE_CALL_NAME);
    }

    if (!LSMessageIsSubscription(message))
    {
        // No need to make subscription - just reply
        return justReply(lsh, message, SUBSCRIBE_CALL_NAME);
    }

    // Get timeout (optional) - default is 10 seconds
    int32_t timeout = getTimeoutFromMessage(message);

    if (timeout <= 0)
        timeout = 100;

    g_subscribe = true;
    g_timeout = timeout;
    return makeSubscription(lsh, message);
}

// Simple call - just reply
// Accept - doesn't care
// Input {}
// Return returnValue and current timestamp
// Output {"returnValue": true, "timestamp": "Apr 01 2014 17:54:11"}
// URI - com.palm.testservice/testCalls/simpleCall
// Example - luna-send -n 1 -f palm://com.palm.testservice/testCalls/simpleCall '{}'
static bool testSimpleCall( LSHandle* sh, LSMessage* message, void* user_data )
{
    justReply(sh, message, SIMPLE_CALL_NAME);
    return true;
}

// Timeout call - reply after specified timeout
// Accept - timeout value in milliseconds
// Input {"timeout": 100}
// Return returnValue and current timestamp
// Output {"returnValue": true, "timestamp": "Apr 01 2014 17:54:11"}
// URI - com.palm.testservice/testCalls/timeoutCall
// Example - luna-send -n 1 -f palm://com.palm.testservice/testCalls/timeoutCall '{"timeout": 100}'
static bool testTimeoutCall( LSHandle* sh, LSMessage* message, void* user_data )
{
  timeoutReply(sh, message);
  return true;
}

// Subscribe call - provides call subscription
// Accept - subscribe flag and timeout value in milliseconds between responses (timeout is optional, default - 100 ms)
// Input {"subscribe": true, "timeout": 100}
// Return returnValue and current timestamp
// Output {"returnValue": true, "timestamp": "Apr 01 2014 17:54:11"}
// URI - com.palm.testservice/testCalls/subscribeCall
// Example - luna-send -n 2 -f palm://com.palm.testservice/testCalls/subscribeCall '{"subscribe": true, "timeout": 100}'
static bool testSubscribeCall( LSHandle* sh, LSMessage* message, void* user_data )
{
  subscribeReply(sh, message);
  return true;
}

static LSMethod testMethods[] =
{
    { SIMPLE_CALL_NAME, testSimpleCall },
    { TIMEOUT_CALL_NAME, testTimeoutCall },
    { SUBSCRIBE_CALL_NAME, testSubscribeCall },
    { },
};


int main(int argc, char **argv)
{
    LSError lserror;
    LSErrorInit( &lserror );

    jschema_info_init(&g_schemaInfo, jschema_all(), NULL, NULL);

    g_mainloop = g_main_loop_new(NULL, FALSE);

    struct sigaction sact;
    memset(&sact, 0, sizeof(sact));
    sact.sa_handler = term_handler;
    (void)sigaction(SIGTERM, &sact, NULL);

    LSPalmService* psh;
    bool retVal;

    retVal = LSRegisterPalmService("com.palm.test_call_service", &psh, &lserror);
    if (!retVal)
        goto error;

    retVal = LSPalmServiceRegisterCategory(psh, "/testCalls",
                                           testMethods, NULL,
                                           NULL,
                                           psh,
                                           &lserror);
    if (!retVal)
        goto error;

    LSSubscriptionSetCancelFunction(LSPalmServiceGetPrivateConnection(psh), subscribeCancelHandler, NULL, &lserror);
    LSSubscriptionSetCancelFunction(LSPalmServiceGetPublicConnection(psh), subscribeCancelHandler, NULL, &lserror);

    retVal = LSGmainAttachPalmService(psh, g_mainloop, &lserror);

    g_main_loop_run(g_mainloop);

    cancelSubscription();

    g_main_loop_unref(g_mainloop);

    goto no_error;

 error:

     LSErrorPrint(&lserror, stderr);

 no_error:

    (void)LSUnregisterPalmService(psh, &lserror);

    if (LSErrorIsSet(&lserror))
    {
        LSErrorFree(&lserror);
    }

    return 0;
}

