/* @@@LICENSE
 *
 *      Copyright (c) 2014 LG Electronics, Inc.
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
 * LICENSE@@@
 */

#include <glib.h>
#include <luna-service2/lunaservice.h>

volatile gboolean hit_reply = FALSE;

/*! [method implementation] */
// callback
static bool
listContacts(LSHandle *sh, LSMessage *message, void *categoryContext)
{
    bool retVal;
    LSError lserror;
    LSErrorInit(&lserror);

    retVal = LSMessageReply(sh, message, "{ JSON REPLY PAYLOAD }", &lserror);
    if (!retVal)
    {
        LSErrorPrint(&lserror, stderr);
        LSErrorFree(&lserror);
    }

    return retVal;
}

static LSMethod ipcMethods[] = {
   { "listContacts", listContacts },
   { },
};
/*! [method implementation] */

static gboolean OnTimeout(gpointer user_data)
{
    g_main_loop_quit((GMainLoop *) user_data);
    return FALSE;
}

static bool listContactsHandler(LSHandle *sh, LSMessage *reply, void *ctx)
{
    printf("Got reply: %s\n", LSMessageGetPayload(reply));
    if (!LSMessageIsHubErrorMessage(reply))
        hit_reply = TRUE;
    g_main_loop_quit((GMainLoop *) ctx);
    return TRUE;
}

static gpointer ClientProc(gpointer data)
{
    GMainLoop *mainLoop = g_main_loop_new(NULL, FALSE);
    gpointer userData = mainLoop;
    g_timeout_add(10000, &OnTimeout, mainLoop);

    /*! [client call] */
    bool retVal;
    LSError lserror;
    LSErrorInit(&lserror);
    LSMessageToken token = LSMESSAGE_TOKEN_INVALID;

    LSHandle *serviceHandle;
    retVal = LSRegister(NULL, &serviceHandle, &lserror);
    if (!retVal) goto error;

    retVal = LSCallOneReply(serviceHandle, "luna://com.palm.contacts/category/listContacts",
                            "{ \"json payload\" }", listContactsHandler, userData, &token, &lserror);
    if (!retVal) goto error;

    LSGmainAttach(serviceHandle, mainLoop, &lserror);
    g_main_loop_run(mainLoop);
    /*! [client call] */

    LSUnregister(serviceHandle, &lserror);
    g_main_loop_unref(mainLoop);
    g_main_loop_quit((GMainLoop *) data); // Finish the service with the client

    return GINT_TO_POINTER(0);

error:
    LSErrorPrint(&lserror, stderr);
    LSErrorFree(&lserror);

    if (serviceHandle) LSUnregister(serviceHandle, &lserror);
    g_main_loop_unref(mainLoop);
    g_main_loop_quit((GMainLoop *) data);
    return GINT_TO_POINTER(1);
}

int main(void)
{
    GMainLoop *mainLoop = g_main_loop_new(NULL, FALSE);
    void *userData = mainLoop;

    g_timeout_add(10000, &OnTimeout, mainLoop);

    GThread *client_thread = g_thread_new(NULL, ClientProc, mainLoop);

    /*! [service registration] */
    bool retVal;
    LSError lserror;
    LSErrorInit(&lserror);

    LSHandle *serviceHandle = NULL;
    retVal = LSRegister("com.palm.contacts", &serviceHandle, &lserror);
    if (!retVal) goto error;

    retVal = LSRegisterCategory(serviceHandle, "/category",  ipcMethods, NULL, NULL, &lserror);
    if (!retVal) goto error;

    retVal = LSCategorySetData(serviceHandle, "/category", userData, &lserror);
    if (!retVal) goto error;

    retVal = LSGmainAttach(serviceHandle, mainLoop, &lserror);
    if (!retVal) goto error;

    g_main_loop_run(mainLoop);
    /*! [service registration] */

    LSUnregister(serviceHandle, &lserror);
    g_main_loop_unref(mainLoop);
    g_thread_join(client_thread);

    if (hit_reply)
    {
        printf("PASS\n");
        return 0;
    }

    printf("FAILED\n");
    return 1;

error:
    LSErrorPrint(&lserror, stderr);
    LSErrorFree(&lserror);

    if (serviceHandle) LSUnregister(serviceHandle, &lserror);
    g_main_loop_unref(mainLoop);
    g_thread_join(client_thread);

    fprintf(stderr, "FAILED\n");
    return 1;
}
