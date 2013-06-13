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

#include <glib.h>
#include <stdio.h>
#include <unistd.h>
#include <cjson/json.h>
#include <luna-service2/lunaservice.h>

#define JSON_ERROR(x) (!x || is_error(x)) 

static int sLogLevel = G_LOG_LEVEL_MESSAGE;

typedef struct MessageInfo {
    const char *uri;
    const char *msg;
    GMainLoop *loop;
} MessageInfo;

static gboolean
_timeout (gpointer data)
{
    g_message("%s: timeout occured", __FUNCTION__);
    GMainLoop *loop = (GMainLoop*)data;
    g_main_loop_quit (loop);
    return FALSE;
}

static bool 
_response(LSHandle *sh, LSMessage *reply, void *ctx)
{
    //LSMessageToken token;
    const char *payload;

    //token = LSMessageGetResponseToken(reply);
    payload = LSMessageGetPayload(reply);

    g_message ("%s: got response %s", __FUNCTION__, payload);

    return true;
}

static bool
_service_status(LSHandle *sh, const char *serviceName, bool connected, void *ctx)
{
    LSError lserror;
    LSErrorInit(&lserror);

    MessageInfo *msg_info = (MessageInfo*)ctx;

    static bool made_call = false;

    if (connected)
    {
        if (!made_call)
        {
            g_message("%s is already on the bus, not doing anything",  serviceName);
        }
        else
        {
            g_message("%s came up",  serviceName);
        }
        g_main_loop_quit(msg_info->loop);
    }
    else
    {
        g_timeout_add(10000, _timeout, msg_info->loop);

        bool retVal = LSCall(sh, msg_info->uri, msg_info->msg, _response, msg_info->loop, NULL, &lserror);
        if (!retVal)
        {
            LSErrorPrint(&lserror, stderr);
            LSErrorFree(&lserror);
            g_main_loop_quit(msg_info->loop);
        }

        made_call = true;
    }

    return true;
}

void
PrintUsage(const char* progname)
{
    printf("%s name uri message\n", progname);
    printf(" -h this help screen\n"
           " -d turn debug logging on\n");
}

void
g_log_filter(const gchar *log_domain,
        GLogLevelFlags log_level,
        const gchar *message,
        gpointer unused_data)
{
    if (log_level > sLogLevel) return;

    g_log_default_handler(log_domain, log_level, message, unused_data);
}

int
main(int argc, char **argv)
{
    int optionCount = 0;
    int opt;

    while ((opt = getopt(argc, argv, "hd")) != -1)
    {
    switch (opt) {
    case 'd':
        sLogLevel = G_LOG_LEVEL_DEBUG;
        optionCount++;
        break;
    case 'h':
    default:
        PrintUsage(argv[0]);
        return 0;
        }
    }

    if (argc < 3 + optionCount) {
        PrintUsage(argv[0]);
        return 0;
    }

    LSError lserror;
    LSErrorInit(&lserror);

    LSHandle *sh = NULL;
    
    GMainLoop *mainLoop = NULL;

    const char * uri = argv[optionCount + 1];
    const char * msg = argv[optionCount + 2];

    struct json_object * serviceJson = NULL;
    char* service = NULL;
    
    struct json_object * msgJson = json_tokener_parse(msg);
    g_return_val_if_fail(!JSON_ERROR(msgJson), -1);
    
    if (!json_object_object_get_ex(msgJson, "serviceName", &serviceJson))
    {
        g_warning("No \"serviceName\" in JSON message");
        goto error;
    }

    if (json_object_get_type(serviceJson) != json_type_string)
    {
        g_warning("serviceName is not a string"); 
        goto error;
    }

    service = json_object_get_string(serviceJson);

    g_log_set_default_handler(g_log_filter, NULL);

    mainLoop = g_main_loop_new(NULL, FALSE); 
    if (NULL == mainLoop) goto error;

    g_return_val_if_fail(mainLoop != NULL, -1);

    bool serviceInit = LSRegister(NULL, &sh, &lserror);
    if (!serviceInit) goto error;

    bool gmainAttach = LSGmainAttach(sh, mainLoop, &lserror);
    if (!gmainAttach) goto error;

    //LSMessageToken sessionToken;
    //bool retVal;

    /* registerServerStatus for the service that we care about and then
     * do the LSCall in the callback */
    MessageInfo msg_info;
    msg_info.uri = uri;
    msg_info.msg = msg;
    msg_info.loop = mainLoop;
   
    g_message("Registering server status for: %s", service);
 
    if (!LSRegisterServerStatus(sh, service, _service_status, &msg_info, &lserror))
    {
        goto error;
    }
    
    g_main_loop_run(mainLoop);

error:
    if (mainLoop)
        g_main_loop_unref(mainLoop);

    if (LSErrorIsSet(&lserror))
    {
        LSErrorPrint(&lserror, stderr);
        LSErrorFree(&lserror);
    }

    if (sh)
    {
        if (!LSUnregister (sh, &lserror))
        {
            LSErrorPrint(&lserror, stderr);
            LSErrorFree(&lserror);
        }
    }

    if (!JSON_ERROR(msgJson)) json_object_put(msgJson);

    return 0;
}
