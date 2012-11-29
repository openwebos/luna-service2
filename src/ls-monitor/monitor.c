/* @@@LICENSE
*
*      Copyright (c) 2008-2012 Hewlett-Packard Development Company, L.P.
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
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#ifdef __APPLE__
#include <mach/mach_time.h>
#endif

#include "utils.h"
#include "transport.h"
#include "monitor_queue.h"

#define DYNAMIC_SERVICE_STR         "dynamic"
#define STATIC_SERVICE_STR          "static"
#define SUBSCRIPTION_DEBUG_METHOD   "/com/palm/luna/private/subscriptions"
#define MALLOC_DEBUG_METHOD         "/com/palm/luna/private/mallinfo"

#define MONITOR_PID_NAME    "ls-monitor.pid"

#define HUB_TYPE_PUBLIC     1
#define HUB_TYPE_PRIVATE    2

typedef struct LSMonitorListInfo
{
    char *unique_name;
    char *service_name;
    int32_t pid;
    char *exe_path;
    char *service_type;
} _LSMonitorListInfo;

typedef struct SubscriptionReplyData
{
    GSList **reply_list;
    int total_replies;
} _SubscriptionReplyData;

static GHashTable *dup_hash_table;

static const char *message_filter_str = NULL;
static gboolean list_clients = false;
static gboolean list_subscriptions = false;
static gboolean list_malloc = false;
static gboolean debug_output = false;
static GMainLoop *mainloop = NULL;

static _LSTransport *transport_priv = NULL;
static _LSTransport *transport_pub = NULL;

/* List of _SubscriptionReplyData for public and private hubs */
static GSList *private_sub_replies = NULL;
static GSList *public_sub_replies = NULL;

static bool transport_priv_local = false;
static bool transport_pub_local = false;

static _LSMonitorQueue *public_queue = NULL;
static _LSMonitorQueue *private_queue = NULL;

void
_LSMonitorGetTime(struct timespec *time)
{
#ifdef __APPLE__
    static mach_timebase_info_data_t info = {0,0};  
  
    if (info.denom == 0) {
      mach_timebase_info(&info);
    }
    uint64_t curtime = mach_absolute_time() * (info.numer / info.denom);
    time->tv_sec = curtime * 1e-9;
    time->tv_nsec = curtime - (time->tv_sec * 1e9);
#else
    clock_gettime(CLOCK_MONOTONIC, time);
#endif
}

/* time1 - time2 */
double
_LSMonitorTimeDiff(struct timespec *time1, struct timespec *time2)
{
    double diff_time;

    /* local variable because we might modify it */
    long time1_nsec = time1->tv_nsec;

    diff_time = (double)(time1->tv_sec - time2->tv_sec);

    if (time1->tv_nsec < time2->tv_nsec) {
        diff_time--;
        time1_nsec = time1->tv_nsec + 1000000000;
    }
    diff_time += ((double)(time1_nsec - time2->tv_nsec) / (double)(1000000000.0));

    return diff_time;
}

/**
 * Print the time that a message was *received*. It doesn't give us the
 * actual time that the message was sent, but it's the best that we can
 * do without sending a timestamp in the message itself
 */
static void
_LSMonitorPrintTime(struct timespec *time)
{
    fprintf(stdout, "%.3f\t", ((double)(time->tv_sec)) + (((double)time->tv_nsec) / (double)1000000000.0));
}

static gboolean
_LSMonitorIdleHandlerPrivate(gpointer data)
{
    _LSMonitorQueue *queue = data;
    _LSMonitorQueuePrint(queue, 1000, dup_hash_table, debug_output);
    return TRUE;
}

static gboolean
_LSMonitorIdleHandlerPublic(gpointer data)
{
    _LSMonitorQueue *queue = data;
    _LSMonitorQueuePrint(queue, 1000, dup_hash_table, debug_output);
    return TRUE;
}

void
_LSMonitorMessagePrint(_LSTransportMessage *message, struct timespec *time, bool public_bus)
{
    if (LSTransportMessageFilterMatch(message, message_filter_str))
    {
        if (time)
        {
            _LSMonitorPrintTime(time);
        }
        else
        {
            struct timespec now;
            _LSMonitorGetTime(&now);
            _LSMonitorPrintTime(&now);
        }

        if (public_bus)
        {
            fprintf(stdout, "[PUB]\t");    
        }
        else
        {
            fprintf(stdout, "[PRV]\t");    
        } 
        LSTransportMessagePrint(message, stdout);
    }
}

static LSMessageHandlerResult
_LSMonitorMessageHandlerPrivate(_LSTransportMessage *message, void *context)
{
    if (!transport_priv_local)
    {
        _LSMonitorMessagePrint(message, NULL, false);
    }
    else
    {
        /* Queue up messages */
        _LSMonitorQueueMessage(private_queue, message);
    }

    return LSMessageHandlerResultHandled;
}

static LSMessageHandlerResult
_LSMonitorMessageHandlerPublic(_LSTransportMessage *message, void *context)
{
    if (!transport_pub_local)
    {
        _LSMonitorMessagePrint(message, NULL, true);
    }
    else
    {
        /* Queue up messages */
        _LSMonitorQueueMessage(public_queue, message);
    }

    return LSMessageHandlerResultHandled;
}

static void
_PrintMonitorListInfo(const GSList *info_list)
{
    _LSMonitorListInfo *cur = NULL;
    for (; info_list != NULL; info_list = g_slist_next(info_list))
    {
        cur = info_list->data;
        fprintf(stdout, "%-10d\t%-30s\t%-35s\t%-20s\t%-20s\n",
                cur->pid, cur->service_name, cur->exe_path, cur->service_type, cur->unique_name);
    }
}

static void
_FreeMonitorListInfoItem(_LSMonitorListInfo *info)
{
    LS_ASSERT(info != NULL);
    g_free(info->unique_name);
    g_free(info->service_name);
    g_free(info->exe_path);
    g_free(info->service_type);
    g_free(info);
}

static void
_FreeMonitorListInfo(GSList **list)
{
    for (; *list != NULL; *list = g_slist_next(*list))
    {
        _LSMonitorListInfo *info = (*list)->data;
        if (info) _FreeMonitorListInfoItem(info);
        *list = g_slist_delete_link(*list, *list);
    } 
}

static bool
_CanGetSubscriptionInfo(_LSMonitorListInfo *info)
{
    /* Needs to have a valid service name and be dynamic
     * or static (i.e., not a client)
     */
    if (info->service_name && ((strcmp(info->service_type, DYNAMIC_SERVICE_STR) == 0)
                           || (strcmp(info->service_type, STATIC_SERVICE_STR) == 0)))
    {
        return true;
    }
    return false;
}

static void
_PrintSubscriptionResultsList(GSList *sub_list)
{
    for (; sub_list != NULL; sub_list = g_slist_next(sub_list))
    {
        LSMessage *msg = sub_list->data;

        /* We may get error messages if the service goes down between the
         * time we find out about it and send the subscription info request */
        if (!LSMessageIsHubErrorMessage(msg))
        {
            const char *sub_text = LSMessageGetPayload(msg);
            const char *service = LSMessageGetSenderServiceName(msg);
            fprintf(stdout, "%s: %s\n", service, sub_text);
        }

        LSMessageUnref(msg);
    }
    fprintf(stdout, "\n");
}

static void
_PrintSubscriptionResults()
{
    fprintf(stdout, list_subscriptions ? "PRIVATE SUBSCRIPTIONS:\n" : "PRIVATE BUS MALLOC DATA:\n");
    _PrintSubscriptionResultsList(private_sub_replies);

    fprintf(stdout, list_subscriptions ? "PUBLIC SUBSCRIPTIONS:\n" : "PUBLIC BUS MALLOC DATA:\n");
    _PrintSubscriptionResultsList(public_sub_replies);
}

static bool
_SubscriptionResultsCallback(LSHandle *sh, LSMessage *reply, void *ctx)
{
    static int received_replies = 0;
    _SubscriptionReplyData *reply_data = ctx;
 
    LSMessageRef(reply);
    (*reply_data->reply_list) = g_slist_prepend((*reply_data->reply_list), reply);

    received_replies++;

    if (received_replies == reply_data->total_replies)
    {
        _PrintSubscriptionResults();

        g_slist_free(private_sub_replies);
        g_slist_free(public_sub_replies);
    
        g_free(reply_data);

        /* done */
        g_main_loop_quit(mainloop);
    }


    return true;
}

static void
_ListServiceSubscriptions(LSHandle *sh, LSFilterFunc callback, GSList *monitor_list, int total_services,
                          GSList **reply_list)
{
    LSError lserror;
    LSErrorInit(&lserror);

    _LSMonitorListInfo *cur = NULL;
    bool retVal = false;

    _SubscriptionReplyData *data = g_malloc(sizeof(_SubscriptionReplyData));

    if (!data)
    {
        g_critical("Out of memory when allocating reply data");
        exit(EXIT_FAILURE);
    }

    /* NOTE: we only allocate one of these items and pass it as the data to all the callbacks */
    data->reply_list = reply_list;
    data->total_replies = total_services;

    for (; monitor_list != NULL; monitor_list = g_slist_next(monitor_list))
    {
        cur = monitor_list->data;
        
        /* skip any non-services and the monitor itself */
        if (!_CanGetSubscriptionInfo(cur))
        {
            continue;
        }

        char *uri = g_strconcat("palm://", cur->service_name, list_subscriptions ? SUBSCRIPTION_DEBUG_METHOD : MALLOC_DEBUG_METHOD, NULL);

        retVal = LSCall(sh, uri, "{}", callback, data, NULL, &lserror);
        if (!retVal)
        {
            LSErrorPrint(&lserror, stderr);
            LSErrorFree(&lserror);
        }
        g_free(uri);
    }
}

static void
_DisconnectCustomTransport()
{
    static bool is_disconnected = false;

    if (!is_disconnected)
    {
        _LSTransportDisconnect(transport_priv, true);
        _LSTransportDeinit(transport_priv);
        _LSTransportDisconnect(transport_pub, true);
        _LSTransportDeinit(transport_pub);
        is_disconnected = true;
    }
}

static LSMessageHandlerResult
_LSMonitorListMessageHandler(_LSTransportMessage *message, void *context)
{
    LS_ASSERT(_LSTransportMessageGetType(message) == _LSTransportMessageTypeListClientsReply);

    static int call_count = 0;
    const char *unique_name = NULL;
    const char *service_name = NULL;
    int32_t pid = 0;
    const char *exe_path = NULL;
    const char *service_type = NULL;
    static int total_sub_services = 0;

    int type = *(int*)context;
    bool iter_ret = false;

    static GSList *public_monitor_info = NULL;
    static GSList *private_monitor_info = NULL;
 
    GSList **cur_list = NULL;

    _LSTransportMessageIter iter;

    if (type == HUB_TYPE_PUBLIC)
    {
        cur_list = &public_monitor_info;
    }
    else
    {
        cur_list = &private_monitor_info;
    }
    
    _LSTransportMessageIterInit(message, &iter);

    while (_LSTransportMessageIterHasNext(&iter))
    {
        _LSMonitorListInfo *info = g_malloc(sizeof(_LSMonitorListInfo));

        if (!info)
        {
            g_critical("Out of memory when allocating list info");
            exit(EXIT_FAILURE);
        }

        iter_ret = _LSTransportMessageGetString(&iter, &unique_name);
        if (!iter_ret) break;
        info->unique_name = g_strdup(unique_name);
        _LSTransportMessageIterNext(&iter);

        iter_ret = _LSTransportMessageGetString(&iter, &service_name);
        if (!iter_ret) break;
        info->service_name = g_strdup(service_name);
        _LSTransportMessageIterNext(&iter);

        iter_ret = _LSTransportMessageGetInt32(&iter, &pid);
        if (!iter_ret) break;
        info->pid = pid;
        _LSTransportMessageIterNext(&iter);
    
        iter_ret = _LSTransportMessageGetString(&iter, &exe_path);
        if (!iter_ret) break;
        info->exe_path = g_strdup(exe_path);
        _LSTransportMessageIterNext(&iter);

        iter_ret = _LSTransportMessageGetString(&iter, &service_type);
        if (!iter_ret) break;
        info->service_type = g_strdup(service_type);
        _LSTransportMessageIterNext(&iter);

        if (_CanGetSubscriptionInfo(info))
        {
            total_sub_services++;
        }
       
        *cur_list = g_slist_prepend(*cur_list, info);
    }

    /* Process and display when we receive public and private responses */
    if (++call_count == 2)
    {
        if (list_subscriptions || list_malloc)
        {
            LSError lserror;
            LSErrorInit(&lserror);

            LSHandle *private_sh = NULL;
            LSHandle *public_sh = NULL;

            _DisconnectCustomTransport();

            if (total_sub_services == 0)
            {
                _PrintSubscriptionResults();
                g_main_loop_quit(mainloop);
                goto Done;
            }

            /* register as a "high-level" client */
            if (!LSRegisterPubPriv(MONITOR_NAME, &private_sh, false, &lserror))
            {
                LSErrorPrint(&lserror, stderr);
                LSErrorFree(&lserror);
            }
            else
            {
                LSGmainAttach(private_sh, mainloop, &lserror);
                _ListServiceSubscriptions(private_sh, _SubscriptionResultsCallback, private_monitor_info, total_sub_services, &private_sub_replies);
            }

            /* Same for the public hub */
            if (!LSRegisterPubPriv(MONITOR_NAME, &public_sh, true, &lserror))
            {
                LSErrorPrint(&lserror, stderr);
                LSErrorFree(&lserror);
            }
            else
            {
                LSGmainAttach(public_sh, mainloop, &lserror);
                _ListServiceSubscriptions(public_sh, _SubscriptionResultsCallback, public_monitor_info, total_sub_services, &public_sub_replies);
            }
        }
        else if (list_clients)
        {
            fprintf(stdout, "PRIVATE HUB CLIENTS:\n");
            fprintf(stdout, "%-10s\t%-30s\t%-35s\t%-20s\t%-20s\n", "PID", "SERVICE NAME", "EXE", "TYPE", "UNIQUE NAME");
            _PrintMonitorListInfo(private_monitor_info);
            fprintf(stdout, "\n");
            _FreeMonitorListInfo(&private_monitor_info);
 
            fprintf(stdout, "PUBLIC HUB CLIENTS:\n");
            fprintf(stdout, "%-10s\t%-30s\t%-35s\t%-20s\t%-20s\n", "PID", "SERVICE NAME", "EXE", "TYPE", "UNIQUE NAME");
            _PrintMonitorListInfo(public_monitor_info);
            fprintf(stdout, "\n");
            _FreeMonitorListInfo(&public_monitor_info);
        
            g_main_loop_quit(mainloop);
        }
    }

Done:
    return LSMessageHandlerResultHandled;
}

static void
_HandleShutdown(int signal)
{
    g_main_loop_quit(mainloop);
}

static void
_HandleCommandline(int argc, char *argv[])
{
    GError *gerror = NULL;
    GOptionContext *opt_context = NULL;

    /* handle commandline args */
    static GOptionEntry opt_entries[] =
    {
        {"filter", 'f', 0, G_OPTION_ARG_STRING, &message_filter_str, "Filter by service name (or unique name)", "com.palm.foo"},
        {"list", 'l', 0, G_OPTION_ARG_NONE, &list_clients, "List all entities connected to the hub", NULL},
        {"subscriptions", 's', 0, G_OPTION_ARG_NONE, &list_subscriptions, "List all subscriptions in the system", NULL},
        {"malloc", 'm', 0, G_OPTION_ARG_NONE, &list_malloc, "List malloc data from all services in the system", NULL},
        {"debug", 'd', 0, G_OPTION_ARG_NONE, &debug_output, "Print extra output for debugging monitor but with UNBOUNDED MEMORY GROWTH", NULL},
        { NULL }
    };
    
    opt_context = g_option_context_new("- Luna Service monitor");
    g_option_context_add_main_entries(opt_context, opt_entries, NULL);

    if (!g_option_context_parse(opt_context, &argc, &argv, &gerror))
    {
        g_critical("Error processing commandline args: %s", gerror->message);
        g_error_free(gerror);
        exit(EXIT_FAILURE);
    }

    g_option_context_free(opt_context);

    if (debug_output)
    {
        g_warning("extra output for debugging monitor enabled, causes UNBOUNDED MEMORY GROWTH");
    }
}

int
main(int argc, char *argv[])
{
    LSError lserror;
    LSErrorInit(&lserror);

    int public = HUB_TYPE_PUBLIC;
    int private = HUB_TYPE_PRIVATE;
    
    if (LSIsRunning(PID_DIR, MONITOR_PID_NAME))
    {
        g_critical("An instance of the monitor is already running");
        exit(EXIT_FAILURE);
    }
    
    mainloop = g_main_loop_new(NULL, FALSE);

    /* send message to hub to let clients know that they should start
     * sending us their messages */
    LSTransportHandlers handler_priv =
    {
        .msg_handler = _LSMonitorMessageHandlerPrivate,
        .msg_context = &private,
        .disconnect_handler = NULL,
        .disconnect_context = NULL,
        .message_failure_handler = NULL,
        .message_failure_context = NULL
    };
    
    LSTransportHandlers handler_pub =
    {
        .msg_handler = _LSMonitorMessageHandlerPublic,
        .msg_context = &public,
        .disconnect_handler = NULL,
        .disconnect_context = NULL,
        .message_failure_handler = NULL,
        .message_failure_context = NULL
    };

    _LSTransportSetupSignalHandler(SIGTERM, _HandleShutdown);
    _LSTransportSetupSignalHandler(SIGINT, _HandleShutdown);

    _HandleCommandline(argc, argv);

    if (list_clients || list_subscriptions || list_malloc)
    {
        handler_priv.msg_handler = _LSMonitorListMessageHandler;
        handler_pub.msg_handler = _LSMonitorListMessageHandler;
    }

    if (!_LSTransportInit(&transport_priv, MONITOR_NAME, &handler_priv, &lserror))
    {
        goto error;
    }
    
    if (!_LSTransportInit(&transport_pub, MONITOR_NAME, &handler_pub, &lserror))
    {
        goto error;
    }
   
    /* connect for "private" messages */ 
    if (!_LSTransportConnect(transport_priv, true, false, &lserror))
    {
        goto error;
    }

    /* connect for "public" messages */
    if (!_LSTransportConnect(transport_pub, true, true, &lserror))
    {
        goto error;
    }
   
    _LSTransportGmainAttach(transport_priv, g_main_loop_get_context(mainloop)); 
    _LSTransportGmainAttach(transport_pub, g_main_loop_get_context(mainloop)); 

    if (_LSTransportGetTransportType(transport_priv) == _LSTransportTypeLocal)
    {
        transport_priv_local = true;

        /* message printing callback */
        //g_idle_add(_LSMonitorIdleHandlerPrivate, NULL);
        private_queue = _LSMonitorQueueNew(false);
        g_timeout_add(500, _LSMonitorIdleHandlerPrivate, private_queue);
    }

    if (_LSTransportGetTransportType(transport_pub) == _LSTransportTypeLocal)
    {
        transport_pub_local = true;
        
        //g_idle_add(_LSMonitorIdleHandlerPublic, NULL);
        public_queue = _LSMonitorQueueNew(true);
        g_timeout_add(500, _LSMonitorIdleHandlerPublic, public_queue);
    }

    if (list_clients || list_subscriptions || list_malloc)
    {
        if (!_LSTransportSendMessageListClients(transport_priv, &lserror))
        {
            goto error;
        }

        if (!_LSTransportSendMessageListClients(transport_pub, &lserror))
        {
            goto error;
        }
    } 
    else
    {
        /* send the message to the hub to tell clients to connect to us */
        if (!LSTransportSendMessageMonitorRequest(transport_priv, &lserror))
        {
            goto error;
        }
        
        if (!LSTransportSendMessageMonitorRequest(transport_pub, &lserror))
        {
            goto error;
        }

        if (debug_output)
        {
            fprintf(stdout, "Debug\tTime\t\tProt\tType\tSerial\t\tSender\t\tDestination\t\tMethod                            \tPayload\n");
        }
        else
        {
            fprintf(stdout, "Time\t\tProt\tType\tSerial\t\tSender\t\tDestination\t\tMethod                            \tPayload\n");
        }
    }

    dup_hash_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    LS_ASSERT(dup_hash_table);

    g_main_loop_run(mainloop);
    g_main_loop_unref(mainloop);

    _DisconnectCustomTransport();

    g_hash_table_destroy(dup_hash_table);

    exit(EXIT_SUCCESS);

error:
    LSErrorPrint(&lserror, stderr);
    LSErrorFree(&lserror);
    exit(EXIT_FAILURE);
}
