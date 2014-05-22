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
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <pbnjson.h>

#include "utils.h"
#include "transport.h"
#include "clock.h"
#include "monitor_queue.h"
#include "debug_methods.h"

#define DYNAMIC_SERVICE_STR         "dynamic"
#define STATIC_SERVICE_STR          "static"
#define SUBSCRIPTION_DEBUG_METHOD   "/com/palm/luna/private/subscriptions"
#define MALLOC_DEBUG_METHOD         "/com/palm/luna/private/mallinfo"

#define MONITOR_PID_NAME    "ls-monitor.pid"

#define HUB_TYPE_PUBLIC     1
#define HUB_TYPE_PRIVATE    2

#define TERMINAL_WIDTH_DEFAULT  80
#define TERMINAL_WIDTH_WIDE     100
#define HEADER_WIDTH_DEFAULT    45

#ifdef PUBLIC_ONLY
#define FINAL_MONITOR_NAME MONITOR_NAME_PUB
#else
#define FINAL_MONITOR_NAME MONITOR_NAME
#endif

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

static const char *list_servicename_methods = NULL;
static const char *message_filter_str = NULL;
static gboolean list_clients = false;
static gboolean list_subscriptions = false;
static gboolean list_malloc = false;
static gboolean debug_output = false;
static gboolean compact_output = false;
static gboolean two_line_output = false;
static gboolean sort_by_timestamps = false;
static GMainLoop *mainloop = NULL;

static uint32_t terminal_width = TERMINAL_WIDTH_DEFAULT;

static _LSTransport *transport_pub = NULL;
/* List of _SubscriptionReplyData for public and private hubs */
static GSList *public_sub_replies = NULL;
static bool transport_pub_local = false;
static _LSMonitorQueue *public_queue = NULL;

#ifndef PUBLIC_ONLY
static int hubs_answers_count = 2;
#else
static int hubs_answers_count = 1;
#endif

#ifndef PUBLIC_ONLY
static _LSTransport *transport_priv = NULL;
/* List of _SubscriptionReplyData for public and private hubs */
static GSList *private_sub_replies = NULL;
static bool transport_priv_local = false;
static _LSMonitorQueue *private_queue = NULL;
#endif

/* time1 - time2 */
double
_LSMonitorTimeDiff(const struct timespec const *time1, const struct timespec const *time2)
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
 * Print message timestamp
 */
static int
_LSMonitorPrintTime(const struct timespec *time)
{
    return fprintf(stdout, "%.3f", ((double)(time->tv_sec)) + (((double)time->tv_nsec) / (double)1000000000.0));
}

/**
 * Print monitor message type
 */
static int
_LSMonitorPrintType(const _LSMonitorMessageType message_type)
{
    switch (message_type)
    {
    case _LSMonitorMessageTypeTx:
        return fprintf(stdout, " TX  ");
    case _LSMonitorMessageTypeRx:
        return fprintf(stdout, " RX ");
    default:
        LOG_LS_ERROR(MSGID_LS_UNKNOWN_MSG, 1, PMLOGKFV("TYPE", "%d", message_type), "Unknown monitor message type");
        return fprintf(stdout, " UN ");
    }
}

#ifndef PUBLIC_ONLY
static gboolean
_LSMonitorIdleHandlerPrivate(gpointer data)
{
    _LSMonitorQueue *queue = data;
    _LSMonitorQueuePrint(queue, 1000, dup_hash_table, debug_output);
    return TRUE;
}
#endif

static gboolean
_LSMonitorIdleHandlerPublic(gpointer data)
{
    _LSMonitorQueue *queue = data;
    _LSMonitorQueuePrint(queue, 1000, dup_hash_table, debug_output);
    return TRUE;
}

void
_LSMonitorMessagePrint(_LSTransportMessage *message, bool public_bus)
{
    if (LSTransportMessageFilterMatch(message, message_filter_str))
    {
        const _LSMonitorMessageData *message_data = _LSTransportMessageGetMonitorMessageData(message);

        if (compact_output)
        {
            int nchar = 0;
            nchar += _LSMonitorPrintTime(&message_data->timestamp);
            nchar += _LSMonitorPrintType(message_data->type);
            nchar += fprintf(stdout, public_bus?" pub ":" prv ");

            int mchar = LSTransportMessagePrintCompactHeader(message, stdout);
            if (mchar > 0)
            {
                nchar += mchar;
                if (two_line_output)
                {
#define _PAYLOAD_LEFT_PADDING 14
                    fprintf(stdout, "\n%*s", _PAYLOAD_LEFT_PADDING, " ");
                    nchar = _PAYLOAD_LEFT_PADDING;
                }
                else
                {
                    nchar += fprintf(stdout, " ");
                }

                /* In case length of header exceed terminal_width, use one more line */
                while (terminal_width < nchar)
                {
                    nchar -= terminal_width;
                }

                LSTransportMessagePrintCompactPayload(message, stdout, terminal_width - nchar - 1);
                fprintf(stdout, "\n");
            }
        }
        else
        {
            _LSMonitorPrintTime(&message_data->timestamp);
            _LSMonitorPrintType(message_data->type);
            fprintf(stdout, public_bus?"\t[PUB]\t":"\t[PRV]\t");
            LSTransportMessagePrint(message, stdout);
        }
        fflush(stdout);
    }
}

#ifndef PUBLIC_ONLY
static LSMessageHandlerResult
_LSMonitorMessageHandlerPrivate(_LSTransportMessage *message, void *context)
{
    if (!transport_priv_local || sort_by_timestamps)
    {
        _LSMonitorMessagePrint(message, false);
    }
    else
    {
        /* Queue up messages */
        _LSMonitorQueueMessage(private_queue, message);
    }

    return LSMessageHandlerResultHandled;
}
#endif

static LSMessageHandlerResult
_LSMonitorMessageHandlerPublic(_LSTransportMessage *message, void *context)
{
    if (!transport_pub_local || sort_by_timestamps)
    {
        _LSMonitorMessagePrint(message, true);
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
    for (; info_list != NULL; info_list = g_slist_next(info_list))
    {
        const _LSMonitorListInfo *cur = info_list->data;
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
    if (info->service_name && ((g_strcmp0(info->service_type, DYNAMIC_SERVICE_STR) == 0)
                           || (g_strcmp0(info->service_type, STATIC_SERVICE_STR) == 0)))
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
    fflush(stdout);
}

static void
_PrintSubscriptionResults()
{
#ifndef PUBLIC_ONLY
    fprintf(stdout, list_subscriptions ? "PRIVATE SUBSCRIPTIONS:\n" : "PRIVATE BUS MALLOC DATA:\n");
    _PrintSubscriptionResultsList(private_sub_replies);
#endif

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

#ifndef PUBLIC_ONLY
        g_slist_free(private_sub_replies);
#endif
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

    bool retVal = false;

    _SubscriptionReplyData *data = g_malloc(sizeof(_SubscriptionReplyData));

    /* NOTE: we only allocate one of these items and pass it as the data to all the callbacks */
    data->reply_list = reply_list;
    data->total_replies = total_services;

    for (; monitor_list != NULL; monitor_list = g_slist_next(monitor_list))
    {
        _LSMonitorListInfo *cur = monitor_list->data;

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
#ifndef PUBLIC_ONLY
        _LSTransportDisconnect(transport_priv, true);
        _LSTransportDeinit(transport_priv);
#endif
        _LSTransportDisconnect(transport_pub, true);
        _LSTransportDeinit(transport_pub);
        is_disconnected = true;
    }
}

static LSMessageHandlerResult
_LSMonitorListMessageHandler(_LSTransportMessage *message, void *context)
{
    LS_ASSERT(_LSTransportMessageGetType(message) == _LSTransportMessageTypeListClientsReply);

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
    if (--hubs_answers_count == 0)
    {
        if (list_subscriptions || list_malloc)
        {
            LSError lserror;
            LSErrorInit(&lserror);

#ifndef PUBLIC_ONLY
            LSHandle *private_sh = NULL;
#endif
            LSHandle *public_sh = NULL;

            _DisconnectCustomTransport();

            if (total_sub_services == 0)
            {
                _PrintSubscriptionResults();
                g_main_loop_quit(mainloop);
                goto Done;
            }

#ifndef PUBLIC_ONLY
            /* register as a "high-level" client */
            if (!LSRegisterPubPriv(FINAL_MONITOR_NAME, &private_sh, false, &lserror))
            {
                LSErrorPrint(&lserror, stderr);
                LSErrorFree(&lserror);
            }
            else
            {
                LSGmainAttach(private_sh, mainloop, &lserror);
                _ListServiceSubscriptions(private_sh, _SubscriptionResultsCallback, private_monitor_info, total_sub_services, &private_sub_replies);
            }
#endif

            /* Same for the public hub */
            if (!LSRegisterPubPriv(FINAL_MONITOR_NAME, &public_sh, true, &lserror))
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

static LSMessageHandlerResult
_LSMonitorMethodListMessageHandler(_LSTransportMessage *message, void *context)
{
    LS_ASSERT(_LSTransportMessageGetType(message) == _LSTransportMessageTypeReply);

    int hub_type = *(int*)context;

    JSchemaInfo schemaInfo;

    // TO-DO: Validate against service.schema when
    // local resolver will be available.
    jschema_info_init(&schemaInfo, jschema_all(), NULL, NULL);
    jvalue_ref params = jdom_parse(j_cstr_to_buffer(_LSTransportMessageGetPayload(message)),
                                   DOMOPT_NOOPT, &schemaInfo);

    bool succeeded = false;
    jboolean_get(jobject_get(params, J_CSTR_TO_BUF("returnValue")), &succeeded);

    if (!succeeded)
    {
        fprintf(stdout, "Client returned error instead of methods list: %s.\n",
                jvalue_tostring_simple(jobject_get(params, J_CSTR_TO_BUF("errorText"))));
    }
    else
    {
        fprintf(stdout, "\nMETHODS AND SIGNALS REGISTERED BY SERVICE '%s' WITH UNIQUE NAME '%s' AT %s HUB\n\n",
                _LSTransportMessageGetSenderServiceName(message),
                _LSTransportMessageGetSenderUniqueName(message),
                hub_type == HUB_TYPE_PUBLIC ? "PUBLIC" : "PRIVATE");

        jobject_iter cat_iterator, meth_iterator;
        jobject_key_value category, method;
        jobject_iter_init(&cat_iterator, jobject_get(params, J_CSTR_TO_BUF("categories")));
        while (jobject_iter_next(&cat_iterator, &category))
        {
            fprintf(stdout, "%*s\%s:\n", 2, "", jvalue_tostring_simple(category.key));

            jobject_iter_init(&meth_iterator, jobject_get(category.value, J_CSTR_TO_BUF("methods")));
            while (jobject_iter_next(&meth_iterator, &method))
            {
                fprintf(stdout, "%*s\%s: %s\n", 6, "", jvalue_tostring_simple(method.key), jvalue_tostring_simple(method.value));
            }
        }
    }

    if (--hubs_answers_count == 0)
        g_main_loop_quit(mainloop);

    return LSMessageHandlerResultHandled;
}

void
_LSMonitorMethodListFailureHandler(LSMessageToken global_token, _LSTransportMessageFailureType failure_type, void *context)
{
    int type = *(int*)context;
    const char *hub_name = HUB_TYPE_PUBLIC == type ? "public" : "private";

    switch (failure_type)
    {
    case _LSTransportMessageFailureTypeServiceNotExist:
        fprintf(stdout, "Service '%s' is not registered at %s hub\n",
                list_servicename_methods, hub_name);
        break;
    case _LSTransportMessageFailureTypeServiceUnavailable:
        fprintf(stdout, "Service '%s' currently is not available at %s hub\n",
                list_servicename_methods, hub_name);
        break;
    default:
        fprintf(stdout, "Recieved error from %s hub for service '%s': %d\n",
                hub_name, list_servicename_methods, failure_type);
    }

    if (--hubs_answers_count == 0)
        g_main_loop_quit(mainloop);
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
        {"introspection", 'i', 0, G_OPTION_ARG_STRING, &list_servicename_methods, "List service methods and signals", "com.palm.foo"},
        {"malloc", 'm', 0, G_OPTION_ARG_NONE, &list_malloc, "List malloc data from all services in the system", NULL},
        {"debug", 'd', 0, G_OPTION_ARG_NONE, &debug_output, "Print extra output for debugging monitor but with UNBOUNDED MEMORY GROWTH", NULL},
        {"compact", 'c', 0, G_OPTION_ARG_NONE, &compact_output, "Print compact output to fit terminal. Take precedence over debug", NULL},
        {"sort-by-timestamps", 't', 0, G_OPTION_ARG_NONE, &sort_by_timestamps, "Sort output by timestamps instead of serials", NULL},
        { NULL }
    };

    opt_context = g_option_context_new("- Luna Service monitor");
    g_option_context_add_main_entries(opt_context, opt_entries, NULL);
    g_option_context_set_description(opt_context, ""
"Compact mode symbols:\n"
"   >*      signal\n"
"   >|      cancel method call\n"
"    >      method call\n"
"   <       reply");

    if (!g_option_context_parse(opt_context, &argc, &argv, &gerror))
    {
        g_critical("Error processing commandline args: %s", gerror->message);
        g_error_free(gerror);
        exit(EXIT_FAILURE);
    }

    g_option_context_free(opt_context);

#ifndef INTROSPECTION_DEBUG
    if (list_servicename_methods)
    {
        g_message("Library is built without introspection support, please rebuild with INTROSPECTION_DEBUG.");
        exit(EXIT_FAILURE);
    }
#endif

    if (compact_output)
    {
        debug_output = false;
    }

    if (debug_output)
    {
        g_warning("extra output for debugging monitor enabled, causes UNBOUNDED MEMORY GROWTH");
    }
}

static void
_HandleTerminal()
{
#ifdef TIOCGWINSZ
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);

    if (w.ws_col > TERMINAL_WIDTH_DEFAULT)
    {
        terminal_width = w.ws_col;
    }
#endif
    two_line_output = terminal_width < TERMINAL_WIDTH_WIDE;
}

#ifdef SIGWINCH
static void
_HandleWindowChange(int signal)
{
    terminal_width = TERMINAL_WIDTH_DEFAULT;
    _HandleTerminal();
}
#endif

int
main(int argc, char *argv[])
{
    LSError lserror;
    LSErrorInit(&lserror);

    int public = HUB_TYPE_PUBLIC;
#ifndef PUBLIC_ONLY
    int private = HUB_TYPE_PRIVATE;
#endif

    if (LSIsRunning(PID_DIR, MONITOR_PID_NAME))
    {
        g_critical("An instance of the monitor is already running");
        exit(EXIT_FAILURE);
    }

    mainloop = g_main_loop_new(NULL, FALSE);

    /* send message to hub to let clients know that they should start
     * sending us their messages */
#ifndef PUBLIC_ONLY
    LSTransportHandlers handler_priv =
    {
        .msg_handler = _LSMonitorMessageHandlerPrivate,
        .msg_context = &private,
        .disconnect_handler = NULL,
        .disconnect_context = NULL,
        .message_failure_handler = NULL,
        .message_failure_context = NULL
    };
#endif

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
#ifdef SIGWINCH
    _LSTransportSetupSignalHandler(SIGWINCH, _HandleWindowChange);
#endif
    _HandleCommandline(argc, argv);
    _HandleTerminal();

    if (list_clients || list_subscriptions || list_malloc)
    {
#ifndef PUBLIC_ONLY
        handler_priv.msg_handler = _LSMonitorListMessageHandler;
#endif
        handler_pub.msg_handler = _LSMonitorListMessageHandler;
    }
    else if (list_servicename_methods)
    {
#ifndef PUBLIC_ONLY
        handler_priv.msg_handler = _LSMonitorMethodListMessageHandler;
        handler_priv.message_failure_handler = _LSMonitorMethodListFailureHandler;
        handler_priv.message_failure_context = &private;
#endif
        handler_pub.msg_handler = _LSMonitorMethodListMessageHandler;
        handler_pub.message_failure_handler = _LSMonitorMethodListFailureHandler;
        handler_pub.message_failure_context = &public;
    }

#ifndef PUBLIC_ONLY
    if (!_LSTransportInit(&transport_priv, FINAL_MONITOR_NAME, &handler_priv, &lserror))
    {
        goto error;
    }
#endif

    if (!_LSTransportInit(&transport_pub, FINAL_MONITOR_NAME, &handler_pub, &lserror))
    {
        goto error;
    }

#ifndef PUBLIC_ONLY
    /* connect for "private" messages */
    if (!_LSTransportConnect(transport_priv, true, false, &lserror))
    {
        goto error;
    }
#endif

    /* connect for "public" messages */
    if (!_LSTransportConnect(transport_pub, true, true, &lserror))
    {
        goto error;
    }

#ifndef PUBLIC_ONLY
    _LSTransportGmainAttach(transport_priv, g_main_loop_get_context(mainloop));
#endif
    _LSTransportGmainAttach(transport_pub, g_main_loop_get_context(mainloop));

#ifndef PUBLIC_ONLY
    if (_LSTransportGetTransportType(transport_priv) == _LSTransportTypeLocal)
    {
        transport_priv_local = true;

        /* message printing callback */
        //g_idle_add(_LSMonitorIdleHandlerPrivate, NULL);
        private_queue = _LSMonitorQueueNew(false);
        g_timeout_add(500, _LSMonitorIdleHandlerPrivate, private_queue);
    }
#endif

    if (_LSTransportGetTransportType(transport_pub) == _LSTransportTypeLocal)
    {
        transport_pub_local = true;

        //g_idle_add(_LSMonitorIdleHandlerPublic, NULL);
        public_queue = _LSMonitorQueueNew(true);
        g_timeout_add(500, _LSMonitorIdleHandlerPublic, public_queue);
    }

    if (list_clients || list_subscriptions || list_malloc)
    {
#ifndef PUBLIC_ONLY
        if (!_LSTransportSendMessageListClients(transport_priv, &lserror))
        {
            goto error;
        }
#endif

        if (!_LSTransportSendMessageListClients(transport_pub, &lserror))
        {
            goto error;
        }
    }
    else if (list_servicename_methods)
    {
#ifndef PUBLIC_ONLY
        if (!_LSTransportSendMessageListServiceMethods(transport_priv, list_servicename_methods, &lserror))
        {
            goto error;
        }
#endif

        if (!_LSTransportSendMessageListServiceMethods(transport_pub, list_servicename_methods, &lserror))
        {
            goto error;
        }
    }
    else
    {
        /* send the message to the hub to tell clients to connect to us */
#ifndef PUBLIC_ONLY
        if (!LSTransportSendMessageMonitorRequest(transport_priv, &lserror))
        {
            goto error;
        }
#endif

        if (!LSTransportSendMessageMonitorRequest(transport_pub, &lserror))
        {
            goto error;
        }

        if (debug_output)
        {
            fprintf(stdout, "Debug\t\tTime\tStatus\tProt\tType\tSerial\t\tSender\t\tDestination\t\tMethod                            \tPayload\n");
        }
        else if (compact_output)
        {
            fprintf(stdout, "Time \tStatus Prot&Type Caller.Serial Callee/Method Payload\n");
        }
        else
        {
            fprintf(stdout, "Time\tStatus\tProt\tType\tSerial\t\tSender\t\tDestination\t\tMethod                            \tPayload\n");
        }
        fflush(stdout);
    }

    dup_hash_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

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
