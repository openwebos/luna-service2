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
#include "transport.h"
#include "transport_priv.h" /* LSTransport */
#include "base.h" /*LSHandle*/

/* Variables ******************************************************************/

/* Not in transport.h */
gboolean _LSTransportSendClient(GIOChannel *source, GIOCondition condition, gpointer data);

int calls_to_disconnect;
int calls_to_shmdeinit;
int calls_to_channeldeinit;
int calls_to_channelclose;
int calls_to_clientref;
int calls_to_clientunref;
int calls_to_shminit;
int calls_to_connectclient;
int calls_to_messagenewref;
int calls_to_messageref;
int calls_to_messageunref;
int calls_to_messagesettype;
int calls_to_messageiterhasnext;
int expected_calls_to_messagesettype = -1;
int headerlen = sizeof(_LSTransportHeader);
_LSTransportMessageType headertype = _LSTransportMessageTypeMethodCall;
_LSTransportMessageType *expected_message_types; /*Array*/
gboolean flush_and_shutdown;
gboolean use_shared_memory;
gboolean has_send_watch = false;
gboolean has_recv_watch = false;
gboolean sendfd_success = true;
gboolean sendfd_need_retry = false;
_LSTransportChannel *listen_channel;
_LSTransportShm *my_shm;
struct LSTransport *this_transport;

void
clear_counters()
{
    calls_to_disconnect = 0;
    calls_to_channeldeinit = 0;
    calls_to_channelclose = 0;
    calls_to_shmdeinit = 0;
    calls_to_clientref = 0;
    calls_to_clientunref = 0;
    calls_to_shminit = 0;
    calls_to_connectclient = 0;
    calls_to_messageunref = 0;
    calls_to_messagenewref = 0;
    calls_to_messageref = 0;
    calls_to_messagesettype = 0;
    calls_to_messageiterhasnext = 0;
    expected_calls_to_messagesettype = 0;
    flush_and_shutdown = false;
    use_shared_memory = false;
    this_transport = NULL;
    headertype = 0;

    _LSTransportMessageType typelist[0] = {};
    expected_message_types = typelist;
}

/* Not a mock function. For internal cleanup purposes.
   Use for example with the following code block:
while(g_hash_table_size(transport->clients) > 0)
{
    g_hash_table_foreach_remove(transport->clients, (GHRFunc)TransportClientUnref, NULL);
}
*/
/*
gboolean
TransportClientUnref(gpointer key, gpointer value, gpointer user_data)
{
    _LSTransportClient *client = (_LSTransportClient*)value;
    calls_to_clientunref++;
    client->ref--;

    gboolean free_struct = (client->ref == 0);

    if(free_struct)
    {
        if(client->incoming != NULL)
        {
            g_queue_free(client->incoming->complete_messages);
            g_slice_free(_LSTransportIncoming, client->incoming);
        }
        if(client->outgoing != NULL)
        {
            g_queue_free(client->outgoing->queue);
            g_slice_free(_LSTransportOutgoing, client->outgoing);
        }
        g_slice_free(_LSTransportClient, client);
    }

    return free_struct;
}
*/

/* Mocks **********************************************************************/

LSMessageHandlerResult
message_return_value = LSMessageHandlerResultHandled;
                                            /*LSMessageHandlerResultNotHandled*/
                                            /*LSMessageHandlerResultUnknownMethod*/

static LSMessageHandlerResult
MessageHandler(_LSTransportMessage *message, void *context)
{
    return message_return_value;
}

void
DisconnectHandler(_LSTransportClient *client, _LSTransportDisconnectType type, void *context)
{
    calls_to_disconnect++;
}
void
FailureHandler(LSMessageToken global_token, _LSTransportMessageFailureType failure_type, void *context)
{
}

_LSTransport*
_LSTransportClientGetTransport(const _LSTransportClient *client)
{
    return this_transport;
}

// PmLogLib.h
PmLogErr _PmLogMsgKV(PmLogContext context, PmLogLevel level, unsigned int flags,
                     const char *msgid, size_t kv_count, const char *check_keywords,
                     const char *check_formats, const char *fmt, ...)
{
    if (level == kPmLogLevel_Debug) return kPmLogErr_None;

    va_list args;

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    putc('\n', stderr);

    // Added to simulate glib error behaviour
    g_assert(false);

    return kPmLogErr_None;
}

void
_LSTransportChannelClose(_LSTransportChannel *channel, bool flush)
{
    calls_to_channelclose++;
    g_assert(flush == flush_and_shutdown);
}

void
_LSTransportChannelDeinit(_LSTransportChannel *channel)
{
    calls_to_channeldeinit++;
}

void
_LSTransportShmDeinit(_LSTransportShm **shm)
{
    calls_to_shmdeinit++;
    g_assert(*shm == my_shm);
}

void
_LSTransportClientRef(_LSTransportClient *client)
{
    calls_to_clientref++;
    client->ref++;
}

void
_LSTransportClientUnref(_LSTransportClient *client)
{
    calls_to_clientunref++;
    client->ref--;

    g_assert_cmpint(client->ref, >=, 0);
    if(client->ref == 0)
    {
        if(client->incoming)
        {
            while (!g_queue_is_empty(client->incoming->complete_messages))
            {
                _LSTransportMessage *message = g_queue_pop_head(client->incoming->complete_messages);
                _LSTransportMessageUnref(message);
            }
            g_queue_free(client->incoming->complete_messages);
            g_slice_free(_LSTransportIncoming, client->incoming);
        }
        if(client->outgoing)
        {
            while (!g_queue_is_empty(client->outgoing->queue))
            {
                _LSTransportMessage *message = g_queue_pop_head(client->outgoing->queue);
                _LSTransportMessageUnref(message);
            }
            g_queue_free(client->outgoing->queue);
            g_slice_free(_LSTransportOutgoing, client->outgoing);
        }
        g_slice_free(_LSTransportClient, client);
    }
}

bool
_LSTransportShmInit(_LSTransportShm** shm, bool public_bus, LSError* lserror)
{
    calls_to_shminit++;
    return use_shared_memory;
}

_LSTransportClient*
_LSTransportConnectClient(_LSTransport *transport, const char *service_name, const char *unique_name, int connected_fd, _LSTransportOutgoing *outgoing, LSError *lserror)
{
    calls_to_connectclient++;
    return NULL; //TODO
}

_LSTransportMessage*
_LSTransportMessageNewRef(unsigned long payload_size)
{
    calls_to_messagenewref++;

    _LSTransportMessage *message = g_slice_new0(_LSTransportMessage);
    message->raw = g_malloc(sizeof(_LSTransportMessageRaw) + payload_size);
    message->raw->header.len = payload_size;
    message->ref = 1;

    return message;
}

_LSTransportMessage*
_LSTransportMessageRef(_LSTransportMessage *message)
{
    calls_to_messageref++;
    message->ref++;

    return message;
}

void
_LSTransportMessageUnref(_LSTransportMessage *message)
{
    calls_to_messageunref++;
    message->ref--;

    if(message->ref == 0)
    {
        _LSTransportMessageFree(message);
    }
}

void
_LSTransportMessageSetType(_LSTransportMessage *message, _LSTransportMessageType type)
{
    g_assert_cmpint(type, ==, expected_message_types[calls_to_messagesettype]);
    calls_to_messagesettype++;

    message->raw->header.type = type;

    /* The last one is actually a sanity check for the test itself. It doesn't really say
    whether the code works properly or not. */
    g_assert_cmpint(calls_to_messagesettype, <=, expected_calls_to_messagesettype);
}

_LSTransportMessageType
_LSTransportMessageGetType(const _LSTransportMessage *message)
{
    return message->raw->header.type;
}

char*
_LSTransportMessageSetBody(_LSTransportMessage *message, const void *body, int body_len)
{
    return NULL;
}

void
_LSTransportMessageSetToken(_LSTransportMessage *message, LSMessageToken token)
{
    g_assert(message != NULL);
}

_LSTransportChannel*
_LSTransportClientGetChannel(_LSTransportClient *client)
{
    return &client->channel;
}

bool
_LSTransportChannelHasSendWatch(const _LSTransportChannel *channel)
{
    return has_send_watch;
}

bool
_LSTransportChannelHasReceiveWatch(const _LSTransportChannel *channel)
{
    return has_recv_watch;
}

void
_LSTransportRemoveSendWatch(_LSTransportChannel *channel)
{
}

void
_LSTransportChannelSetBlock(_LSTransportChannel *channel, bool *prev_state_blocking)
{
}

void
_LSTransportChannelRestoreBlockState(_LSTransportChannel *channel, const bool *prev_state_blocking)
{
}

bool
_LSTransportMessageAppendString(_LSTransportMessageIter *iter, const char *str)
{
    return true;
}

bool
_LSTransportMessageAppendInt32(_LSTransportMessageIter *iter, int32_t value)
{
    return true;
}

bool
_LSTransportMessageAppendInvalid(_LSTransportMessageIter *iter)
{
    return true;
}

_LSTransportMessageIter*
_LSTransportMessageIterNext(_LSTransportMessageIter *iter)
{
    return NULL; //TODO make this configurable
}

bool
_LSTransportMessageIterHasNext(_LSTransportMessageIter *iter)
{
    calls_to_messageiterhasnext++;

    return calls_to_messageiterhasnext < 2;
}

bool
_LSTransportMessageGetString(_LSTransportMessageIter *iter, const char **ret)
{
    return true;
}

bool
_LSTransportMessageGetInt32(_LSTransportMessageIter *iter, int32_t *ret)
{
    //TODO make this configurable
    *ret = LS_TRANSPORT_PUSH_ROLE_SUCCESS;
    return true;
}

_LSTransportOutgoing*
_LSTransportOutgoingNew()
{
    _LSTransportOutgoing* outgoing = g_slice_new0(_LSTransportOutgoing);
    outgoing->queue = g_queue_new();
    outgoing->serial = g_slice_new0(_LSTransportSerial);
    outgoing->serial->queue = g_queue_new();
    outgoing->serial->map = g_hash_table_new_full(g_int_hash, g_int_equal, NULL, (GDestroyNotify)_LSTransportSerialMapEntryFree);

    return outgoing;
}

bool
_LSTransportSerialSave(_LSTransportSerial *serial_info, _LSTransportMessage *message, LSError *lserror)
{
    return true;
}

const char*
_LSTransportMessageGetAppId(_LSTransportMessage *message)
{
    return NULL; //TODO
}

void
_LSTransportMessageIterInit(_LSTransportMessage *message, _LSTransportMessageIter *iter)
{
    iter->message = message;
    iter->actual_iter = NULL;//_LSTransportMessageGetBody(message);
    iter->iter_end = 0;//iter->actual_iter + _LSTransportMessageGetBodySize(message);
    iter->valid = true;
}

/* Mocks (system) *************************************************************/

ssize_t
send(int sockfd, const void *buf, size_t len, int flags)
{
    return len;
}

ssize_t
recv(int sockfd, void *buf, size_t len, int flags)
{
    ((_LSTransportHeader*)buf)->type = headertype;
    ((_LSTransportHeader*)buf)->len = headerlen;

    return sizeof(_LSTransportHeader);
}

ssize_t
sendmsg(int sockfd, /*const struct msghdr*/int *msg, int flags)
{
    return sendfd_success ? 1: -1;
}

/* Test cases *****************************************************************/

void
test_LSTransportLifespan_execute(const char *service_name, int number_of_connections, int number_of_messages, int number_of_clients, gboolean flush_and_send_shutdown, gboolean use_shm)
{
    clear_counters();

    flush_and_shutdown = flush_and_send_shutdown;
    use_shared_memory = use_shm;
    headertype = _LSTransportMessageTypeMethodCall;
    expected_calls_to_messagesettype = number_of_clients + number_of_connections + (flush_and_send_shutdown ? 1 : 0); /*+1 for hub*/
    _LSTransportMessageType typelist[expected_calls_to_messagesettype];
    int cli;
    for(cli=0; cli < expected_calls_to_messagesettype; cli++)
    {
        typelist[cli] = _LSTransportMessageTypeShutdown;
    }
    expected_message_types = typelist;

    int expected_calls_to_connectclient = use_shm ? 3 : 0; /* x3 = localhost, public hub and internet */
    int expected_shm_deinit_count = use_shm ? 1 : 0;
    /*gboolean is_this_hub = (g_strcmp0(service_name, HUB_NAME) == 0);*/
    gboolean expected_connect_success = false; //TODO find a failure case

    LSHandle sh;
    LSTransportHandlers handlers;
    handlers.msg_handler = MessageHandler;
    handlers.msg_context = &sh;
    handlers.disconnect_handler = DisconnectHandler;
    handlers.disconnect_context = &sh;
    handlers.message_failure_handler = FailureHandler;
    handlers.message_failure_context = &sh;

    LSError error;
    LSErrorInit(&error);

    /* Test: Check init (init was done in construction phase. */
    /****************************************************/
    gboolean construct_success = _LSTransportInit(&this_transport, service_name, &handlers, &error);

    g_assert(construct_success);
    g_assert(this_transport != NULL);
    g_assert_cmpstr(this_transport->service_name, ==, service_name);
    g_assert(!LSErrorIsSet(&error));
    /* The mutex should be initialized. */
    g_assert_cmpint(pthread_mutex_trylock(&this_transport->lock), !=, EINVAL);
    pthread_mutex_unlock(&this_transport->lock);
    /* Continue setup */
    /******************/
    listen_channel = &this_transport->listen_channel;

    int i;
    /* Populate connections table. */
    for(i=0; i<number_of_connections; i++)
    {
        _LSTransportClient *connection = g_slice_new0(_LSTransportClient);
        connection->incoming = g_slice_new0(_LSTransportIncoming);
        connection->incoming->complete_messages = g_queue_new();
        connection->outgoing = g_slice_new0(_LSTransportOutgoing);
        connection->outgoing->queue = g_queue_new();
        connection->transport = this_transport;
        //connection->is_dynamic = true;
        connection->ref = 1;
        /* Populate outgoing->queue message queue causes a warning in _LSTransportFlushOutgoingMessages().
           TODO trap LSTransportDisconnect() and try it out.*/

        g_hash_table_insert(this_transport->all_connections, GINT_TO_POINTER(i), connection);
    }
    /* Populate clients table. */
    for(i=0; i<number_of_clients; i++)
    {
        _LSTransportClient *client = g_slice_new0(_LSTransportClient);
        client->incoming = g_slice_new0(_LSTransportIncoming);
        client->incoming->complete_messages = g_queue_new();
        client->transport = this_transport;
        client->ref = 1;
        /* Populate message queue. */
        /* (Nov 2012: Will cause a warning in _LSTransportDiscardIncomingMessages(),
           which causes the case to fail. TODO*/
        /*
        int j;
        for(j=0; j<number_of_messages; j++)
        {
            g_queue_push_tail(client->incoming->complete_messages, GINT_TO_POINTER(777));
        }*/
        g_hash_table_insert(this_transport->clients, g_strdup_printf("key%d", i), client);
    }

    if(use_shm)
    {
        this_transport->shm = GINT_TO_POINTER(11111111);
    }
    my_shm = this_transport->shm;

    /* Test: Check connect - More comprehensive testing for connect is done separately */
    /*****************************************************************************/
    gboolean connect_success = _LSTransportConnect(this_transport, true, true, &error);

    g_assert(connect_success == expected_connect_success);
    g_assert(!LSErrorIsSet(&error));
    if(expected_connect_success)
    {
        g_assert(this_transport->hub != NULL);
    }
    g_assert_cmpint(calls_to_connectclient, ==, expected_calls_to_connectclient);
    g_assert_cmpint(calls_to_shminit, ==, 1);
    g_assert_cmpint(calls_to_clientunref, ==, 0);

    /* Test: Check disconnect */
    /********************/
    gboolean run_success = _LSTransportDisconnect(this_transport, flush_and_send_shutdown); /* Causes also an unref to clients */
    g_assert(run_success);
    /* Functions for disconnections called sufficiently? */
    /* _LSTransportDiscardIncomingMessages() can be caught if necessary. */
    /* Shutdown messages aren't really sent in this test (mocked send function)
       so disconnect handler is never called.
    g_assert_cmpint(calls_to_disconnect, ==, number_of_connections);*/
    g_assert_cmpint(calls_to_channeldeinit, ==, number_of_connections+1); /*+1 from hub*/
    g_assert_cmpint(calls_to_channelclose, ==, number_of_connections+1);
    g_assert_cmpint(calls_to_shmdeinit, ==, expected_shm_deinit_count);
    g_assert_cmpint(calls_to_clientunref, ==, number_of_clients);

    /* Test: Check deinit */
    /**********************/
    //_LSTransportDeinit(NULL); /* TODO fix crash bug? Can this ever happen? */
    _LSTransportDeinit(this_transport);
    g_assert_cmpint(calls_to_clientunref, ==, number_of_clients*2 + number_of_connections); /* number_of_clients+1 for hub (LSTransportConnect) */
}

/* Test init, connect, disconnect and deinit. */
void
test_LSTransportLifespan()
{
    /*const char *service_name
    int number_of_connections
    int number_of_messages
    int number_of_clients
    gboolean flush_and_send_shutdown
    gboolean use_shm*/

    test_LSTransportLifespan_execute(HUB_NAME, 0, 0, 0, TRUE, TRUE);
    test_LSTransportLifespan_execute(NULL, 0, 0, 0, TRUE, TRUE);
    test_LSTransportLifespan_execute(NULL, 0, 1, 1, FALSE, TRUE);
    test_LSTransportLifespan_execute("huuhaa", 2, 12, 0, TRUE, FALSE);
    test_LSTransportLifespan_execute("huuhaa", 2, 100, 0, TRUE, TRUE);
    test_LSTransportLifespan_execute("huuhaa", 1, 0, 1, TRUE, TRUE);
    test_LSTransportLifespan_execute("huuhaa", 1, 0, 2, TRUE, TRUE);
    test_LSTransportLifespan_execute("huuhaa", 1, 7, 3, FALSE, TRUE);
    test_LSTransportLifespan_execute(HUB_NAME, 140, 0, 100, FALSE, TRUE);
    test_LSTransportLifespan_execute(HUB_NAME, 100, 3, 100, TRUE, TRUE);
    test_LSTransportLifespan_execute(HUB_NAME, 100, 0, 100, FALSE, TRUE);
}

void
test_LSTransportSend_execute(const char *service_name, const char *category, const char *method, const char *payload, const char *applicationId, gboolean expected_success)
{
    clear_counters();

    headertype = _LSTransportMessageTypeMethodCall;
    expected_calls_to_messagesettype = 1;
    _LSTransportMessageType typelist[1] = {_LSTransportMessageTypeQueryName};
    expected_message_types = typelist;


    /*First let's create a minimal transport struct for the test.*/
    _LSTransport *transport = g_new0(_LSTransport, 1);
    transport->clients = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, (GDestroyNotify)_LSTransportClientUnref);
    transport->pending = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, (GDestroyNotify)_LSTransportOutgoingFree);
    transport->global_token = g_new0(_LSTransportGlobalToken, 1);
    transport->global_token->value = LSMESSAGE_TOKEN_INVALID;
    transport->hub = g_slice_new0(_LSTransportClient);
    transport->hub->transport = transport;
    transport->hub->outgoing = g_slice_new0(_LSTransportOutgoing);
    transport->hub->outgoing->queue = g_queue_new();

    LSMessageToken token;
    LSError error;
    LSErrorInit(&error);

    /* Test: Call LSTransportSend and see what happens. */
    gboolean function_success = LSTransportSend(transport, service_name, category, method, payload, applicationId, &token, &error);
    g_assert(function_success == expected_success);

    /* Cleanup. */
    g_hash_table_unref(transport->clients);
    g_hash_table_unref(transport->pending);
    g_free(transport->global_token);
    while (!g_queue_is_empty(transport->hub->outgoing->queue))
    {
        _LSTransportMessage *message = g_queue_pop_head(transport->hub->outgoing->queue);
        _LSTransportMessageUnref(message);
    }
    g_queue_free(transport->hub->outgoing->queue);
    g_slice_free(_LSTransportOutgoing, transport->hub->outgoing);
    g_slice_free(_LSTransportClient, transport->hub);
    g_free(transport);
}

void
test_LSTransportSend()
{
    /*
    const char *service_name
    const char *category
    const char *method
    const char *payload
    const char *applicationId
    gboolean expect_success
    */

    char *reallylong = "poiuytrewqasdfghjklöä-.,mnbvcxz<asdfghjklöäpoiuytrewq   1234567890+0u76t5432qwertyuiopöl,kmjnhgfdsaz cvbnm,.-ölkijuhygtfdpoiuytrewqasdfghjklöä-.,mnbvcxz<asdfghjklöäpoiuytrewq   1234567890+0u76t5432qwertyuiopöl,kmjnhgfdsaz cvbnm,.-ölkijuhygtfdpoiuytrewqasdfghjklöä-.,mnbvcxz<asdfghjklöäpoiuytrewq   1234567890+0u76t5432qwertyuiopöl,kmjnhgfdsaz cvbnm,.-ölkijuhygtfd";

    /*Failure. No checks for null -> crashes. TODO Write a bug report?*/
    /*test_LSTransportSend_execute(NULL, NULL, NULL, NULL, NULL, false);*/
    test_LSTransportSend_execute("", "", "", "", "", true);
    test_LSTransportSend_execute("somename", reallylong, "", "", "", true);
    test_LSTransportSend_execute(HUB_NAME, "", "", "", "", true);
    test_LSTransportSend_execute(reallylong, "category", "doesntexist", reallylong, "killer-app", true);
}

void
test_LSTransportPushRole_execute(const char *path, gboolean expeced_success)
{
    clear_counters();

    headertype = _LSTransportMessageTypePushRoleReply;
    expected_calls_to_messagesettype = 2;
    _LSTransportMessageType typelist[2] = {_LSTransportMessageTypePushRole,
                                           _LSTransportMessageTypeQueryName};
    expected_message_types = typelist;

    /* First let's create a minimal transport struct for the test. */

    _LSTransport *transport = g_new0(_LSTransport, 1);
    transport->hub = g_slice_new0(_LSTransportClient);
    transport->hub->transport = transport;
    transport->hub->outgoing = g_slice_new0(_LSTransportOutgoing);
    transport->hub->outgoing->queue = g_queue_new();
    transport->global_token = g_new0(_LSTransportGlobalToken, 1);
    transport->global_token->value = LSMESSAGE_TOKEN_INVALID;

    LSError error;
    LSErrorInit(&error);
    /* Test: Run PushRole */
    gboolean success = LSTransportPushRole(transport, path, &error);
    g_assert_cmpint(success, ==, expeced_success);

    /* Cleanup. */
    g_free(transport->global_token);
    g_free(transport);
    transport = NULL;
}

void
test_LSTransportPushRole()
{
    test_LSTransportPushRole_execute("", true);
    test_LSTransportPushRole_execute("somepath", true);
    test_LSTransportPushRole_execute(NULL, true);
}

void
test_LSTransportSendMessageMonitorRequest()
{
    clear_counters();

    expected_calls_to_messagesettype = 1;
    _LSTransportMessageType typelist[1] = {_LSTransportMessageTypeMonitorRequest};
    expected_message_types = typelist;

    /*First let's create a minimal transport struct for the test.*/
    _LSTransport *transport = g_new0(_LSTransport, 1);
    transport->global_token = g_new0(_LSTransportGlobalToken, 1);
    transport->global_token->value = LSMESSAGE_TOKEN_INVALID;
    transport->hub = g_slice_new0(_LSTransportClient);
    transport->hub->transport = transport;
    transport->hub->outgoing = g_slice_new0(_LSTransportOutgoing);
    transport->hub->outgoing->queue = g_queue_new();

    LSError error;
    LSErrorInit(&error);

    /* Test it. */
    /* Message stays at ref==unref+1 because it is pushed in queue and _LSTransportMessageUnref is called when
       the message is sent. */
    LSTransportSendMessageMonitorRequest(transport, &error);
    g_assert_cmpint(calls_to_messagesettype, ==, 1);
    g_assert_cmpint(calls_to_messageunref, ==, calls_to_messageref + calls_to_messagenewref - 1);

    /* Cleanup. */
    g_free(transport->global_token);
    while (!g_queue_is_empty(transport->hub->outgoing->queue))
    {
        _LSTransportMessage *message = g_queue_pop_head(transport->hub->outgoing->queue);
        _LSTransportMessageUnref(message);
    }
    g_queue_free(transport->hub->outgoing->queue);
    g_slice_free(_LSTransportOutgoing, transport->hub->outgoing);
    g_slice_free(_LSTransportClient, transport->hub);
    g_free(transport);
}

void
test_LSTransportCancelMethodCall_execute(char *service_name, int number_of_clients, int number_of_pending, gboolean expected_success)
{
    clear_counters();

    expected_calls_to_messagesettype = 2;
    _LSTransportMessageType typelist[2] = {_LSTransportMessageTypeCancelMethodCall,
                                           _LSTransportMessageTypeQueryName};
    expected_message_types = typelist;

    /*First let's create a minimal transport struct for the test.*/
    _LSTransport *transport = g_new0(_LSTransport, 1);
    transport->clients = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, (GDestroyNotify)_LSTransportClientUnref);
    transport->pending = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, (GDestroyNotify)_LSTransportOutgoingFree);
    transport->global_token = g_new0(_LSTransportGlobalToken, 1);
    transport->global_token->value = LSMESSAGE_TOKEN_INVALID;
    transport->hub = g_slice_new0(_LSTransportClient);
    transport->hub->transport = transport;
    transport->hub->outgoing = g_slice_new0(_LSTransportOutgoing);
    transport->hub->outgoing->queue = g_queue_new();
    transport->unique_name = "TMM!";

    //TODO test also with monitor
    /* Populate transport->clients */
    char *toRelease[number_of_clients];
    int i;
    for(i=0; i<number_of_clients; i++)
    {
        _LSTransportClient *client = g_slice_new0(_LSTransportClient);

        client->ref = 1;
        toRelease[i] = g_strdup_printf("tmm%d", i);
        client->unique_name = toRelease[i];
        client->service_name = service_name;
        client->transport = transport;
        client->incoming = g_slice_new0(_LSTransportIncoming);
        client->incoming->complete_messages = g_queue_new();
        client->outgoing = g_slice_new0(_LSTransportOutgoing);
        client->outgoing->queue = g_queue_new();

        g_hash_table_insert(transport->clients, g_strdup_printf("key%d", i), client);
    }
    for(i=0; i<number_of_pending; i++)
    {
        g_hash_table_insert(transport->pending, g_strdup_printf("key%d", i), _LSTransportOutgoingNew());
    }
    LSMessageToken serial = 11111;

    LSError error;
    LSErrorInit(&error);

    /* Test it. */
    /* Message stays at ref==unref+1 because it is pushed in queue and _LSTransportMessageUnref is called when
       the message is sent.
       Message also ref+1 in LSTransportSerialSave() (LSTransportSerialListItemNew()). Unref(message) in LSTransportSerialListItemFree().
       -> In this test message unref count == ref count +2 */
    gboolean success = LSTransportCancelMethodCall(transport, service_name, serial, &error);

    int expected_message_unrefs = calls_to_messagenewref + calls_to_messageref;
    expected_message_unrefs--; /* sending message */
    if(!g_str_has_prefix(service_name, "key")) /*also number_of_clients==0*/
    {
        expected_message_unrefs--; /* LsTransportSerialSave */
    }

    g_assert_cmpint(success, ==, expected_success);
    g_assert_cmpint(calls_to_clientunref, ==, calls_to_clientref);
    g_assert_cmpint(calls_to_messageunref, ==, expected_message_unrefs);
    g_assert_cmpint(number_of_clients, ==, g_hash_table_size(transport->clients));

    /* Cleanup. */

    g_assert_cmpint(g_hash_table_size(transport->clients), ==, number_of_clients);
    g_hash_table_destroy(transport->clients);
    g_hash_table_destroy(transport->pending);
    while (!g_queue_is_empty(transport->hub->outgoing->queue))
    {
        _LSTransportMessage *message = g_queue_pop_head(transport->hub->outgoing->queue);
        _LSTransportMessageUnref(message);
    }
    g_queue_free(transport->hub->outgoing->queue);
    g_slice_free(_LSTransportOutgoing, transport->hub->outgoing);
    g_slice_free(_LSTransportClient, transport->hub);
    g_free(transport->global_token);
    g_free(transport);
    for(i=0; i<number_of_clients; i++) {
        g_free(toRelease[i]);
    }
}

void
test_LSTransportCancelMethodCall()
{
    char *reallylong = "poiuytrewqasdfghjklöä-.,mnbvcxz<asdfghjklöäpoiuytrewq   1234567890+0u76t5432qwertyuiopöl,kmjnhgfdsaz cvbnm,.-ölkijuhygtfdpoiuytrewqasdfghjklöä-.,mnbvcxz<asdfghjklöäpoiuytrewq   1234567890+0u76t5432qwertyuiopöl,kmjnhgfdsaz cvbnm,.-ölkijuhygtfdpoiuytrewqasdfghjklöä-.,mnbvcxz<asdfghjklöäpoiuytrewq   1234567890+0u76t5432qwertyuiopöl,kmjnhgfdsaz cvbnm,.-ölkijuhygtfd";

    /* Called _LSTransportSendMessageToService() crashes if service name is NULL.
       That shouldn't be possible in the real life. */
    test_LSTransportCancelMethodCall_execute("", 0, 0, true);
    test_LSTransportCancelMethodCall_execute("key0", 1, 0, true);
    test_LSTransportCancelMethodCall_execute("key1", 3, 4, true);
    test_LSTransportCancelMethodCall_execute("key9", 10, 100, true);
    test_LSTransportCancelMethodCall_execute("poiuytrewsdfghj", 0, 0, true);
    test_LSTransportCancelMethodCall_execute("poiuytrewsdfghj", 1, 1, true);
    test_LSTransportCancelMethodCall_execute("servicename", 10, 1, true);
    test_LSTransportCancelMethodCall_execute(HUB_NAME, 10, 100, true);
    test_LSTransportCancelMethodCall_execute(reallylong, 10, 10, true);
}

void
test_LSTransportSendQueryServiceStatus_execute(char *service_name)
{
    clear_counters();

    expected_calls_to_messagesettype = 1;
    _LSTransportMessageType typelist[1] = {_LSTransportMessageTypeQueryServiceStatus};
    expected_message_types = typelist;

    /*First let's create a minimal transport struct for the test.*/
    _LSTransport *transport = g_new0(_LSTransport, 1);
    transport->global_token = g_new0(_LSTransportGlobalToken, 1);
    transport->global_token->value = LSMESSAGE_TOKEN_INVALID;
    transport->hub = g_slice_new0(_LSTransportClient);
    transport->hub->transport = transport;
    transport->hub->outgoing = g_slice_new0(_LSTransportOutgoing);
    transport->hub->outgoing->queue = g_queue_new();
    transport->unique_name = "TMM!";

    LSMessageToken serial = 11111;

    LSError error;
    LSErrorInit(&error);

    /* Test it. */
    /************/
    /* Message stays at ref==unref+1 because it is pushed in queue and _LSTransportMessageUnref is called when
       the message is sent. */
    LSTransportSendQueryServiceStatus(transport, service_name, &serial, &error);
    g_assert_cmpint(calls_to_messageunref, ==, calls_to_messagenewref + calls_to_messageref - 1);
    g_assert_cmpint(calls_to_messagesettype, ==, 1);

    /* Cleanup. */
    while (!g_queue_is_empty(transport->hub->outgoing->queue))
    {
        _LSTransportMessage *message = g_queue_pop_head(transport->hub->outgoing->queue);
        _LSTransportMessageUnref(message);
    }
    g_queue_free(transport->hub->outgoing->queue);
    g_slice_free(_LSTransportOutgoing, transport->hub->outgoing);
    g_slice_free(_LSTransportClient, transport->hub);
    g_free(transport->global_token);
    g_free(transport);
}

void
test_LSTransportSendQueryServiceStatus()
{
    char *reallylong = "poiuytrewqasdfghjklöä-.,mnbvcxz<asdfghjklöäpoiuytrewq   1234567890+0u76t5432qwertyuiopöl,kmjnhgfdsaz cvbnm,.-ölkijuhygtfdpoiuytrewqasdfghjklöä-.,mnbvcxz<asdfghjklöäpoiuytrewq   1234567890+0u76t5432qwertyuiopöl,kmjnhgfdsaz cvbnm,.-ölkijuhygtfdpoiuytrewqasdfghjklöä-.,mnbvcxz<asdfghjklöäpoiuytrewq   1234567890+0u76t5432qwertyuiopöl,kmjnhgfdsaz cvbnm,.-ölkijuhygtfd";

    test_LSTransportSendQueryServiceStatus_execute("");
    test_LSTransportSendQueryServiceStatus_execute("servicename");
    test_LSTransportSendQueryServiceStatus_execute(HUB_NAME);
    test_LSTransportSendQueryServiceStatus_execute(reallylong);
}

void
test_LSTransportSendClient_execute(int number_of_messages, int include_null, int include_wrong_type,
                                        int remaining_bytes)
{
    clear_counters();

    /* Build minimal transport client. */
    _LSTransportClient *client = g_slice_new0(_LSTransportClient);
    client->ref = 1;
    client->outgoing = g_slice_new0(_LSTransportOutgoing);
    client->outgoing->queue = g_queue_new();

    int i;
    for(i=0; i<number_of_messages; i++)
    {
        _LSTransportMessage* message = NULL;

        if(include_null != i)
        {
            message = _LSTransportMessageNewRef(20);
            message->tx_bytes_remaining = remaining_bytes;

            if(include_wrong_type != i)
            {
                message->raw->header.type = _LSTransportMessageTypeQueryNameReply;
            }
        }

        g_queue_push_tail(client->outgoing->queue, message);
    }

    /* Test it. */
    /* The first two argument aren't even used in the function! */
    /* return_value is TRUE if there's still data to be sent */
    /* In some cases we expect failure (g_warning or g_critical causes assert etc).
       Some branches aren't reachable when warnings or criticals are fatal. */
    if (g_test_trap_fork(1000000, G_TEST_TRAP_SILENCE_STDOUT | G_TEST_TRAP_SILENCE_STDERR))
    {
        gboolean return_value = _LSTransportSendClient(NULL, 0, client);

        g_assert(!return_value);
        int expected_message_unrefs = calls_to_messagenewref + calls_to_messageref;
        if(include_wrong_type >= 0)
        {
            expected_message_unrefs--;
        }
        g_assert_cmpint(calls_to_messageunref, ==, expected_message_unrefs);

        exit(0);
    }

    if(include_null < 0 && sendfd_success)
    {
        g_test_trap_assert_passed();
    }
    else
    {
        g_test_trap_assert_failed();
    }

    /* Cleanup. */
    while (!g_queue_is_empty(client->outgoing->queue))
    {
        _LSTransportMessage *message = g_queue_pop_head(client->outgoing->queue);
        // Message can be NULL when `include_null` parameter is set.
        if (message)
        {
            _LSTransportMessageUnref(message);
        }
    }
    g_queue_free(client->outgoing->queue);
    g_slice_free(_LSTransportOutgoing, client->outgoing);
    g_slice_free(_LSTransportClient, client);
}

void
test_LSTransportSendClient()
{
    /*
    int, number of messages
    int, index of NULL message: <0 = none
    int, index of wrong type of message: <0 = none
    int, remaining bytes to send in a message
    */
    test_LSTransportSendClient_execute(0, -1, -1, 0);
    test_LSTransportSendClient_execute(1, -1, -1, 0);
    test_LSTransportSendClient_execute(1, 0, -1, 0);
    test_LSTransportSendClient_execute(3, 0, 0, 0);
    test_LSTransportSendClient_execute(3, 0, 2, 0);
    test_LSTransportSendClient_execute(3, 2, -1, 0);
    test_LSTransportSendClient_execute(100, -1, -1, 0);
    test_LSTransportSendClient_execute(1, -1, -1, 10);
    test_LSTransportSendClient_execute(3, -1, -1, 10);

    sendfd_success = false;
    test_LSTransportSendClient_execute(1, -1, -1, 0);
    test_LSTransportSendClient_execute(3, -1, -1, 10);
    /*Reset*/
    sendfd_success = true;
}

/* Test suite **************************************************************/

int
main(int argc, char *argv[])
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/luna-service2/LSTransportLifespan", test_LSTransportLifespan);
    g_test_add_func("/luna-service2/LSTransportSend", test_LSTransportSend);
    g_test_add_func("/luna-service2/LSTransportPushRole", test_LSTransportPushRole);
    g_test_add_func("/luna-service2/LSTransportSendMessageMonitorRequest", test_LSTransportSendMessageMonitorRequest);
    g_test_add_func("/luna-service2/LSTransportCancelMethodCall", test_LSTransportCancelMethodCall);
    g_test_add_func("/luna-service2/LSTransportSendQueryServiceStatus", test_LSTransportSendQueryServiceStatus);
    g_test_add_func("/luna-service2/LSTransportSendClient", test_LSTransportSendClient);

    return g_test_run();
}
