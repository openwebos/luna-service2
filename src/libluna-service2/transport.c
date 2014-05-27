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
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pbnjson.h>

#include "transport.h"
#include "transport_priv.h"
#include "transport_utils.h"
#include "base.h"
#include "message.h"
#include "clock.h"
//#include "callmap.h"

/**
 * @defgroup LunaServiceTransport
 * @ingroup LunaServiceInternals
 * @brief Underlying transport implementation
 */

/**
 * @addtogroup LunaServiceTransport
 * @{
 */

#define LISTEN_BACKLOG  30

#if 0
FILE *debug_print_file = NULL;

void debug_print(const char *format, ...)
{
    if (!debug_print_file)
    {
        debug_print_file = fopen("/home/root/service.out", "w");
    }

    va_list args;
    va_start(args, format);
    fprintf(debug_print_file, "%d:%ld: ", getpid(), pthread_self());
    g_vfprintf(debug_print_file, format, args);
    va_end(args);

    fflush(debug_print_file);
}
#endif

/** Used as a queue item when processing message failures */
typedef struct _LSTransportMessageFailureItem
{
    LSMessageToken serial;              /**< serial number of failed message */
    _LSTransportMessageFailureType failure_type;    /**< type of failure */
} _LSTransportMessageFailureItem;

gboolean _LSTransportAcceptConnection(GIOChannel *source, GIOCondition condition, gpointer data);
gboolean _LSTransportReceiveClient(GIOChannel *source, GIOCondition condition, gpointer data);
gboolean _LSTransportSendClient(GIOChannel *source, GIOCondition condition, gpointer data);
void _LSTransportAddSendWatch(_LSTransportChannel *channel, GMainContext *context, _LSTransportClient *client);
void _LSTransportRemoveSendWatch(_LSTransportChannel *channel);
void _LSTransportAddReceiveWatch(_LSTransportChannel *channel, GMainContext *context, _LSTransportClient *client);
void _LSTransportRemoveReceiveWatch(_LSTransportChannel *channel);

bool _LSTransportProcessIncomingMessages(_LSTransportClient *client, LSError *lserror);


bool _LSTransportSendMessageClientInfo(_LSTransportClient *client, const char *service_name, const char *unique_name, bool prepend, LSError *lserror);
static bool _LSTransportSendMessageMonitor(_LSTransportMessage *message, _LSTransportClient *monitor, _LSMonitorMessageType type, const struct timespec *timestamp, LSError *lserror);
static bool _LSTransportSendMessageRaw(_LSTransportMessage *message, _LSTransportClient *client, bool set_token, LSMessageToken *token, bool prepend, LSError *lserror);
bool _LSTransportSendMessageToService(_LSTransport *transport, const char *service_name, _LSTransportMessage *message, LSMessageToken *token, LSError *lserror);
bool _LSTransportAddPendingMessageWithToken(_LSTransport *transport, const char *service_name, _LSTransportMessage *message, LSMessageToken msg_token, LSError *lserror);
bool _LSTransportAddPendingMessage(_LSTransport *transport, const char *service_name, _LSTransportMessage *message, LSMessageToken *token, LSError *lserror);
bool _LSTransportSendErrorReply(const _LSTransportMessage *message, _LSTransportMessageType error_type, const char *error_msg, LSError *lserror);

void _LSTransportRemoveClientHash(_LSTransport *transport, _LSTransportClient *client);
bool _LSTransportRemoveAllConnectionHash(_LSTransport *transport, _LSTransportClient *client);

bool _LSTransportQueryName(_LSTransportClient *hub, _LSTransportMessage *trigger_message, const char *service_name, LSError *lserror);

static bool s_is_hub = false;   /**< true if the process using this library is
                                  the hub. Note that this is not secure in any
                                  way so it should not be used for anything
                                  that would cause bad side effects if spoofed */

/**
 *******************************************************************************
 * @brief Get the next token for the given transport. This will wrap around
 * when exceeding the size of @ref LSMessageToken.
 *
 * @attention Locks the global token lock.
 *
 * @param  transport    IN  transport
 *
 * @retval token
 *******************************************************************************
 */
LSMessageToken
_LSTransportGetNextToken(_LSTransport *transport)
{
    LSMessageToken ret;

    GLOBAL_TOKEN_LOCK(&transport->global_token->lock);
    ret = ++transport->global_token->value;

    /* skip over invalid token */
    if (ret == LSMESSAGE_TOKEN_INVALID)
    {
        LOG_LS_ERROR(MSGID_LS_TOKEN_ERR, 0, "Token value rolled over");
        ret = ++transport->global_token->value;
    }
    GLOBAL_TOKEN_UNLOCK(&transport->global_token->lock);

    return ret;
}

void
_LSHandleDisconnect(_LSTransport *client, _LSTransportDisconnectType type, LSMessageToken token)
{
    /* don't need to do anything else ? */

}


/**
 *******************************************************************************
 * @brief  Calls the message failure handler callback for outstanding method
 * calls (i.e., method calls that haven't received a reply).
 *
 * @attention locks the serial info lock.
 *
 * @param  serial_info   IN  serial info
 * @param  last_serial   IN  last serial for which we received a reply
 * @param  type          IN  disconnect reason
 * @param  message_failure_handler  IN  failure callback
 * @param  message_failure_context  IN  failure callback context
 *******************************************************************************
 */
void
_LSTransportSerialHandleShutdown(_LSTransportSerial *serial_info, LSMessageToken last_serial, _LSTransportDisconnectType type, LSTransportMessageFailure message_failure_handler, void *message_failure_context)
{
    LOG_LS_DEBUG("%s\n", __func__);

    _LSTransportMessageFailureType failure_type;
    _LSTransportMessageFailureItem *fail_item = NULL;

    if (last_serial == LSMESSAGE_TOKEN_INVALID)
    {
        LOG_LS_DEBUG("no outstanding method calls to cancel\n");
        return;
    }

    GQueue *failure_queue = g_queue_new();

    SERIAL_INFO_LOCK(&serial_info->lock);

    GList *iter = g_queue_peek_head_link(serial_info->queue);
    bool not_processed = false;

    while (iter != NULL)
    {
        GList *tmp = iter;
        LSMessageToken serial = ((_LSTransportSerialListItem*)(iter->data))->serial;

        if (serial > last_serial)
        {
            /* last_serial is the last serial that the far side processed. We've
             * now moved past that and know that the far side didn't process this
             * serial */
            not_processed = true;
        }

        if (type == _LSTransportDisconnectTypeDirty)
        {
            failure_type = _LSTransportMessageFailureTypeUnknown;
        }
        else if (not_processed)
        {
            failure_type = _LSTransportMessageFailureTypeNotProcessed;
        }
        else
        {
            failure_type = _LSTransportMessageFailureTypeUnknown;
        }

        /* We don't call the failure callback here since that can result
         * in recursion and a deadlock. See NOV-100522 */
        if (failure_queue)
        {
            fail_item = g_slice_new0(_LSTransportMessageFailureItem);

            fail_item->serial = serial;
            fail_item->failure_type = failure_type;

            g_queue_push_tail(failure_queue, fail_item);
        }

        iter = g_list_next(iter);

        /* remove item from list */
        _LSTransportSerialListItemFree(tmp->data);
        g_queue_delete_link(serial_info->queue, tmp);

        /* remove from hash table */
        _LSTransportSerialMapEntry *entry = g_hash_table_lookup(serial_info->map, &serial);
        g_hash_table_remove(serial_info->map, &entry->serial);
    }

    SERIAL_INFO_UNLOCK(&serial_info->lock);

    if (failure_queue)
    {
        while (!g_queue_is_empty(failure_queue))
        {
            fail_item = g_queue_pop_head(failure_queue);

            LOG_LS_DEBUG("message failure: serial: %d, failure_type: %d\n",
                        (int)fail_item->serial, fail_item->failure_type);

            message_failure_handler(fail_item->serial, fail_item->failure_type, message_failure_context);

            g_slice_free(_LSTransportMessageFailureItem, fail_item);
        }

        g_queue_free(failure_queue);
    }
}

/**
 *******************************************************************************
 * @brief Perform any remaining clean up on a disconnecting client.
 *
 * @param  client   IN  client that has disconnected
 *******************************************************************************
 */
void
_LSTransportDisconnectCleanup(_LSTransportClient *client)
{
    LS_ASSERT(client != NULL);

    /* remove send watch */
    if (client->channel.send_watch)
    {
        _LSTransportRemoveSendWatch(&client->channel);
    }

    /* receive watch will be removed by return value in ReceiveWatch
     * (also rest of client info destruction happens then) */
}

/**
 *******************************************************************************
 * @brief Get the shutdown token (last serial processed on the far side) from
 * the shutdown message.
 *
 * @param  message  IN  shutdown message
 * @param  token    OUT shutdown token
 *
 * @retval true on success
 * @retval false on failure
 *******************************************************************************
 */
bool
_LSTransportGetShutdownToken(_LSTransportMessage *message, LSMessageToken *token)
{
    LS_ASSERT(message != NULL);
    LS_ASSERT(token != NULL);
    LS_ASSERT(_LSTransportMessageGetType(message) == _LSTransportMessageTypeShutdown);

    /* extract the serial sent by the other side */
    int token_size = sizeof(LSMessageToken);
    char *body = _LSTransportMessageGetBody(message);
    if (body && _LSTransportMessageGetBodySize(message) >= token_size)
    {
        memcpy(token, body, token_size);
        return true;
    }
    return false;
}

/**
 *******************************************************************************
 * @brief Call the failure handler for any remaining items in the outgoing
 * queue and process failure for any method calls that haven't received a
 * reply.
 *
 * @attention locks outgoing lock
 *
 * @param  transport    IN  transport
 * @param  outgoing     IN  outgoing queue
 * @param  last_serial  IN  last serial processed
 * @param  type         IN  disconnect reason
 *******************************************************************************
 */
void
_LSTransportClientShutdownProcessQueue(_LSTransport *transport, _LSTransportOutgoing *outgoing, LSMessageToken last_serial, _LSTransportDisconnectType type)
{
    LS_ASSERT(transport != NULL);
    LS_ASSERT(outgoing != NULL);

    /* TODO: make sure that the client going down is removed from the clients
     * list before we call this function, so we don't attempt to send any
     * more messages to it while trying to tear it down
     *
     * may also need to have some sort of flag to indicate that we can't
     * send any messages */

    /* cancel messages in the outbound queue -- even if they are only
     * partially sent we know that they couldn't have been processed by
     * the other end */

    /* go through and cancel all messages above the token in this message by looking
       up the serial number and getting the globally unique token */

    /* custom message failure handler */
    if (transport->message_failure_handler)
    {
        LOG_LS_DEBUG("last serial: %d\n", (int)last_serial);

        OUTGOING_LOCK(&outgoing->lock);

        /* for each item in outbound queue */
        while (!g_queue_is_empty(outgoing->queue))
        {
            /* grab message off queue */
            _LSTransportMessage *failed_message = (_LSTransportMessage*)g_queue_pop_head(outgoing->queue);

            // We can be reentered from the callback. So don't hold the lock during the callback
            OUTGOING_UNLOCK(&outgoing->lock);
            transport->message_failure_handler(_LSTransportMessageGetToken(failed_message), _LSTransportMessageFailureTypeNotProcessed, transport->message_failure_context);
            OUTGOING_LOCK(&outgoing->lock);

            /* remove the serial from the set if it is a method call; other control
             * messages won't be put on the list */
            if (_LSTransportMessageGetType(failed_message) == _LSTransportMessageTypeMethodCall)
            {
                _LSTransportSerialRemove(outgoing->serial, _LSTransportMessageGetToken(failed_message));
            }

            _LSTransportMessageUnref(failed_message);
        }

        OUTGOING_UNLOCK(&outgoing->lock);

        _LSTransportSerialHandleShutdown(outgoing->serial, last_serial, type, transport->message_failure_handler, transport->message_failure_context);
    }
}

/**
 *******************************************************************************
 * @brief Perform shutdown handling for a client.
 *
 * @attention locks transport lock
 *
 * @param  client       IN  client that is shutting down
 * @param  last_serial  IN  last serial processed
 * @param  type         IN  disconnect reason
 * @param  no_fail      IN  if true don't call failure callback for pending messages
 *******************************************************************************
 */
void
_LSTransportClientShutdown(_LSTransportClient *client, LSMessageToken last_serial, _LSTransportDisconnectType type, bool no_fail)
{
    LS_ASSERT(client != NULL);

    LOG_LS_DEBUG("%s\n", __func__);

    _LSTransportClientRef(client);

    _LSTransportOutgoing *pending = NULL;
    _LSTransport *transport = client->transport;

    /* Remove ref-counted client from hash tables.
     *
     * NOV-104865: We remove the client from the hash tables *before* calling
     * the failure callbacks so that any calls in the callback to the same client
     * will kick off a new QueryName. */
    LOG_LS_DEBUG("removing client from hash tables\n");

    TRANSPORT_LOCK(&transport->lock);

    /* First, attempt to remove from client hash; it may not be in here
     * if it's not providing a service (i.e., doesn't have a service name */
    _LSTransportRemoveClientHash(client->transport, client);

    /* Then, remove from all connection hash which must have it */
    _LSTransportRemoveAllConnectionHash(client->transport, client);

    // Only examine the pending outgoing messages if we are a client that initiate the connection
    const bool is_monitor = transport->monitor == client;
    if (!client->initiator || is_monitor)
    {
        TRANSPORT_UNLOCK(&transport->lock);
        goto skip_pending;
    }

    if (client->service_name)
    {
        /* NOTE: this lookup needs to be protected by the transport lock */
        pending = g_hash_table_lookup(transport->pending, client->service_name);

        if (pending)
        {
            g_hash_table_remove(transport->pending, client->service_name);
        }
    }

    // There shouldn't be messages in the both the pending and outgoing queues
    if (client->outgoing->queue)
    {
        LS_ASSERT(!pending || g_queue_is_empty(client->outgoing->queue));
    }

    TRANSPORT_UNLOCK(&transport->lock);

    if (!no_fail)
    {
        /*
         * If we have any pending messages to this service, then we need to
         * process the failure callback for those
         */
        if (pending)
        {
            _LSTransportClientShutdownProcessQueue(transport, pending, last_serial, type);
            _LSTransportOutgoingFree(pending);
        }

        _LSTransportClientShutdownProcessQueue(transport, client->outgoing, last_serial, type);
    }

skip_pending:
    /* call custom disconnect cleanup handler */
    if (!no_fail && transport->disconnect_handler)
    {
        transport->disconnect_handler(client, type, transport->disconnect_context);
    }

    /* default cleanup */
    _LSTransportDisconnectCleanup(client);

    _LSTransportClientUnref(client);
}

/**
 *******************************************************************************
 * @brief Perform "dirty shutdown" cleanup.
 *
 * @attention locks outgoing serial lock
 *
 * @param  client   IN  client that shutdown
 *******************************************************************************
 */
void
_LSTransportClientShutdownDirty(_LSTransportClient *client)
{
    /* "last_serial" is the first item on the serial list because we
     * need to treat all of them as having failed */
    LSMessageToken last_serial;

    OUTGOING_SERIAL_LOCK(&client->outgoing->serial->lock);

    _LSTransportSerialListItem *item = (_LSTransportSerialListItem*) g_queue_peek_head(client->outgoing->serial->queue);

    if (item)
    {
        last_serial = item->serial;
    }
    else
    {
        /* no outstanding method calls */
        last_serial = LSMESSAGE_TOKEN_INVALID;
    }

    OUTGOING_SERIAL_UNLOCK(&client->outgoing->serial->lock);

    _LSTransportClientShutdown(client, last_serial, _LSTransportDisconnectTypeDirty, false);

    /* mark client as shutdown -- TODO: separate state for dirty shutdown? */
    client->state = _LSTransportClientStateShutdown;
}

bool
_LSTransportGetCancelToken(_LSTransportMessage *message, int *token)
{
    JSchemaInfo schemaInfo;
    jschema_info_init(&schemaInfo, jschema_all(), NULL, NULL);

    *token = 0;
    bool success = false;
    jvalue_ref tokenObj = NULL;

    LS_ASSERT(_LSTransportMessageGetType(message) == _LSTransportMessageTypeCancelMethodCall);

    const char *payload = _LSTransportMessageGetPayload(message);

    jvalue_ref object = jdom_parse(j_cstr_to_buffer(payload), DOMOPT_NOOPT,
                                   &schemaInfo);
    if (jis_null(object))
    {
        goto error;
    }

    if (!jobject_get_exists(object, J_CSTR_TO_BUF("token"), &tokenObj))
    {
        goto error;
    }

    (void)jnumber_get_i32(tokenObj, token);/* TODO: handle appropriately */

    success = true;
error:
    j_release(&object);
    return success;
}

static bool
_call_pending(_LSTransportClient *client, int serial)
{
    _LSTransportOutgoing *pending = g_hash_table_lookup(client->transport->pending, client->service_name);

    if (pending)
    {
        return g_hash_table_lookup(pending->serial->map, &serial) != NULL;
    }
    else
    {
        return false;
    }
}

/**
 *******************************************************************************
 * @brief Process a shutdown message.
 *
 * @param  message  IN  shutdown message
 *******************************************************************************
 */
void
_LSTransportHandleShutdown(_LSTransportMessage *message)
{
    LS_ASSERT(message != NULL);

    LOG_LS_DEBUG("%s\n", __func__);

    LSMessageToken last_serial;
    _LSTransportClient *client = message->client;

    bool ret = _LSTransportGetShutdownToken(message, &last_serial);
    if (!ret)
    {
        LOG_LS_DEBUG("Unable to get the shutdown token");
        LS_ASSERT(0);
    }

    LOG_LS_DEBUG("last serial: %d\n", (int)last_serial);

    GQueue *new_pending = g_queue_new();

    // We only need to look at pending outgoing messages if we initiated the connection
    if (client->initiator && client->is_dynamic && client->service_name)
    {
        TRANSPORT_LOCK(&client->transport->lock);

        OUTGOING_LOCK(&client->outgoing->lock);

        LS_ASSERT(g_hash_table_lookup(client->transport->pending, client->service_name) == NULL);

        /*
            A message can be:
                - only in the serial queue, it was completely sent.
                - in the serial and outgoing queues, 0 to n-1 bytes have been sent.
                - only in the outgoing queue, it isn't a method call.
        */

        // Move the contents (if any) of the serial queue to the new pending queue
        _LSTransportMessage *serial_message = NULL;
        _LSTransportMessage *outgoing_message = NULL;
        LSMessageToken serial_message_token = 0;

        while ((serial_message = _LSTransportSerialPopHead(client->outgoing->serial)) != NULL)
        {
            LS_ASSERT(_LSTransportMessageTypeMethodCall == _LSTransportMessageGetType(serial_message));
            serial_message_token = _LSTransportMessageGetToken(serial_message);
            LSMessageToken outgoing_message_token;

            /*
                Process all tokens in outgoing->queue that are less than or equal to the token of the message from
                outgoing->serial. This assumes that lower token numbers come first in outgoing->queue.
            */
            while (
                   (outgoing_message = g_queue_peek_head(client->outgoing->queue)) != NULL &&
                   (outgoing_message_token = _LSTransportMessageGetToken(outgoing_message)) <= serial_message_token
            )
            {
                outgoing_message = g_queue_pop_head(client->outgoing->queue);

                if (outgoing_message_token < serial_message_token)
                {
                    LS_ASSERT(_LSTransportMessageTypeMethodCall != _LSTransportMessageGetType(outgoing_message));
                    g_queue_push_tail(new_pending, outgoing_message);
                }
                else
                {
                    LS_ASSERT(serial_message_token == outgoing_message_token);
                    _LSTransportMessageUnref(outgoing_message);
                }

                LS_ASSERT(outgoing_message->ref);
            }
            // Add message from outgoing->serial now that we have moved all messages with lower tokens
            g_queue_push_tail(new_pending, serial_message);
        }

        // Move the remaining contents (if any) of the outgoing queue to the new pending queue
        while ((outgoing_message = g_queue_pop_head(client->outgoing->queue)) != NULL)
        {
            LS_ASSERT(_LSTransportMessageTypeMethodCall != _LSTransportMessageGetType(outgoing_message));
            LS_ASSERT(_LSTransportMessageGetToken(outgoing_message) > serial_message_token);
            g_queue_push_tail(new_pending, outgoing_message);
        }

        OUTGOING_UNLOCK(&client->outgoing->lock);

        TRANSPORT_UNLOCK(&client->transport->lock);
    }

    /*
        For a dynamic service since there are no pending messages and the outgoing queue is empty the call to
        _LSTransportClientShutdown should not execute any callbacks. So even though we can't hold the lock no
        one will have a chance to send any new messages and have them get ahead of the older messages we are moving.
    */
    _LSTransportClientShutdown(client, last_serial, _LSTransportDisconnectTypeClean, client->is_dynamic);

    if (g_queue_get_length(new_pending) > 0)
    {
        LSError lserror;
        LSErrorInit(&lserror);

#if 0
        // FIXME - take this expensive operation out after testing
        OUTGOING_LOCK(&client->outgoing->serial->lock);
        LS_ASSERT(g_queue_get_length(client->outgoing->serial->queue) == 0);
        OUTGOING_UNLOCK(&client->outgoing->serial->lock);

        // FIXME - take this expensive operation out after testing
        OUTGOING_LOCK(&client->outgoing->lock);
        LS_ASSERT(g_queue_get_length(client->outgoing->queue) == 0);
        OUTGOING_UNLOCK(&client->outgoing->lock);
#endif

        // There should still be no pending messages after calling _LSTransportClientShutdown
        LS_ASSERT(g_hash_table_lookup(client->transport->pending, client->service_name) == NULL);

        guint pending_length = g_queue_get_length(new_pending);
        if (pending_length)
        {
            LOG_LS_WARNING(MSGID_LS_QUEUE_ERROR, 1,
                           PMLOGKS("APP_ID", client->service_name),
                           "%s: requeueing %u messages for service \"%s\"",
                           __func__, pending_length, client->service_name);
            while ((message = g_queue_pop_head(new_pending)) != NULL)
            {
                int serial;

                if (_LSTransportMessageGetType(message) == _LSTransportMessageTypeCancelMethodCall &&
                    _LSTransportGetCancelToken(message, &serial) &&
                    !_call_pending(client, serial)
                   )
                {
                    LOG_LS_WARNING(MSGID_LS_TOKEN_ERR, 1,
                                   PMLOGKS("APP_ID", client->service_name),
                                   "%s: not requeueing cancel-method-call for service \"%s\", token %d"
                                   " because the matching call is not present", __func__,
                                   client->service_name, serial);
                }
                else
                {
                    _LSTransportMessageReset(message);
                    /* ref's the message */
                    if (!_LSTransportAddPendingMessageWithToken(client->transport, client->service_name, message, _LSTransportMessageGetToken(message), &lserror))
                    {
                        LOG_LSERROR(MSGID_LS_QUEUE_ERROR, &lserror);
                        LSErrorFree(&lserror);
                    }
                }
                // In the case where we don't requeue a cancel this should free the message
                _LSTransportMessageUnref(message);
            }
        }
    }

    if (new_pending)
    {
        g_queue_free(new_pending);
    }

    /* mark client as shutdown */
    client->state = _LSTransportClientStateShutdown;
}

/**
 *******************************************************************************
 * @brief Add a watch to a channel and attach it to the main context.
 *
 * @param  channel       IN  channel to watch
 * @param  condition     IN  condition to watch
 * @param  context       IN  main context
 * @param  transport_cb  IN  callback when watch is triggered
 * @param  user_data     IN  context passed to callback
 * @param  destroy_cb    IN  callback when watch is destroyed
 * @param  *out_watch    OUT newly created watch
 *******************************************************************************
 */
static void
_LSTransportAddWatch(_LSTransportChannel *channel, GIOCondition condition, GMainContext *context, GIOFunc transport_cb, void *user_data, GDestroyNotify destroy_cb, GSource **out_watch)
{
    LS_ASSERT(channel != NULL);
    LS_ASSERT(channel->channel != NULL);
    LS_ASSERT(context != NULL);
    LS_ASSERT(out_watch != NULL);
    LS_ASSERT(*out_watch == NULL);

    GSource *watch = g_io_create_watch(channel->channel, condition);

    if (channel->priority != G_PRIORITY_DEFAULT)
    {
        g_source_set_priority(watch, channel->priority);
    }

    g_source_set_callback(watch, (GSourceFunc)transport_cb, user_data, destroy_cb);

    /* we set this before attaching because once we call attach, we can potentially
     * wake a separate thread running the mainloop associated with this context */
    *out_watch = watch;

    g_source_attach(watch, context);

	/* We should be able to unref the channel here because g_io_create_watch
     * increments the ref count */
    //g_io_channel_unref(channel->channel);

    //g_source_unref(watch);
}

/**
 *******************************************************************************
 * @brief Remove a watch from a channel.
 *
 * @param  channel      IN      channel that watch is on
 * @param  *out_watch   IN/OUT  watch (set to NULL after destroying)
 *******************************************************************************
 */
static void
_LSTransportRemoveWatch(_LSTransportChannel *channel, GSource **out_watch)
{
    LS_ASSERT(channel != NULL);
    LS_ASSERT(out_watch != NULL);
    LS_ASSERT(*out_watch != NULL);

    /* The user_data will be cleaned up by the GDestroyNotify callback */
    g_source_destroy(*out_watch);
    g_source_unref(*out_watch);
    *out_watch = NULL;
}

/**
 *******************************************************************************
 * @brief Add a send watch to a channel.
 *
 * @param  channel  IN  channel
 * @param  context  IN  main loop context
 * @param  client   IN  client to pass to watch callback
 *******************************************************************************
 */
void
_LSTransportAddSendWatch(_LSTransportChannel *channel, GMainContext *context, _LSTransportClient *client)
{
    LS_ASSERT(channel != NULL);
    LS_ASSERT(context != NULL);

    if (!channel->send_watch)
    {
        LOG_LS_DEBUG("%s: channel: %p, context: %p, client: %p\n", __func__, channel, context, client);

        _LSTransportClientRef(client);
        _LSTransportAddWatch(channel, G_IO_OUT, context, _LSTransportSendClient, client, (GDestroyNotify) _LSTransportClientUnref, &channel->send_watch);
    }
}

/**
 *******************************************************************************
 * @brief Remove a send watch from a channel.
 *
 * @param  channel  IN  channel
 *******************************************************************************
 */
void
_LSTransportRemoveSendWatch(_LSTransportChannel *channel)
{
    LS_ASSERT(channel != NULL);
    LS_ASSERT(channel->send_watch != NULL);

    LOG_LS_DEBUG("%s: channel: %p\n", __func__, channel);

    if (channel->send_watch)
    {
        _LSTransportRemoveWatch(channel, &channel->send_watch);
        /* client is unref'd by GDestroyNotify callback */
    }
}

/**
 *******************************************************************************
 * @brief Add a receive watch to a channel.
 *
 * @param  channel  IN  channel
 * @param  context  IN  main loop context
 * @param  client   IN  client to pass to watch callback
 *******************************************************************************
 */
void
_LSTransportAddReceiveWatch(_LSTransportChannel *channel, GMainContext *context, _LSTransportClient *client)
{
    LS_ASSERT(channel != NULL);
    LS_ASSERT(context != NULL);

    if (!channel->recv_watch)
    {
        LOG_LS_DEBUG("%s: channel: %p, context: %p, client: %p\n", __func__, channel, context, client);

        _LSTransportClientRef(client);
        _LSTransportAddWatch(channel, G_IO_IN | G_IO_ERR | G_IO_HUP, context, _LSTransportReceiveClient, client, (GDestroyNotify) _LSTransportClientUnref, &channel->recv_watch);
    }
}

/**
 *******************************************************************************
 * @brief Remove a receive watch from a channel.
 *
 * @param  channel  IN  channel
 *******************************************************************************
 */
void
_LSTransportRemoveReceiveWatch(_LSTransportChannel *channel)
{
    LS_ASSERT(channel != NULL);
    LS_ASSERT(channel->recv_watch != NULL);

    LOG_LS_DEBUG("%s: channel: %p\n", __func__, channel);

    if (channel->recv_watch)
    {
        _LSTransportRemoveWatch(channel, &channel->recv_watch);
        /* client is unref'd by GDestroyNotify callback */
    }
}

/**
 *******************************************************************************
 * @brief Add an accept watch to a channel.
 *
 * @param  channel  IN  channel
 * @param  context  IN  main loop context
 * @param  user_data IN user data to pass to watch callback
 *******************************************************************************
 */
void
_LSTransportAddAcceptWatch(_LSTransportChannel *channel, GMainContext *context, void *user_data)
{
    LS_ASSERT(channel != NULL);
    LS_ASSERT(context != NULL);

    LOG_LS_DEBUG("%s: channel: %p, context: %p, transport: %p\n", __func__, channel, context, user_data);

    _LSTransportAddWatch(channel, G_IO_IN | G_IO_ERR | G_IO_HUP, context, _LSTransportAcceptConnection, user_data, NULL, &channel->accept_watch);
}

/**
 *******************************************************************************
 * @brief Remove an accept watch from a channel.
 *
 * @param  channel  IN  channel
 *******************************************************************************
 */
void
_LSTransportRemoveAcceptWatch(_LSTransportChannel *channel)
{
    LS_ASSERT(channel != NULL);
    LS_ASSERT(channel->accept_watch != NULL);

    LOG_LS_DEBUG("%s: channel: %p\n", __func__, channel);

    _LSTransportRemoveWatch(channel, &channel->accept_watch);
}

/**
 *******************************************************************************
 * @brief Add send and receive watches to a client's channel.
 *
 * @param  ignored              IN  ignored
 * @param  client               IN  client to add watches to
 * @param  mainloop_context     IN  main loop context
 *******************************************************************************
 */
void
_LSTransportAddClientWatches(void *ignored, _LSTransportClient *client, GMainContext *mainloop_context)
{
    LS_ASSERT(client != NULL);
    LS_ASSERT(mainloop_context != NULL);

    LOG_LS_DEBUG("%s: client: %p, mainloop_context: %p\n", __func__, client, mainloop_context);

    _LSTransportAddSendWatch(&client->channel, mainloop_context, client);
    _LSTransportAddReceiveWatch(&client->channel, mainloop_context, client);
}

/**
 *******************************************************************************
 * @brief Add the first set of watches to kick off sending messages.
 *
 * @attention locks the transport lock
 *
 * @param  transport    IN  transport
 * @param  context      IN  main loop context
 *******************************************************************************
 */
void
_LSTransportAddInitialWatches(_LSTransport *transport, GMainContext *context)
{
    /* set up send/receive watches on all clients and hub so we can
     * kickstart sending of messages */
    TRANSPORT_LOCK(&transport->lock);
    g_hash_table_foreach(transport->clients, (GHFunc)_LSTransportAddClientWatches, context);
    TRANSPORT_UNLOCK(&transport->lock);

    /* kickstart the monitor */
    if (transport->monitor)
    {
        _LSTransportAddClientWatches(NULL, transport->monitor, context);
    }

    /* Watch and accept incoming connections */
    _LSTransportAddAcceptWatch(&transport->listen_channel, context, transport);
}

/**
 *******************************************************************************
 * @brief Associate a GMainContext set of sources with this transport.
 *
 * @param  transport    IN  transport
 * @param  context      IN  main loop context
 *******************************************************************************
 */
void
_LSTransportGmainAttach(_LSTransport *transport, GMainContext *context)
{
    LS_ASSERT(transport != NULL);
    LS_ASSERT(context != NULL);

    LOG_LS_DEBUG("%s: mainloop_context: %p\n", __func__, transport->mainloop_context);

    transport->mainloop_context = g_main_context_ref(context);

    _LSTransportAddInitialWatches(transport, transport->mainloop_context);
}

/**
 *******************************************************************************
 * @brief Get the GMainContext associated with this transport.
 *
 * @param  transport    IN  transport
 *
 * @retval  GMainContext or NULL
 *******************************************************************************
 */
GMainContext*
_LSTransportGetGmainContext(const _LSTransport *transport)
{
    LS_ASSERT(transport != NULL);
    return transport->mainloop_context;
}

/**
 *******************************************************************************
 * @brief Set the glib mainloop priority for sending and receiving.
 *
 * @param  unused       IN      dummy arg for GHFunc callback
 * @param  client       IN      client
 * @param  priority     IN      priority to set
 *******************************************************************************
 */
static void
_LSTransportClientSetPriority(int unused, _LSTransportClient *client, int priority)
{
    _LSTransportChannelSetPriority(&client->channel, priority);
}

/**
 *******************************************************************************
 * @brief Set the glib mainloop priority for the send, receive, and
 * accept watches (sources).
 *
 * @todo I think this should be deprecated. Searching around with cscope
 * shows that only LunaSysMgr uses it, and I'm not sure if it really
 * provides much benefit.
 *
 * @param  transport    IN  transport
 * @param  priority     IN  glib mainloop priority (e.g., G_PRIORITY_DEFAULT)
 * @param  lserror      OUT error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
_LSTransportGmainSetPriority(_LSTransport *transport, int priority, LSError *lserror)
{
    _LSErrorIfFail(transport != NULL, lserror, MSGID_LS_PARAMETER_IS_NULL);

    /* set priority for all existing sources */
    TRANSPORT_LOCK(&transport->lock);
    g_hash_table_foreach(transport->all_connections, (GHFunc)_LSTransportClientSetPriority, GINT_TO_POINTER(priority));
    TRANSPORT_UNLOCK(&transport->lock);

    /* set the priority for our accept watch */
    _LSTransportChannelSetPriority(&transport->listen_channel, priority);

    /* keep track of priority for future source creation */
    transport->source_priority = priority;

    return true;
}

bool
_LSTransportListenLocal(const char *unique_name, mode_t mode, int *fd, LSError *lserror)
{
    struct sockaddr_un addr;

    int tmp_fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (tmp_fd < 0)
    {
        goto error;
    }

    memset(&addr, 0, sizeof(struct sockaddr_un));

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, unique_name, sizeof(addr.sun_path) -1);

    unlink(unique_name);

    if (bind(tmp_fd, (struct sockaddr*) &addr, sizeof(struct sockaddr_un)) < 0)
    {
        LOG_LS_ERROR(MSGID_LS_SOCK_ERROR, 0, "Socket bind error");
        goto error;
    }

    chmod(unique_name, mode);

    if (listen(tmp_fd, LISTEN_BACKLOG) < 0)
    {
        LOG_LS_ERROR(MSGID_LS_SOCK_ERROR, 0, "Socket listen error");
        goto error;
    }

    *fd = tmp_fd;

    return true;

error:
    _LSErrorSetFromErrno(lserror, MSGID_LS_SOCK_ERROR, errno);

    if (tmp_fd >= 0)
    {
        close(tmp_fd);
    }

    return false;
}

bool
_LSTransportSetupListenerLocalRaw(_LSTransport *transport, const char *name, int listen_fd, mode_t mode, LSError* lserror)
{
    bool ret = true;

    LOG_LS_DEBUG("%s: transport: %p, name: %s\n", __func__, transport, name);

    transport->type = _LSTransportTypeLocal;

    /* -1 means that we don't have a valid fd already set up */
    if (listen_fd == -1)
    {
        ret = _LSTransportListenLocal(name, mode, &listen_fd, lserror);
    }

    /* create the channel */
    if (ret)
    {
        _LSTransportChannelInit(transport, &transport->listen_channel, listen_fd, transport->source_priority);
    }

    /* we'll add the accept watch when we get a gmain context to attach it to */

    return ret;
}

static bool
_LSTransportSetupListenerLocalWithFd(_LSTransport *transport, const char *name, int listen_fd, LSError *lserror)
{
    LS_ASSERT(listen_fd != -1);
    return _LSTransportSetupListenerLocalRaw(transport, name, listen_fd, 0, lserror);

#if 0
    LOG_LS_DEBUG("%s: transport: %p, name: %s\n", __func__, transport, name);
    transport->type = _LSTransportTypeLocal;

    /* create the channel */
    _LSTransportChannelInit(transport, &transport->listen_channel, listen_fd, transport->source_priority);

    /* we'll add the accept watch when we get a gmain context to attach it to */

    return true;
#endif
}

/**
 *******************************************************************************
 * @brief Set up the listen channel for the unix domain socket @ref name.
 *
 * @param  transport    IN  transport
 * @param  name         IN  full path to unix domain socket
 * @param  listen_fd    IN  fd that is already bound to @name and set up to listen
 * @mode   mode         IN  permissions for
 * @param  lserror      OUT set on error
 *
 * @retval true on success
 * @retval false on error
 *******************************************************************************
 */
bool
_LSTransportSetupListenerLocal(_LSTransport *transport, const char *name, mode_t mode, LSError *lserror)
{
    return _LSTransportSetupListenerLocalRaw(transport, name, -1, mode, lserror);

#if 0
    //char err_buf[256];
    //struct sockaddr_un addr;

    LOG_LS_DEBUG("%s: transport: %p, name: %s\n", __func__, transport, name);
    transport->type = _LSTransportTypeLocal;

#if 0
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (fd < 0)
    {
        goto error;
    }

    memset(&addr, 0, sizeof(struct sockaddr_un));

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, name, sizeof(addr.sun_path) -1);

    unlink(name);

    if (bind(fd, (struct sockaddr*) &addr, sizeof(struct sockaddr_un)) < 0)
    {
        LOG_LS_ERROR(MSGID_LS_SOCK_ERROR, 0, "Socket bind error");
        goto error;
    }

    if (listen(listen_fd, LISTEN_BACKLOG) < 0)
    {
        LOG_LS_ERROR(MSGID_LS_SOCK_ERROR, 0, "Socket listen error");
        goto error;
    }
#endif

    /* create the channel */
    _LSTransportChannelInit(transport, &transport->listen_channel, listen_fd, transport->source_priority);

    /* we'll add the accept watch when we get a gmain context to attach it to */

    return true;

#if 0
error:
    strerror_r(errno, err_buf, sizeof(err_buf));
    _LSErrorSetLiteral(lserror, errno, err_buf);

    if (fd > 0)
    {
        close(fd);
    }

    return false;
#endif

#endif
}

/**
 *******************************************************************************
 * @brief Set up the listen channel on an inet address.
 *
 * @param  transport    IN  transport
 * @param  port         IN  port to listen on (negative means any)
 * @param  lserror      OUT set on error
 *
 * @retval true on success
 * @retval false on error
 *******************************************************************************
 */
bool
_LSTransportSetupListenerInet(_LSTransport *transport, int port, LSError *lserror)
{
    struct sockaddr_in addr;

    LOG_LS_DEBUG("%s: transport: %p, port: %d\n", __func__, transport, port);

    transport->type = _LSTransportTypeInet;

    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0)
    {
        goto error;
    }

    if (port >= 0)
    {
        memset(&addr, 0, sizeof(struct sockaddr_in));

        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = INADDR_ANY;

        int optval = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

        if (bind(fd, (struct sockaddr*) &addr, sizeof(struct sockaddr_in)) < 0)
        {
            LOG_LS_ERROR(MSGID_LS_SOCK_ERROR, 0, "Socket bind error");
            goto error;
        }
    }

    if (listen(fd, LISTEN_BACKLOG) < 0)
    {
        LOG_LS_ERROR(MSGID_LS_SOCK_ERROR, 0, "Socket listen error");
        goto error;
    }

    /* create the channel */
    _LSTransportChannelInit(transport, &transport->listen_channel, fd, transport->source_priority);

    /* we'll add the accept watch when we get a gmain context to attach it to */

    return true;

error:
    _LSErrorSetFromErrno(lserror, MSGID_LS_SOCK_ERROR, errno);

    if (fd >= 0)
    {
        close(fd);
    }

    return false;
}

/**
 *******************************************************************************
 * @brief Add client to hash of service name to client.
 *
 * @attention should be called with transport lock
 *
 * @param  transport    IN  transport
 * @param  client       IN  client to add (value)
 * @param  client_name  IN  client service name (key)
 *
 * @retval true on success
 * @retval false on failure
 *******************************************************************************
 */
bool
_LSTransportAddClientHash(_LSTransport *transport, _LSTransportClient *client, const char *client_name)
{
    LOG_LS_DEBUG("%s: inserting client: %s (%p)\n", __func__, client_name, client);

    const char* name = g_strdup(client_name);
    if (!name)
    {
        return false;
    }

    _LSTransportClientRef(client);

    /* TODO: insert or replace ? */
    g_hash_table_insert(transport->clients, (gpointer)name, client);

    return true;
}

/**
 *******************************************************************************
 * @brief Callback for removing a client fromt the client hash.
 *
 * @param  key          IN     ignored
 * @param  value        IN     client for this @ref key
 * @param  user_data    IN     client we're searching for
 *
 * @retval TRUE if client matches client we're trying to remove
 * @retval FALSE otherwise
 *******************************************************************************
 */
gboolean
_LSTransportClientHashRemoveFunc(gpointer key, gpointer value, gpointer user_data)
{
    _LSTransportClient *search_client = (_LSTransportClient*)(user_data);
    _LSTransportClient *value_client = (_LSTransportClient*)(value);

    if (search_client == value_client)
    {
        LOG_LS_DEBUG("%s: removing client: %p\n", __func__, search_client);
        return TRUE;
    }
    return FALSE;
}

/**
 *******************************************************************************
 * @brief Remove the specified client from the client hash.
 *
 * @param  transport    IN  transport
 * @param  client       IN  client to remove
 *******************************************************************************
 */
void
_LSTransportRemoveClientHash(_LSTransport *transport, _LSTransportClient *client)
{
    LOG_LS_DEBUG("%s: transport: %p, client: %p\n", __func__, transport, client);

    /*
     * TODO: this is a linear search; it's only done on shutdown, but we should
     * still probably change it.
     */
    int ret = g_hash_table_foreach_remove(transport->clients, _LSTransportClientHashRemoveFunc, client);

    LS_ASSERT(ret == 1 || ret == 0);
}

/**
 *******************************************************************************
 * @brief Add client to hash of all clients. Key is file descriptor and value
 * is @ref _LSTransportClient.
 *
 * @attention must be called with transport lock
 *
 * @param  transport    IN  transport
 * @param  client       IN  client to add
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
_LSTransportAddAllConnectionHash(_LSTransport *transport, _LSTransportClient *client)
{
    LOG_LS_DEBUG("%s: inserting client %p\n", __func__, client);

    _LSTransportClientRef(client);

    client->state = _LSTransportClientStateConnected;

    /* TODO: insert or replace ? */
    g_hash_table_insert(transport->all_connections, GINT_TO_POINTER(client->channel.fd), client);

    return true;
}

/**
 *******************************************************************************
 * @brief Remove specified client from the all connection hash.
 *
 * @param  transport    IN  transport
 * @param  client       IN  client to remove
 *
 * @retval true if client was removed
 * @retval false otherwise
 *******************************************************************************
 */
bool
_LSTransportRemoveAllConnectionHash(_LSTransport *transport, _LSTransportClient *client)
{
    LOG_LS_DEBUG("%s: removing client: %p\n", __func__, client);

    /* Monitor connection is going down */
    if (client == transport->monitor)
    {
        /* we had a ref associated with this */
        _LSTransportClientUnref(client);
        transport->monitor = NULL;
    }

    /* destroy function will unref client */
    return g_hash_table_remove(transport->all_connections, GINT_TO_POINTER(client->channel.fd));
}

/**
*******************************************************************************
* @brief Split a unique name string of the form "ip:port" into ip address
* and port number
*
* @param  unique_name
* @param  ip
* @param  port
* @param  lserror
*
* @retval
*******************************************************************************
*/
bool
_LSTransportSplitInetUniqueName(const char *unique_name, struct in_addr *ip, uint16_t *port, LSError *lserror)
{
    LS_ASSERT(unique_name != NULL);

    struct in_addr tmp_ip;
    uint16_t tmp_port;
    char *delim = NULL;
    bool ret = false;

    char *unique_name_copy = g_strdup(unique_name);

    delim = strchr(unique_name_copy, ':');

    if (delim == NULL)
    {
        _LSErrorSet(lserror, MSGID_LS_ADDR_ERR, -1, "Unable to find ':'");
        goto error;
    }

    *delim = '\0';

    if (inet_pton(AF_INET, unique_name_copy, &tmp_ip) <= 0)
    {
        _LSErrorSet(lserror, MSGID_LS_ADDR_ERR, -1, "Unable to convert address");
        goto error;
    }

    delim = delim + 1;

    if (*delim == '\0')
    {
        _LSErrorSet(lserror, MSGID_LS_ADDR_ERR, -1, "Badly formatted address:port");
        goto error;
    }

    errno = 0;
    tmp_port = strtol(delim, NULL, 10);

    if (errno != 0)
    {
        _LSErrorSetFromErrno(lserror, MSGID_LS_ADDR_ERR, errno);
        goto error;
    }

    *ip = tmp_ip;
    *port = htons(tmp_port);

    ret = true;

error:
    g_free(unique_name_copy);
    return ret;
}

/**
 *******************************************************************************
 * @brief Connect to a local (domain socket) endpoint. This function operates
 * in two modes depending on the value of "new_socket"
 *
 * new_socket is true:
 *      fd is the output arg that has the fd for the newly created and
 *      connected socket. On non-fatal errors the socket will be returned
 *      through the fd arg; on fatal errors (_LSTransportConnectStateOtherFailure)
 *      there will be no new socket
 *
 *  new_socket is false:
 *      fd is the input arg and is the fd for an already created socket. This
 *      function will attempt to connect the socket to the specfied
 *      unique_name. The input socket (fd) will never be closed (even on
 *      error).
 *
 * @param  unique_name  IN  unique name to connect to
 * @param  new_socket   IN  true means create a new socket, otherwise use
 *                          existing
 * @param  fd        IN/OUT input when new_socket is false, output otherwise
 * @param  lserror      OUT set on fatal error (_LSTransportConnectStateOtherFailure)
 *
 * @retval  _LSTransportConnectStateNoError on success
 * @retval  _LSTransportConnectStateOtherFailure on fatal error
 * @retval  _LSTransportConnectStateEinprogress on EINPROGRESS (would block)
 * @retval  _LSTransportConnectStateEagain on EAGAIN (would block)
 *******************************************************************************
 */
_LSTransportConnectState
_LSTransportConnectLocal(const char *unique_name, bool new_socket, int *fd, LSError *lserror)
{
    LS_ASSERT(unique_name != NULL);
    LS_ASSERT(fd != NULL);

    struct sockaddr_un addr;
    int tmp_fd;

    if (new_socket)
    {
        tmp_fd = socket(AF_UNIX, SOCK_STREAM, 0);

        if (tmp_fd < 0)
        {
            _LSErrorSetFromErrno(lserror, MSGID_LS_SOCK_ERROR, errno);
            return _LSTransportConnectStateOtherFailure;
        }
    }
    else
    {
        tmp_fd = *fd;
    }

    _LSTransportFdSetNonBlock(tmp_fd, NULL);

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, unique_name, sizeof(addr.sun_path) -1);

    int ret = connect(tmp_fd, (struct sockaddr*)&addr, sizeof(addr));

    if (ret < 0)
    {
        /* POSIX says EINPROGRESS is the return value when the socket is
         * non-blocking and can't be completed immediately. However, on Linux
         * when using domain sockets if the backlog queue is full, it will
         * return EAGAIN. See unix_stream_connect() in net/unix/af_unix.c */
        if (errno == EINPROGRESS)
        {
            if (new_socket)
            {
                *fd = tmp_fd;
            }
            return _LSTransportConnectStateEinprogress;
        }
        else if (errno == EAGAIN)
        {
            if (new_socket)
            {
                *fd = tmp_fd;
            }
            return _LSTransportConnectStateEagain;
        }
        else
        {
            /* Some function callers log this error also, but
             * sometimes they shadow original socket error, so
             * this log message makes debugging much easier */
            LOG_LS_ERROR(MSGID_LS_SOCK_ERROR, 2,
                         PMLOGKFV("ERROR_CODE", "%d", errno),
                         PMLOGKS("ERROR", g_strerror(errno)),
                         "Could not connect to the socket: %s", unique_name);
            _LSErrorSetNoPrint(lserror, errno, g_strerror(errno));
            if (new_socket)
            {
                close(tmp_fd);
                *fd = -1;
            }
            return _LSTransportConnectStateOtherFailure;
        }
    }

    _LSTransportFdSetBlock(tmp_fd, NULL);

    if (new_socket)
    {
        *fd = tmp_fd;
    }

    return _LSTransportConnectStateNoError;
}

/**
 *******************************************************************************
 * @brief Connect to a inet endpoint.
 *
 * @param  unique_name  IN  unique name to connect to
 * @param  fd           OUT output arg that has the fd for the newly created and
 *                          connected socket. On non-fatal errors the socket will be returned
 *                          through the fd arg; on fatal errors (_LSTransportConnectStateOtherFailure)
 *                          there will be no new socket
 * @param  lserror      OUT set on fatal error (_LSTransportConnectStateOtherFailure)
 *
 * @retval  _LSTransportConnectStateNoError on success
 * @retval  _LSTransportConnectStateOtherFailure on fatal error
 * @retval  _LSTransportConnectStateEinprogress on EINPROGRESS (would block)
 * @retval  _LSTransportConnectStateEagain on EAGAIN (would block)
 *******************************************************************************
 */
_LSTransportConnectState
_LSTransportConnectInet(const char *unique_name, int *fd, LSError *lserror)
{
    struct sockaddr_in addr;

    int tmp_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (tmp_fd < 0)
    {
        _LSErrorSetFromErrno(lserror, MSGID_LS_SOCK_ERROR, errno);
        return _LSTransportConnectStateOtherFailure;
    }

    /* split up unique_name into ip and port */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;

    if (!_LSTransportSplitInetUniqueName(unique_name, &addr.sin_addr, &addr.sin_port, lserror))
    {
        close(tmp_fd);
        *fd = -1;
        return _LSTransportConnectStateOtherFailure;
    }

    int ret = connect(tmp_fd, (struct sockaddr*)&addr, sizeof(addr));

    if (ret < 0)
    {
        /* POSIX says EINPROGRESS is the return value when the socket is
         * non-blocking and can't be completed immediately. However, on Linux
         * when using domain sockets if the backlog queue is full, it will
         * return EAGAIN. See unix_stream_connect() in net/unix/af_unix.c */
        if (errno == EINPROGRESS)
        {
            *fd = tmp_fd;
            return _LSTransportConnectStateEinprogress;
        }
        else if (errno == EAGAIN)
        {
            *fd = tmp_fd;
            return _LSTransportConnectStateEagain;
        }
        else
        {
            _LSErrorSetNoPrint(lserror, errno, g_strerror(errno));
            close(tmp_fd);
            *fd = -1;
            return _LSTransportConnectStateOtherFailure;
        }
    }

    *fd = tmp_fd;

    return _LSTransportConnectStateNoError;
}

/**
 *******************************************************************************
 * @brief Connect to a client of a given unique name. If @ref outgoing is
 * specified, then use it as the outbound queue of messages. Otherwise,
 * create a new one.
 *
 * @param  transport
 * @param  service_name
 * @param  unique_name
 * @param  connected_fd         IN      use the already connected fd (local only)
 * @param  outgoing
 * @param  lserror
 *
 * @retval client with ref count of 1 on success
 * @retval NULL on failure
 *******************************************************************************
 */
_LSTransportClient*
_LSTransportConnectClient(_LSTransport *transport, const char *service_name, const char *unique_name, int connected_fd, _LSTransportOutgoing *outgoing, LSError *lserror)
{
    int fd = -1;

    if (transport->type == _LSTransportTypeLocal)
    {
        if (connected_fd != -1)
        {
            /* the hub made the connection for us already */
            fd = connected_fd;
        }
        else
        {
            _LSTransportConnectState cs = _LSTransportConnectLocal(unique_name, true, &fd, lserror);
            if (cs != _LSTransportConnectStateNoError)
            {
                if (cs == _LSTransportConnectStateEagain)
                {
                    _LSErrorSetEAgain(lserror);
                    return NULL;
                }
                goto error;
            }
        }
    }
    else
    {
        _LSTransportConnectState cs = _LSTransportConnectInet(unique_name, &fd, lserror);
        if (cs != _LSTransportConnectStateNoError)
        {
            if (cs == _LSTransportConnectStateEagain)
            {
                _LSErrorSetEAgain(lserror);
                return NULL;
            }
            goto error;
        }
    }

    _LSTransportClient *client = _LSTransportClientNewRef(transport, fd, service_name, unique_name, outgoing, true);

    if (!client)
    {
        close(fd);
        _LSErrorSet(lserror, MSGID_LS_CONN_ERROR, -1, "Could not create new transport client");
        return NULL;
    }

    client->state = _LSTransportClientStateConnected;

    /* Make sure the channel is non-blocking */
    _LSTransportChannelSetNonblock(_LSTransportClientGetChannel(client), NULL);

    LOG_LS_DEBUG("%s: unique_name: %s, client: %p\n", __func__, unique_name, client);

    return client;

error:
    /* Don't log the error, since it will show up when we're searching for the
     * right hub (for tethering) */
    // LOG_LSERROR(&lserror);
    LSErrorFree(lserror);
    _LSErrorSetNoPrint(lserror, LS_ERROR_CODE_CONNECT_FAILURE, LS_ERROR_TEXT_CONNECT_FAILURE, service_name, unique_name);
    return NULL;
}


#define FD_CMSG_LEN     CMSG_LEN(sizeof(int))
#define FD_CMSG_SPACE   CMSG_SPACE(sizeof(int))

static bool
_LSTransportRecvFd(int fd, int *fd_to_recv, bool *retry, LSError *lserror)
{
    char cmsg_buf[FD_CMSG_SPACE];
    struct msghdr fdmsg;
    struct cmsghdr *cmsg = NULL;
    struct iovec iov[1];
    char iov_buf[1];
    int ret = 0;

    iov[0].iov_base = iov_buf;
    iov[0].iov_len = sizeof(iov_buf);

    fdmsg.msg_iov = iov;
    fdmsg.msg_iovlen = ARRAY_SIZE(iov);
    fdmsg.msg_name = NULL;
    fdmsg.msg_namelen = 0;
    fdmsg.msg_control = cmsg_buf;
    fdmsg.msg_controllen = sizeof(cmsg_buf);
    fdmsg.msg_flags = 0;

    while ((ret = recvmsg(fd, &fdmsg, 0)) != 1)
    {
        if (ret == -1)
        {
            if (errno == EAGAIN && retry)
            {
                *retry = true;
                return false;
            }
            else if (errno == EINTR)
            {
                // Interrupted by a system signal. But we need that fd, so let's try again.
                continue;
            }
        }
        _LSErrorSetFromErrno(lserror, MSGID_LS_SOCK_ERROR, errno);
        LOG_LS_ERROR(MSGID_LS_SOCK_ERROR, 0, "Recvmsg failed: errno: %d", errno);

        return false;
    }

    if (iov_buf[0] != 0)
    {
        /* The far side sent an error code instead of an fd.
         * We just set the fd to -1 to mark the fd as invalid, but don't
         * set an error. */
        *fd_to_recv = -1;
        return true;
    }

    if (fdmsg.msg_controllen != sizeof(cmsg_buf))
    {
        /* expecting to get an fd, but it wasn't there */
        _LSErrorSet(lserror, MSGID_LS_SOCK_ERROR, -1, "Expected an fd in message, but didn't receive one (expected len: %zd actual len: %zd)", sizeof(cmsg_buf), fdmsg.msg_controllen);
        return false;
    }

    cmsg = CMSG_FIRSTHDR(&fdmsg);

    int *cmsg_data = (int*)CMSG_DATA(cmsg);
    *fd_to_recv = *cmsg_data;

    return true;
}

static bool
_LSTransportSendFd(int fd, int fd_to_send, bool *retry, LSError *lserror)
{
    char cmsg_buf[FD_CMSG_SPACE];
    struct msghdr fdmsg;
    struct iovec iov[1];
    char iov_buf[1] = {0};
    int ret = 0;

    iov[0].iov_base = iov_buf;
    iov[0].iov_len = sizeof(iov_buf);

    fdmsg.msg_iov = iov;
    fdmsg.msg_iovlen = ARRAY_SIZE(iov);
    fdmsg.msg_name = NULL;
    fdmsg.msg_namelen = 0;
    fdmsg.msg_flags = 0;

    if (fd_to_send < 0)
    {
        fdmsg.msg_control = NULL;
        fdmsg.msg_controllen = 0;

        iov_buf[0] = 1;     /* non-zero means invalid fd, since we can't send
                             * an invalid fd with the control message */
    }
    else
    {
        struct cmsghdr *cmsg = NULL;

        fdmsg.msg_control = cmsg_buf;
        fdmsg.msg_controllen = sizeof(cmsg_buf);

        cmsg = CMSG_FIRSTHDR(&fdmsg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = FD_CMSG_LEN;

        int *cmsg_data = (int*)CMSG_DATA(cmsg);
        *cmsg_data = fd_to_send;
    }

    if ((ret = sendmsg(fd, &fdmsg, 0)) != 1)
    {
        if ((ret == -1) && (errno == EAGAIN) && retry)
        {
            *retry = true;
        }
        else
        {
            _LSErrorSetFromErrno(lserror, MSGID_LS_SOCK_ERROR, errno);
            LOG_LS_ERROR(MSGID_LS_SOCK_ERROR, 0, "Sendmsg failed");
        }
        return false;
    }

    return true;
}

/**
 *******************************************************************************
 * @brief Send data until all has been sent or an error is encountered.
 *
 * @param  fd       IN  destination fd
 * @param  buf      IN  data to send
 * @param  len      IN  size of @ref buf
 * @param  lserror  IN  set on error
 *
 * @retval  bytes sent (same as len) on success
 * @retval  -1 on failure
 *******************************************************************************
 */
static int
_LSTransportSendComplete(int fd, void *buf, int len, LSError *lserror)
{
    int total_bytes_sent = 0;

    while (total_bytes_sent < len)
    {

        int bytes_sent = send(fd, (char*)buf + total_bytes_sent, len - total_bytes_sent, 0);

        /*
         * We encountered an error. This could happen for a variety of
         * reasons. One example would be if a client goes down after
         * we've already started sending to it (or we haven't yet processed
         * the fact that it's down because the mainloop hasn't run yet).
         * See the LSUnregister.c test for an artificial example.
         */
        if (bytes_sent < 0)
        {
            if (errno == EAGAIN || errno == EINTR)
            {
                /* keep going */
                bytes_sent = 0;
            }
            else
            {
                _LSErrorSetFromErrno(lserror, MSGID_LS_SOCK_ERROR, errno);
                return -1;
            }
        }

        total_bytes_sent += bytes_sent;
    }

    return total_bytes_sent;
}

/**
 *******************************************************************************
 * @brief Receive data until all has been received or an error is encountered.
 *
 * @param  fd       IN  source fd
 * @param  buf      IN  buf to store data
 * @param  len      IN  size of @buf
 * @param  lserror  IN  set on error
 *
 * @retval bytes read on success (same as len)
 * @retval -1 on failure
 *******************************************************************************
 */
static int
_LSTransportRecvComplete(int fd, void *buf, int len, LSError *lserror)
{
    int total_bytes_recvd = 0;

    while (total_bytes_recvd < len)
    {
        int bytes_recvd = recv(fd, (char*)buf + total_bytes_recvd, len - total_bytes_recvd, 0);

        if (bytes_recvd <= 0)
        {
            if (bytes_recvd == 0)
            {
                _LSErrorSet(lserror, MSGID_LS_SOCK_ERROR, -1, "Orderly shutdown of connection");
                return -1;
            }
            else if (errno == EAGAIN || errno == EINTR)
            {
                /* keep going */
                bytes_recvd = 0;
            }
            else
            {
                _LSErrorSetFromErrno(lserror, MSGID_LS_SOCK_ERROR, errno);
                return -1;
            }
        }

        total_bytes_recvd += bytes_recvd;
    }

    return total_bytes_recvd;
}

/**
 *******************************************************************************
 * @brief  Block until we receive the complete message of the specified type.
 *
 * @warning This must not be called at a point in time where we have a receive
 * watch set on a client or there will be a race between the two. It's really
 * only meant for use during startup and shutdown.
 *
 * @param  client       IN   client
 * @param  types        IN   array of message types to wait for
 * @param  num_types    IN   num items in types array
 * @param  timeout_ms   IN   timeout in ms
 * @param  lserror      OUT  set on error
 *
 * @retval message on success
 * @retval NULL on failure
 *******************************************************************************
 */
_LSTransportMessage*
_LSTransportRecvMessageBlocking(_LSTransportClient *client, _LSTransportMessageType *types, int num_types, int timeout_ms, LSError *lserror)
{
    LOG_LS_DEBUG("%s: client: %p\n", __func__, client);

    bool restore_watch = false;
    _LSTransportMessage *message = NULL;
    _LSTransportHeader header;
    bool old_block_state = false;

    /* If there is a send watch for this client, temporarily remove it so that
     * the two won't conflict if the mainloop is running in one thread and this
     * function is running in another */
    if (_LSTransportChannelHasReceiveWatch(_LSTransportClientGetChannel(client)))
    {
        restore_watch = true;
        _LSTransportRemoveReceiveWatch(_LSTransportClientGetChannel(client));
    }

    /* Make sure the channel is blocking */
    _LSTransportChannelSetBlock(_LSTransportClientGetChannel(client), &old_block_state);

    /* receive incoming messages until we get type or timeout */

    /* if the message doesn't match what we're looking for, queue it up
     * to be handled later -- how do we kick the message handler? */

    /* TODO: use poll() with timeout value */
    int bytes_recvd = _LSTransportRecvComplete(client->channel.fd, &header, sizeof(header), lserror);

    if (bytes_recvd == -1)
    {
        goto exit;
    }

    LS_ASSERT(bytes_recvd == sizeof(header));

    int i;
    bool msg_type_match = false;
    for (i = 0; i < num_types; i++)
    {
        if (header.type == types[i])
        {
            msg_type_match = true;
            break;
        }
    }

    LS_ASSERT(msg_type_match == true);

    message = _LSTransportMessageNewRef(header.len);

    _LSTransportMessageSetHeader(message, &header);

    bytes_recvd = _LSTransportRecvComplete(client->channel.fd, _LSTransportMessageGetBody(message), message->raw->header.len, lserror);

    if (bytes_recvd == -1)
    {
        _LSTransportMessageUnref(message);
        message = NULL;
        goto exit;
    }

    LS_ASSERT(bytes_recvd == message->raw->header.len);

    _LSTransportMessageSetClient(message, client);

    /* Check to see if we need to get the fd */
    if (_LSTransportMessageIsConnectionFdType(message))
    {
        int recv_fd = -1;
        bool need_retry = false;
        if (!_LSTransportRecvFd(client->channel.fd, &recv_fd, &need_retry, lserror))
        {
            LS_ASSERT(!need_retry);
            _LSTransportMessageUnref(message);
            message = NULL;
            goto exit;
        }

        _LSTransportMessageSetConnectionFd(message, recv_fd);
    }

exit:
    _LSTransportChannelRestoreBlockState(_LSTransportClientGetChannel(client), &old_block_state);

    if (restore_watch)
    {
        GMainContext *context = _LSTransportGetGmainContext(_LSTransportClientGetTransport(client));
        _LSTransportAddReceiveWatch(_LSTransportClientGetChannel(client), context, client);
    }

    return message;
}


/**
 *******************************************************************************
 * @brief Send a message and block until it has been completely sent. The
 * message ref count does not change when calling this function.
 *
 * If there is a send watch for the client, this function will remove and restore
 * it so that the two do not conflict if running in different threads.
 *
 * @param  message  IN  message to send
 * @param  client   IN  client performing send
 * @param  token    OUT token of message
 * @param  lserror  OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
_LSTransportSendMessageBlocking(_LSTransportMessage *message, _LSTransportClient *client,
                                LSMessageToken *token, LSError *lserror)
{
    LOG_LS_DEBUG("%s: client: %p, message type: %d\n", __func__, client, _LSTransportMessageGetType(message));

    bool ret = false;
    bool restore_watch = false;

    /* If there is a send watch for this client, temporarily remove it so that
     * the two won't conflict if the mainloop is running in one thread and this
     * function is running in another */
    if (_LSTransportChannelHasSendWatch(_LSTransportClientGetChannel(client)))
    {
        restore_watch = true;
        _LSTransportRemoveSendWatch(_LSTransportClientGetChannel(client));
    }

    bool old_block_state = false;

    _LSTransportChannelSetBlock(_LSTransportClientGetChannel(client), &old_block_state);

    /* TODO: flush the outgoing queue before sending the requested message
     * so that we preserve ordering? */

    /* LOCK -- this grabs global_token lock */
    _LSTransportMessageSetToken(message, _LSTransportGetNextToken(client->transport));

    message->tx_bytes_remaining = message->raw->header.len + sizeof(_LSTransportHeader);

    int send_ret = _LSTransportSendComplete(client->channel.fd, (char*)message->raw + message->raw->header.len + sizeof(_LSTransportHeader) - message->tx_bytes_remaining, message->tx_bytes_remaining, lserror);

    if (send_ret == -1)
    {
        ret = false;
        goto exit;
    }

    LS_ASSERT(send_ret == message->tx_bytes_remaining);
    message->tx_bytes_remaining = 0;

    if (token)
    {
        *token = _LSTransportMessageGetToken(message);
    }

    /* TODO: MONITOR: send message to monitor as well */

    ret = true;

exit:
    _LSTransportChannelRestoreBlockState(_LSTransportClientGetChannel(client), &old_block_state);

    if (restore_watch)
    {
        GMainContext *context = _LSTransportGetGmainContext(_LSTransportClientGetTransport(client));
        _LSTransportAddSendWatch(_LSTransportClientGetChannel(client), context, client);
    }

    return ret;
}

/**
 *******************************************************************************
 * @brief Process a monitor message, which involves connecting to the monitor
 * and sending our client info to it.
 *
 * @attention locks transport lock
 *
 * @param  message  IN  monitor message
 *******************************************************************************
 */
static void
_LSTransportHandleMonitor(_LSTransportMessage *message)
{
    LSError lserror;
    LSErrorInit(&lserror);

    const char *unique_name = NULL;

    _LSTransport *transport = message->client->transport;

    /* get the unique name out of the message */
    _LSTransportMessageIter iter;
    _LSTransportMessageIterInit(message, &iter);
    _LSTransportMessageGetString(&iter, &unique_name);

    /* This means that there is no monitor in the system -- we receive
     * this message when first connecting to the hub */
    if (unique_name == NULL)
    {
        return;
    }

    LS_ASSERT(_LSTransportMessageGetType(message) != _LSTransportMessageTypeMonitorNotConnected);

    LOG_LS_DEBUG("%s: connecting to monitor: %s\n", __func__, unique_name);

    transport->monitor = _LSTransportConnectClient(transport, NULL, unique_name, dup(_LSTransportMessageGetConnectionFd(message)), NULL, &lserror);

    if (!transport->monitor)
    {
        LOG_LSERROR(MSGID_LS_TRANSPORT_CONNECT_ERR, &lserror);
        LSErrorFree(&lserror);
        return;
    }

    /* MONITOR -- send client info so monitor knows who we are */
    if (!_LSTransportSendMessageClientInfo(transport->monitor, transport->service_name, transport->unique_name, false, &lserror))
    {
        LOG_LSERROR(MSGID_LS_TRANSPORT_NETWORK_ERR, &lserror);
        LSErrorFree(&lserror);
    }

    /* add to hash of all connected clients, but not named client hash */
    TRANSPORT_LOCK(&transport->lock);
    /* client ref +1 (total = 2) */
    _LSTransportAddAllConnectionHash(transport, transport->monitor);
    TRANSPORT_UNLOCK(&transport->lock);

    if (transport->mainloop_context)
    {
        _LSTransportAddSendWatch(&transport->monitor->channel, transport->mainloop_context, transport->monitor);
        _LSTransportAddReceiveWatch(&transport->monitor->channel, transport->mainloop_context, transport->monitor);
    }
}

/**
 *******************************************************************************
 * @brief Run the user's message handler for the message. If the message is of
 * method call type, check the return value from the callback and possibly
 * send an error message in reply.
 *
 * @param  message  IN  message
 *******************************************************************************
 */
static void
_LSTransportHandleUserMessageHandler(_LSTransportMessage *message)
{
    LOG_LS_DEBUG("%s: calling user's msg_handler\n", __func__);

    LSError lserror;
    LSErrorInit(&lserror);

    _LSTransportClient *client = _LSTransportMessageGetClient(message);
    void *msg_context = client->transport->msg_context;

    LSMessageHandlerResult ret = (*client->transport->msg_handler)(message, msg_context);

    /*
     * We only care about whether the message was handled if the message type
     * is a method call, since we need to send a reply error message in that
     * case
     */
    if (_LSTransportMessageGetType(message) != _LSTransportMessageTypeMethodCall)
    {
        return;
    }

    switch (ret)
    {
    case LSMessageHandlerResultHandled:
    {
        /* success, don't need to do anything */
        break;
    }
    case LSMessageHandlerResultNotHandled:
    {
        char *error_msg = g_strdup_printf("Method \"%s\" for category \"%s\" was not handled", _LSTransportMessageGetMethod(message), _LSTransportMessageGetCategory(message));

        if (!_LSTransportSendErrorReply(message, _LSTransportMessageTypeError, error_msg, &lserror))
        {
            LOG_LSERROR(MSGID_LS_TRANSPORT_NETWORK_ERR, &lserror);
            LSErrorFree(&lserror);
        }

        g_free(error_msg);

        break;
    }
    case LSMessageHandlerResultUnknownMethod:
    {
        LS_ASSERT(_LSTransportMessageGetType(message) == _LSTransportMessageTypeMethodCall);

        char *error_msg = g_strdup_printf("Unknown method \"%s\" for category \"%s\"", _LSTransportMessageGetMethod(message), _LSTransportMessageGetCategory(message));

        if (!_LSTransportSendErrorReply(message, _LSTransportMessageTypeErrorUnknownMethod, error_msg, &lserror))
        {
            LOG_LSERROR(MSGID_LS_TRANSPORT_NETWORK_ERR, &lserror);
            LSErrorFree(&lserror);
        }

        g_free(error_msg);

        break;
    }
    default:
    {
        LOG_LS_ERROR(MSGID_LS_MSG_ERR, 0, "Unexpected handler result: %d", ret);
        LS_ASSERT(0);
        break;
    }
    }

    return;
}

/**
 *******************************************************************************
 * @brief Get the status of the monitor when first connecting to the hub so we
 * know whether to send our messages to the monitor.
 *
 * @param  transport    IN  transport
 * @param  client       IN  client
 * @param  lserror      OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
static bool
_LSTransportReceiveMonitorStatus(_LSTransport *transport, _LSTransportClient *client, LSError *lserror)
{
    _LSTransportMessageType msg_types[2] = {
        _LSTransportMessageTypeMonitorConnected,
        _LSTransportMessageTypeMonitorNotConnected
    };

    _LSTransportMessage *message = _LSTransportRecvMessageBlocking(client, msg_types, ARRAY_SIZE(msg_types), -1, lserror);

    if (!message)
    {
        return false;
    }

    _LSTransportHandleMonitor(message);
    _LSTransportMessageUnref(message);

    return true;
}

/**
 *******************************************************************************
 * @brief Request a service name from the hub. NULL means we just need a unique
 * name.
 *
 * @attention This call blocks until a name has been received from the hub.
 *
 * @param  requested_name   IN  service name or NULL for only unique name
 * @param  client           IN  client
 * @param  fd               OUT fd passed from hub that we should listen on
 * @param  privileged       OUT true if the service is privileged
 * @param  lserror          OUT set on error
 *
 * @retval  name that is allocated (and must be free'd) on success
 * @retval  NULL on failure
 *******************************************************************************
 */
char*
_LSTransportRequestNameLocal(const char *requested_name, _LSTransportClient *client, int *fd, bool *privileged, LSError *lserror)
{
    _LSTransportMessageIter iter;
    const char *unique_name_tmp = NULL;
    char *unique_name = NULL;

    LOG_LS_DEBUG("%s: requested_name: %s, client: %p\n", __func__, requested_name, client);

    _LSTransportMessage *message = _LSTransportMessageNewRef(LS_TRANSPORT_MESSAGE_DEFAULT_PAYLOAD_SIZE);

    _LSTransportMessageSetType(message, _LSTransportMessageTypeRequestNameLocal);

    _LSTransportMessageIterInit(message, &iter);
    if (!_LSTransportMessageAppendInt32(&iter, LS_TRANSPORT_PROTOCOL_VERSION)) goto error;
    if (!_LSTransportMessageAppendString(&iter, requested_name)) goto error;
    if (!_LSTransportMessageAppendInvalid(&iter)) goto error;

    if (!_LSTransportSendMessageBlocking(message, client, NULL, lserror))
    {
        _LSTransportMessageUnref(message);
        return NULL;
    }

    _LSTransportMessageUnref(message);

    /* get the response */
    _LSTransportMessageType msg_type = _LSTransportMessageTypeRequestNameLocalReply;
    message = _LSTransportRecvMessageBlocking(client, &msg_type, 1, -1, lserror);

    if (!message)
    {
        return NULL;
    }

    /* TODO: create accessor for getting the return code and name */
    _LSTransportMessageIterInit(message, &iter);

    int32_t err_code;
    if (!_LSTransportMessageGetInt32(&iter, &err_code))
    {
        LOG_LS_ERROR(MSGID_LS_MSG_ERR, 0, "FIXME!");
    }

    LOG_LS_DEBUG("%s: received err_code: %"PRId32"\n", __func__, err_code);

    switch (err_code)
    {

    case LS_TRANSPORT_REQUEST_NAME_SUCCESS:
    {
        _LSTransportMessageIterNext(&iter);
        _LSTransportMessageGetBool(&iter, privileged);
        _LSTransportMessageIterNext(&iter);
        _LSTransportMessageGetString(&iter, &unique_name_tmp);

        /* need copy since iterator points inside message */
        unique_name = g_strdup(unique_name_tmp);

        if (!unique_name)
        {
            LS_ASSERT(0);
        }

        int message_fd = _LSTransportMessageGetConnectionFd(message);
        LS_ASSERT(message_fd != -1);

        *fd = dup(message_fd);
        if (-1 == *fd)
        {
            LOG_LS_ERROR(MSGID_LS_DUP_ERR, 2,
                         PMLOGKFV("ERROR_CODE", "%d", errno),
                         PMLOGKS("ERROR", g_strerror(errno)),
                         "%s: dup() failed, errno %d, \"%s\"", __func__, errno, g_strerror(errno));
        }
        LS_ASSERT(*fd != -1);

        LOG_LS_DEBUG("%s: received unique_name: %s, %sprivileged\n", __func__, unique_name, *privileged ? "" : "not ");

        break;
    }

    case LS_TRANSPORT_REQUEST_NAME_PERMISSION_DENIED:
        _LSErrorSet(lserror, MSGID_LS_REQUEST_NAME, LS_ERROR_CODE_PERMISSION, LS_ERROR_TEXT_PERMISSION, requested_name);
        break;

    case LS_TRANSPORT_REQUEST_NAME_NAME_ALREADY_REGISTERED:
        _LSErrorSet(lserror, MSGID_LS_REQUEST_NAME, LS_ERROR_CODE_DUPLICATE_NAME, LS_ERROR_TEXT_DUPLICATE_NAME, requested_name);
        break;

    default:
        _LSErrorSet(lserror, MSGID_LS_REQUEST_NAME, LS_ERROR_CODE_UNKNOWN_ERROR, LS_ERROR_TEXT_UNKNOWN_ERROR);
        break;
    }

    _LSTransportMessageUnref(message);

    return unique_name;

error:
    if (message) _LSTransportMessageUnref(message);
    _LSErrorSetOOM(lserror);
    return NULL;
}

/**
 *******************************************************************************
 * @brief Request a service name from the hub. NULL means we just need a unique
 * name.
 *
 * @attention This call blocks until a name has been received from the hub.
 *
 * @param  requested_name   IN  service name or NULL for only unique name
 * @param  client           IN  client
 * @param  privileged       OUT true if the service is privileged
 * @param  lserror          OUT set on error
 *
 * @retval  name that is allocated (and must be free'd) on success
 * @retval  NULL on failure
 *******************************************************************************
 */
char*
_LSTransportRequestNameInet(const char *requested_name, _LSTransportClient *client, bool *privileged, LSError *lserror)
{
    const char *unique_name_tmp = NULL;
    char *unique_name = NULL;
    int32_t port = 0;
    _LSTransportMessage *message = NULL;
    bool alloc_error = true;
    _LSTransportMessageIter iter;

    LOG_LS_DEBUG("%s: requested_name: %s, client: %p\n", __func__, requested_name, client);

    int listen_fd = _LSTransportChannelGetFd(&client->transport->listen_channel);

    /* send our listen port to the hub */
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);

    if (getsockname(listen_fd, (struct sockaddr*) &addr, &addrlen) != 0)
    {
        _LSErrorSetFromErrno(lserror, MSGID_LS_SOCK_ERROR, errno);
        goto exit;
    }

    port = ntohs(addr.sin_port);

    LOG_LS_DEBUG("%s: port: %d\n", __func__, port);

    message = _LSTransportMessageNewRef(LS_TRANSPORT_MESSAGE_DEFAULT_PAYLOAD_SIZE);

    _LSTransportMessageSetType(message, _LSTransportMessageTypeRequestNameInet);

    _LSTransportMessageIterInit(message, &iter);
    if (!_LSTransportMessageAppendInt32(&iter, LS_TRANSPORT_PROTOCOL_VERSION)) goto error;
    if (!_LSTransportMessageAppendString(&iter, requested_name)) goto error;
    if (!_LSTransportMessageAppendInt32(&iter, port)) goto error;
    if (!_LSTransportMessageAppendInvalid(&iter)) goto error;

    if (!_LSTransportSendMessageBlocking(message, client, NULL, lserror)) goto exit;

    _LSTransportMessageUnref(message);

    /* get the response */
    _LSTransportMessageType msg_type = _LSTransportMessageTypeRequestNameInetReply;
    message = _LSTransportRecvMessageBlocking(client, &msg_type, 1, -1, lserror);

    if (!message) goto exit;

    /* TODO: create accessor for getting the return code and name */
    _LSTransportMessageIterInit(message, &iter);

    int32_t err_code;
    if (!_LSTransportMessageGetInt32(&iter, &err_code))
    {
        LOG_LS_ERROR(MSGID_LS_MSG_ERR, 0, "FIXME!");
    }

    LOG_LS_DEBUG("%s: received err_code: %"PRId32"\n", __func__, err_code);

    switch (err_code)
    {

    case LS_TRANSPORT_REQUEST_NAME_SUCCESS:
    {
        _LSTransportMessageIterNext(&iter);
        _LSTransportMessageGetBool(&iter, privileged);
        _LSTransportMessageIterNext(&iter);
        _LSTransportMessageGetString(&iter, &unique_name_tmp);

        /* need copy since iterator points inside message */
        unique_name = g_strdup(unique_name_tmp);

        if (!unique_name)
        {
            LS_ASSERT(0);
        }

        LOG_LS_DEBUG("%s: received unique_name: %s, %sprivileged\n", __func__, unique_name, *privileged ? "" : "not ");

        break;
    }

    case LS_TRANSPORT_REQUEST_NAME_PERMISSION_DENIED:
        _LSErrorSet(lserror, MSGID_LS_REQUEST_NAME, LS_ERROR_CODE_PERMISSION, LS_ERROR_TEXT_PERMISSION, requested_name);
        break;

    case LS_TRANSPORT_REQUEST_NAME_NAME_ALREADY_REGISTERED:
        _LSErrorSet(lserror, MSGID_LS_REQUEST_NAME, LS_ERROR_CODE_DUPLICATE_NAME, LS_ERROR_TEXT_DUPLICATE_NAME, requested_name);
        break;

    case LS_TRANSPORT_REQUEST_NAME_INVALID_PROTOCOL_VERSION:
        _LSErrorSet(lserror, MSGID_LS_REQUEST_NAME, LS_ERROR_CODE_PROTOCOL_VERSION, LS_ERROR_TEXT_PROTOCOL_VERSION, LS_TRANSPORT_PROTOCOL_VERSION);

        break;

    default:
        _LSErrorSet(lserror, MSGID_LS_REQUEST_NAME, LS_ERROR_CODE_UNKNOWN_ERROR, LS_ERROR_TEXT_UNKNOWN_ERROR);
        break;
    }

exit:
    alloc_error = false;
error:
    if (message) _LSTransportMessageUnref(message);
    if (alloc_error)
    {
        unique_name = NULL;
        _LSErrorSetOOM(lserror);
    }

    return unique_name;
}

char*
_LSTransportRequestName(const char *requested_name, _LSTransportClient *client, int *fd, bool *privileged, LSError *lserror)
{
    if (client->transport->type == _LSTransportTypeLocal)
    {
        return _LSTransportRequestNameLocal(requested_name, client, fd, privileged, lserror);
    }
    else
    {
        return _LSTransportRequestNameInet(requested_name, client, privileged, lserror);
    }
}

/**
 *******************************************************************************
 * @brief Send a "QueryName" message to the hub.
 *
 * @param  hub                   IN  client info for hub
 * @param  trigger_message       IN  message that triggered this "QueryName"
 * @param  service_name          IN  service name to look up
 * @param  lserror               OUT set on error
 *
 * @retval true on success
 * @retval false on failure
 *******************************************************************************
 */
bool
_LSTransportQueryName(_LSTransportClient *hub, _LSTransportMessage *trigger_message, const char *service_name, LSError *lserror)
{
    bool ret = true;

    LOG_LS_DEBUG("%s: service_name %s, hub: %p\n", __func__, service_name, hub);

    const char *app_id = _LSTransportMessageGetAppId(trigger_message);

    /* allocate query message */
    _LSTransportMessage *message = _LSTransportMessageNewRef(LS_TRANSPORT_MESSAGE_DEFAULT_PAYLOAD_SIZE);

    _LSTransportMessageSetType(message, _LSTransportMessageTypeQueryName);

    _LSTransportMessageIter iter;
    _LSTransportMessageIterInit(message, &iter);

    if (!_LSTransportMessageAppendString(&iter, service_name)) goto error;
    if (!_LSTransportMessageAppendString(&iter, app_id)) goto error;
    if (!_LSTransportMessageAppendInvalid(&iter)) goto error;

    /* send */
    if (!_LSTransportSendMessage(message, hub, NULL, lserror))
    {
        ret = false;
    }

    _LSTransportMessageUnref(message);

    return ret;

error:
    if (message) _LSTransportMessageUnref(message);
    _LSErrorSetOOM(lserror);
    return false;
}

/**
 *******************************************************************************
 * @brief Get the return value out of a "QueryName" reply message.
 *
 * @param  message  IN  query name message
 *
 * @retval  return val (numeric value)
 *******************************************************************************
 */
int32_t
_LSTransportQueryNameReplyGetReturnVal(_LSTransportMessage *message)
{
    LS_ASSERT(message != NULL);
    LS_ASSERT(_LSTransportMessageGetType(message) == _LSTransportMessageTypeQueryNameReply);
    _LSTransportMessageIter iter;
    int32_t ret;

    _LSTransportMessageIterInit(message, &iter);

    if (_LSTransportMessageGetInt32(&iter, &ret))
    {
        return ret;
    }
    return LS_TRANSPORT_QUERY_NAME_MESSAGE_CONTENT_ERROR;
}

/* @warn these point inside the message, so you should ref the message or copy the
 * string if you want it to persist */
/**
 *******************************************************************************
 * @brief Get the service name from a "QueryName" reply message.
 *
 * @warning The returned pointer points inside the message so you should ref
 * the message or copy the string if you want it to persist.
 *
 * @param  message  IN  query name message
 *
 * @retval name on success
 * @retval NULL on failure
 *******************************************************************************
 */
const char*
_LSTransportQueryNameReplyGetServiceName(_LSTransportMessage *message)
{
    LS_ASSERT(message != NULL);
    LS_ASSERT(_LSTransportMessageGetType(message) == _LSTransportMessageTypeQueryNameReply);
    _LSTransportMessageIter iter;
    const char *ret = NULL;

    _LSTransportMessageIterInit(message, &iter);
    /* move past return code */
    _LSTransportMessageIterNext(&iter);

    if (_LSTransportMessageGetString(&iter, &ret))
    {
        return ret;
    }
    return NULL;
}

/**
 *******************************************************************************
 * @brief Get the unique name from a message.
 *
 * @warning The returned pointer points inside the message, so you should ref
 * the message or copy the string if you need it to persist.
 *
 * @param  message  IN  message
 *
 * @retval name on success
 * @retval NULL on failure
 *******************************************************************************
 */
const char*
_LSTransportQueryNameReplyGetUniqueName(_LSTransportMessage *message)
{
    LS_ASSERT(message != NULL);
    LS_ASSERT(_LSTransportMessageGetType(message) == _LSTransportMessageTypeQueryNameReply);
    _LSTransportMessageIter iter;
    const char *ret = NULL;

    _LSTransportMessageIterInit(message, &iter);
    /* move past return code and service name */
    _LSTransportMessageIterNext(&iter);
    _LSTransportMessageIterNext(&iter);

    if (_LSTransportMessageGetString(&iter, &ret))
    {
        return ret;
    }
    return NULL;
}

/**
 *******************************************************************************
 * @brief Get is_dynamic boolean out of a "QueryName" reply message.
 *
 * @param  message  IN  query name message
 *
 * @retval  is_dynamic
 *******************************************************************************
 */
bool
_LSTransportQueryNameReplyGetIsDynamic(_LSTransportMessage *message)
{
    LS_ASSERT(message != NULL);
    LS_ASSERT(_LSTransportMessageGetType(message) == _LSTransportMessageTypeQueryNameReply);
    _LSTransportMessageIter iter;
    int32_t ret = 0;

    _LSTransportMessageIterInit(message, &iter);

    /* move past return code, service name, and unique name */
    _LSTransportMessageIterNext(&iter);
    _LSTransportMessageIterNext(&iter);
    _LSTransportMessageIterNext(&iter);

    if (_LSTransportMessageGetInt32(&iter, &ret))
    {
        return ret ? true : false;
    }
    return false;
}

/**
 *******************************************************************************
 * @brief Helper callback to send a message to a monitor if it's a message
 * that we care about monitoring.
 *
 * @param  message  IN  message
 * @param  client   IN  client
 *******************************************************************************
 */
static void
_LSTransportSendMessageMonitorHelper(_LSTransportMessage *message, _LSTransportClient *client)
{
    if (_LSTransportMessageIsMonitorType(message))
    {
        _LSTransportSendMessageMonitor(message, client, _LSMonitorMessageTypeTx, NULL, NULL);
    }
}

/**
 *******************************************************************************
 * @brief Send messages on the pending queue to the monitor.
 *
 * @attention locks the outgoing lock
 *
 * @param  transport    IN  transport
 * @param  client       IN  client
 * @param  pending      IN  outgoing queue
 *******************************************************************************
 */
static void
_LSTransportSendPendingMonitorMessages(_LSTransport *transport, _LSTransportClient *client, _LSTransportOutgoing *pending)
{
    LOG_LS_DEBUG("%s: client: %p, pending: %p\n", __func__, client, pending);

    OUTGOING_LOCK(&pending->lock);
    g_queue_foreach(pending->queue, (GFunc)_LSTransportSendMessageMonitorHelper, client);
    OUTGOING_UNLOCK(&pending->lock);
}

/**
 *******************************************************************************
 * @brief Handle a failure reply to a "QueryName" message.
 *
 * @attention locks both the transport and outgoing lock
 *
 * @param  message          IN  query name reply message
 * @param  err_code         IN  error code - see @LunaServiceQueryNameReturnCodes
 * @param  service_name     IN  service name that we failed to find
 * @param  is_dynamic       IN  true if the service is dynamic
 *******************************************************************************
 */
void
_LSTransportHandleQueryNameFailure(_LSTransportMessage *message, long err_code, const char *service_name, bool is_dynamic)
{
    LS_ASSERT(err_code != LS_TRANSPORT_QUERY_NAME_SUCCESS);

    LSError lserror;
    LSErrorInit(&lserror);

    if (!service_name)
    {
        LOG_LS_ERROR(MSGID_LS_QNAME_ERR, 0, "%s: NULL service name given in query name failure", __func__);
        return;
    }

    /* error case */
    _LSTransport *transport = _LSTransportMessageGetClient(message)->transport;

    TRANSPORT_LOCK(&transport->lock);

    _LSTransportOutgoing *pending = g_hash_table_lookup(transport->pending, service_name);

    if (!pending)
    {
        LOG_LS_ERROR(MSGID_LS_QNAME_ERR, 1,
                     PMLOGKS("APP_ID", service_name),
                     "%s: Unable to find service: \"%s\" when processing query name failure",
                     __func__, service_name);
        TRANSPORT_UNLOCK(&transport->lock);
        return;
    }

    OUTGOING_LOCK(&pending->lock);

    /* Grab the first message on the pending queue, since the target that it is
     * destined for has failed in some manner */
    _LSTransportMessage *failed_message = g_queue_pop_head(pending->queue);

    LS_ASSERT(failed_message);

    /* At the point where we're querying for a name we should only be
     * queuing up method calls or canceling method calls
     * See LSCall_kill_server_continue_sending_messages test for an example of the latter */
    _LSTransportMessageType msg_type = _LSTransportMessageGetType(failed_message);
    LS_ASSERT(msg_type == _LSTransportMessageTypeMethodCall
              || msg_type == _LSTransportMessageTypeCancelMethodCall);


    if (is_dynamic && LS_TRANSPORT_QUERY_NAME_SERVICE_NOT_AVAILABLE == err_code)
    {
        if (--failed_message->retries > 0)
        {
            g_queue_push_head(pending->queue, failed_message);
            OUTGOING_UNLOCK(&pending->lock);

            LOG_LS_WARNING(MSGID_LS_MSG_ERR, 1,
                           PMLOGKS("APP_ID", service_name),
                           "%s: retrying sending query name to service \"%s\", %d retries remain",
                           __func__, service_name, failed_message->retries);

            if (!_LSTransportQueryName(transport->hub, failed_message, service_name, &lserror))
            {
                LS_ASSERT(!"_LSTransportQueryName failed");
            }
            TRANSPORT_UNLOCK(&transport->lock);
            goto done;
        }
        else
        {
            LOG_LS_ERROR(MSGID_LS_MSG_ERR, 1,
                         PMLOGKS("APP_ID", service_name),
                         "%s: too many retries sending query name to service \"%s\"", __func__, service_name);
        }
    }

    if (msg_type == _LSTransportMessageTypeMethodCall)
    {
        _LSTransportSerialRemove(pending->serial, _LSTransportMessageGetToken(failed_message));
    }

    _LSTransportMessage *next_message = g_queue_peek_head(pending->queue);
    if (NULL != next_message)
    {
        OUTGOING_UNLOCK(&pending->lock);

        LS_ASSERT(transport->hub);
        /* we still have messages destined for this service, so send another
         * query message to see if the service has come up since */

        LS_ASSERT(MAX_SEND_RETRIES == next_message->retries);

        if (!_LSTransportQueryName(transport->hub, next_message, service_name, &lserror))
        {
            LS_ASSERT(0);
        }
    }
    else
    {
        /* pending queue is empty, so we need to clean up */
        if (!g_hash_table_remove(transport->pending, service_name))
        {
            LS_ASSERT(0);
        }

        OUTGOING_UNLOCK(&pending->lock);

        /* the key was free'd, but we need to clean up the value */
        _LSTransportOutgoingFree(pending);
    }

    TRANSPORT_UNLOCK(&transport->lock);

    /* call failure handler for this message -- only makes sense for method calls */
    if (msg_type == _LSTransportMessageTypeMethodCall)
    {
        _LSTransportMessageFailureType failure_type;

        switch (err_code)
        {
        case LS_TRANSPORT_QUERY_NAME_SERVICE_NOT_AVAILABLE:
        case LS_TRANSPORT_QUERY_NAME_TIMEOUT:
        case LS_TRANSPORT_QUERY_NAME_CONNECT_TIMEOUT:
            failure_type = _LSTransportMessageFailureTypeServiceUnavailable;
            break;
        case LS_TRANSPORT_QUERY_NAME_SERVICE_NOT_EXIST:
            failure_type = _LSTransportMessageFailureTypeServiceNotExist;
            break;
        case LS_TRANSPORT_QUERY_NAME_PERMISSION_DENIED:
            failure_type = _LSTransportMessageFailureTypePermissionDenied;
            break;
        case LS_TRANSPORT_QUERY_NAME_MESSAGE_CONTENT_ERROR:
            failure_type = _LSTransportMessageFailureTypeMessageContentError;
            break;
        default:
            failure_type = _LSTransportMessageFailureTypeUnknown;
            break;
        }

        transport->message_failure_handler(_LSTransportMessageGetToken(failed_message), failure_type, transport->message_failure_context);
    }

    /* we're done with this message */
    _LSTransportMessageUnref(failed_message);
done:;
}

/**
 *******************************************************************************
 * @brief Handle a reply to a "QueryName" message from the hub.
 *
 * @attention locks transport lock
 *
 * @param  message  IN  query name reply message
 *******************************************************************************
 */
void
_LSTransportHandleQueryNameReply(_LSTransportMessage *message)
{
    LOG_LS_DEBUG("%s\n", __func__);

    LSError lserror;
    LSErrorInit(&lserror);

    int32_t ret_code = 0;
    int dup_fd = -1;

    _LSTransport *transport = _LSTransportClientGetTransport(_LSTransportMessageGetClient(message));

    /* get the service name out of the message -- always have this, even in failure */
    const char *service_name = _LSTransportQueryNameReplyGetServiceName(message);

    /* check return code */
    ret_code = _LSTransportQueryNameReplyGetReturnVal(message);

    int message_fd = _LSTransportMessageGetConnectionFd(message);

    /* get is_dynamic out of the message */
    bool is_dynamic = _LSTransportQueryNameReplyGetIsDynamic(message);

    /*
        In the hub there *was* a race where the reply was created with a non-error code but the
        client went down before we could connect. In that case we arrive here with an error code of
        LS_TRANSPORT_QUERY_NAME_SUCCESS but message_fd is -1. This race has been fixed but a
        little paranoia is in order.
    */
    if (unlikely((ret_code == LS_TRANSPORT_QUERY_NAME_SUCCESS) && (message_fd == -1)))
    {
        if (_LSTransportGetTransportType(transport) == _LSTransportTypeLocal)
        {
            ret_code = LS_TRANSPORT_QUERY_NAME_SERVICE_NOT_AVAILABLE;
        }
    }

    if (ret_code != LS_TRANSPORT_QUERY_NAME_SUCCESS)
    {
        _LSTransportHandleQueryNameFailure(message, ret_code, service_name, is_dynamic);
        return;
    }

    /* get the unique name out of the message */
    const char *unique_name = _LSTransportQueryNameReplyGetUniqueName(message);

    /* make sure we have a valid service_name and unique_name */
    if (unique_name == NULL || service_name == NULL)
    {
        _LSTransportHandleQueryNameFailure(message, LS_TRANSPORT_QUERY_NAME_MESSAGE_CONTENT_ERROR, service_name, is_dynamic);
        return;
    }

    LOG_LS_DEBUG("%s: service_name: %s, unique_name: %s, %s\n", __func__, service_name, unique_name, is_dynamic ? "dynamic" : "static");

    /* Atomically move messages from pending queue to hash of available services */
    TRANSPORT_LOCK(&transport->lock);

    /* move set of messages in pending queue to outbound queue for the now-connected client -- by defintion if we get here there should be at least one message on the queue for this service */
    _LSTransportOutgoing *pending = (_LSTransportOutgoing*)g_hash_table_lookup(transport->pending, service_name);

    LS_ASSERT(pending);

    if (_LSTransportGetTransportType(transport) == _LSTransportTypeLocal)
    {
        dup_fd = dup(message_fd);
        if (-1 == dup_fd)
        {
            LOG_LS_ERROR(MSGID_LS_DUP_ERR, 2,
                         PMLOGKFV("ERROR_CODE", "%d", errno),
                         PMLOGKS("ERROR", g_strerror(errno)),
                         "%s: dup() failed", __func__);
        }
        LS_ASSERT(dup_fd != -1);
    }

    /* connect to our new friend */
    _LSTransportClient *client = _LSTransportConnectClient(transport, service_name,
                                                           unique_name,
                                                           dup_fd,
                                                           pending, &lserror);

    if (!client)
    {
        LOG_LSERROR(MSGID_LS_TRANSPORT_CONNECT_ERR, &lserror);
        LSErrorFree(&lserror);
        TRANSPORT_UNLOCK(&transport->lock);
        _LSTransportHandleQueryNameFailure(message, LS_TRANSPORT_QUERY_NAME_SERVICE_NOT_AVAILABLE, service_name, is_dynamic);
        return;
    }

    client->is_dynamic = is_dynamic;

    /* We successfully connected to the far side, so remove the service from
     * the transport lookup queue.
     *
     * This frees the key, but not the value due to choice in
     * g_hash_table_new_full */
    if (!g_hash_table_remove(transport->pending, service_name))
    {
        LS_ASSERT(0);
    }

    /* client ref +1 (total = 1) */

    /* client ref +1 (total = 2) */
    if (!_LSTransportAddClientHash(transport, client, service_name))
    {
        LS_ASSERT(0);
    }

    /* client ref +1 (total = 3) */
    _LSTransportAddAllConnectionHash(transport, client);

    TRANSPORT_UNLOCK(&transport->lock);

    LS_ASSERT(client->transport->mainloop_context);

    /* MONITOR -- send our info to the newly connected client
     *
     * This message *must* be put at the beginning of the pending queue
     * because it contains our identity information that the other side needs
     * before sending a reply (specifically, for monitoring the far end needs
     * to know our service name and unique name so that it can put that in
     * the message to the monitor)
     */
    if (!_LSTransportSendMessageClientInfo(client, transport->service_name, transport->unique_name, true, &lserror))
    {
        LOG_LSERROR(MSGID_LS_TRANSPORT_NETWORK_ERR, &lserror);
        LSErrorFree(&lserror);
    }

    /* kickstart sending to the monitor */
    if (transport->monitor)
    {
        /* MONITOR -- we need to send any pending method calls to the monitor
         * and add the destination info to the message */
        _LSTransportSendPendingMonitorMessages(transport, client, pending);
    }

    /* By definition, when we receive this message, there is at least
     * one item on the queue to send */
    _LSTransportAddSendWatch(&client->channel, client->transport->mainloop_context, client);

    _LSTransportAddReceiveWatch(&client->channel, client->transport->mainloop_context, client);

    /* client ref -1 (total = 2) */
    LOG_LS_DEBUG("%s: unref'ing\n", __func__);
    _LSTransportClientUnref(client);
}

/**
 *******************************************************************************
 * @brief Tell the client (always the hub) that we're up
 *
 * @param  client   IN  hub
 * @param  lserror  OUT set on error
 *
 * @retval true on success
 * @retval false on failure
 *******************************************************************************
 */
bool
_LSTransportNodeUp(_LSTransportClient *client, LSError *lserror)
{
    LOG_LS_DEBUG("%s: client: %p\n", __func__, client);

    bool ret = true;

    _LSTransportMessage *message = _LSTransportMessageNewRef(0);

    _LSTransportMessageSetType(message, _LSTransportMessageTypeNodeUp);

    if (!_LSTransportSendMessageBlocking(message, client, NULL, lserror))
    {
        ret = false;
    }

    _LSTransportMessageUnref(message);

    return ret;
}


/**
 *******************************************************************************
 * @brief Connect and get a name from the hub.
 *
 * @attention This blocks until we get a name from the hub.
 *
 * @param  transport    IN  transport
 * @param  local        IN  true for unix domain sockets
 * @param  public_bus   IN  true to connect to public hub
 * @param  lserror      OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
_LSTransportConnect(_LSTransport *transport, bool local, bool public_bus, LSError *lserror)
{
    LOG_LS_DEBUG("%s: transport: %p, service_name: %s\n", __func__, transport, transport->service_name);

    bool ret = false;
    const char *hub_addr = _LSGetHubLocalSocketAddress(public_bus);

    /* ignore SIGPIPE -- we'll handle the synchronous return val (EPIPE) */
    signal(SIGPIPE, SIG_IGN);

    /* set up shared memory for the monitor */
    if (!_LSTransportShmInit(&transport->shm, public_bus, lserror))
    {
        return false;
    }

    /*
     * 1. Attempt to connect to local hub.
     * 2. Attempt to connect to inet hub on device.
     * 3. Attempt to connecto to inet hub on emulator.
     */

    transport->type = _LSTransportTypeLocal;

    LOG_LS_DEBUG("Trying to find a hub at: %s", hub_addr);

    /* try to connect to the local hub */
    _LSTransportClient *hub = _LSTransportConnectClient(transport, HUB_NAME, hub_addr, -1, NULL, lserror);

#ifndef TARGET_EMULATOR
    if (!hub)
    {
        if (lserror)
        {
            LSErrorFree(lserror);
            LSErrorInit(lserror);
        }

        /* try connecting to the inet hub */
        transport->type = _LSTransportTypeInet;

        if (!(hub_addr = getenv("HUB_INET_ADDRESS")))
        {
            /* defaults */
            if (public_bus)
            {
                hub_addr = HUB_INET_ADDRESS_PUBLIC;
            }
            else
            {
                hub_addr = HUB_INET_ADDRESS_PRIVATE;
            }
        }

        hub = _LSTransportConnectClient(transport, HUB_NAME, hub_addr, -1, NULL, lserror);
#endif  /* !TARGET_EMULATOR */

        /* try to connect to emulator hub */
        if (!hub)
        {
            if (lserror)
            {
                LSErrorFree(lserror);
                LSErrorInit(lserror);
            }

            transport->type = _LSTransportTypeInet;

#ifdef TARGET_DESKTOP
            /* Running on the desktop and connecting to emulator */
            if (public_bus)
            {
                hub_addr = EMULATOR_DESKTOP_INET_ADDRESS_PUBLIC;
            }
            else
            {
                hub_addr = EMULATOR_DESKTOP_INET_ADDRESS_PRIVATE;
            }
#else
            /* Running on the emulator and connecting to emulator */
            if (public_bus)
            {
                hub_addr = EMULATOR_INET_ADDRESS_PUBLIC;
            }
            else
            {
                hub_addr = EMULATOR_INET_ADDRESS_PRIVATE;
            }
#endif

            hub = _LSTransportConnectClient(transport, HUB_NAME, hub_addr, -1, NULL, lserror);

            if (!hub)
            {
                /* Couldn't connect to any hub; failure */
                goto Done;
            }
        }
#ifndef TARGET_EMULATOR
    }
#endif

    transport->hub = hub;
    /* hub ref +1 (total = 1) */

    /* add hub to our hash table of known names (common names) */
    TRANSPORT_LOCK(&transport->lock);
    /* hub ref +1 (total = 2) */
    _LSTransportAddClientHash(transport, hub, HUB_NAME);
    /* hub ref +1 (total = 3) */
    _LSTransportAddAllConnectionHash(transport, hub);
    TRANSPORT_UNLOCK(&transport->lock);

    if (transport->type == _LSTransportTypeInet)
    {
        if (!_LSTransportSetupListenerInet(transport, -1, lserror))
        {
            goto Done;
        }
    }

    int listen_fd = -1;

    /* blocking send our requested name info to the hub */
    transport->unique_name = _LSTransportRequestName(transport->service_name, hub, &listen_fd, &transport->privileged, lserror);

    if (!transport->unique_name)
    {
        goto Done;
    }

    /* blocking recv of monitor message (tells us whether we have a
     * monitor in the system or not) */
    if (!_LSTransportReceiveMonitorStatus(transport, hub, lserror))
    {
        goto Done;
    }

    if (transport->type == _LSTransportTypeLocal)
    {
        /* we've got our name and fd, so we start listening for messages */
        if (!_LSTransportSetupListenerLocalWithFd(transport, transport->unique_name, listen_fd, lserror))
        {
            goto Done;
        }
    }

    /* Send the message to acknowledge we're up */
    if (!_LSTransportNodeUp(hub, lserror))
    {
        goto Done;
    }

    /* MONITOR: send *our* information to the client (hub in this case) */
    if (!_LSTransportSendMessageClientInfo(hub, transport->service_name, transport->unique_name, false, lserror))
    {
        goto Done;
    }

    ret = true;

Done:

    return ret;
}

/**
 *******************************************************************************
 * @brief Notify the hub about category change.
 *
 * @param  transport    IN  transport
 * @param  lserror      OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
_LSTransportAppendCategory(_LSTransport *transport, const char *category, LSMethod *methods, LSError *lserror)
{
    if (!category)
        category = "/";  /* Default category */

    if (!strcmp(category, "/com/palm/luna/private"))
        return true;  /* Omit private service category */

    LSMessageToken token;

    LOG_LS_DEBUG("%s: transport: %p, service_name: %s\n", __func__, transport, transport->service_name);

    _LSTransportMessage *message = _LSTransportMessageNewRef(LS_TRANSPORT_MESSAGE_DEFAULT_PAYLOAD_SIZE);

    _LSTransportMessageSetType(message, _LSTransportMessageTypeAppendCategory);

    _LSTransportMessageIter iter;
    _LSTransportMessageIterInit(message, &iter);
    if (!_LSTransportMessageAppendString(&iter, category)) goto error;

    if (methods)
    {
        for (; methods->name && methods->function; ++methods)
        {
            if (!_LSTransportMessageAppendString(&iter, methods->name)) goto error;
        }
    }

    if (!_LSTransportSendMessage(message, transport->hub, &token, lserror))
        goto error;

    _LSTransportMessageUnref(message);
    return true;

error:
    if (message) _LSTransportMessageUnref(message);
    return false;
}


/**
 *******************************************************************************
 * @brief Called when watch indicates that there is data to be read from a
 * channel. This function does non-blocking reads of the incoming data and
 * processes the complete messages.
 *
 * @param  source       IN  io source
 * @param  condition    IN  condition that triggered this callback
 * @param  data         IN  client
 *
 * @retval TRUE when client is still alive
 * @retval FALSE when client goes away so that this watch is removed
 *******************************************************************************
 */
gboolean
_LSTransportReceiveClient(GIOChannel *source, GIOCondition condition,
                         gpointer data)
{
    LSError lserror;
    LSErrorInit(&lserror);

    _LSTransportClient *client = (_LSTransportClient*)data;

    LOG_LS_DEBUG("%s: client: %p\n", __func__, client);

    /* calculate bytes remaining in buf */
    int num_bytes_to_read;
    unsigned long offset;

    /* we're using the client's incoming buffer, so ref it */
    _LSTransportClientRef(client);
    _LSTransportIncoming *incoming = client->incoming;

    bool shutdown = false;

    /*
     * TODO: limit the number of messages that we queue up before processing
     * them. We don't want to starve other parts of the program's operation
     * and we don't want to use too much memory; this should be configurable
     */

    /* TODO: review locking */

    //INCOMING_LOCK(&incoming->lock);

    while (1)
    {
        char* buf = (char*)&incoming->tmp_header;

        if (incoming->tmp_msg)
        {
            /* We have a message with at least a header, so attempt to read
             * in the rest of the message */
            num_bytes_to_read = incoming->tmp_msg->raw->header.len - incoming->tmp_msg_offset;
            buf = incoming->tmp_msg->raw->data;
            offset = incoming->tmp_msg_offset;
        }
        else
        {
            /* We haven't read in a complete header yet, so attempt to construct
             * a complete header */
            num_bytes_to_read = sizeof(client->incoming->tmp_header) - incoming->tmp_header_offset;
            offset = incoming->tmp_header_offset;
        }

        if (num_bytes_to_read > 0)
        {
            int ret = recv(client->channel.fd, buf + offset, num_bytes_to_read, MSG_DONTWAIT);

            /* If there was an error or we would block, we're done reading in data */
            if (ret <= 0)
            {
                if (ret == 0)
                {
                    LOG_LS_DEBUG("%s: Orderly shutdown\n", __func__);
                    shutdown = true;
                    break;
                }
                else if (errno == EAGAIN || errno == EINTR)
                {
                    /* We don't retry immediately relying on the main loop
                     * to signal socket readiness again.
                     */
                    break;
                }
                else if (errno == ECONNRESET)
                {
                    /* Client disappearance isn't LS2 problem */
                    LOG_LS_WARNING(MSGID_LS_MSG_ERR, 4,
                                   PMLOGKFV("ERROR_CODE", "%d", errno),
                                   PMLOGKS("ERROR", g_strerror(errno)),
                                   PMLOGKS("APP_ID", _LSTransportClientGetServiceName(client)),
                                   PMLOGKS("UNIQUE_NAME", _LSTransportClientGetUniqueName(client)),
                                   "Encountered ECONNRESET during recv: fd: %d", client->channel.fd);
                    shutdown = true;
                    break;
                }
                else
                {
                    LOG_LS_ERROR(MSGID_LS_MSG_ERR, 4,
                                 PMLOGKFV("ERROR_CODE", "%d", errno),
                                 PMLOGKS("ERROR", g_strerror(errno)),
                                 PMLOGKS("APP_ID", _LSTransportClientGetServiceName(client)),
                                 PMLOGKS("UNIQUE_NAME", _LSTransportClientGetUniqueName(client)),
                                 "Encountered error during recv: fd: %d", client->channel.fd);
                    shutdown = true;
                    break;
                }
            }

            /* ret > 0 */
            LS_ASSERT(ret > 0);

            if (incoming->tmp_msg)
            {
                /* We're continuing an already allocated msg */
                incoming->tmp_msg_offset += ret;
            }
            else
            {
                /* We're reading in the header */
                incoming->tmp_header_offset += ret;
            }
        }

        if (incoming->tmp_msg)
        {
            /* complete message */
            if (incoming->tmp_msg_offset == incoming->tmp_msg->raw->header.len)
            {
                //printf("recvd message: token %d, type: %d, len: %d\n", (int)incoming->tmp_msg->raw->header.token, (int)incoming->tmp_msg->raw->header.type, (int)incoming->tmp_msg->raw->header.len);

                /* check to see if we need to read in the special file
                 * descriptor message for this type of message */
                if (_LSTransportMessageIsConnectionFdType(incoming->tmp_msg))
                {
                    LSError lserror;
                    LSErrorInit(&lserror);
                    int recv_fd = -1;
                    bool need_retry = false;

                    if (!_LSTransportRecvFd(client->channel.fd, &recv_fd, &need_retry, &lserror))
                    {
                        if (need_retry)
                        {
                            /* We would have blocked, so now we retry by
                             * breaking out of the while loop */
                            break;
                        }
                        else
                        {
                            /* real error */
                            LOG_LSERROR(MSGID_LS_TRANSPORT_NETWORK_ERR, &lserror);
                            LSErrorFree(&lserror);
                        }
                    }

                    _LSTransportMessageSetConnectionFd(incoming->tmp_msg, recv_fd);
                }

                g_queue_push_tail(incoming->complete_messages, incoming->tmp_msg);
                incoming->tmp_msg = NULL;
                incoming->tmp_msg_offset = 0;
            }
        }
        else
        {
            LS_ASSERT(incoming->tmp_header_offset <= sizeof(_LSTransportHeader));

            if (incoming->tmp_header_offset == sizeof(incoming->tmp_header))
            {
                /* construct the new message */
                LS_ASSERT(incoming->tmp_msg == NULL);

                if (incoming->tmp_header.len > MAX_MESSAGE_SIZE_BYTES)
                {
                    const _LSTransportCred *cred = _LSTransportClientGetCred(client);
                    LOG_LS_ERROR(MSGID_LS_MSG_ERR, 4,
                                 PMLOGKS("APP_ID", _LSTransportClientGetServiceName(client)),
                                 PMLOGKS("UNIQUE_NAME", _LSTransportClientGetUniqueName(client)),
                                 PMLOGKS("EXE", _LSTransportCredGetExePath(cred)),
                                 PMLOGKS("CMD", _LSTransportCredGetCmdLine(cred)),
                                 "Received message of size %ld bytes; shutting down client",
                                 incoming->tmp_header.len);
                    shutdown = true;
                    break;
                }

                incoming->tmp_msg = _LSTransportMessageNewRef(incoming->tmp_header.len);

                /* copy header and sender */
                _LSTransportMessageSetHeader(incoming->tmp_msg, &incoming->tmp_header);
                //printf("recvd message alloc: token %d, type: %d, len: %d\n", (int)incoming->tmp_msg->raw->header.token, (int)incoming->tmp_msg->raw->header.type, (int)incoming->tmp_msg->raw->header.len);

                _LSTransportMessageSetClient(incoming->tmp_msg, client);

                /* TODO: can we fold this in better to the above code? */
                if (_LSTransportMessageGetHeader(incoming->tmp_msg)->len == 0)
                {
                    g_queue_push_tail(incoming->complete_messages, incoming->tmp_msg);
                    incoming->tmp_msg = NULL;
                }

                incoming->tmp_msg_offset = 0;
                incoming->tmp_header_offset = 0;
            }
        }
    }

    /*
     * Call the callbacks for methods and filter function callbacks for replies
     * TODO: should this be done in another callback (idle handler?)

     * <eeh> probably.  You want watch callbacks to return quickly.  But you
     * don't want heavy network activity to starve message handlers either.
     * Can you schedule the incomming queue to be processed in the main loop
     * at a higher priority than idle?  Caveate: if this function and the one
     * to process the queue have to hold the same mutex then they're going to
     * starve one another anyway.  To avoid that you'd have to allow
     * _LSTransportProcessIncomingMessages to return without emptying the
     * queue and then reschedule it.  Maybe leave things alone but be aware
     * when evaluating bug reports and performance data that this could be an
     * issue.
     */

    //INCOMING_UNLOCK(&incoming->lock);

    if (!_LSTransportProcessIncomingMessages(client, &lserror))
    {
        LOG_LSERROR(MSGID_LS_TRANSPORT_NETWORK_ERR, &lserror);
        LSErrorFree(&lserror);
    }

    if (shutdown)
    {
        if (client->state != _LSTransportClientStateShutdown)
        {
            /* we didn't get a shutdown message, so we need to clean up */
            _LSTransportClientShutdownDirty(client);
        }

        _LSTransportClientUnref(client);

        return FALSE;
    }
    else
    {
        _LSTransportClientUnref(client);
        return TRUE;    /* FALSE means this source should be removed */
    }
}

/**
 *******************************************************************************
 * @brief Callback to accept incoming connections.
 *
 * @param  source       IN  io source
 * @param  condition    IN  condition that triggered callback
 * @param  data         IN  transport
 *
 * @retval TRUE always
 *******************************************************************************
 */
gboolean
_LSTransportAcceptConnection(GIOChannel *source, GIOCondition condition,
                             gpointer data)
{
    _LSTransport *transport = (_LSTransport*)data;
    struct sockaddr_un client_addr;

    /* Call accept to accept the connection */
    if (condition & G_IO_IN)
    {
        /*
         * This socket is set as blocking, but we should only get the
         * G_IO_IN condition if data is available (and no one else is
         * watching this socket), so we won't block.
         */
        socklen_t len = sizeof(client_addr);
        int fd = accept(g_io_channel_unix_get_fd(source), (struct sockaddr*) &client_addr, &len);

        if (fd < 0)
        {
            LOG_LS_CRITICAL(MSGID_LS_SOCK_ERROR, 2,
                            PMLOGKFV("ERROR_CODE", "%d", errno),
                            PMLOGKS("ERROR", g_strerror(errno)),
                            "Accept error");
        }
        else
        {
            /* Create a new io channel and add to mainloop */
            _LSTransportClient *new_client = _LSTransportClientNewRef(transport, fd, NULL, NULL, NULL, false);
            if (new_client)
            {
                LOG_LS_DEBUG("%s: new_client: %p\n", __func__, new_client);

                /* client ref +1 (total = 1) */

                TRANSPORT_LOCK(&transport->lock);
                /* client ref +1 (total = 2) */
                _LSTransportAddAllConnectionHash(transport, new_client);
                TRANSPORT_UNLOCK(&transport->lock);

                /* TODO: maybe ref the client again here */
                _LSTransportAddReceiveWatch(&new_client->channel, transport->mainloop_context, new_client);

                /* client ref -1 (total = 1) */
                LOG_LS_DEBUG("%s: unref'ing\n", __func__);
                _LSTransportClientUnref(new_client);
            }
        }
    }
    else
    {
        /* something unexpected -- probably an error */
        LOG_LS_ERROR(MSGID_LS_SOCK_ERROR, 0, "Condition: %d", condition);
    }

    return TRUE;    /* FALSE means this source should be removed */
}

/**
 *******************************************************************************
 * @brief Send a message that has been constructed as an io vector.
 *
 * @warning This function does NOT set the token like @ref
 * _LSTransportSendMessage since it does not know where in the vector the
 * token lies.
 *
 * @attention locks outgoing lock
 *
 * @param  iov              IN  array of io vectors
 * @param  iovcnt           IN  size of @ref iov array
 * @param  total_len        IN  total size of @ref iov array
 * @param  app_id_offset    IN  offset of app_id from beginning of raw message
 * @param  client           IN  client
 * @param  lserror          OUT set on error
 *
 * @retval true on success
 * @retval false on failure
 *******************************************************************************
 */
bool
_LSTransportSendVector(const struct iovec *iov, int iovcnt, unsigned long total_len, unsigned long app_id_offset, _LSTransportClient *client, LSError *lserror)
{
    /* FIXME - review locking */
    //int i = 0;
    int bytes_written = 0;

    LOG_LS_DEBUG("%s: client: %p\n", __func__, client);

    /* If there is anything in the queue, we can't do a fast send
     * or we risk re-ordering the messages */
    OUTGOING_LOCK(&client->outgoing->lock);

    if (g_queue_is_empty(client->outgoing->queue))
    {
        //int total_bytes = 0;

        /* writev -- send as much of the message as possible without blocking */
        bytes_written = writev(client->channel.fd, iov, iovcnt);

        if (bytes_written < 0)
        {
            if (errno == EAGAIN || errno == EINTR)
            {
                bytes_written = 0;
            }
            else if (errno == EPIPE)
            {
                /* Client went away -- this could happen if the client
                 * crashes or disconnects for some other reason (e.g.,
                 * the monitor may disconnect at any time */

                /* If the destination service is dynamic then we want to queue
                 * the message so that it's automatically sent when the
                 * service is available. Otherwise, if it's a static service
                 * it's an error */
                if (!client->is_dynamic)
                {
                    _LSErrorSetFromErrno(lserror, MSGID_LS_CHANNEL_ERR, errno);
                    OUTGOING_UNLOCK(&client->outgoing->lock);
                    return false;
                }
                else
                {
                    bytes_written = 0;
                }
            }
            else
            {
                LOG_LS_ERROR(MSGID_LS_CHANNEL_ERR, 0, "writev error");
                LS_ASSERT(0);
            }
        }

        //printf("writev: sent %d bytes out of %ld\n", bytes_written, total_len);
        if (bytes_written == total_len)
        {
            //_LSTransportHeader *header = (_LSTransportHeader*)iov[0].iov_base;
            //printf("writev: sent message: token %d, type: %d, len: %d\n", (int)header->token, (int)header->type, (int)header->len);
            OUTGOING_UNLOCK(&client->outgoing->lock);
            return true;
        }
    }

    /* either we don't send all the data or there is data on the queue,
     * queue up the rest of the message to be sent */
    _LSTransportMessage *message = _LSTransportMessageFromVectorNewRef(iov, iovcnt, total_len);

    if (!message)
    {
        LS_ASSERT(0);
        OUTGOING_UNLOCK(&client->outgoing->lock);
        return false;
    }

    _LSTransportMessageSetAppId(message, _LSTransportMessageGetBody(message) + app_id_offset);

    message->tx_bytes_remaining = total_len - bytes_written;

    /* if the queue is empty, there's no send watch set on it, so we
     * need to add one */
    if (g_queue_is_empty(client->outgoing->queue))
    {
        /* we can only do this once the mainloop has been attached with
         * LSGmainAttach */
        if (client->transport->mainloop_context)
        {
            _LSTransportAddSendWatch(&client->channel, client->transport->mainloop_context, client);
        }
    }

    g_queue_push_tail(client->outgoing->queue, message);

    OUTGOING_UNLOCK(&client->outgoing->lock);

    return true;
}

/**
 *******************************************************************************
 * @brief Send a message that has been constructed as an io vector.
 *
 * @warning This function does NOT set the token like @ref
 * _LSTransportSendMessage since it does not know where in the vector the
 * token lies.
 *
 * @attention locks outgoing lock
 *
 * @param  iov              IN  array of io vectors
 * @param  iovcnt           IN  size of @ref iov array
 * @param  total_len        IN  total size of @ref iov array
 * @param  app_id_offset    IN  offset of app_id from beginning of raw message
 * @param  client           IN  client
 * @param  lserror          OUT set on error
 *
 * @retval message on success
 * @retval NULL on failure
 *******************************************************************************
 */
_LSTransportMessage *
_LSTransportSendVectorRet(const struct iovec *iov, int iovcnt, unsigned long total_len, unsigned long app_id_offset, _LSTransportClient *client, LSError *lserror)
{
    /* FIXME - review locking */
    //int i = 0;
    int bytes_written = 0;

    LOG_LS_DEBUG("%s: client: %p\n", __func__, client);

    /* If there is anything in the queue, we can't do a fast send
     * or we risk re-ordering the messages */
    OUTGOING_LOCK(&client->outgoing->lock);

    _LSTransportMessage *message = _LSTransportMessageFromVectorNewRef(iov, iovcnt, total_len);

    if (!message)
    {
        LS_ASSERT(0);
        OUTGOING_UNLOCK(&client->outgoing->lock);
        return NULL;
    }

    _LSTransportMessageSetAppId(message, _LSTransportMessageGetBody(message) + app_id_offset);

    if (g_queue_is_empty(client->outgoing->queue))
    {
        //int total_bytes = 0;

        /* write -- send as much of the message as possible without blocking */
        bytes_written = write(client->channel.fd, message->raw, total_len);

        if (bytes_written < 0)
        {
            if (errno == EAGAIN || errno == EINTR)
            {
                bytes_written = 0;
            }
            else if (errno == EPIPE)
            {
                /* Client went away -- this could happen if the client
                 * crashes or disconnects for some other reason (e.g.,
                 * the monitor may disconnect at any time */

                /* If the destination service is dynamic then we want to queue
                 * the message so that it's automatically sent when the
                 * service is available. Otherwise, if it's a static service
                 * it's an error */
                if (!client->is_dynamic)
                {
                    _LSTransportMessageUnref(message);
                    _LSErrorSetFromErrno(lserror, MSGID_LS_CHANNEL_ERR, errno);
                    OUTGOING_UNLOCK(&client->outgoing->lock);
                    return NULL;
                }
                else
                {
                    bytes_written = 0;
                }
            }
            else
            {
                LOG_LS_ERROR(MSGID_LS_CHANNEL_ERR, 0, "writev error");
                LS_ASSERT(0);
            }
        }

        //printf("writev: sent %d bytes out of %ld\n", bytes_written, total_len);
        if (bytes_written == total_len)
        {
            //_LSTransportHeader *header = (_LSTransportHeader*)iov[0].iov_base;
            //printf("writev: sent message: token %d, type: %d, len: %d\n", (int)header->token, (int)header->type, (int)header->len);
            OUTGOING_UNLOCK(&client->outgoing->lock);
            return message;
        }
    }

    message->tx_bytes_remaining -= bytes_written;

    /* if the queue is empty, there's no send watch set on it, so we
     * need to add one */
    if (g_queue_is_empty(client->outgoing->queue))
    {
        /* we can only do this once the mainloop has been attached with
         * LSGmainAttach */
        if (client->transport->mainloop_context)
        {
            _LSTransportAddSendWatch(&client->channel, client->transport->mainloop_context, client);
        }
    }

    _LSTransportMessageRef(message);
    g_queue_push_tail(client->outgoing->queue, message);

    OUTGOING_UNLOCK(&client->outgoing->lock);

    return message;
}

/**
 *******************************************************************************
 * @brief Send a message to the monitor.
 *
 * @warning Make sure that the message token (serial) has been set before
 * calling this function.
 *
 * @param  message  IN   message
 * @param  client   IN   client
 * @param  lserror  OUT  set on error
 *
 * @retval true on success
 * @retval false on failure
 *******************************************************************************
 */
static bool
_LSTransportSendMessageMonitor(_LSTransportMessage *message, _LSTransportClient *client, _LSMonitorMessageType type,
                               const struct timespec *timestamp, LSError *lserror)
{
    bool ret = true;

    _LSMonitorMessageData message_data;
    /* Get a serial number from the shared memory area (global serial) */
    message_data.serial = _LSTransportShmGetSerial(client->transport->shm);
    message_data.type = type;
    if (timestamp)
    {
        message_data.timestamp = *timestamp;
    }
    else
    {
        ClockGetTime(&message_data.timestamp);
    }

    unsigned long message_data_size = sizeof(_LSMonitorMessageData);

    /* do the message copy and add the destination info */
    char nul = '\0';
    unsigned long orig_msg_size = _LSTransportMessageGetBodySize(message);
    const char *dest_service_name = client->service_name;
    const char *dest_unique_name = client->unique_name;
    unsigned long dest_service_name_len = strlen_safe(client->service_name) + 1;
    if (dest_service_name_len == 1)
    {
        dest_service_name = &nul;
    }

    LS_ASSERT(dest_unique_name != NULL);
    unsigned long dest_unique_name_len = strlen(client->unique_name) + 1;

    unsigned long monitor_message_body_size = orig_msg_size + dest_service_name_len + dest_unique_name_len;

    unsigned long padding_bytes = PADDING_BYTES_TYPE(void *, sizeof(_LSTransportHeader) + monitor_message_body_size);

    monitor_message_body_size += padding_bytes + message_data_size;

    _LSTransportMessage *monitor_message = _LSTransportMessageNewRef(monitor_message_body_size);

    _LSTransportMessageCopy(monitor_message, message);

    char *body = _LSTransportMessageGetBody(monitor_message);
    body += orig_msg_size;
    memcpy(body, dest_service_name, dest_service_name_len);
    body += dest_service_name_len;
    memcpy(body, dest_unique_name, dest_unique_name_len);
    body += dest_unique_name_len;

    /* padding for alignment */
    body += padding_bytes;

    memcpy(body, &message_data, message_data_size);

    if (!_LSTransportSendMessageRaw(monitor_message, client->transport->monitor, false, NULL, false, NULL))
    {
        ret = false;
    }
    _LSTransportMessageUnref(monitor_message);

    return ret;
}

/**
 *******************************************************************************
 * @brief Send a "MonitorRequest" message, which is sent from the monitor to
 * the hub so that the hub can tell all the clients to connect to the monitor.
 *
 * @param  transport    IN   transport
 * @param  lserror      OUT  set on error
 *
 * @retval true on success
 * @retval false on failure
 *******************************************************************************
 */
bool
LSTransportSendMessageMonitorRequest(_LSTransport *transport, LSError *lserror)
{
    LS_ASSERT(transport != NULL);
    LS_ASSERT(transport->hub != NULL);

    _LSTransportMessage *message = _LSTransportMessageNewRef(0);

    _LSTransportMessageSetType(message, _LSTransportMessageTypeMonitorRequest);

    /* no body for the message */

    /* send special message to the hub so that it can tell clients
     * to connect */
    _LSTransportSendMessage(message, transport->hub, NULL, lserror);

    _LSTransportMessageUnref(message);

    return true;
}

/**
 *******************************************************************************
 * @brief Send a message to the hub requesting a list of all connected clients.
 *
 * @param  transport    IN  transport connected to the hub
 * @param  lserror      OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
_LSTransportSendMessageListClients(_LSTransport *transport, LSError *lserror)
{
    LS_ASSERT(transport != NULL);
    LS_ASSERT(transport->hub != NULL);

    bool ret = false;

    _LSTransportMessage *message = _LSTransportMessageNewRef(0);

    _LSTransportMessageSetType(message, _LSTransportMessageTypeListClients);

    /* no body for message */

    ret = _LSTransportSendMessage(message, transport->hub, NULL, lserror);

    _LSTransportMessageUnref(message);

    return ret;
}

/**
*******************************************************************************
* @brief Send a message to the service requesting a list of all registered methods and signals.
*
* @param transport IN transport connected to the hub
* @param service_name IN service name which methods we want to know
* @param lserror OUT set on error
*
* @retval true on success
* @retval false on failure
*******************************************************************************
*/
bool
_LSTransportSendMessageListServiceMethods(_LSTransport *transport, const char *service_name, LSError *lserror)
{
    return LSTransportSend(transport, service_name, "/com/palm/luna/private", "introspection",
                           "{\"type\":\"description\"}", NULL, NULL, lserror);
}

/**
 *******************************************************************************
 * @brief  Process a "ClientInfo" message. This message is used to know who
 * has connected to us.
 *
 * @param  message  IN  client info message
 *******************************************************************************
 */
static void
_LSTransportHandleClientInfo(_LSTransportMessage *message)
{
    LS_ASSERT(message != NULL);

    _LSTransportMessageIter iter;
    const char *service_name = NULL;
    const char *unique_name = NULL;

    _LSTransportClient *client = _LSTransportMessageGetClient(message);

    LS_ASSERT(client->service_name == NULL);
    LS_ASSERT(client->unique_name == NULL);

    _LSTransportMessageIterInit(message, &iter);

    _LSTransportMessageGetString(&iter, &service_name);
    if (service_name)
    {
        client->service_name = g_strdup(service_name);
    }

    _LSTransportMessageIterNext(&iter);

    _LSTransportMessageGetString(&iter, &unique_name);
    if (unique_name)
    {
        client->unique_name = g_strdup(unique_name);
    }

    LOG_LS_DEBUG("%s: client: %p, service_name: %s, unique_name: %s\n", __func__, client, client->service_name, client->unique_name);
}

/**
 *******************************************************************************
 * @brief Send a message and put it at the front of the outgoing queue.
 *
 * @warning This function does not change the serial number of the messages on
 * the queue and as a result, the serial numbers will be out of order. Do not
 * use this function unless you absolutely know what you are doing.
 *
 * @param  message      IN  message
 * @param  client       IN  client
 * @param  token        OUT message token
 * @param  lserror      OUT set on error
 *
 * @retval true on success
 * @retval false on failure
 *******************************************************************************
 */
bool
_LSTransportSendMessagePrepend(_LSTransportMessage *message, _LSTransportClient *client,
                               LSMessageToken *token, LSError *lserror)
{
    LOG_LS_DEBUG("%s: client: %p\n", __func__, client);

    return _LSTransportSendMessageRaw(message, client, true, token, true, lserror);
}

/**
 *******************************************************************************
 * @brief Allocate a new "ClientInfo" message with ref count of 1.
 *
 * @param  service_name     IN  service name
 * @param  unique_name      IN  unique name
 *
 * @retval message on success
 * @retval NULL on failure
 *******************************************************************************
 */
_LSTransportMessage*
_LSTransportMessageClientInfoNewRef(const char *service_name, const char *unique_name)
{
    LS_ASSERT(unique_name != NULL);
    _LSTransportMessageIter iter;

    _LSTransportMessage *message = _LSTransportMessageNewRef(LS_TRANSPORT_MESSAGE_DEFAULT_PAYLOAD_SIZE);

    _LSTransportMessageSetType(message, _LSTransportMessageTypeClientInfo);

    _LSTransportMessageIterInit(message, &iter);
    if (!_LSTransportMessageAppendString(&iter, service_name)) goto error;
    if (!_LSTransportMessageAppendString(&iter, unique_name)) goto error;
    if (!_LSTransportMessageAppendInvalid(&iter)) goto error;

    return message;

error:
    if (message) _LSTransportMessageUnref(message);
    return NULL;
}

/**
 *******************************************************************************
 * @brief Send a "ClientInfo" message, which contains the service name and
 * unique name of the client so the newly connected client knows who we are.
 *
 * @param  client        IN  destination client
 * @param  service_name  IN  service name of client
 * @param  unique_name   IN  unique name of client
 * @param  prepend       IN  true means put this message at beginning of
 *                           outgoing queue
 * @param  lserror       OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
_LSTransportSendMessageClientInfo(_LSTransportClient *client, const char *service_name, const char *unique_name, bool prepend, LSError *lserror)
{
    LOG_LS_DEBUG("%s: client: %p\n", __func__, client);

    bool ret = false;

    _LSTransportMessage *message = _LSTransportMessageClientInfoNewRef(service_name, unique_name);

    if (!message)
    {
        _LSErrorSet(lserror, MSGID_LS_OOM_ERR, -ENOMEM, "OOM");
        goto error;
    }

    if (prepend)
    {
        if (!_LSTransportSendMessagePrepend(message, client, NULL, lserror))
        {
            goto error;
        }
    }
    else
    {
        if (!_LSTransportSendMessage(message, client, NULL, lserror))
        {
            goto error;
        }
    }

    ret = true;

error:
    if (message) _LSTransportMessageUnref(message);

    return ret;
}

/**
 *******************************************************************************
 * @brief Send a "NodeUp" message, which tells the hub that this client is up.
 *
 * @param  client   IN  client
 * @param  lserror  OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
_LSTransportSendMessageNodeUp(_LSTransportClient *client, LSError *lserror)
{
    LOG_LS_DEBUG("%s: client: %p\n", __func__, client);

    /* no body because this is just an ACK message */
    _LSTransportMessage *message = _LSTransportMessageNewRef(0);

    _LSTransportMessageSetType(message, _LSTransportMessageTypeNodeUp);

    if (!_LSTransportSendMessage(message, client, NULL, lserror))
    {
        _LSTransportMessageUnref(message);
        return false;
    }

    _LSTransportMessageUnref(message);

    return true;
}

/**
 *******************************************************************************
 * @brief Underlying message sending function.
 *
 * @param  message      IN  message to send
 * @param  client       IN  client
 * @param  set_token    IN  true means this function will set the token
 * @param  token        OUT token if @ref set_token is true
 * @param  prepend      IN  true means prepend message (You probably don't
 *                          want to use this
 * @param  lserror      OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
static bool
_LSTransportSendMessageRaw(_LSTransportMessage *message, _LSTransportClient *client,
                           bool set_token, LSMessageToken *token,
                           bool prepend, LSError *lserror)
{
    /* TODO: attempt fast send if queue is empty, but we can also use the vector
     * version for that */

    LOG_LS_DEBUG("%s: client: %p\n", __func__, client);

    /* add message to outgoing queue */
    _LSTransportMessageRef(message);
    message->tx_bytes_remaining = message->raw->header.len + sizeof(message->raw->header);

    /* For some messages we may not want to set the token
     * (e.g., monitor messages are clones of regular messages, so we
     * don't want to create a new token)
     */
    if (set_token)
    {
        /* give it a serial number -- LOCKS serial lock */
        _LSTransportMessageSetToken(message, _LSTransportGetNextToken(client->transport));

        if (token)
        {
            *token = _LSTransportMessageGetToken(message);
        }
    }

    /* TODO: lock the hash table of queues as well? (or only that?) */
    OUTGOING_LOCK(&client->outgoing->lock);

    /* if the queue is empty, there's no send watch set on it, so we
     * need to add one */
    if (g_queue_is_empty(client->outgoing->queue))
    {
        /* we can only do this once the mainloop has been attached with
         * LSGmainAttach */
        if (client->transport->mainloop_context)
        {
            /* TODO */
            /* <eeh> There's an optimization in dbus whereby IFF the socket is
               writable and the queue is empty it tries to write immediately
               rather than enqueue and schedule for later write.  I suspect
               that's a really common case.  Worth considering?  I'll grant
               this things are beautifully simple this way.  */

            _LSTransportAddSendWatch(&client->channel, client->transport->mainloop_context, client);
        }
    }

    if (prepend)
    {
#if 0
        /* preserve serial order */
        LSMessageToken msg_token = _LSTransportMessageGetToken(message);
        GList *iter = NULL;
        _LSTransportMessage *cur_msg = NULL;
        _LSTransportMessage *next_msg = NULL;

        g_queue_push_head(client->outgoing->queue, message);

        for (iter = g_queue_peek_head_link(client->outgoing->queue);
             iter != NULL && g_list_next(iter) != NULL;
             iter = g_list_next(iter))
        {
            cur_msg = iter->data;
            next_msg = g_list_next(iter)->data;
            _LSTransportMessageSetToken(cur_msg, _LSTransportMessageGetToken(next_msg));
        }
        cur_msg = iter->data;
        _LSTransportMessageSetToken(cur_msg, msg_token);
#endif

        /*
         * Note that we don't preserve the ordering of serial numbers
         * when we do this. If we re-ordered the serial numbers as shown above,
         * we would be changing the serial number that could have been saved
         * by a caller. In our current usage, that means that we would break
         * the callmap lookups for a message.
         */
        g_queue_push_head(client->outgoing->queue, message);
    }
    else
    {
        g_queue_push_tail(client->outgoing->queue, message);
    }
    OUTGOING_UNLOCK(&client->outgoing->lock);

    return true;
}

/**
 *******************************************************************************
 * @brief Send a message.
 *
 * @param  message  IN  message to send
 * @param  client   IN  client
 * @param  token    OUT token
 * @param  lserror  OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
_LSTransportSendMessage(_LSTransportMessage *message, _LSTransportClient *client,
                        LSMessageToken *token, LSError *lserror)
{
    /* current time to add proper timestamp into the monitor message copy */
    struct timespec now;

    if (client->transport->monitor)
    {
        ClockGetTime(&now);
    }

    /* sets the token field in the message */
    bool ret = _LSTransportSendMessageRaw(message, client, true, token, false, lserror);

    /* MONITOR */
    if (client->transport->monitor)
    {
        if (_LSTransportMessageIsMonitorType(message))
        {
            _LSTransportSendMessageMonitor(message, client, _LSMonitorMessageTypeTx, &now, lserror);
        }
    }

    return ret;
}

/**
 *******************************************************************************
 * @brief Underlying message reply implementation.
 *
 * @param  message  IN  message to reply to
 * @param  type     IN  reply type
 * @param  payload  IN  payload
 * @param  lserror  OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
static bool
_LSTransportSendReplyRaw(const _LSTransportMessage *message, _LSTransportMessageType type, const char *payload, LSError *lserror)
{
    LS_ASSERT(_LSTransportMessageTypeIsReplyType(type));

    /* TODO: use vector send */

    /* construct the reply message */
    unsigned long payload_size = strlen(payload) + 1;

    _LSTransportMessage *reply = _LSTransportMessageNewRef(payload_size + sizeof(LSMessageToken));

    /* set type */
    _LSTransportMessageSetType(reply, type);

    /* format: reply_serial + payload */
    int offset = 0;
    LSMessageToken msg_token = _LSTransportMessageGetToken(message);
    char *body = _LSTransportMessageGetBody(reply);

    memcpy(body + offset, &msg_token, sizeof(LSMessageToken));
    offset += sizeof(LSMessageToken);
    memcpy(body + offset, payload, payload_size);

    LOG_LS_DEBUG("sending reply reply_token %d, type: %d, len: %d\n", (int)msg_token, (int)reply->raw->header.type, (int)reply->raw->header.len);

    _LSTransportSendMessage(reply, message->client, NULL, NULL);

    _LSTransportMessageUnref(reply);

    return true;
}

/**
 *******************************************************************************
 * @brief Send an error reply message.
 *
 * @param  message      IN  message to reply to
 * @param  error_type   IN  error type
 * @param  error_msg    IN  error message
 * @param  lserror      OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
_LSTransportSendErrorReply(const _LSTransportMessage *message, _LSTransportMessageType error_type, const char *error_msg, LSError *lserror)
{
    LS_ASSERT(_LSTransportMessageTypeIsErrorType(error_type));

    return _LSTransportSendReplyRaw(message, error_type, error_msg, lserror);
}

/**
 *******************************************************************************
 * @brief Send a rely to a message.
 *
 * @param  message  IN  message to reply to
 * @param  payload  IN  payload to send
 * @param  lserror  OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
_LSTransportSendReply(const _LSTransportMessage *message, const char *payload, LSError *lserror)
{
    return _LSTransportSendReplyRaw(message, _LSTransportMessageTypeReply, payload, lserror);
}

/**
 *******************************************************************************
 * @brief Send a "cancel method call" message to the far side.
 *
 * @param  transport        IN  transport
 * @param  service_name     IN  service name
 * @param  serial           IN  serial of message to cancel
 * @param  lserror          OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
LSTransportCancelMethodCall(_LSTransport *transport, const char *service_name, LSMessageToken serial, LSError *lserror)
{
    /*
     * FIXME: add generic code that can be shared with normal method call sending
     *
     * TODO: re-think this when we modify subscription handling
     */

    bool ret = true;
    _LSTransportMessage *message = NULL;

    const char *category = "/com/palm/luna/private";
    const char *method = "cancel";

    char *payload = g_strdup_printf("{\"token\":%li}", serial);

    int category_len = strlen(category) + 1;
    int method_len = strlen(method) + 1;
    int payload_len = strlen(payload) + 1;

    message = _LSTransportMessageNewRef(category_len + method_len + payload_len);

    _LSTransportMessageSetType(message, _LSTransportMessageTypeCancelMethodCall);

    char *message_body = _LSTransportMessageGetBody(message);

    memcpy(message_body, category, category_len);
    message_body += category_len;
    memcpy(message_body, method, method_len);
    message_body += method_len;
    memcpy(message_body, payload, payload_len);

    ret = _LSTransportSendMessageToService(transport, service_name, message, NULL, lserror);

    g_free(payload);
    if (message) _LSTransportMessageUnref(message);
    return ret;
}

/**
 *******************************************************************************
 * @brief Check to see if a service is up or not.
 *
 * The message argument is just the service name string (e.g., "com.palm.foo")
 *
 * The hub will reply with a boolean value of whether the service is up.
 *
 * @param  transport        IN  transport
 * @param  service_name     IN  service name to check status of
 * @param  serial           OUT serial for this query message
 * @param  lserror          OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
LSTransportSendQueryServiceStatus(_LSTransport *transport, const char *service_name,
                                  LSMessageToken *serial, LSError *lserror)
{
    LS_ASSERT(transport != NULL);
    LS_ASSERT(service_name != NULL);

    _LSTransportMessageIter iter;
    bool ret = false;

    _LSTransportMessage *message = _LSTransportMessageNewRef(LS_TRANSPORT_MESSAGE_DEFAULT_PAYLOAD_SIZE);

    _LSTransportMessageSetType(message, _LSTransportMessageTypeQueryServiceStatus);
    _LSTransportMessageIterInit(message, &iter);
    if (!_LSTransportMessageAppendString(&iter, service_name)) goto error;
    if (!_LSTransportMessageAppendInvalid(&iter)) goto error;

    LS_ASSERT(transport->hub != NULL);

    ret = _LSTransportSendMessage(message, transport->hub, serial, lserror);

    if (message) _LSTransportMessageUnref(message);

    return ret;

error:
    if (message) _LSTransportMessageUnref(message);
    _LSErrorSetOOM(lserror);
    return false;
}

/**
 *******************************************************************************
 * @brief Check to see registered categories in the service.
 *
 * The message argument is just the service name string (e.g., "com.palm.foo")
 *
 * The hub will reply with a boolean value of whether the service is up.
 *
 * @param  transport        IN  transport
 * @param  service_name     IN  service name to check status of
 * @param  category         IN  category to filter
 * @param  serial           OUT serial for this query message
 * @param  lserror          OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
LSTransportSendQueryServiceCategory(_LSTransport *transport,
                                    const char *service_name, const char *category,
                                    LSMessageToken *serial, LSError *lserror)
{
    LS_ASSERT(transport != NULL);
    LS_ASSERT(service_name != NULL);

    _LSTransportMessageIter iter;
    bool ret = false;

    _LSTransportMessage *message = _LSTransportMessageNewRef(LS_TRANSPORT_MESSAGE_DEFAULT_PAYLOAD_SIZE);

    _LSTransportMessageSetType(message, _LSTransportMessageTypeQueryServiceCategory);
    _LSTransportMessageIterInit(message, &iter);
    if (!_LSTransportMessageAppendString(&iter, service_name)) goto error;
    if (!_LSTransportMessageAppendString(&iter, category)) goto error;
    if (!_LSTransportMessageAppendInvalid(&iter)) goto error;

    LS_ASSERT(transport->hub != NULL);

    ret = _LSTransportSendMessage(message, transport->hub, serial, lserror);

    if (message) _LSTransportMessageUnref(message);

    return ret;

error:
    if (message) _LSTransportMessageUnref(message);
    _LSErrorSetOOM(lserror);
    return false;
}

/**
 *******************************************************************************
 * @brief Add a message to the pending queue for the given service with a specified token.
 *
 * @attention locks the transport lock
 *
 * @param  transport        IN  transport
 * @param  service_name     IN  service name
 * @param  message          IN  message to add
 * @param  token            IN  token for message
 * @param  lserror          OUT set on error
 *
 * @retval true on success
 * @retval false on failure
 *******************************************************************************
 */
bool
_LSTransportAddPendingMessageWithToken(_LSTransport *transport, const char *service_name, _LSTransportMessage *message, LSMessageToken msg_token, LSError *lserror)
{
    /* check to see if we already have a pending queue for this service name */
    TRANSPORT_LOCK(&transport->lock);

    _LSTransportOutgoing *pending = g_hash_table_lookup(transport->pending, service_name);

    if (pending)
    {
        /* yes, stick it on the pending queue */
        OUTGOING_LOCK(&pending->lock);

        _LSTransportMessageSetToken(message, msg_token);

        if (_LSTransportMessageGetType(message) == _LSTransportMessageTypeMethodCall)
        {
            _LSTransportSerialSave(pending->serial, message, lserror);
        }

        LOG_LS_DEBUG("%s: adding message to queue: serial: %d\n", __func__, (int)msg_token);

        _LSTransportMessageRef(message);
        g_queue_push_tail(pending->queue, message);
        OUTGOING_UNLOCK(&pending->lock);
        TRANSPORT_UNLOCK(&transport->lock);
    }
    else
    {
        /* no existing queue, create one and push message on it */
        _LSTransportOutgoing *out = _LSTransportOutgoingNew();

        if (!out)
        {
            /* LOCKED */
            TRANSPORT_UNLOCK(&transport->lock);
            _LSErrorSet(lserror, MSGID_LS_TRANSPORT_INIT_ERR, -1, "Could not initialize outgoing transport");
            return false;
        }

        _LSTransportMessageSetToken(message, msg_token);

        _LSTransportMessageType type = _LSTransportMessageGetType(message);

        if (type == _LSTransportMessageTypeMethodCall)
        {
            _LSTransportSerialSave(out->serial, message, lserror);
        }

        LOG_LS_DEBUG("%s: adding message to new pending: %p, serial: %d\n", __func__, out, (int)msg_token);
        _LSTransportMessageRef(message);
        g_queue_push_tail(out->queue, message);

        LOG_LS_DEBUG("%s: inserting \"%s\" into pending: %p\n", __func__, service_name, transport->pending);
        g_hash_table_insert(transport->pending, g_strdup(service_name), out);

        TRANSPORT_UNLOCK(&transport->lock);

        LS_ASSERT(transport->hub != NULL);

        if (!_LSTransportQueryName(transport->hub, message, service_name, lserror))
        {
            return false;
        }
    }

    return true;
}

/**
 *******************************************************************************
 * @brief Add a message to the pending queue for the given service.
 *
 * @attention locks the transport lock
 *
 * @param  transport        IN  transport
 * @param  service_name     IN  service name
 * @param  message          IN  message to add
 * @param  token            OUT token for message
 * @param  lserror          OUT set on error
 *
 * @retval true on success
 * @retval false on failure
 *******************************************************************************
 */
bool
_LSTransportAddPendingMessage(_LSTransport *transport, const char *service_name, _LSTransportMessage *message, LSMessageToken *token, LSError *lserror)
{
    LSMessageToken msg_token = _LSTransportGetNextToken(transport);

    bool retVal = _LSTransportAddPendingMessageWithToken(transport, service_name, message, msg_token, lserror);

    if (retVal && token)
    {
        *token = msg_token;
    }

    return retVal;
}

/**
 *******************************************************************************
 * @brief Send a message to the specified service.
 *
 * @attention locks the transport lock
 *
 * @param  transport        IN  transport
 * @param  service_name     IN  service
 * @param  message          IN  message to send
 * @param  token            OUT token for message
 * @param  lserror          OUT set on error
 *
 * @retval true on success
 * @retval false on failure
 *******************************************************************************
 */
bool
_LSTransportSendMessageToService(_LSTransport *transport, const char *service_name, _LSTransportMessage *message, LSMessageToken *token, LSError *lserror)
{
    TRANSPORT_LOCK(&transport->lock);
    _LSTransportClient *client = g_hash_table_lookup(transport->clients, service_name);
    TRANSPORT_UNLOCK(&transport->lock);

    if (!client)
    {
        return _LSTransportAddPendingMessage(transport, service_name, message, token, lserror);
    }
    else
    {
        return _LSTransportSendMessage(message, client, token, lserror);
    }
}

/**
 *******************************************************************************
 * @brief Send a method call.
 *
 * @param  transport        IN  transport
 * @param  service_name     IN  destination service name
 * @param  category         IN  method category
 * @param  method           IN  method
 * @param  payload          IN  payload
 * @param  applicationId    IN  application id
 * @param  token            OUT message token
 * @param  lserror          OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
LSTransportSend(_LSTransport *transport, const char *service_name,
                const char *category, const char *method,
                const char *payload, const char* applicationId,
                LSMessageToken *token, LSError *lserror)
{
    _LSTransportMessage *message = NULL;
    _LSTransportHeader header;
    struct iovec iov[5];
    char nul = '\0';
    unsigned long app_id_offset = 0;

    unsigned long category_len = strlen(category) + 1;
    unsigned long method_len = strlen(method) + 1;
    unsigned long payload_len = strlen(payload) + 1;
    unsigned long app_id_len = strlen_safe(applicationId) + 1;
    unsigned long total_size =  sizeof(_LSTransportMessageRaw) + category_len + method_len + payload_len + app_id_len;

    struct timespec now;

    /* header */
    iov[0].iov_base = &header;
    iov[0].iov_len = sizeof(header);

    /* category */
    iov[1].iov_base = (char*)category;
    iov[1].iov_len = category_len;

    /* method */
    iov[2].iov_base = (char*)method;
    iov[2].iov_len = method_len;

    /* payload */
    iov[3].iov_base = (char*)payload;
    iov[3].iov_len = payload_len;

    /* app id */
    if (!applicationId)
    {
        iov[4].iov_base = &nul;
    }
    else
    {
        iov[4].iov_base = (char*)applicationId;
    }
    iov[4].iov_len = app_id_len;

    /* The _LSTransportMessageGetBody() function skips the header */
    app_id_offset = iov[1].iov_len + iov[2].iov_len + iov[3].iov_len;

    /* TODO: use accessors */
    header.len = category_len + method_len + payload_len + app_id_len;
    header.type = _LSTransportMessageTypeMethodCall;

    /* Look up destination and connect to it if we haven't already */
    TRANSPORT_LOCK(&transport->lock);
    _LSTransportClient *client = g_hash_table_lookup(transport->clients, service_name);

    TRANSPORT_UNLOCK(&transport->lock);

    if (!client)
    {
        /* NOTE: timeout is on the server side */

        /* build up the message */
        message = _LSTransportMessageFromVectorNewRef(iov, ARRAY_SIZE(iov), total_size);

        if (!message)
        {
            return false;
        }

        const char *app_id_in_raw_msg = _LSTransportMessageGetBody(message) + app_id_offset;
        _LSTransportMessageSetAppId(message, app_id_in_raw_msg);

        /* ref's the message */
        if (!_LSTransportAddPendingMessage(transport, service_name, message, token, lserror))
        {
            _LSTransportMessageUnref(message);
            return false;
        }

        LOG_LS_DEBUG("method call: token: %d, category: %s, method: %s, payload: %s\n", (int)_LSTransportMessageGetToken(message), _LSTransportMessageGetCategory(message), _LSTransportMessageGetMethod(message), _LSTransportMessageGetPayload(message));
    }
    else
    {
        /* *WARN*: if this function is ever changed to be called for anything
         * but method call */

        /* we have to set the token here SendVector doesn't know which vector
         * has the token */

        LSMessageToken msg_token = _LSTransportGetNextToken(transport);

        _LSTransportMonitorSerial monitor_serial = 0;
        if (transport->monitor)
        {
            monitor_serial = _LSTransportShmGetSerial(client->transport->shm);
            ClockGetTime(&now);
        }

        LOG_LS_DEBUG("method call: token: %d, category: %s, method: %s, payload: %s\n", (int)msg_token, category, method, payload);

        header.token = msg_token;

        message = _LSTransportSendVectorRet(iov, ARRAY_SIZE(iov), total_size, app_id_offset, client, lserror);
        if (!message)
        {
            return false;
        }

        /* Successfully sent the message so save the serial and set the
         * return token val */

        /* Ref's the message */
        _LSTransportSerialSave(client->outgoing->serial, message, lserror);
        *token = msg_token;

        /* MONITOR */
        if (transport->monitor)
        {
            /*
             * Add destination service name and destination unique name
             * so that the monitor knows where this message was going. It
             * knows the source since it receives it directly from the
             * source (i.e., not through the hub)
             */
            struct iovec iov_monitor[ARRAY_SIZE(iov) + 4];
            memcpy(iov_monitor, iov, sizeof(iov));

            LS_ASSERT(client->service_name != NULL);
            LS_ASSERT(client->unique_name != NULL);

            _LSMonitorMessageData message_data;
            message_data.serial = monitor_serial;
            message_data.type = _LSMonitorMessageTypeTx;
            message_data.timestamp = now;

            unsigned long message_data_size = sizeof(_LSMonitorMessageData);

            unsigned long dest_service_name_len = strlen(client->service_name) + 1;
            unsigned long dest_unique_name_len = strlen(client->unique_name) + 1;
            unsigned long monitor_total_size = total_size + dest_service_name_len + dest_unique_name_len;

            unsigned long padding_bytes = PADDING_BYTES_TYPE(void *, monitor_total_size);
            char padding[padding_bytes];
            memset(padding, 0, padding_bytes);

            monitor_total_size += padding_bytes + message_data_size;

            /* Set the new header size
             *
             * Note that monitor_total_size includes the size of the header
             * itself and this doesn't */
            header.len += dest_service_name_len + dest_unique_name_len + padding_bytes + message_data_size;

            iov_monitor[ARRAY_SIZE(iov)].iov_base = client->service_name;
            iov_monitor[ARRAY_SIZE(iov)].iov_len = dest_service_name_len;

            iov_monitor[ARRAY_SIZE(iov) + 1].iov_base = client->unique_name;
            iov_monitor[ARRAY_SIZE(iov) + 1].iov_len = dest_unique_name_len;

            iov_monitor[ARRAY_SIZE(iov) + 2].iov_base = padding;
            iov_monitor[ARRAY_SIZE(iov) + 2].iov_len = padding_bytes;

            iov_monitor[ARRAY_SIZE(iov) + 3].iov_base = &message_data;
            iov_monitor[ARRAY_SIZE(iov) + 3].iov_len = message_data_size;

            /* We don't really care if this fails and it may fail when the
             * monitor goes down */
            (void)_LSTransportSendVector(iov_monitor, ARRAY_SIZE(iov_monitor), monitor_total_size, app_id_offset, transport->monitor, lserror);
        }
    }
    _LSTransportMessageUnref(message);

    return true;
}

/**
 *******************************************************************************
 * @brief Callback that is called when a watch is ready to send.
 *
 * @attention locks the outgoing lock
 *
 * @param  source       IN  io source
 * @param  condition    IN  condition that triggered the watch
 * @param  data         IN  client
 *
 * @retval  TRUE when we have more data to send
 * @retval  FALSE when we're done sending data and want the callback removed
 *******************************************************************************
 */
gboolean
_LSTransportSendClient(GIOChannel *source, GIOCondition condition,
                       gpointer data)
{
    /* send as many messages as we can out of the outgoing client queues
     * and quit if the call will block */

    _LSTransportClient *client = (_LSTransportClient*)data;

    LOG_LS_DEBUG("%s: client: %p\n", __func__, client);

    /* attempt to send out of this client queue */
    OUTGOING_LOCK(&client->outgoing->lock);

    while (1)
    {
        int ret = 0;

    	if (g_queue_is_empty (client->outgoing->queue))
    	{
                /* remove the watch since we're done sending */
                _LSTransportRemoveSendWatch(&client->channel);

                OUTGOING_UNLOCK(&client->outgoing->lock);
                return FALSE;
    	}

        /* grab message off queue */
        _LSTransportMessage *message = g_queue_pop_head(client->outgoing->queue);

        /* Warn and exit if we dequeue a null */
        if (!message)
        {
            LOG_LS_WARNING(MSGID_LS_QUEUE_ERROR, 0, "%s: Found null message in outgoing queue", __func__);
            continue;
        }

        //printf("SendClient: sending message: token %d, type: %d, len: %d, data: %s\n", (int)_LSTransportMessageGetToken(message), (int)_LSTransportMessageGetType(message), (int)message->raw->header.len, _LSTransportMessageGetBody(message));
        //printf("sending %ld bytes\n", message->tx_bytes_remaining);

        if (message->tx_bytes_remaining > 0)
        {
            /* attempt to send message */

            /* TODO */
            /* <eeh> This is a lot of math.  Can you calc a ptr upfront and increment it by ret? */
            ret = send(client->channel.fd, (char*)message->raw + message->raw->header.len + sizeof(_LSTransportHeader) - message->tx_bytes_remaining, message->tx_bytes_remaining, MSG_DONTWAIT);

            if (ret >= 0)
            {
                message->tx_bytes_remaining -= ret;

            }
            else if (errno == EAGAIN || errno == EINTR)
            {
                /* still have data left, so put it back on the queue
                 * from where we took it off */
                g_queue_push_head(client->outgoing->queue, message);
                goto Done;
            }
            else if (errno == EPIPE)
            {
                /* Broken pipe is considered a normal situation, because it means
                 * the peer has disconnected suddenly.
                 */
                LOG_LS_WARNING(MSGID_LS_SOCK_ERROR, 4,
                               PMLOGKFV("ERROR_CODE", "%d", errno),
                               PMLOGKS("ERROR", g_strerror(errno)),
                               PMLOGKS("APP_ID", _LSTransportClientGetServiceName(client)),
                               PMLOGKS("UNIQUE_NAME", _LSTransportClientGetUniqueName(client)),
                               "Error when attempting to send to fd: %d", client->channel.fd);
                _LSTransportMessageUnref(message);
                goto Done;
            }
            else
            {
                /* TODO: Handle better */
                LOG_LS_ERROR(MSGID_LS_SOCK_ERROR, 4,
                             PMLOGKFV("ERROR_CODE", "%d", errno),
                             PMLOGKS("ERROR", g_strerror(errno)),
                             PMLOGKS("APP_ID", _LSTransportClientGetServiceName(client)),
                             PMLOGKS("UNIQUE_NAME", _LSTransportClientGetUniqueName(client)),
                             "Error when attempting to send to fd: %d", client->channel.fd);
                _LSTransportMessageUnref(message);
                goto Done;     /* <eeh> You're going to return TRUE here.  Want that? */
            }
        }

        if (message->tx_bytes_remaining == 0)
        {
            /* transmitted entire message */

            /* Send the connection fd if we have one
             *
             * TODO: make sure this handles failure case correctly.
             */
            if (_LSTransportMessageIsConnectionFdType(message))
            {
                bool need_retry = false;
                LSError lserror;
                LSErrorInit(&lserror);

                if (!_LSTransportSendFd(client->channel.fd, _LSTransportMessageGetConnectionFd(message), &need_retry, &lserror))
                {
                    if (need_retry)
                    {
                        /* Still need to send fd, so push message back on
                         * queue where it was and wait for fd to become
                         * ready for sending */
                        g_queue_push_head(client->outgoing->queue, message);
                        goto Done;
                    }
                    else
                    {
                        LOG_LSERROR(MSGID_LS_TRANSPORT_NETWORK_ERR, &lserror);
                        LSErrorFree(&lserror);
                    }
                }
            }

            /* the fd is closed when the message ref count goes to 0 */

            //_LSTransportHeader *header = &message->raw->header;
            LOG_LS_DEBUG("%s: sent message: client: %p, token %d, type: %d, len: %d\n",
                        __func__,
                        client,
                        (int)_LSTransportMessageGetToken(message),
                        (int)_LSTransportMessageGetType(message),
                        (int)message->raw->header.len);

            _LSTransportMessageUnref(message);
        }
        else
        {
            /* still have data left, so put it back on the queue from
             * where we took it off.
             *
             * TODO: we don't actually have to exit the loop here; as long as we're
             * calling send with MSG_DONTWAIT, it won't block and we can
             * give it another shot.. we'll get EAGAIN if we would block */
            g_queue_push_head(client->outgoing->queue, message);
            goto Done;
        }
    }

Done:
    OUTGOING_UNLOCK(&client->outgoing->lock);
    return TRUE;    /* FALSE means this source should be removed */
}

/**
 *******************************************************************************
 * @brief Free a global token structure.
 *
 * @param  token    IN  structure to free
 *******************************************************************************
 */
void
_LSTransportGlobalTokenFree(_LSTransportGlobalToken *token)
{
    LS_ASSERT(token != NULL);

#ifdef MEMCHECK
    memset(token, 0xFF, sizeof(_LSTransportGlobalToken));
#endif

    g_free(token);
}

/**
 *******************************************************************************
 * @brief Allocate a new "global token" structure.
 *
 * @retval global token on success
 * @retval NULL on failure
 *******************************************************************************
 */
_LSTransportGlobalToken*
_LSTransportGlobalTokenNew()
{
    _LSTransportGlobalToken* ret = g_new0(_LSTransportGlobalToken, 1);

    if (pthread_mutex_init(&ret->lock, NULL))
    {
        LOG_LS_ERROR(MSGID_LS_MUTEX_ERR, 0, "Could not initialize mutex");
        goto error;
    }
    ret->value = LSMESSAGE_TOKEN_INVALID;

    return ret;

error:
    _LSTransportGlobalTokenFree(ret);
    return NULL;
}

/**
 *******************************************************************************
 * @brief Returns true if the current process using this library is the hub.
 * Note that this is not secure in any way and can easily be spoofed so it
 * shouldn't be used for anything where that would cause a problem.
 *
 * @retval  true if process calling this command is hub
 * @retval  false otherwise
 *******************************************************************************
 */
inline bool
_LSTransportIsHub(void)
{
    return s_is_hub;
}

/**
 *******************************************************************************
 * @brief Mark this process as being the hub.
 *
 * @param  is_hub
 *******************************************************************************
 */
static inline void
_LSTransportSetIsHub(bool is_hub)
{
    s_is_hub = is_hub;
}

/**
 *******************************************************************************
 * @brief Allocate and initialize a new transport.
 *
 * @param  *ret_transport   OUT  new transport
 * @param  service_name     IN   service name
 * @param  handlers         IN   handler callbacks
 * @param  lserror          OUT  set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
_LSTransportInit(_LSTransport **ret_transport, const char *service_name,
                 LSTransportHandlers *handlers, LSError *lserror)
{
    LOG_LS_DEBUG("%s\n", __func__);

    _LSTransport *transport = g_new0(_LSTransport, 1);

    /* set to a real value when we call _LSTransportConnect or _LSTransportSetupListener/Local/Inet */
    transport->type = _LSTransportTypeInvalid;
    transport->service_name = g_strdup(service_name);

    if (service_name && strcmp(service_name, HUB_NAME) == 0)
    {
        _LSTransportSetIsHub(true);
    }

    transport->mainloop_context = NULL; /* not really necessary, but... */

    /*
     * use default glib priority; can be changed with _LSTransportGmainSetPriority
     */
    transport->source_priority = G_PRIORITY_DEFAULT;

    transport->shm = NULL;      /* Set in _LSTransportConnect */

    if (pthread_mutex_init(&transport->lock, NULL))
    {
        _LSErrorSet(lserror, MSGID_LS_MUTEX_ERR, -1, "Could not initialize mutex");
        goto error;
    }

    transport->global_token = _LSTransportGlobalTokenNew();
    if (!transport->global_token)
    {
        LOG_LS_ERROR(MSGID_LS_TOKEN_ERR, 0, "Could not allocate new global token");
    }

    /* TODO: wrap this? */
    transport->clients = g_hash_table_new_full(g_str_hash, g_str_equal,
        (GDestroyNotify)g_free, (GDestroyNotify)_LSTransportClientUnref);
    transport->all_connections = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, (GDestroyNotify)_LSTransportClientUnref);
    transport->pending = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

    /* TODO: just copy the struct! */
    transport->message_failure_handler = handlers->message_failure_handler;
    transport->message_failure_context = handlers->message_failure_context;

    transport->disconnect_handler = handlers->disconnect_handler;
    transport->disconnect_context = handlers->disconnect_context;

    transport->msg_handler = handlers->msg_handler;
    transport->msg_context = handlers->msg_context;

    *ret_transport = transport;
    return true;

error:
    if (transport->shm) _LSTransportShmDeinit(&transport->shm);
    if (transport->global_token) _LSTransportGlobalTokenFree(transport->global_token);
    if (transport->clients) g_hash_table_destroy(transport->clients);
    if (transport->all_connections) g_hash_table_destroy(transport->all_connections);
    if (transport->pending) g_hash_table_destroy(transport->pending);
    g_free(transport);

    return false;
}

/**
 *******************************************************************************
 * @brief Send shutdown messages (and block until sent or connection is
 * broken).
 *
 * @attention This function blocks.
 *
 * @param  client   IN  client
 * @param  lserror  OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
_LSTransportSendShutdownMessageBlocking(_LSTransportClient *client, LSError *lserror)
{
    LOG_LS_DEBUG("%s: client: %p\n", __func__, client);

    bool ret = true;

    /* construct message with last serial processed */
    _LSTransportMessage *message = _LSTransportMessageNewRef(sizeof(LSMessageToken));

    _LSTransportMessageSetType(message, _LSTransportMessageTypeShutdown);

    _LSTransportMessageSetBody(message, (char*)&client->incoming->last_serial_processed, sizeof(LSMessageToken));

    if (!_LSTransportSendMessageBlocking(message, client, NULL, lserror))
    {
        ret = false;
    }

    _LSTransportMessageUnref(message);

    return ret;
}

#if 0
/* queue must be locked before calling this function */
bool
_LSTransportFlushQueueMessages(_LSTransportClient *client, GQueue *queue, LSError *lserror)
{
    bool ret = true;

    while (!g_queue_is_empty(queue))
    {
        _LSTransportMessage *message = g_queue_pop_head(queue);
        if (!message)
        {
            LOG_LS_ERROR(MSGID_LS_QUE_ERR, 0, "Message queue should not be empty");
            LS_ASSERT(0);
        }

        if (!_LSTransportSendMessageBlocking(message, client, NULL, lserror))
        {
            ret = false;
        }
    }

    return ret;
}
#endif

/**
 *******************************************************************************
 * @brief Process incoming messages by calling the appropriate message
 * handlers or user callback.
 *
 * @attention locks the incoming queue
 *
 * @param  client   IN  client
 * @param  lserror  OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
_LSTransportProcessIncomingMessages(_LSTransportClient *client, LSError *lserror)
{
    _LSTransportClientRef(client);
    _LSTransportIncoming *incoming = client->incoming;

    /* TODO: review locking, this function can be called recursively because
     * we can call out to user code, which can potentially call LSUnregister,
     * which would call this function to clean up */
    /* <eeh> Does this (that you can't lock the queue) in turn mean you have
       to guarantee that only one thread accesses it?  socket reader and
       message dispatcher have to be same thread? */
    //INCOMING_LOCK(&incoming->lock);

    while (!g_queue_is_empty(incoming->complete_messages))
    {
        /* check message type and handle appropriately (method, reply, signal, etc.) */

        _LSTransportMessage *tmsg = (_LSTransportMessage*) g_queue_pop_head(incoming->complete_messages);

        //INCOMING_UNLOCK(&incoming->lock);

        /* MONITOR */
        if (client->transport->monitor)
        {
            if (_LSTransportMessageIsMonitorType(tmsg))
            {
                _LSTransportSendMessageMonitor(tmsg, client, _LSMonitorMessageTypeRx, NULL, lserror);
            }
        }

        /* Handle "internal" messages, otherwise, let the registered handler take over */
        LOG_LS_DEBUG("%s: received message token %d, type: %d, len: %d\n", __func__, (int)tmsg->raw->header.token, (int)tmsg->raw->header.type, (int)tmsg->raw->header.len);

        switch (_LSTransportMessageGetType(tmsg))
        {
        case _LSTransportMessageTypeQueryNameReply:
            _LSTransportHandleQueryNameReply(tmsg);
            break;

        case _LSTransportMessageTypeShutdown:
            _LSTransportHandleShutdown(tmsg);
            break;

        case _LSTransportMessageTypeError:
        case _LSTransportMessageTypeErrorUnknownMethod:
        case _LSTransportMessageTypeReply:
            /* FIXME -- signal replies currently have this same type,
             * but signals are not in the serial hash
             * -- see _LSHubHandleSignalRegister */
            LOG_LS_DEBUG("%s: removing reply serial: %d, message serial: %d\n", __func__, (int)_LSTransportMessageGetReplyToken(tmsg), (int)_LSTransportMessageGetToken(tmsg));
            _LSTransportSerialRemove(client->outgoing->serial, _LSTransportMessageGetReplyToken(tmsg));
            _LSTransportHandleUserMessageHandler(tmsg);
            //client->transport->msg_handler(tmsg, client->transport->msg_context);
            break;

        case _LSTransportMessageTypeMonitorConnected:
        case _LSTransportMessageTypeMonitorNotConnected:
            _LSTransportHandleMonitor(tmsg);
            break;

        case _LSTransportMessageTypeClientInfo:
            _LSTransportHandleClientInfo(tmsg);
            break;

        case _LSTransportMessageTypeMethodCall:
            /* Save message serial so we know what has been processed */
            incoming->last_serial_processed = _LSTransportMessageGetToken(tmsg);
            /* fallthrough */

        default:
            _LSTransportHandleUserMessageHandler(tmsg);
            break;
        }

        _LSTransportMessageUnref(tmsg);

        //INCOMING_LOCK(&incoming->lock);
    }

    //INCOMING_UNLOCK(&incoming->lock);

    _LSTransportClientUnref(client);

    return true;
}

/**
 *******************************************************************************
 * @brief Flush all messages in the outgoing queue.
 *
 * @attention locks the outgoing queue
 *
 * @param  client   IN  client
 * @param  lserror  OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
_LSTransportFlushOutgoingMessages(_LSTransportClient *client, LSError *lserror)
{
    bool ret = true;

    LOG_LS_DEBUG("%s: client: %p\n", __func__, client);

    OUTGOING_LOCK(&client->outgoing->lock);

    while (!g_queue_is_empty(client->outgoing->queue))
    {
        _LSTransportMessage *message = g_queue_pop_head(client->outgoing->queue);
        if (!message)
        {
            /* LOCKED */
            OUTGOING_UNLOCK(&client->outgoing->lock);
            LOG_LS_ERROR(MSGID_LS_QUEUE_ERROR, 0, "Queue should not be empty");
            _LSErrorSet(lserror, MSGID_LS_QUEUE_ERROR, -1, "Outgoing queue should not be empty");
            return false;
        }

        /* See NOV-93612 */
        if (_LSTransportMessageGetType(message) == _LSTransportMessageTypeQueryName)
        {
            LOG_LS_WARNING(MSGID_LS_QUEUE_ERROR, 1,
                           PMLOGKS("APP_ID", _LSTransportMessageTypeQueryNameGetQueryName(message)),
                           "Shutting down with unsent QueryName message for service: %s."
                           " Any messages to that service will not be sent.",
                           _LSTransportMessageTypeQueryNameGetQueryName(message));
        }

        ret = _LSTransportSendMessageBlocking(message, client, NULL, lserror);

        _LSTransportMessageUnref(message);
    }

    OUTGOING_UNLOCK(&client->outgoing->lock);

    return ret;
}

/**
 *******************************************************************************
 * @brief Callback to send shutdown messages.
 *
 * @attention This is callled with the transport lock held.
 *
 * @param  key          IN  pointer to fd
 * @param  value        IN  client
 * @param  user_data    IN  transport
 *******************************************************************************
 */
void
_LSTransportSendShutdownMessages(gpointer key, gpointer value, gpointer user_data)
{
    LSError lserror;
    LSErrorInit(&lserror);

    //int *fd = (int*)key;
    _LSTransportClient *client = (_LSTransportClient*)value;
    bool flush_and_send_shutdown = (bool)(GPOINTER_TO_INT(user_data));

    LOG_LS_DEBUG("%s: client: %p\n", __func__, client);

    /* remove watches */
    if (client->channel.send_watch)
    {
        _LSTransportRemoveSendWatch(&client->channel);
    }

    if (client->channel.recv_watch)
    {
        _LSTransportRemoveReceiveWatch(&client->channel);
    }

    _LSTransport *transport = _LSTransportClientGetTransport(client);
    if (transport->listen_channel.accept_watch)
    {
        _LSTransportRemoveAcceptWatch(&transport->listen_channel);
        _LSTransportChannelClose(&transport->listen_channel, false);
    }

    /* we may not want to flush and send the shutdown messages if we are
     * detaching from the mainloop */
    if (flush_and_send_shutdown)
    {
        /* NOV-99802
         *
         * Don't process any more incoming messages. Otherwise we might
         * trigger more callbacks and activity. When we send the shutdown
         * message the far side will know the last message that we processed
         * and generate errors for the others.
         *
         * TODO: What happens when two services talking with each other shut
         * down at the exact same time?
         */

        /* flush any remaining messages in the outgoing queue */
        if (!_LSTransportFlushOutgoingMessages(client, &lserror))
        {
            LOG_LSERROR(MSGID_LS_TRANSPORT_NETWORK_ERR, &lserror);
            LSErrorFree(&lserror);
        }

        /* If we got a shutdown message from this client already, then don't try
         * to send a shutdown message to it */
        if (client->state != _LSTransportClientStateShutdown)
        {
            /* send blocking shutdown messages to client (includes hub) */
            /* not much we can do if any of these fail except log the fact that it
             * happened */
            if (!_LSTransportSendShutdownMessageBlocking(client, &lserror))
            {
                LOG_LSERROR(MSGID_LS_TRANSPORT_NETWORK_ERR, &lserror);
                LSErrorFree(&lserror);
            }
            client->state = _LSTransportClientStateShutdown;
        }
        else
        {
            /* We don't expect this to happen */
            LOG_LS_ERROR(MSGID_LS_ALREADY_SHUTDOWND, 1,
                         PMLOGKS("APP_ID", client->service_name),
                         "%s: did not expect client [%s (%s)] to have already sent shut down message",
                         __func__, client->service_name, client->unique_name);
        }
    }

    /* close connections */
    _LSTransportChannelClose(&client->channel, flush_and_send_shutdown);
    _LSTransportChannelDeinit(&client->channel);
}

/**
 *******************************************************************************
 * @brief Callback to discard pending incoming messages for a given client.
 *
 * @attention This is callled with the transport lock held.
 *
 * @param  client       IN  client
 *******************************************************************************
 */
void
_LSTransportDiscardIncomingMessages(void *ignored, _LSTransportClient *client, GMainContext *ignored_mainloop_context)
{
    LS_ASSERT(client != NULL);

    LOG_LS_DEBUG("%s: client: %p\n", __func__, client);

    _LSTransportClientRef(client);
    _LSTransportIncoming *incoming = client->incoming;
    int discards = 0;

    while (!g_queue_is_empty(incoming->complete_messages))
    {
        _LSTransportMessage *tmsg = (_LSTransportMessage*) g_queue_pop_head(incoming->complete_messages);
        _LSTransportMessageUnref(tmsg);
        discards++;
    }

    if (discards)
    {
        LOG_LS_WARNING(MSGID_LS_QUEUE_ERROR, 0, "%s: discarded %d messages", __func__, discards);
    }

    _LSTransportClientUnref(client);
}

/**
 *******************************************************************************
 * @brief Discards all pending incoming messages for all clients in a transport.
 *
 * @attention locks the transport lock.
 *
 * @param  transport    IN  transport
 *******************************************************************************
 */
void
_LSTransportDiscardAllClientIncoming(_LSTransport *transport)
{
    TRANSPORT_LOCK(&transport->lock);
    g_hash_table_foreach(transport->clients, (GHFunc)_LSTransportDiscardIncomingMessages, NULL);
    TRANSPORT_UNLOCK(&transport->lock);
}

/**
 *******************************************************************************
 * @brief Perform disconnect operations. Removes the watches, sends shutdown
 * messages (if requested) and closes the connections.
 *
 * @attention locks the transport lock
 *
 * @param  transport    IN  transport
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
_LSTransportDisconnect(_LSTransport *transport, bool flush_and_send_shutdown)
{
    LS_ASSERT(transport != NULL);

    LOG_LS_DEBUG("%s: transport: %p\n", __func__, transport);

    TRANSPORT_LOCK(&transport->lock);
    g_hash_table_foreach(transport->all_connections, _LSTransportSendShutdownMessages, GINT_TO_POINTER((gint)flush_and_send_shutdown));
    TRANSPORT_UNLOCK(&transport->lock);

    _LSTransportDiscardAllClientIncoming(transport);

    _LSTransportChannelClose(&transport->listen_channel, flush_and_send_shutdown);
    _LSTransportChannelDeinit(&transport->listen_channel);

    if (transport->shm) _LSTransportShmDeinit(&transport->shm);

    return true;
}

static gboolean
_freePending(gpointer key, _LSTransportOutgoing *outgoing, gpointer user_data)
{
    LS_ASSERT(outgoing != NULL);

    //printf("%s: outgoing queue entries: %u, serial queue entries: %u\n", __func__,
    //       g_queue_get_length(outgoing->queue), g_queue_get_length(outgoing->serial->queue));

    _LSTransportOutgoingFree(outgoing);

    return true;
}

/**
 *******************************************************************************
 * @brief Clean up a disconnected transport. This function should be called
 * after @ref _LSTransportDisconnect.
 *
 * @param  transport    IN  transport
 *******************************************************************************
 */
void
_LSTransportDeinit(_LSTransport *transport)
{
    LOG_LS_DEBUG("%s: transport: %p\n", __func__, transport);

    if (transport)
    {
        /* destroy all hash tables */
        if (transport->clients) g_hash_table_unref(transport->clients);
        transport->clients = NULL;

        if (transport->all_connections) g_hash_table_unref(transport->all_connections);
        transport->all_connections = NULL;

        g_hash_table_foreach_remove(transport->pending, (GHRFunc)_freePending, NULL);
        if (transport->pending) g_hash_table_unref(transport->pending);
        transport->pending = NULL;

        if (transport->hub) _LSTransportClientUnref(transport->hub);
        transport->hub = NULL;

        if (transport->global_token) _LSTransportGlobalTokenFree(transport->global_token);
        transport->global_token = NULL;

        /* unref the GMainContext */
        if (transport->mainloop_context) g_main_context_unref(transport->mainloop_context);
        transport->mainloop_context = NULL;

        g_free(transport->service_name);
        transport->service_name = NULL;

        g_free(transport->unique_name);
        transport->unique_name = NULL;

        g_free(transport);
    }
}

_LSTransportType
_LSTransportGetTransportType(const _LSTransport *transport)
{
    LS_ASSERT(transport != NULL);
    return transport->type;
}

bool
_LSTransportGetPrivileged(const _LSTransport *transport)
{
    LS_ASSERT(transport != NULL);
    return transport->privileged;
}

/* NOTE: This is a blocking call */
static bool
_LSTransportSendMessagePushRole(_LSTransportClient *hub, const char *role_path, LSError *lserror)
{
    LS_ASSERT(hub != NULL);

    _LSTransportMessageIter iter;
    bool ret = false;

    _LSTransportMessage *message = _LSTransportMessageNewRef(LS_TRANSPORT_MESSAGE_DEFAULT_PAYLOAD_SIZE);

    _LSTransportMessageSetType(message, _LSTransportMessageTypePushRole);

    _LSTransportMessageIterInit(message, &iter);
    if (!_LSTransportMessageAppendString(&iter, role_path)) goto error;
    if (!_LSTransportMessageAppendInvalid(&iter)) goto error;

    ret = _LSTransportSendMessageBlocking(message, hub, NULL, lserror);

    _LSTransportMessageUnref(message);

    return ret;

error:
    if (message) _LSTransportMessageUnref(message);
    _LSErrorSetOOM(lserror);
    return false;
}

bool
LSTransportPushRole(_LSTransport *transport, const char *path, LSError *lserror)
{
    LS_ASSERT(transport != NULL);
    LS_ASSERT(transport->hub != NULL);

    _LSTransportMessage *message = NULL;
    _LSTransportMessageIter iter;
    int32_t err_code = 0;
    bool ret = false;

    /* Blocking send a "push role" message to the hub */
    if (!_LSTransportSendMessagePushRole(transport->hub, path, lserror))
    {
        return false;
    }

    /* Get the reply from the hub */
    _LSTransportMessageType msg_type = _LSTransportMessageTypePushRoleReply;
    message = _LSTransportRecvMessageBlocking(transport->hub, &msg_type, 1, -1, lserror);

    if (!message)
    {
        return false;
    }

    _LSTransportMessageIterInit(message, &iter);

    LS_ASSERT(_LSTransportMessageIterHasNext(&iter));

    /* Get the return code */
    bool err_ret = _LSTransportMessageGetInt32(&iter, &err_code);

    /* If there was an error, get the error string */
    if (!err_ret || err_code != LS_TRANSPORT_PUSH_ROLE_SUCCESS)
    {
        _LSTransportMessageIterNext(&iter);
        const char *err_string = NULL;
        if (_LSTransportMessageGetString(&iter, &err_string))
        {
            _LSErrorSet(lserror, MSGID_LS_MSG_ERR, err_code, "%s", err_string);
        }
        else
        {
            _LSErrorSet(lserror, MSGID_LS_MSG_ERR, err_code, "Unable to get error string");
        }
        ret = false;
    }

    ret = true;

    _LSTransportMessageUnref(message);

    return ret;
}

void _LSTransportSetTransportType(_LSTransport *transport, _LSTransportType type)
{
    transport->type = type;
}

/* @} END OF LunaServiceTransport */
