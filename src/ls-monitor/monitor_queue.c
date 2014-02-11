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


#include "monitor.h"
#include "monitor_queue.h"

struct _LSMonitorQueueItem
{
    struct timespec timestamp;
    _LSTransportMessage *message;
};

struct _LSMonitorQueue
{
    bool public;
    GQueue *queue;
};

typedef struct _LSMonitorQueueItem _LSMonitorQueueItem;

_LSMonitorQueue*
_LSMonitorQueueNew(bool public_bus)
{
    _LSMonitorQueue *queue = g_new0(_LSMonitorQueue, 1);
    if (queue)
    {
        queue->public = public_bus;
        queue->queue = g_queue_new();
    }
    return queue;
}

void
_LSMonitorQueueFree(_LSMonitorQueue *queue)
{
    LS_ASSERT(queue != NULL);
    g_queue_free(queue->queue);
}

void
_LSMonitorQueueMessage(_LSMonitorQueue *queue, _LSTransportMessage *message)
{
    /* save the time that the message was received along with the message */
    _LSMonitorQueueItem *item = g_slice_new0(_LSMonitorQueueItem);

    _LSMonitorGetTime(&item->timestamp);
    item->message = message;
    _LSTransportMessageRef(message);

    g_queue_push_tail(queue->queue, item);
}

static void
_LSMonitorQueueItemFree(_LSMonitorQueueItem *item)
{
    _LSTransportMessageUnref(item->message);
    g_slice_free(_LSMonitorQueueItem, item);
}

static bool
_OutOfOrder(GHashTable *hash_table, _LSTransportMessage *message)
{
    bool out_of_order = false;
    char *key = NULL;

    switch (_LSTransportMessageGetType(message))
    {
    case _LSTransportMessageTypeMethodCall:
        key = g_strdup_printf("%s|%s|%lu",
                        _LSTransportMessageGetSenderUniqueName(message),
                        _LSTransportMessageGetDestUniqueName(message),
                        _LSTransportMessageGetToken(message));
        g_hash_table_insert(hash_table, key, message);
        break;

    case _LSTransportMessageTypeReply:
        key = g_strdup_printf("%s|%s|%lu",
                        _LSTransportMessageGetDestUniqueName(message),
                        _LSTransportMessageGetSenderUniqueName(message),
                        _LSTransportMessageGetReplyToken(message));
        out_of_order = NULL == g_hash_table_lookup(hash_table, key);
        g_free(key);
        break;

    default:
        break;
    }

    return out_of_order;
}

static gint
_LSMonitorQueueSortFunc(gconstpointer a, gconstpointer b, gpointer user_data)
{
    const _LSMonitorQueueItem *item_a = a;
    const _LSMonitorQueueItem *item_b = b;

    _LSTransportMonitorSerial serial_a = _LSTransportMessageGetMonitorSerial(item_a->message);
    _LSTransportMonitorSerial serial_b = _LSTransportMessageGetMonitorSerial(item_b->message);

    return (serial_a - serial_b);
}

void
_LSMonitorQueuePrint(_LSMonitorQueue *queue, int msecs, GHashTable *hash_table, gboolean debug_output)
{
    struct timespec now;
    _LSMonitorGetTime(&now);

    /* Get all messages older than msecs and save in a new queue */
    GQueue *orig_queue = queue->queue;
    GQueue *print_queue = g_queue_new();
    _LSMonitorQueueItem *item = NULL;

    while ((item = g_queue_peek_head(orig_queue)) != NULL)
    {
        double time_diff = _LSMonitorTimeDiff(&now, &item->timestamp);

        if (time_diff * 1000.0 >= msecs)
        {
            g_queue_push_tail(print_queue, g_queue_pop_head(orig_queue));
        }
        else
        {
           break;
        }
    }

    /* sort the print list by serial number */
    g_queue_sort(print_queue, _LSMonitorQueueSortFunc, NULL);

    char first = 'F';
    /* print and free the sorted items */
    while (!g_queue_is_empty(print_queue))
    {
        item = g_queue_pop_head(print_queue);

        if (debug_output)
        {
            char last = g_queue_is_empty(print_queue) ? 'L' : ' ';
            fprintf(stdout, "[%c%c%c %"PRIu64"]\t", _OutOfOrder(hash_table, item->message) ? 'X' : ' ', first, last, _LSTransportMessageGetMonitorSerial(item->message));
        }

        _LSMonitorMessagePrint(item->message, &item->timestamp, queue->public);
        _LSMonitorQueueItemFree(item);

        first = ' ';
    }

    g_queue_free(print_queue);
}
