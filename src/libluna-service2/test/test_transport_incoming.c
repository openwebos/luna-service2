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
#include "transport_message.h"
#include "transport_incoming.h"

/* Test cases *****************************************************************/

static void
test_LSTransportIncoming_execute(int number_of_messages)
{
    _LSTransportIncoming *inqueue = _LSTransportIncomingNew();

    /* Is incoming message queue constructed? */
    g_assert(NULL != inqueue);
    g_assert(NULL != inqueue->complete_messages);

    /* The mutex should be initialized. */
    g_assert_cmpint(pthread_mutex_trylock(&inqueue->lock), !=, EINVAL);
    pthread_mutex_unlock(&inqueue->lock);

    _LSTransportMessage *messages[number_of_messages];
    int i;

    /* Fill queue with (possible) test data. */
    for(i = 0; i < number_of_messages; i++)
    {
        _LSTransportMessage *message = _LSTransportMessageNewRef(LS_TRANSPORT_MESSAGE_DEFAULT_PAYLOAD_SIZE);
        /* Increment ref count (possible to check message ref count after _LSTransportIncomingFree) */
        _LSTransportMessageRef(message);
        g_assert_cmpint(message->ref, ==, 2);
        messages[i] = message;

        g_queue_push_head(inqueue->complete_messages, message);
    }

    /* Simulate the message are processed */
    while (!g_queue_is_empty(inqueue->complete_messages))
    {
        _LSTransportMessage *message = g_queue_pop_head(inqueue->complete_messages);
        _LSTransportMessageUnref(message);
    }

    /* See if the messages in the queue were unreferenced. */
    for(i = 0; i < number_of_messages; i++)
    {
        g_assert_cmpint(messages[i]->ref, ==, 1);
    }

    /* Cleanup. All testing is now over. */
    _LSTransportIncomingFree(inqueue);
    for(i = 0; i < number_of_messages; i++)
    {
        _LSTransportMessageUnref(messages[i]);
    }
}

static void
test_LSTransportIncoming()
{
    test_LSTransportIncoming_execute(0);
    /* Currently LSTransportIncomingFree() isn't supposed to free the queue,
     * but to assert instead. */
    test_LSTransportIncoming_execute(1);
    test_LSTransportIncoming_execute(3);
    test_LSTransportIncoming_execute(500);
}

/* Test suite *****************************************************************/

int
main(int argc, char *argv[])
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/luna-service2/LSTransportIncoming",
                     test_LSTransportIncoming);

    return g_test_run();
}

