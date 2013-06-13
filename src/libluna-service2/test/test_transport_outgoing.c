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


#include <stdlib.h>
#include <glib.h>
#include "transport_message.h"
#include "transport_outgoing.h"

/* Mock variables *************************************************************/

static _LSTransportSerial* mvar_serial_ptr =
    (_LSTransportSerial*) 0x3456;
static _LSTransportMessage* mvar_message_ptr[3] =
    { (_LSTransportMessage*) 0x82345,
      (_LSTransportMessage*) 0x1493f,
      (_LSTransportMessage*) 0x92835 };
static int mvar_unref_count = 0;
static int mvar_serial_freed = 0;

/* Test cases *****************************************************************/

static void
test_LSTransportOutgoing(void)
{
    _LSTransportOutgoing* outqueue = NULL;
    int i;

    /* Test creation of a new outgoing queue. */

    outqueue = _LSTransportOutgoingNew();
    /* case: _LSTransportOutgoing instance was created */
    g_assert(NULL != outqueue);
    /* case: Queue was created */
    g_assert(NULL != outqueue->queue);
    /* case: Serial number was aquired */
    g_assert_cmphex(GPOINTER_TO_INT(outqueue->serial),
                    ==,
                    GPOINTER_TO_INT(mvar_serial_ptr));

    /* Fill queue with test data. */
    for (i = 0; i < 3; i++)
    {
        g_queue_push_head(outqueue->queue, mvar_message_ptr[i]);
    }

    /* Test deletion of outgoing queue. */

    _LSTransportOutgoingFree(outqueue);
    /* case: All three items removed and unreferenced */
    g_assert_cmpint(mvar_unref_count, ==, 3);
    /* case: serial number released */
    g_assert_cmpint(mvar_serial_freed, !=, 0);
}

/* Mocks **********************************************************************/

_LSTransportSerial*
_LSTransportSerialNew(void)
{
    return mvar_serial_ptr;
}

void
_LSTransportMessageUnref(_LSTransportMessage *message)
{
    int i;
    for (i = 0; i < 3; i++)
    {
        if (message == mvar_message_ptr[i])
        {
            mvar_unref_count++;
            mvar_message_ptr[i]++;
            break;
        }
    }
}

void
_LSTransportSerialFree(_LSTransportSerial *serial_info)
{
    mvar_serial_freed++;
}

/* Test suite *****************************************************************/

int
main(int argc, char *argv[])
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/luna-service2/LSTransportOutgoing",
                    test_LSTransportOutgoing);

    return g_test_run();
}

