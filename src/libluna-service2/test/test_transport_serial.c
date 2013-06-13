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
#include <transport_message.h>
#include <transport_serial.h>

/* Test data ******************************************************************/

static int transport_message_ref_call_count = 0;

typedef struct TestData
{
    // Object to use in LSTransportSerial -tests.
    _LSTransportSerial *serial;
} TestData;

static void
test_setup(TestData *fixture, gconstpointer user_data)
{
    transport_message_ref_call_count = 0;

    fixture->serial = _LSTransportSerialNew();
    g_assert(NULL != fixture->serial);
}

static void
test_teardown(TestData *fixture, gconstpointer user_data)
{
    _LSTransportSerialFree(fixture->serial);
}

/* Test cases *****************************************************************/

static void
test_LSTransportSerialMapEntryNewAndFree()
{
    _LSTransportSerialMapEntry *entry = _LSTransportSerialMapEntryNew(1, GINT_TO_POINTER(2));
    g_assert(NULL != entry);

    g_assert_cmpint(entry->serial, ==, 1);
    g_assert_cmpint(GPOINTER_TO_INT(entry->serial_list_item), ==, GPOINTER_TO_INT(2));

    _LSTransportSerialMapEntryFree(entry);
}

static void
test_LSTransportSerialListItemNewAndFree()
{
    transport_message_ref_call_count = 0;

    _LSTransportSerialListItem *item = _LSTransportSerialListItemNew(1, GINT_TO_POINTER(2));
    g_assert(NULL != item);

    g_assert_cmpint(item->serial, ==, 1);
    g_assert_cmpint(GPOINTER_TO_INT(item->message), ==, GPOINTER_TO_INT(2));

    // _LSTransportSerialListItemNew should increment message ref count
    g_assert_cmpint(transport_message_ref_call_count, ==, 1);

    _LSTransportSerialListItemFree(item);

    // _LSTransportSerialListItemFree should decrement message ref count
    g_assert_cmpint(transport_message_ref_call_count, ==, 0);
}

static void
test_LSTransportSerialNewAndFree()
{
    transport_message_ref_call_count = 0;

    _LSTransportSerial *serial = _LSTransportSerialNew();
    g_assert(NULL != serial);

    g_assert_cmpint(GPOINTER_TO_INT(serial->queue), !=, GPOINTER_TO_INT(NULL));
    g_assert_cmpint(GPOINTER_TO_INT(serial->map), !=, GPOINTER_TO_INT(NULL));

    _LSTransportSerialListItem *items[] =
    {
        _LSTransportSerialListItemNew(1, GINT_TO_POINTER(2)),
        _LSTransportSerialListItemNew(3, GINT_TO_POINTER(4))
    };
    g_assert_cmpint(transport_message_ref_call_count, ==, 2);

    int i;
    for (i = 0; i < sizeof(items)/sizeof(items[0]); ++i)
    {
        g_queue_push_tail(serial->queue, items[i]);
    }

    _LSTransportSerialFree(serial);

    g_assert_cmpint(transport_message_ref_call_count, ==, 0);
}

static void
test_LSTransportSerialSaveAndRemove(TestData *fixture, gconstpointer user_data)
{
    _LSTransportSerial *serial = fixture->serial;

    LSError error;
    LSErrorInit(&error);

    _LSTransportMessage *message = GINT_TO_POINTER(1);

    g_assert(_LSTransportSerialSave(serial, message, &error));

    g_assert_cmpint(g_hash_table_size(serial->map), ==, 1);
    g_assert_cmpint(g_queue_get_length(serial->queue), ==, 1);
    g_assert_cmpint(transport_message_ref_call_count, ==, 1);

    _LSTransportSerialRemove(serial, 1);

    g_assert_cmpint(g_hash_table_size(serial->map), ==, 0);
    g_assert_cmpint(g_queue_get_length(serial->queue), ==, 0);
    g_assert_cmpint(transport_message_ref_call_count, ==, 0);
}

static void
test_LSTransportSerialPopHead(TestData *fixture, gconstpointer user_data)
{
    _LSTransportSerial *serial = fixture->serial;

    LSError error;
    LSErrorInit(&error);

    _LSTransportMessage *message = GINT_TO_POINTER(1);

    _LSTransportSerialSave(serial, message, &error);

    message = _LSTransportSerialPopHead(serial);
    g_assert_cmpint(GPOINTER_TO_INT(message), ==, 1);

    g_assert_cmpint(g_hash_table_size(serial->map), ==, 0);
    g_assert_cmpint(g_queue_get_length(serial->queue), ==, 0);

    // Message returned, there should be one reference!
    g_assert_cmpint(transport_message_ref_call_count, ==, 1);
}

/* Mocks **********************************************************************/

_LSTransportMessage*
_LSTransportMessageRef(_LSTransportMessage *message)
{
    ++transport_message_ref_call_count;
    return message;
}

void
_LSTransportMessageUnref(_LSTransportMessage *message)
{
    --transport_message_ref_call_count;
}

LSMessageToken
_LSTransportMessageGetToken(const _LSTransportMessage *message)
{
    return GPOINTER_TO_INT(message);
}

/* Test suite *****************************************************************/

#define LSTEST_ADD(name, func) \
    g_test_add(name, TestData, NULL, test_setup, func, test_teardown)

int
main(int argc, char *argv[])
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/luna-service2/LSTransportSerialMapEntryNew", test_LSTransportSerialMapEntryNewAndFree);
    g_test_add_func("/luna-service2/LSTransportSerialListItemNew", test_LSTransportSerialListItemNewAndFree);
    g_test_add_func("/luna-service2/LSTransportSerialNew", test_LSTransportSerialNewAndFree);

    LSTEST_ADD("/luna-service2/LSTransportSerialSaveAndRemove", test_LSTransportSerialSaveAndRemove);
    LSTEST_ADD("/luna-service2/LSTransportSerialPopHead", test_LSTransportSerialPopHead);

    return g_test_run();
}

