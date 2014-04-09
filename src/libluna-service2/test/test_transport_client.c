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
#include <transport_priv.h>
#include <transport_client.h>

/* Mock variables *************************************************************/

static _LSTransport mvar_transport;
static const int mvar_fd = 5;
static const char mvar_service_name[] = "stest_test";
static const char mvar_unique_name[] = "utest_test";
static _LSTransportOutgoing* mvar_outqueue = (_LSTransportOutgoing*)0x2345;
static _LSTransportIncoming* mvar_inqueue = (_LSTransportIncoming*)0x8484;
static bool mvar_initiator = true;
static const int mvar_source_priority = 4;
static _LSTransportCred* mvar_transport_cred_ptr = (_LSTransportCred*)0x9494;
static _LSTransportType mvar_transport_type = _LSTransportTypeLocal;
static bool mvar_getcredentials_succeeds = true;
static bool mvar_outqueue_creation_succeeds = true;
static bool mvar_inqueue_creation_succeeds = true;

static int mvar_incoming_free_count = 0;
static int mvar_outgoing_free_count = 0;
static int mvar_cred_free_count = 0;
static int mvar_channel_close_count = 0;
static int mvar_channel_deinit_count = 0;
static int mvar_errorprint_count = 0;

/* Test cases *****************************************************************/

static void
test_LSTransportClientNewFree(void)
{
    mvar_transport.source_priority = mvar_source_priority;

    /* Test creation of new client */
    _LSTransportClient* client = _LSTransportClientNewRef(
                                    &mvar_transport,
                                    mvar_fd,
                                    mvar_service_name,
                                    mvar_unique_name,
                                    mvar_outqueue,
                                    mvar_initiator);
    /* case: verify client creation. */
    g_assert_cmpint(client->ref, ==, 1);
    g_assert_cmpstr(client->unique_name, ==, mvar_unique_name);
    g_assert_cmpstr(client->service_name, ==, mvar_service_name);
    g_assert_cmpint(client->state, ==, _LSTransportClientStateInvalid);
    g_assert_cmphex(GPOINTER_TO_INT(client->transport),
                     ==,
                     GPOINTER_TO_INT(&mvar_transport));
    g_assert_cmphex(GPOINTER_TO_INT(client->channel.transport),
                     ==,
                     GPOINTER_TO_INT(&mvar_transport));
    g_assert_cmpint(client->channel.fd, ==, mvar_fd);
    g_assert_cmpint(client->channel.priority, ==, mvar_source_priority);
    g_assert_cmphex(GPOINTER_TO_INT(client->cred),
                     ==,
                     GPOINTER_TO_INT(mvar_transport_cred_ptr));
    g_assert_cmphex(GPOINTER_TO_INT(client->outgoing),
                     ==,
                     GPOINTER_TO_INT(mvar_outqueue));
    g_assert_cmphex(GPOINTER_TO_INT(client->incoming),
                     ==,
                     GPOINTER_TO_INT(mvar_inqueue));
    g_assert(client->is_sysmgr_app_proxy == false);
    g_assert(client->is_dynamic == false);
    g_assert_cmpint(client->initiator, ==, mvar_initiator);

    /* Test reference count handling. */

    /* case: incrementing ref count. */
    _LSTransportClientRef(client);
    g_assert_cmpint(client->ref, ==, 2);
    /* case: decrementing ref count. */
    _LSTransportClientUnref(client);
    g_assert_cmpint(client->ref, ==, 1);

    /* Test getters. */

    /* case: get unique name. */
    g_assert_cmpstr(_LSTransportClientGetUniqueName(client),
                     ==,
                     mvar_unique_name);
    /* case: get service name. */
    g_assert_cmpstr(_LSTransportClientGetServiceName(client),
                     ==,
                     mvar_service_name);
    /* case: get channel. */
    g_assert_cmphex(
        GPOINTER_TO_INT(_LSTransportClientGetChannel(client)),
        ==,
        GPOINTER_TO_INT(&client->channel));
    /* case: get transport. */
    g_assert_cmphex(
        GPOINTER_TO_INT(_LSTransportClientGetTransport(client)),
        ==,
        GPOINTER_TO_INT(client->transport));
    /* case: get credentials. */
    g_assert_cmphex(
        GPOINTER_TO_INT(_LSTransportClientGetCred(client)),
        ==,
        GPOINTER_TO_INT(client->cred));

    /* Test deletion. */
    _LSTransportClientFree(client);
    /* case: credentials freed. */
    g_assert_cmpint(mvar_cred_free_count, ==, 1);
    /* case: queues freed. */
    g_assert_cmpint(mvar_incoming_free_count, ==, 1);
    g_assert_cmpint(mvar_outgoing_free_count, ==, 1);
    /* case: channel freed. */
    g_assert_cmpint(mvar_channel_close_count, ==, 1);
    g_assert_cmpint(mvar_channel_deinit_count, ==, 1);
}

static void
test_LSTransportClientNewFreeErrorHandling(void)
{
    mvar_transport.source_priority = mvar_source_priority;

    /* Test creation of new client in error situations */

    /* case: getting transport credentials fails. */
    mvar_transport_cred_ptr = (_LSTransportCred*)0x9494;
    mvar_getcredentials_succeeds = false;
    _LSTransportClient *client = _LSTransportClientNewRef(
        &mvar_transport,
        mvar_fd,
        mvar_service_name,
        mvar_unique_name,
        mvar_outqueue,
        mvar_initiator);
    g_assert_cmpint(mvar_errorprint_count, ==, 1);
    _LSTransportClientFree(client);
    /* case: outqueu creation fails. */
    mvar_incoming_free_count = 0;
    mvar_outgoing_free_count = 0;
    mvar_outqueue_creation_succeeds = false;
    client = _LSTransportClientNewRef(
        &mvar_transport,
        mvar_fd,
        mvar_service_name,
        mvar_unique_name,
        NULL,
        mvar_initiator);
    g_assert_cmphex(GPOINTER_TO_INT(client),
                     ==,
                     0);
    g_assert_cmpint(mvar_incoming_free_count, ==, 0);
    g_assert_cmpint(mvar_outgoing_free_count, ==, 0);
    /* case: inqueue creation fails. */
    mvar_incoming_free_count = 0;
    mvar_outgoing_free_count = 0;
    mvar_outqueue_creation_succeeds = true;
    mvar_inqueue_creation_succeeds = false;
    client = _LSTransportClientNewRef(
        &mvar_transport,
        mvar_fd,
        mvar_service_name,
        mvar_unique_name,
        mvar_outqueue,
        mvar_initiator);
    g_assert_cmphex(GPOINTER_TO_INT(client),
                     ==,
                     0);
    g_assert_cmpint(mvar_incoming_free_count, ==, 0);
    g_assert_cmpint(mvar_outgoing_free_count, ==, 0);
}

/* Mocks **********************************************************************/

bool
_LSTransportChannelInit(_LSTransport *transport,
                        _LSTransportChannel *channel,
                        int fd,
                        int priority)
{
    channel->transport = transport;
    channel->fd = fd;
    channel->priority = priority;
    return true;
}

_LSTransportCred *
_LSTransportCredNew(void)
{
    return mvar_transport_cred_ptr;
}

_LSTransportType
_LSTransportGetTransportType(const _LSTransport *transport)
{
    return mvar_transport_type;
}

bool
LSErrorInit(LSError *error)
{
    return true;
}

bool
_LSTransportGetCredentials(int fd, _LSTransportCred *cred, LSError *lserror)
{
    return mvar_getcredentials_succeeds;
}

void
LSErrorFree(LSError *error)
{
}

void
LSErrorLog(PmLogContext context, const char *message_id, LSError *lserror)
{
    mvar_errorprint_count++;
}

_LSTransportOutgoing *
_LSTransportOutgoingNew(void)
{
    return mvar_outqueue_creation_succeeds ? mvar_outqueue : NULL;
}

_LSTransportIncoming *
_LSTransportIncomingNew(void)
{
    return mvar_inqueue_creation_succeeds ? mvar_inqueue : NULL;
}

void
_LSTransportOutgoingFree(_LSTransportOutgoing *outgoing)
{
    mvar_outgoing_free_count++;
}

void
_LSTransportIncomingFree(_LSTransportIncoming *incoming)
{
    mvar_incoming_free_count++;
}

void
_LSTransportCredFree(_LSTransportCred *cred)
{
    mvar_cred_free_count++;
}

void
_LSTransportChannelClose(_LSTransportChannel *channel, bool flush)
{
    mvar_channel_close_count++;
}

void
_LSTransportChannelDeinit(_LSTransportChannel *channel)
{
    mvar_channel_deinit_count++;
}

/* Test suite *****************************************************************/

int
main(int argc, char *argv[])
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/luna-service2/LSTransportClientNewFree",
                     test_LSTransportClientNewFree);
    g_test_add_func("/luna-service2/LSTransportClientNewFreeErrorHandling",
                     test_LSTransportClientNewFreeErrorHandling);

    return g_test_run();
}

