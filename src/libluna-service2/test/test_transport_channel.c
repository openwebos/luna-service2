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
#include <unistd.h>
#include "transport.h"
#include "transport_priv.h"

/* Mock variables *************************************************************/

static _LSTransport mvar_transport;
static _LSTransportChannel mvar_channel;

static const int mvar_priority = G_PRIORITY_DEFAULT_IDLE;

static int mvar_blockfd_out = 0;
static bool mvar_blockprev_out = false;

/* Test cases *****************************************************************/

static void
test_LSTransportChannelPositive(void)
{
    gchar tmpfilename[32] = "ut_transportchannel_testXXXXXX";
    int tempfd = g_mkstemp(tmpfilename);
    bool prev = true;

    /* Test channel handling. */
    bool retval = _LSTransportChannelInit(&mvar_transport,
                                           &mvar_channel,
                                           tempfd,
                                           mvar_priority);
    /* case: check initialized channel info. */
    g_assert(retval);
    g_assert_cmphex(GPOINTER_TO_INT(mvar_channel.transport),
                     ==,
                     GPOINTER_TO_INT(&mvar_transport));
    g_assert_cmpint(mvar_channel.fd, ==, tempfd);
    g_assert_cmpint(mvar_channel.priority, ==, mvar_priority);
    g_assert(NULL != mvar_channel.channel);
    g_assert(NULL == mvar_channel.send_watch);
    g_assert(NULL == mvar_channel.recv_watch);
    g_assert(NULL == mvar_channel.accept_watch);
    /* case: fd getter */
    g_assert_cmpint(_LSTransportChannelGetFd(&mvar_channel),
                     ==,
                     tempfd);
    /* case: set priority. */
    mvar_channel.send_watch = g_io_create_watch(mvar_channel.channel, G_IO_NVAL);
    mvar_channel.recv_watch = g_io_create_watch(mvar_channel.channel, G_IO_NVAL);
    g_source_set_priority(mvar_channel.send_watch, mvar_priority);
    g_source_set_priority(mvar_channel.recv_watch, mvar_priority);
    _LSTransportChannelSetPriority(&mvar_channel, G_PRIORITY_LOW);
    g_assert_cmpint(mvar_channel.send_watch->priority,
                     ==,
                     G_PRIORITY_LOW);
    g_assert_cmpint(mvar_channel.recv_watch->priority,
                     ==,
                     G_PRIORITY_LOW);
    g_assert_cmpint(mvar_channel.priority, ==, G_PRIORITY_LOW);
    /* case: watch checkers. */
    g_assert(_LSTransportChannelHasReceiveWatch(&mvar_channel));
    g_assert(_LSTransportChannelHasSendWatch(&mvar_channel));
    /* case: block/nonblock. */
    mvar_blockfd_out = 0;
    mvar_blockprev_out = false;
    _LSTransportChannelSetBlock(&mvar_channel, &prev);
    g_assert_cmpint(mvar_blockfd_out, ==, tempfd);
    g_assert(mvar_blockprev_out);
    mvar_blockfd_out = 0;
    mvar_blockprev_out = false;
    _LSTransportChannelSetNonblock(&mvar_channel, &prev);
    g_assert_cmpint(mvar_blockfd_out, ==, tempfd);
    g_assert(mvar_blockprev_out);
    mvar_blockfd_out = 0;
    mvar_blockprev_out = false;
    _LSTransportChannelRestoreBlockState(&mvar_channel, &prev);
    g_assert_cmpint(mvar_blockfd_out, ==, tempfd);
    g_assert(mvar_blockprev_out);
    mvar_blockfd_out = 0;
    prev = false;
    _LSTransportChannelRestoreBlockState(&mvar_channel, &prev);
    g_assert_cmpint(mvar_blockfd_out, ==, tempfd);
    g_assert(!mvar_blockprev_out);
    mvar_channel.accept_watch = (GSource*)1;
    _LSTransportChannelDeinit(&mvar_channel);
    /* case: Deinit correct. */
    g_assert(NULL == mvar_channel.send_watch);
    g_assert(NULL == mvar_channel.recv_watch);
    g_assert(NULL == mvar_channel.accept_watch);
    g_assert(NULL == mvar_channel.channel);
    g_assert(NULL == mvar_channel.transport);

    /* Test channel close. */
    _LSTransportChannelInit(&mvar_transport,
                             &mvar_channel,
                             tempfd,
                             mvar_priority);
    _LSTransportChannelClose(&mvar_channel, false);
    g_assert(NULL == mvar_channel.channel);

    close(tempfd);

    unlink(tmpfilename);
}

/* Mocks **********************************************************************/

void
_LSTransportFdSetBlock(int fd, bool *prev_state_blocking)
{
    mvar_blockfd_out = fd;
    mvar_blockprev_out = prev_state_blocking?*prev_state_blocking:true;
}

void
_LSTransportFdSetNonBlock(int fd, bool *prev_state_blocking)
{
    mvar_blockfd_out = fd;
    mvar_blockprev_out = prev_state_blocking?*prev_state_blocking:false;
}

void
_LSTransportRemoveSendWatch(_LSTransportChannel *channel)
{
    if (channel == &mvar_channel)
    {
        g_source_destroy(channel->send_watch);
        g_source_unref(channel->send_watch);
        channel->send_watch = NULL;
    }
}

void
_LSTransportRemoveReceiveWatch(_LSTransportChannel *channel)
{
    if (channel == &mvar_channel)
    {
        g_source_destroy(channel->recv_watch);
        g_source_unref(channel->recv_watch);
        channel->recv_watch = NULL;
    }
}

void
_LSTransportRemoveAcceptWatch(_LSTransportChannel *channel)
{
    if (channel == &mvar_channel)
    {
        channel->accept_watch = NULL;
    }
}

/* Test suite *****************************************************************/

int
main(int argc, char *argv[])
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/luna-service2/LSTransportChannelPositive",
                     test_LSTransportChannelPositive);

    return g_test_run();
}

