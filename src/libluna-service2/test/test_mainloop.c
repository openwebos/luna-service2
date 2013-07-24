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
#include <luna-service2/lunaservice.h>
#include <base.h>

/* Mock variables *************************************************************/

static const int mvar_priority = 8;

static _LSTransport* mvar_priv_trans;
static _LSTransport* mvar_publ_trans;
static GMainContext* mvar_context;
static LSHandle mvar_priv_sh;
static LSHandle mvar_publ_sh;

static unsigned int mvar_attach_count = 0;
static unsigned int mvar_priority_count = 0;
static unsigned int mvar_public_detached = 0;
static unsigned int mvar_private_detached = 0;

/* Test cases *****************************************************************/

static void
test_LSMainAttachDetachPositive(void)
{
    /* Attach service. */
    LSError error;
    LSErrorInit(&error);
    LSPalmService service;
    mvar_priv_sh.context = NULL;
    mvar_publ_sh.context = NULL;
    mvar_priv_trans = (_LSTransport*)0x3456;
    mvar_publ_trans = (_LSTransport*)0x4567;
    mvar_priv_sh.transport = mvar_priv_trans;
    mvar_publ_sh.transport = mvar_publ_trans;
    service.public_sh = &mvar_publ_sh;
    service.private_sh = &mvar_priv_sh;
    mvar_context = g_main_context_default();
    GMainLoop* mainloop = g_main_loop_new(mvar_context, false);
    bool ret = LSGmainAttachPalmService(&service, mainloop, &error);
    /* case: return value. */
    g_assert(ret);
    /* case: both services attached. */
    g_assert_cmpint(mvar_attach_count, ==, 2);
    /* case: both contexts saved. */
    g_assert(NULL != mvar_priv_sh.context);
    g_assert(NULL != mvar_publ_sh.context);

    /* Change priority. */
    mvar_priv_trans = (_LSTransport*)0x3456;
    mvar_publ_trans = (_LSTransport*)0x4567;
    ret = LSGmainSetPriorityPalmService(&service, mvar_priority, &error);
    /* case: return value. */
    g_assert(ret);
    /* case: both service priorities changed. */
    g_assert_cmpint(mvar_priority_count, ==, 2);

    /* Detach services. */
    /* NOTE: LSGmainDetachPalmService seems to be dead code... it is not
     * declared outside the .c file. Using lower level function instead.
     */
    //ret = LSGmainDetachPalmService(&service, &error);
    ret = LSGmainDetach(service.public_sh, &error);
    g_assert(ret);
    ret = LSGmainDetach(service.private_sh, &error);
    g_assert(ret);
    /* case: both services detached. */
    g_assert_cmpint(mvar_private_detached, ==, 1);
    g_assert_cmpint(mvar_public_detached, ==, 1);

    /* Cleanup. */
    g_main_context_unref(mvar_priv_sh.context);
    g_main_context_unref(mvar_publ_sh.context);

    g_main_loop_unref(mainloop);
}

/* Mocks **********************************************************************/

void
_lshandle_validate(LSHandle *sh)
{
}

bool
_LSUnregisterCommon(LSHandle *sh,
                    bool flush_and_send_shutdown,
                    void *call_ret_addr,
                    LSError *lserror)
{
    if (!flush_and_send_shutdown && call_ret_addr && lserror)
    {
        if (&mvar_priv_sh == sh)
        {
            mvar_private_detached++;
        }
        else if (&mvar_publ_sh == sh)
        {
            mvar_public_detached++;
        }
    }
    return true;
}

bool
_LSTransportGmainSetPriority(_LSTransport *transport,
                             int priority,
                             LSError *lserror)
{
    if (mvar_priority == priority && lserror)
    {
        if (transport == mvar_priv_trans)
        {
            mvar_priv_trans = (_LSTransport*)0x1234;
            mvar_priority_count++;
        }
        else if (transport == mvar_publ_trans)
        {
            mvar_publ_trans = (_LSTransport*)0x1234;
            mvar_priority_count++;
        }
    }
    return true;
}

void
_LSTransportGmainAttach(_LSTransport* transport,
                        GMainContext* context)
{
    if (mvar_context == context)
    {
        if (transport == mvar_priv_trans)
        {
            mvar_priv_trans = (_LSTransport*)0x1234;
            mvar_attach_count++;
        }
        else if (transport == mvar_publ_trans)
        {
            mvar_publ_trans = (_LSTransport*)0x1234;
            mvar_attach_count++;
        }
    }
}

/* Test suite *****************************************************************/

/* NOTE: mainloop.c contains many deprecated functions. No tests were written
 * for those functions.
 */
int
main(int argc, char *argv[])
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/luna-service2/LSMainAttachDetachPositive",
                     test_LSMainAttachDetachPositive);

    return g_test_run();
}

