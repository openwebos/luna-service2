// @@@LICENSE
//
//      Copyright (c) 2014 LG Electronics, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// LICENSE@@@

#include <gtest/gtest.h>
#include <luna-service2/lunaservice.hpp>
#include "util.hpp"

#include <thread>
#include <chrono>
#include <ctime>


namespace
{

#define SIMPLE_URI "palm://com.palm.test_call_service/testCalls/simpleCall"
#define TIMEOUT_URI "palm://com.palm.test_call_service/testCalls/timeoutCall"
#define SUBSCRIBE_URI "palm://com.palm.test_call_service/testCalls/subscribeCall"

class CallTest : public ::testing::Test
{
protected:

    CallTest():
        _mainloop{nullptr},
        _call{nullptr},
        _resultFlag{NOT_SET}
    {
    }

    virtual void SetUp()
    {
        LS::Error error;
        _mainloop = g_main_loop_new(nullptr, FALSE);
        ASSERT_NE(nullptr, _mainloop);
        ASSERT_NO_THROW(_service = LS::registerService("com.palm.test_call"));
        ASSERT_NO_THROW(_service.attachToLoop(_mainloop));
    }

    virtual void TearDown()
    {
        g_main_loop_unref(_mainloop);
    }

    GMainLoop * _mainloop;
    LS::Handle _service;
    LS::Call * _call;

    enum ResultFlag
    {
        NOT_SET,
        ON_REPLY,
        ON_TIMEOUT,
        ON_MAINLOOP_FAILURE
    };

    ResultFlag _resultFlag;

    static bool onReplyCB(LSHandle * sh, LSMessage * reply, void * context)
    {
        if (reply)
        {
            (static_cast<CallTest *>(context))->_resultFlag = ON_REPLY;
        }
        g_main_loop_quit((static_cast<CallTest *>(context))->_mainloop);
        return true;
    }

    static gboolean onTimeoutSetCB(gpointer context)
    {
        (static_cast<CallTest *>(context))->_call->continueWith(onReplyCB, context);
        return FALSE;
    }

    static gboolean onTimeoutCallWithCB(gpointer context)
    {
        CallTest * callTest = static_cast<CallTest *>(context);
        *callTest->_call = callTest->_service.callOneReply(SIMPLE_URI, "{}", onReplyCB, context);
        return FALSE;
    }

    static gboolean onHangingCB(gpointer context)
    {
        (static_cast<CallTest *>(context))->_resultFlag = ON_MAINLOOP_FAILURE;
        g_main_loop_quit((static_cast<CallTest *>(context))->_mainloop);
        return FALSE;
    }

    static gboolean onTimeoutCB(gpointer context)
    {
        g_main_loop_quit((static_cast<CallTest *>(context))->_mainloop);
        return FALSE;
    }

};

// Tests LS::Call basic call
TEST_F(CallTest, BasicCall)
{
    LS::Call call;
    ASSERT_NO_THROW(call = _service.callOneReply(SIMPLE_URI, "{}"));
}

// Tests LS::Call throw exception if LSCallXXXX fails
TEST_F(CallTest, ExceptionOnInvalidPayload)
{
    ASSERT_THROW(_service.callOneReply(SIMPLE_URI, ""), LS::Error);
}

// Tests LS::Call throw exception if LSCallXXXX fails
TEST_F(CallTest, ExceptionOnInvalidHandle)
{
    LS::Handle service;
    ASSERT_THROW(service.callOneReply(SIMPLE_URI, "{}"), LS::Error);
}

// Tests set reply callback before main loop
TEST_F(CallTest, SetReplyCBBeforeLoop)
{
    LS::Call call = _service.callOneReply(SIMPLE_URI, "{}");
    call.continueWith(onReplyCB, this);
    GTimeout hangingCB{1000, [this]{return onHangingCB(this);}};
    hangingCB.attach(g_main_loop_get_context(_mainloop));
    g_main_loop_run(_mainloop);
    ASSERT_FALSE(ON_MAINLOOP_FAILURE == _resultFlag) << "Main loop quit condition failed - loop not finished in time";
    ASSERT_EQ(ON_REPLY, _resultFlag);
}

// Tests set reply callback after loop
TEST_F(CallTest, SetReplyCBAfterLoop)
{
    LS::Call call = _service.callOneReply(SIMPLE_URI, "{}");
    _call = &call;
    GTimeout setCB{100, [this]{return onTimeoutSetCB(this);}};
    setCB.attach(g_main_loop_get_context(_mainloop));
    GTimeout hangingCB{1000, [this]{return onHangingCB(this);}};
    hangingCB.attach(g_main_loop_get_context(_mainloop));
    g_main_loop_run(_mainloop);
    ASSERT_FALSE(ON_MAINLOOP_FAILURE == _resultFlag) << "Main loop quit condition failed - loop not finished in time";
    ASSERT_EQ(ON_REPLY, _resultFlag);
}

// Tests calling with callback before main loop started
TEST_F(CallTest, CallCBBeforeLoop)
{
    LS::Call call = _service.callOneReply(SIMPLE_URI, "{}", onReplyCB, this);
    GTimeout hangingCB{1000, [this]{return onHangingCB(this);}};
    hangingCB.attach(g_main_loop_get_context(_mainloop));
    g_main_loop_run(_mainloop);
    ASSERT_FALSE(ON_MAINLOOP_FAILURE == _resultFlag) << "Main loop quit condition failed - loop not finished in time";
    ASSERT_EQ(ON_REPLY, _resultFlag);
}

// Tests calling with callback after main loop started
TEST_F(CallTest, CallCBAfterLoop)
{
    LS::Call call;
    _call = &call;
    GTimeout callWithCB{100, [this]{return onTimeoutCallWithCB(this);}};
    callWithCB.attach(g_main_loop_get_context(_mainloop));
    GTimeout hangingCB{1000, [this]{return onHangingCB(this);}};
    hangingCB.attach(g_main_loop_get_context(_mainloop));
    g_main_loop_run(_mainloop);
    ASSERT_FALSE(ON_MAINLOOP_FAILURE == _resultFlag) << "Main loop quit condition failed - loop not finished in time";
    ASSERT_EQ(ON_REPLY, _resultFlag);
}

// Tests call timeout
TEST_F(CallTest, CallTimeout)
{
    LS::Call call = _service.callOneReply(TIMEOUT_URI, R"({"timeout": 100})", onReplyCB, this);
    call.setTimeout(200);
    GTimeout hangingCB{1000, [this]{return onHangingCB(this);}};
    hangingCB.attach(g_main_loop_get_context(_mainloop));
    g_main_loop_run(_mainloop);
    ASSERT_FALSE(ON_MAINLOOP_FAILURE == _resultFlag) << "Main loop quit condition failed - loop not finished in time";
    ASSERT_EQ(ON_REPLY, _resultFlag);
}

// Tests call timeout expiration
TEST_F(CallTest, CallTimeoutExpiration)
{
    LS::Call call = _service.callOneReply(TIMEOUT_URI, R"({"timeout": 300})", onReplyCB, this);
    call.setTimeout(150);
    _resultFlag = ON_TIMEOUT;
    GTimeout hangingCB{1000, [this]{return onHangingCB(this);}};
    hangingCB.attach(g_main_loop_get_context(_mainloop));
    GTimeout timeoutCB{500, [this]{return onTimeoutCB(this);}};
    timeoutCB.attach(g_main_loop_get_context(_mainloop));
    g_main_loop_run(_mainloop);
    ASSERT_FALSE(ON_MAINLOOP_FAILURE == _resultFlag) << "Main loop quit condition failed - loop not finished in time";
    ASSERT_EQ(ON_TIMEOUT, _resultFlag);
}

// Tests get interface
TEST_F(CallTest, MainLoopGet)
{
    LS::Call call = _service.callMultiReply(SUBSCRIBE_URI, R"({"subscribe": true, "timeout": 100})");
    auto reply = call.get();
    ASSERT_TRUE(bool(reply));
    reply = call.get();
    ASSERT_TRUE(bool(reply));
}

// Tests get interface with timeout (wait failed)
TEST_F(CallTest, MainLoopGetTimeoutFail)
{
    LS::Call call = _service.callMultiReply(TIMEOUT_URI, R"({"subscribe": true, "timeout": 300})");
    auto reply = call.get(150);
    ASSERT_FALSE(bool(reply));
    reply = call.get();
    ASSERT_TRUE(bool(reply));
}

// Tests get interface with timeout (wait succeeded)
TEST_F(CallTest, MainLoopGetTimeoutSuccess)
{
    LS::Call call = _service.callMultiReply(TIMEOUT_URI, R"({"subscribe": true, "timeout": 200})");
    auto reply = call.get(250);
    ASSERT_TRUE(bool(reply));
}

struct CallTimeoutCallbacks
{
    static bool stopOnceCB_LS(LSHandle * sh, LSMessage * reply, void * context)
    {
        g_main_loop_quit(static_cast<GMainLoop *>(context));
        return true;
    }
    static bool stopMultiCB_LS(LSHandle * sh, LSMessage * reply, void * context)
    {
        static int counter{0};
        ++counter;
        if (counter > 1)
        {
            g_main_loop_quit(static_cast<GMainLoop *>(context));
        }
        return true;
    }
    static gboolean stopCB_GLIB(gpointer context)
    {
        g_main_loop_quit(static_cast<GMainLoop *>(context));
        return FALSE;
    }
};

TEST(CallTimeoutTest, BHV_7106_CallTimeoutAfterUnregisterOneReply)
{
    GMainLoop *mainloop = g_main_loop_new(g_main_context_new(), FALSE);
    {
        LS::Handle service;
        ASSERT_NO_THROW(service = LS::registerService("com.palm.test_call"));
        ASSERT_NO_THROW(service.attachToLoop(mainloop));

        LS::Call call = service.callOneReply(TIMEOUT_URI, R"({"timeout": 50})",
            CallTimeoutCallbacks::stopOnceCB_LS, mainloop);
        call.setTimeout(100);
        g_main_loop_run(mainloop);
    }
    GSource *source = g_timeout_source_new(200);
    g_source_set_callback(source, CallTimeoutCallbacks::stopCB_GLIB, mainloop, nullptr);
    g_source_attach(source, g_main_loop_get_context(mainloop));
    g_main_loop_run(mainloop);
    g_main_context_unref(g_main_loop_get_context(mainloop));
    g_main_loop_unref(mainloop);
}

TEST(CallTimeoutTest, BHV_7106_CallTimeoutAfterUnregisterMultiReplyWithCancel)
{
    GMainLoop *mainloop = g_main_loop_new(g_main_context_new(), FALSE);
    {
        LS::Handle service;
        ASSERT_NO_THROW(service = LS::registerService("com.palm.test_call"));
        ASSERT_NO_THROW(service.attachToLoop(mainloop));

        LS::Call call = service.callMultiReply(
            SUBSCRIBE_URI, R"({"subscribe": true, "timeout": 50})", CallTimeoutCallbacks::stopMultiCB_LS, mainloop);
        call.setTimeout(100);
        g_main_loop_run(mainloop);
    }
    GSource *source = g_timeout_source_new(200);
    g_source_set_callback(source, CallTimeoutCallbacks::stopCB_GLIB, mainloop, nullptr);
    g_source_attach(source, g_main_loop_get_context(mainloop));
    g_main_loop_run(mainloop);
    g_main_context_unref(g_main_loop_get_context(mainloop));
    g_main_loop_unref(mainloop);
}

TEST(CallTimeoutTest, BHV_7106_CallTimeoutAfterUnregisterMultiReplyNoCancel)
{
    GMainLoop *mainloop = g_main_loop_new(g_main_context_new(), FALSE);
    {
        LS::Handle service;
        ASSERT_NO_THROW(service = LS::registerService("com.palm.test_call"));
        ASSERT_NO_THROW(service.attachToLoop(mainloop));

        LSMessageToken token;
        LSCall(service.get(), SUBSCRIBE_URI, R"({"subscribe": true, "timeout": 50})",
            CallTimeoutCallbacks::stopMultiCB_LS, mainloop, &token, LS::Error().get());
        LSCallSetTimeout(service.get(), token, 100, LS::Error().get());
        g_main_loop_run(mainloop);
    }
    GSource *source = g_timeout_source_new(200);
    g_source_set_callback(source, CallTimeoutCallbacks::stopCB_GLIB, mainloop, nullptr);
    g_source_attach(source, g_main_loop_get_context(mainloop));
    g_main_loop_run(mainloop);
    g_main_context_unref(g_main_loop_get_context(mainloop));
    g_main_loop_unref(mainloop);
}

}  // anonymous namespace

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

