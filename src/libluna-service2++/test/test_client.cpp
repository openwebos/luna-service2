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
#include <list>
#include <thread>
#include <chrono>
#include "util.hpp"

using namespace std;

TEST(TestClient, RegisterService)
{
    // TO-DO: Test category registration with new method tables
    const char *service_name = "com.palm.test_client";

    LS::Handle srv;

    EXPECT_NO_THROW(srv = LS::registerService(service_name));
    EXPECT_THROW(LS::registerService(service_name), LS::Error);

    EXPECT_STREQ(srv.getName(), service_name);
    EXPECT_NO_THROW(srv.registerCategory("/test_cat", nullptr, nullptr, nullptr));
}

TEST(TestClient, RegisterPalmService)
{
    const char *service_name = "com.palm.test_client2";

    LS::PalmService srv;

    EXPECT_NO_THROW(srv = LS::registerPalmService(service_name));

    // Both public and private services are registered
    EXPECT_THROW(LS::registerPalmService(service_name), LS::Error);
    EXPECT_THROW(LS::registerService(service_name), LS::Error);
    EXPECT_THROW(LS::registerService(service_name, true), LS::Error);

    EXPECT_STREQ(srv.getPrivateHandle().getName(), service_name);
    EXPECT_STREQ(srv.getPublicHandle().getName(), service_name);

    EXPECT_NO_THROW(srv.registerCategory("/test_cat", nullptr, nullptr, nullptr));
}

TEST(TestClient, Mainloop)
{
    const char *service_name = "com.palm.test_client3";

    GMainLoop *main_loop = g_main_loop_new(nullptr, false);

    LS::Handle srv = LS::registerService(service_name);
    EXPECT_NO_THROW(srv.attachToLoop(main_loop));
    EXPECT_NO_THROW(srv.detach());

    srv = LS::registerService(service_name);
    EXPECT_NO_THROW(srv.attachToLoop(g_main_loop_get_context(main_loop)));
    EXPECT_NO_THROW(srv.setPriority(5));
    EXPECT_NO_THROW(srv.detach());

    LS::PalmService plmsrv = LS::registerPalmService(service_name);
    EXPECT_NO_THROW(plmsrv.attachToLoop(g_main_loop_get_context(main_loop)));
    EXPECT_NO_THROW(plmsrv.setPriority(5));
    EXPECT_NO_THROW(plmsrv.getPrivateHandle().detach());
    EXPECT_NO_THROW(plmsrv.getPublicHandle().detach());
}

TEST(TestClient, BHV_7106_CallTimeoutOverlapExplicitContext)
{
    // boost probability of race and overlap
    for (size_t n = 0; n < 10; ++n)
    {
        GMainContext *main_ctx = g_main_context_new();
        GMainLoop *main_loop = g_main_loop_new(main_ctx, false);
        ASSERT_NE(nullptr, main_loop);
        OnDescope descope_loop { [&] {
            g_main_loop_unref(main_loop);
            g_main_context_unref(main_ctx);
        }};

        LS::Handle srv;
        ASSERT_NO_THROW({ srv = LS::registerService("com.palm.test_client"); });
        EXPECT_NO_THROW({ srv.attachToLoop(main_loop); });

        LS::Call call = srv.callOneReply("luna://com.palm.test_client/foo", "{}");

        GTimeout timeout {50, [&] { g_main_loop_quit(main_loop); return FALSE; }};
        timeout.attach(main_ctx);

        call.setTimeout(50);

        // run the race between call-cancel timeout and main-loop timeout
        g_main_loop_run(main_loop);

        srv = {}; // unregister so call-cancel timeout shouldn't be valid anymor

        // next iteration will fire outstanding call-cancel timeout
    }
}

TEST(TestClient, BHV_7106_CallTimeoutOverlapDefaultContext)
{
    // boost probability of race and overlap
    for (size_t n = 0; n < 10; ++n)
    {
        GMainLoop *main_loop = g_main_loop_new(nullptr, false);
        ASSERT_NE(nullptr, main_loop);
        OnDescope descope_loop { [&] {
            g_main_loop_unref(main_loop);
        }};

        LS::Handle srv;
        ASSERT_NO_THROW({ srv = LS::registerService("com.palm.test_client"); });
        EXPECT_NO_THROW({ srv.attachToLoop(main_loop); });

        LS::Call call = srv.callOneReply("luna://com.palm.test_client/foo", "{}");

        GTimeout timeout {50, [&] { g_main_loop_quit(main_loop); return FALSE; }};
        timeout.attach(g_main_loop_get_context(main_loop));

        call.setTimeout(50);

        // run the race between call-cancel timeout and main-loop timeout
        g_main_loop_run(main_loop);

        srv = {}; // unregister so call-cancel timeout shouldn't be valid anymor

        // next iteration will fire outstanding call-cancel timeout
    }
}

namespace {

int call_count = 0;

bool onSignalCallback(LSHandle *sh, LSMessage *reply, void *ctx)
{
    ++call_count;

    return true;
}

} //namespace;

TEST(TestClient, Signals)
{
    auto context = mk_ptr(g_main_context_new(), g_main_context_unref);

    LS::Handle provider = LS::registerService("com.palm.test_signal_provider");
    provider.attachToLoop(context.get());

    LS::Handle receiver = LS::registerService("com.palm.test_signal_receiver");
    receiver.attachToLoop(context.get());

    LS::Call signal;

    EXPECT_NO_THROW(signal = receiver.callSignal("/test", "activated", onSignalCallback, nullptr));
    process_context(context.get(), 100);
    // Hub returns registration response
    EXPECT_EQ(call_count, 1);

    EXPECT_NO_THROW(provider.sendSignal("luna://com.palm.test_signal_receiver/test/activated", "{}"));
    process_context(context.get(), 100);
    EXPECT_EQ(call_count, 2);

    EXPECT_NO_THROW(signal.cancel());
    process_context(context.get(), 100);
    EXPECT_NO_THROW(provider.sendSignal("luna://com.palm.test_signal_receiver/test/activated", "{}"));
    process_context(context.get(), 100);
    EXPECT_EQ(call_count, 2);
}

TEST(TestClient, ServerStatus)
{
    bool is_active = false;

    LS::ServerStatusCallback statusCallback = [&](bool isact)
    {
        is_active = isact;

        return true;
    };

    auto context = mk_ptr(g_main_context_new(), g_main_context_unref);

    LS::Handle listener = LS::registerService("com.palm.test_status_listener");
    listener.attachToLoop(context.get());

    LS::ServerStatus status;
    EXPECT_NO_THROW(status = listener.registerServerStatus("com.palm.test_status_server", statusCallback));
    process_context(context.get(), 100);
    EXPECT_FALSE(is_active);

    LS::Handle server = LS::registerService("com.palm.test_status_server");
    server.attachToLoop(context.get());
    process_context(context.get(), 100);
    EXPECT_TRUE(is_active);

    server.detach();
    process_context(context.get(), 100);
    EXPECT_FALSE(is_active);
}
