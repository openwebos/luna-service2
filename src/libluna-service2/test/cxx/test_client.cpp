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
#include <thread>
#include <chrono>

using namespace std;

#define RUN_IN_THREAD(x)                     \
do {                                         \
    thread trd([&](){ g_main_loop_run(x); });\
    trd.detach();                            \
} while (0)                                  \

TEST(TestClient, RegisterService)
{
    // TO-DO: Test category registration with new method tables
    const char *service_name = "com.palm.test_client";

    LS::Service srv;

    EXPECT_NO_THROW(srv = LS::registerService(service_name));
    EXPECT_THROW(LS::registerService(service_name), LS::Error);

    EXPECT_STREQ(srv.getName(), service_name);
    EXPECT_NO_THROW(srv.registerCategory("test_cat", nullptr, nullptr, nullptr));
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

    EXPECT_STREQ(srv.getPrivateConnection().getName(), service_name);
    EXPECT_STREQ(srv.getPublicConnection().getName(), service_name);

    EXPECT_NO_THROW(srv.registerCategory("test_cat", nullptr, nullptr, nullptr));
}

TEST(TestClient, Mainloop)
{
    const char *service_name = "com.palm.test_client3";

    GMainLoop *main_loop = g_main_loop_new(nullptr, false);

    LS::Service srv = LS::registerService(service_name);
    EXPECT_NO_THROW(srv.attachToLoop(main_loop));
    EXPECT_NO_THROW(srv.detach());

    srv = LS::registerService(service_name);
    EXPECT_NO_THROW(srv.attachToLoop(g_main_loop_get_context(main_loop)));
    EXPECT_NO_THROW(srv.setPriority(5));
    EXPECT_NO_THROW(srv.detach());

    LS::PalmService plmsrv = LS::registerPalmService(service_name);
    EXPECT_NO_THROW(plmsrv.attachToLoop(g_main_loop_get_context(main_loop)));
    EXPECT_NO_THROW(plmsrv.setPriority(5));
    EXPECT_NO_THROW(plmsrv.getPrivateConnection().detach());
    EXPECT_NO_THROW(plmsrv.getPublicConnection().detach());
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
    GMainLoop *provider_main_loop = g_main_loop_new(nullptr, false);
    RUN_IN_THREAD(provider_main_loop);

    GMainLoop *receiver_main_loop = g_main_loop_new(nullptr, false);
    RUN_IN_THREAD(receiver_main_loop);

    LS::Service provider = LS::registerService("com.palm.test_signal_provider");
    provider.attachToLoop(provider_main_loop);

    LS::Service receiver = LS::registerService("com.palm.test_signal_receiver");
    receiver.attachToLoop(receiver_main_loop);

    LS::Call signal;

    EXPECT_NO_THROW(signal = receiver.callSignal("/test", "activated", onSignalCallback, nullptr));
    this_thread::sleep_for(chrono::milliseconds(1));
    // Hub returns registration response
    EXPECT_EQ(call_count, 1);

    EXPECT_NO_THROW(provider.sendSignal("luna://com.palm.test_signal_receiver/test/activated", "{}"));
    this_thread::sleep_for(chrono::milliseconds(1));
    EXPECT_EQ(call_count, 2);

    EXPECT_NO_THROW(signal.cancel());
    EXPECT_NO_THROW(provider.sendSignal("luna://com.palm.test_signal_receiver/test/activated", "{}"));
    this_thread::sleep_for(chrono::milliseconds(1));
    EXPECT_EQ(call_count, 2);
}
