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

#include "util.hpp"

#include <glib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

#include <iostream>
#include <string>
#include <chrono>
#include <thread>
#include <atomic>

#include <gtest/gtest.h>

#include <luna-service2/lunaservice.hpp>
#include <payload.hpp>

#define TEST_CLASS_NAME "TestService"
std::atomic_uint g_counter{0};

class TestService
{
public:
    TestService() : _postId{1}, _mainloop{nullptr}
    {
        _mainloop = g_main_loop_new(nullptr, FALSE);
        _service = LS::registerService("com.palm.test_subscription_service");

        LSMethod methods[] =
        {
            { "stopCall", onStop },
            { "subscribeCall", onRequest },
            { },
        };
        _service.registerCategory("testCalls", methods, nullptr, nullptr);
        _service.setCategoryData("testCalls", this);
        _service.attachToLoop(_mainloop);
        _sp.setServiceHandle(&_service);
    }

    ~TestService()
    {
        g_main_loop_unref(_mainloop);
    }

    bool handleRequest(LSMessage *request)
    {
        if (LSMessageIsSubscription(request))
        {
            LS::Message message{request};
            LS::JSONPayload json;
            json.set("class", TEST_CLASS_NAME);
            json.set("subscribed", _sp.subscribe(message));
            json.set("returnValue", true);
            message.respond(json.getJSONString().c_str());
        }
        return true;
    }

    void postUpdate()
    {
        _postId++;
        LS::JSONPayload json;
        json.set("id", _postId);
        _sp.post(json.getJSONString().c_str());
    }

    void run()
    {
        g_timeout_add(100, onPostTimeout, this);
        g_main_loop_run(_mainloop);
    }

    void stop()
    {
        g_timeout_add(100, onStopTimeout, this);
    }

    static bool onStop(LSHandle *sh, LSMessage *request, void *context)
    {
        TestService * ts = static_cast<TestService *>(context);
        ts->stop();
        return true;
    }

    static bool onRequest(LSHandle *sh, LSMessage *request, void *context)
    {
        TestService * ts = static_cast<TestService *>(context);
        ts->handleRequest(request);
        return true;
    }

    static gboolean onPostTimeout(gpointer context)
    {
        TestService * ts = static_cast<TestService *>(context);
        ts->postUpdate();
        return G_SOURCE_CONTINUE;
    }

    static gboolean onStopTimeout(gpointer context)
    {
        TestService * ts = static_cast<TestService *>(context);
        g_main_loop_quit(ts->_mainloop);
        return G_SOURCE_REMOVE;
    }

private:
    int32_t _postId;
    GMainLoop * _mainloop;
    LS::Handle _service;
    LS::SubscriptionPoint _sp;

};

void serviceThreadFunc()
{
    try
    {
        TestService ts;
        ts.run();
    }
    catch (std::exception &e)
    {
        FAIL() << "TestService exception: " << e.what();
    }
    catch (...)
    {
        FAIL();
    }
}

void clientThreadFunc()
{
    auto context = mk_ptr(g_main_context_new(), g_main_context_unref);
    LS::Handle client = LS::registerService();
    client.attachToLoop(context.get());

    LS::Call call = client.callMultiReply("palm://com.palm.test_subscription_service/testCalls/subscribeCall",
        R"({"subscribe":true})");
    auto reply = call.get();
    EXPECT_TRUE(bool(reply)) << "No response from test service";
    LS::JSONPayload replyJSON{reply.getPayload()};
    EXPECT_TRUE(replyJSON.isValid());
    bool returnValue = false, isSubscribed = false;
    EXPECT_TRUE(replyJSON.get("returnValue", returnValue));
    EXPECT_TRUE(returnValue);
    EXPECT_TRUE(replyJSON.get("subscribed", isSubscribed));
    EXPECT_TRUE(isSubscribed);
    std::string serviceClass;
    EXPECT_TRUE(replyJSON.get("class", serviceClass));
    EXPECT_EQ(std::string(TEST_CLASS_NAME), serviceClass);

    reply = call.get(200);
    EXPECT_TRUE(bool(reply)) << "No post from test service";
    LS::JSONPayload postJSON{reply.getPayload()};
    EXPECT_TRUE(postJSON.isValid());
    int32_t postId{0};
    EXPECT_TRUE(postJSON.get("id", postId));
    EXPECT_LE(1, postId);
    ++g_counter;

    call.cancel();
}

TEST(TestSubscriptionPoint, SubscriptionDisconnectTest)
{
    std::thread serviceThread{serviceThreadFunc};
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    auto context = mk_ptr(g_main_context_new(), g_main_context_unref);
    {
        LS::Handle client = LS::registerService();
        client.attachToLoop(context.get());

        LS::Call call = client.callMultiReply("palm://com.palm.test_subscription_service/testCalls/subscribeCall",
            R"({"subscribe":true})");

        auto reply = call.get();
        ASSERT_TRUE(bool(reply)) << "No response from test service";
        LS::JSONPayload replyJSON{reply.getPayload()};
        ASSERT_TRUE(replyJSON.isValid());
        bool returnValue = false, isSubscribed = false;
        ASSERT_TRUE(replyJSON.get("returnValue", returnValue));
        ASSERT_TRUE(returnValue);
        ASSERT_TRUE(replyJSON.get("subscribed", isSubscribed));
        ASSERT_TRUE(isSubscribed);
        std::string serviceClass;
        ASSERT_TRUE(replyJSON.get("class", serviceClass));
        ASSERT_EQ(std::string(TEST_CLASS_NAME), serviceClass);

        reply = call.get(800);
        ASSERT_TRUE(bool(reply)) << "No post from test service";
        LS::JSONPayload postJSON{reply.getPayload()};
        ASSERT_TRUE(postJSON.isValid());
        int32_t postId{0};
        ASSERT_TRUE(postJSON.get("id", postId));
        ASSERT_LE(1, postId);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    LS::Handle client = LS::registerService("com.palm.test_subscription_client");
    client.attachToLoop(context.get());

    LS::Call callStop = client.callOneReply("palm://com.palm.test_subscription_service/testCalls/stopCall", "{}");
    callStop.get(200);
    serviceThread.join();

}

TEST(TestSubscriptionPoint, SubscriptionCancelTest)
{
    std::thread serviceThread{serviceThreadFunc};
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    auto context = mk_ptr(g_main_context_new(), g_main_context_unref);
    LS::Handle client = LS::registerService("com.palm.test_subscription_client");
    client.attachToLoop(context.get());

    LS::Call call = client.callMultiReply("palm://com.palm.test_subscription_service/testCalls/subscribeCall",
        R"({"subscribe":true})");

    auto reply = call.get();
    ASSERT_TRUE(bool(reply)) << "No response from test service";
    LS::JSONPayload replyJSON{reply.getPayload()};
    ASSERT_TRUE(replyJSON.isValid());
    bool returnValue = false, isSubscribed = false;
    ASSERT_TRUE(replyJSON.get("returnValue", returnValue));
    ASSERT_TRUE(returnValue);
    ASSERT_TRUE(replyJSON.get("subscribed", isSubscribed));
    ASSERT_TRUE(isSubscribed);
    std::string serviceClass;
    ASSERT_TRUE(replyJSON.get("class", serviceClass));
    ASSERT_EQ(std::string(TEST_CLASS_NAME), serviceClass);

    reply = call.get(200);
    ASSERT_TRUE(bool(reply)) << "No post from test service";
    LS::JSONPayload postJSON{reply.getPayload()};
    ASSERT_TRUE(postJSON.isValid());
    int32_t postId{0};
    ASSERT_TRUE(postJSON.get("id", postId));
    ASSERT_LE(1, postId);

    call.cancel();

    call = client.callOneReply("palm://com.palm.test_subscription_service/testCalls/stopCall", "{}");
    call.get(200);
    serviceThread.join();
}

TEST(TestSubscriptionPoint, SubscriptionTestMultiClientTest)
{
    std::thread serviceThread{serviceThreadFunc};
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    std::thread client1{clientThreadFunc};
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    std::thread client2{clientThreadFunc};
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    std::thread client3{clientThreadFunc};

    client1.join();
    client2.join();
    client3.join();

    ASSERT_EQ(uint{3}, g_counter);
    GMainLoop * mainloop = g_main_loop_new(nullptr, FALSE);
    LS::Handle client = LS::registerService("com.palm.test_subscription_client");
    client.attachToLoop(mainloop);

    client.callOneReply("palm://com.palm.test_subscription_service/testCalls/stopCall", "{}");
    serviceThread.join();
    g_main_loop_unref(mainloop);
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
