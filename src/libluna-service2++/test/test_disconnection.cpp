/* @@@LICENSE
*
*      Copyright (c) 2014 LG Electronics, Inc.
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

#include <atomic>
#include <iostream>
#include <thread>

#include <gtest/gtest.h>
#include <luna-service2/lunaservice.hpp>

using namespace std;

atomic_uint g_disc_count{0};

#define TEST_CLASS_NAME "TestService"

class TestService
{
public:
    TestService() : _mainloop{nullptr}
    {
        _mainloop = g_main_loop_new(nullptr, FALSE);
        _service = LS::registerService("com.palm.test_disconnection");

        LSMethod methods[] =
        {
            { "killFork", onKillFork },
            { "shutdown", onShutdown },
            { },
        };

        EXPECT_TRUE(LSSubscriptionSetCancelFunction(_service.get(), onDisconnect, nullptr, nullptr));

        _service.registerCategory("testCalls", methods, nullptr, nullptr);
        _service.setCategoryData("testCalls", this);
        _service.attachToLoop(_mainloop);
    }

    static bool onDisconnect(LSHandle *, LSMessage *, void *)
    {
        ++g_disc_count;
        return true;
    }

    static bool onKillFork(LSHandle *sh, LSMessage *request, void *)
    {
        uint pid;
        sscanf(LSMessageGetPayload(request), R"({"pid":%d})", &pid);

        EXPECT_TRUE(LSSubscriptionAdd(sh, "sub", request, nullptr));
        EXPECT_TRUE(0 == kill(pid, SIGKILL));
        return true;
    }

    static bool onShutdown(LSHandle *, LSMessage *, void *user_data)
    {
        TestService *self = static_cast<TestService *>(user_data);
        self->stop();
        return true;
    }

    void run()
    {
        g_main_loop_run(_mainloop);
    }

    void stop()
    {
        g_main_loop_quit(_mainloop);
    }

private:
    GMainLoop *_mainloop;
    LS::Handle _service;
};

void serviceFunc()
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

TEST(TestDiconnection, SubscriptionDisconnectCounter)
{
    const uint TRIES = 100;

    /* Make our fork to spawn copies and start service
    * to kill them all */
    if (!fork())
    {
        for (uint i = 0; i <= TRIES; ++i)
        {
            if (!fork())
            {
                auto context = mk_ptr(g_main_context_new(), g_main_context_unref);
                LS::Handle client = LS::registerService();
                client.attachToLoop(context.get());

                LS::Call call;
                if (TRIES != i)
                {
                    char payload[50];
                    sprintf(payload, R"({"pid":%d})", getpid());
                    call = client.callMultiReply("palm://com.palm.test_disconnection/testCalls/killFork", payload);
                }
                else
                {
                    call = client.callMultiReply("palm://com.palm.test_disconnection/testCalls/shutdown", "{}");
                }
                call.get();
            }
            else
            {
                int pid_status;
                wait(&pid_status);
            }
        }
        exit(0);
    }
    else
    {
        serviceFunc();

        ASSERT_EQ(TRIES, g_disc_count);
    }
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
