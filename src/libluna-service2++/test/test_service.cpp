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

#include <functional>
#include <chrono>

#include <gtest/gtest.h>
#include <luna-service2/lunaservice.hpp>

#include "util.hpp"

using namespace std;

class TestService
    : public ::testing::Test
{
protected:
    GMainLoop *main_loop;
    function<bool(LSMessage *)> pong;

    static bool cbPong(LSHandle *, LSMessage *message, void *ctx)
    { return static_cast<TestService*>(ctx)->pong(message); }

    void loop(int ms = -1, GMainLoop *loop = nullptr)
    {
        auto ctx = g_main_loop_get_context(loop ? loop : main_loop);
        if (ms > 0)
        {
            using namespace std::chrono;
            auto start = steady_clock::now();
            while (true)
            {
                g_main_context_iteration(ctx, false);
                auto end = steady_clock::now();
                if (duration_cast<milliseconds>(end - start).count() > ms)
                    break;
                g_usleep(500);
            }
        }
        else if (ms < 0)
        {
            g_main_context_iteration(ctx, true);
        }

        // roll yet more while there is non-blocking actions
        while (g_main_context_iteration(ctx, false));
    }

private:
    void SetUp()
    {
        main_loop = g_main_loop_new(nullptr, false);

        pong = [&](LSMessage *) { return false; };
    }

    void TearDown()
    {
        g_main_loop_unref(main_loop);
    }
};

TEST_F(TestService, SimpleCall)
{
    LS::Error e;
    LS::Handle s, c;

    LSMessageToken token;
    bool havePong;

    ASSERT_NO_THROW({ s = LS::registerService("com.palm.test"); });
    ASSERT_NO_THROW({ s.attachToLoop(main_loop); });

    ASSERT_NO_THROW({ c = LS::registerService(); });
    ASSERT_NO_THROW({ c.attachToLoop(main_loop); });

    // let both services to interact with hub and settle down
    loop(100);

    havePong = false;
    pong = [&](LSMessage *m) {
        havePong = true;
        auto response = fromJson(LSMessageGetPayload(m));
        EXPECT_EQ(JRef(false), response["returnValue"]);
        EXPECT_EQ(JRef("Unknown method \"ping\" for category \"/\""), response["errorText"]);
        return true;
    };

    ASSERT_TRUE(LSCallOneReply(c.get(),
                               "luna://com.palm.test/ping", "{}",
                               cbPong, this, &token, e.get())) << e.what();

    // spin a bit for a response
    while (!havePong) loop();

    EXPECT_TRUE(havePong);
}

// BUG BHV-4681: no notification about call timeout
// enable and change if needed after resolving BHV-4681
TEST_F(TestService, DISABLED_CallTimeout)
{
    LS::Error e;
    LS::Handle s, c;

    LSMessageToken token;
    bool havePong;

    ASSERT_NO_THROW({ s = LS::registerService("com.palm.test"); });
    // do not attach to any loop (service is kinda hang)

    ASSERT_NO_THROW({ c = LS::registerService(); });
    ASSERT_NO_THROW({ c.attachToLoop(main_loop); });

    // let client to interact with hub and settle down
    loop(100);

    havePong = false;
    pong = [&](LSMessage *m) {
        havePong = true;
        auto response = fromJson(LSMessageGetPayload(m));
        EXPECT_EQ(JRef(false), response["returnValue"]);
        EXPECT_EQ(JRef("Unknown method \"ping\" for category \"/\""), response["errorText"]);
        return true;
    };

    ASSERT_TRUE(LSCallOneReply(c.get(),
                               "luna://com.palm.test/ping", "{}",
                               cbPong, this, &token, e.get())) << e.what();

    // set timeout
    ASSERT_TRUE(LSCallSetTimeout(c.get(), token, 250, e.get())) << e.what();

    // spin a loop for a 500ms (only sender side)
    loop(500);
    EXPECT_TRUE(havePong);
}

// BHV-4680: after register/unregister no error responses received "from" service
// enable once fixed
TEST_F(TestService, DISABLED_UnregisterConnected)
{
    LS::Error e;
    LS::Handle s, c;

    LSMessageToken token;
    bool havePong;

    ASSERT_NO_THROW({ s = LS::registerService("com.palm.test"); });
    ASSERT_NO_THROW({ s.attachToLoop(main_loop); });

    ASSERT_NO_THROW({ c = LS::registerService(); });
    ASSERT_NO_THROW({ c.attachToLoop(main_loop); });

    havePong = false;
    pong = [&](LSMessage *m) {
        havePong = true;
        auto response = fromJson(LSMessageGetPayload(m));
        EXPECT_EQ(JRef(false), response["returnValue"]);
        EXPECT_EQ(JRef("Unknown method \"ping\" for category \"/\""), response["errorText"]);
        return true;
    };

    ASSERT_TRUE(LSCallOneReply(c.get(),
                               "luna://com.palm.test/ping", "{}",
                               cbPong, this, &token, e.get())) << e.what();

    // wait for response
    loop(100);
    ASSERT_TRUE(havePong);

    ASSERT_NO_THROW({ s = LS::Handle(); }); // unregister

    // let service to settle down
    loop(100);

    havePong = false;

    pong = [&](LSMessage *m) {
        havePong = true;
        auto response = fromJson(LSMessageGetPayload(m));
        EXPECT_EQ(JRef(false), response["returnValue"]);
        EXPECT_EQ(JRef("Service does not exist: com.palm.test."), response["errorText"]);
        return true;
    };

    ASSERT_TRUE(LSCallOneReply(c.get(),
                               "luna://com.palm.test/ping", "{}",
                                cbPong, this,
                                &token, e.get())) << e.what();

    // there is a big chances to lose that message, so lets set timeout to re-send it
    loop(250);
    if (!havePong)
    {
        ASSERT_TRUE(LSCallOneReply(c.get(),
                                   "luna://com.palm.test/ping", "{}",
                                    cbPong, this,
                                    &token, e.get())) << e.what();
        loop(250); // wait for response
    }
    EXPECT_TRUE(havePong);
}

// enable once BHV-4680 will be fixed
TEST_F(TestService, DISABLED_UnregisterUnconnected)
{
    LS::Error e;
    LS::Handle s, c;

    LSMessageToken token;
    bool havePong;

    ASSERT_NO_THROW({ s = LS::registerService("com.palm.test"); });
    ASSERT_NO_THROW({ s.attachToLoop(main_loop); });

    ASSERT_NO_THROW({ c = LS::registerService(); });
    ASSERT_NO_THROW({ c.attachToLoop(main_loop); });

    // give some time for both sides to settle down
    loop(200);

    ASSERT_NO_THROW({ s = LS::Handle(); }); // unregister

    // let receiver to settle down
    loop(100);

    havePong = false;

    pong = [&](LSMessage *m) {
        havePong = true;
        auto response = fromJson(LSMessageGetPayload(m));
        EXPECT_EQ(JRef(false), response["returnValue"]);
        EXPECT_EQ(JRef("Service does not exist: com.palm.test."), response["errorText"]);
        return true;
    };

    ASSERT_TRUE(LSCallOneReply(c.get(),
                               "luna://com.palm.test/ping", "{\"no\":1}",
                               cbPong, this,
                               &token, e.get())) << e.what();

    // there is a big chances to lose that message, so lets set timeout to re-send it
    loop(250);
    if (!havePong)
    {
        ASSERT_TRUE(LSCallOneReply(c.get(),
                                   "luna://com.palm.test/ping", "{}",
                                    cbPong, this,
                                    &token, e.get())) << e.what();
        loop(250); // wait for response
    }
    EXPECT_TRUE(havePong);
}

TEST_F(TestService, ServiceMoveCtor)
{
    LS::Handle s1;
    EXPECT_FALSE( !!s1 );

    ASSERT_NO_THROW({ s1 = LS::registerService("com.palm.test"); });
    EXPECT_TRUE( !!s1 );

    EXPECT_NO_THROW({ LS::Handle s2 { std::move(s1) }; });
    EXPECT_FALSE( !!s1 );
}

TEST_F(TestService, ServiceMoveAssign)
{
    LS::Error e;
    LS::Handle s1, s2, s3;

    LSMessageToken token;
    bool havePong;

    ASSERT_NO_THROW({ s1 = LS::registerService("com.palm.test"); });
    ASSERT_NO_THROW({ s1.attachToLoop(main_loop); });
    EXPECT_TRUE( !!s1 );

    EXPECT_NO_THROW({ s2 = std::move(s1); });
    EXPECT_FALSE( !!s1 );
    EXPECT_TRUE( !!s2 );

    ASSERT_NO_THROW({ s1 = LS::registerService(); });
    ASSERT_NO_THROW({ s1.attachToLoop(main_loop); });

    EXPECT_NO_THROW({ s2 = std::move(s1); }); // overwrite s2
    EXPECT_FALSE( !!s1 );
    EXPECT_TRUE( !!s2 );

    // lets verify that original s2 was actually unregistered
    havePong = false;
    pong = [&](LSMessage *m) {
        havePong = true;
        auto response = fromJson(LSMessageGetPayload(m));
        EXPECT_EQ(JRef(false), response["returnValue"]);
        EXPECT_EQ(JRef("Service does not exist: com.palm.test."), response["errorText"]);
        return true;
    };

    ASSERT_TRUE(LSCallOneReply(s2.get(),
                               "luna://com.palm.test/ping", "{}",
                               cbPong, this, &token, e.get())) << e.what();

    // wait for response
    loop(200);
    // once BHV-4680 will be fixed we should do EXPECT_TRUE(havePong)
}
