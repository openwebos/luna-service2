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

#include <pbnjson.hpp>

#include "luna-service2/lunaservice.hpp"
#include "luna-service2/lunaservice-meta.h"

#include <gtest/gtest.h>
#include "util.hpp"

using namespace LS;
using namespace std;
using pbnjson::JValue;
using pbnjson::JSchemaFragment;


class SimpleService
    : public Service
{
public:
    bool cbPing(LSMessage& message);

    bool cbPong(LSMessage& message);

    template <typename... ParamsT>
    SimpleService(ParamsT&&... p) : Service(std::forward<ParamsT>(p)...) {}

    void regCategoryByMacro() {
        LS_CATEGORY_BEGIN(SimpleService, CategoryName)
            LS_CATEGORY_METHOD(cbPing)
            LS_CATEGORY_METHOD(cbPong)
        LS_CATEGORY_END
    }

    void regCategory(const char* name, LSMethodFlags customFlag = static_cast<LSMethodFlags>(0)) {
        LSMethod methodTable[] = {
            {"ping", &Service::methodWraper<SimpleService, &SimpleService::cbPing>, customFlag},
            {"pong", &Service::methodWraper<SimpleService, &SimpleService::cbPong>, customFlag},
            {0}
        };
        registerCategory(name, methodTable, nullptr, nullptr);
    }
};


class TestCategory
    : public ::testing::Test
{
protected:
    SimpleService sh, sh_client;
    GMainLoop *main_loop;

private:
    bool done; // still waiting

    virtual void SetUp()
    {
        done = false;
        ping = [&](LSMessage *) { finish(); return false; };
        pong = [&](LSMessage *) { finish(); return false; };

        main_loop = g_main_loop_new(nullptr, false);

        LS::Error e;
        ASSERT_NO_THROW({ sh = SimpleService(LS::registerService("com.palm.test")); });
        ASSERT_NO_THROW({ sh.attachToLoop(main_loop); });

        ASSERT_NO_THROW({ sh_client = SimpleService(""); });
        ASSERT_NO_THROW({ sh_client.attachToLoop(main_loop); });
    }

    virtual void TearDown()
    {
        LS::Error e;
        ASSERT_NO_THROW({ sh = SimpleService(); });
        ASSERT_NO_THROW({ sh_client = SimpleService(); });
        g_main_loop_unref(main_loop);
    }

protected:

    void finish(bool done = true)
    { this->done = done; }

    void wait()
    {
        auto ctx = g_main_loop_get_context(main_loop);

        while (!done)
        { (void) g_main_context_iteration(ctx, true); }
        finish(false);
    }

public:
    static function<bool(LSMessage *message)> ping, pong;
};

function<bool(LSMessage *message)> TestCategory::ping, TestCategory::pong;

bool SimpleService::cbPing(LSMessage& message)
{
    return TestCategory::ping(&message);
}

bool SimpleService::cbPong(LSMessage& message)
{
    return TestCategory::pong(&message);
}

TEST_F(TestCategory, DummyRegister)
{
    ASSERT_NO_THROW({ sh.regCategory("/"); });
}

TEST_F(TestCategory, UnregisteredSet)
{
    EXPECT_THROW({ sh.setCategoryData("/", this); }, LS::Error);
    EXPECT_THROW({ sh.setCategoryDescription("/", jnull()); }, LS::Error);
}

TEST_F(TestCategory, SetDescription)
{
    JRef description {
        { "methods", {
            { "ping", {
                { "type", "object" },
                { "description", "simple ping" },
                { "additionalProperties", false },
            }},
        }},
    };

    ASSERT_NO_THROW({ sh.regCategory("/"); });
    EXPECT_NO_THROW({ sh.setCategoryDescription("/", description.get()); });

    // Actually we should to check that effect of prev setting disappeared
    // without any leaks. But at least we'll test that it doesn't fall.
    JRef description2 {
        { "methods", {
            { "ping", {
                { "type", "object" },
                { "description", "simple ping" },
                { "additionalProperties", false },
            }},
            { "pong", {
                { "type", "object" },
                { "description", "simple ping" },
                { "additionalProperties", false },
            }},
        }},
    };
    EXPECT_NO_THROW({ sh.setCategoryDescription("/", description2.get()); });
}


TEST_F(TestCategory, BasicScenario)
{
    LS::Error e;
    LSMessageToken token;
    bool havePong = false, havePing = false;

    // call to bare service (even without categories)
    pong = [&](LSMessage *m) {
        finish();
        havePong = true;
        auto response = fromJson(LSMessageGetPayload(m));
        EXPECT_EQ(JValue(false), response["returnValue"]);
        EXPECT_EQ(JValue("Unknown method \"ping\" for category \"/\""), response["errorText"]) << toJson(response);
        return true;
    };

    EXPECT_TRUE(
        LSCallOneReply(
            sh_client.get(), "luna://com.palm.test/ping", "{}",
            [](LSHandle* h, LSMessage* m, void* ctx) { return pong(m); },
            this, &token,
            e.get()
        )
    ) << e.what();
    wait();
    ASSERT_TRUE(havePong);

    ASSERT_NO_THROW({ sh.regCategory("/"); });

    // call complete service for /ping
    havePing = havePong = false;
    ping = [&](LSMessage *m) {
        finish();
        havePing = true;
        LS::Error e;
        EXPECT_TRUE(LSMessageRespond(m, "{\"returnValue\":true, \"answer\":42}", e.get())) << e.what();
        return true;
    };
    pong = [&](LSMessage *m) {
        finish();
        havePong = true;
        auto response = fromJson(LSMessageGetPayload(m));
        EXPECT_EQ(JValue(true), response["returnValue"]);
        EXPECT_EQ(JValue(42), response["answer"]);
        return true;
    };

    EXPECT_TRUE(
        LSCallOneReply(
            sh_client.get(), "luna://com.palm.test/ping", "{}",
            [](LSHandle* h, LSMessage* m, void* ctx) { return pong(m); },
            this, &token,
            e.get()
        )
    ) << e.what();
    wait();
    EXPECT_TRUE(havePing);
    wait();
    EXPECT_TRUE(havePong);
}

TEST_F(TestCategory, Introspection)
{
    ASSERT_NO_THROW({ sh.regCategory("/"); });

    JRef description {
        { "methods", {
            { "ping", {
                { "type", "object" },
                { "description", "simple ping" },
                { "additionalProperties", false },
            }},
        }},
    };

    ASSERT_NO_THROW({ sh.setCategoryDescription("/", description.get()); });

    // TODO: call for introspection
}

TEST_F(TestCategory, DISABLED_Validation)
{
    LS::Error e;
    LSMessageToken token;

    ASSERT_NO_THROW({ sh.regCategory("/", LUNA_METHOD_FLAG_VALIDATE_IN); });

    JRef description {
        { "methods", {
            { "ping", {
                { "type", "object" },
                { "description", "simple ping" },
                { "additionalProperties", false },
            }},
        }},
    };

    ASSERT_NO_THROW({ sh.setCategoryDescription( "/", description.get()); });

    bool havePong = false, havePing = false;
    ping = [&](LSMessage *m) {
        finish();
        havePing = true;
        auto params = fromJson(LSMessageGetPayload(m));
        EXPECT_TRUE( params.isObject() );
        LS::Error e;
        EXPECT_TRUE(LSMessageRespond(m, "{\"returnValue\":true, \"answer\":42}", e.get())) << e.what();
        return true;
    };
    pong = [&](LSMessage *m) {
        finish();
        havePong = true;
        auto response = fromJson(LSMessageGetPayload(m));
        EXPECT_EQ(JRef(false), response["returnValue"]);
        return true;
    };
    EXPECT_TRUE(
        LSCallOneReply(
            sh_client.get(),
            "luna://com.palm.test/ping", "{\"wrong\":42}",
            [](LSHandle* h, LSMessage* m, void* ctx) { return pong(m); },
            this,
            &token,
            e.get()
        )
    ) << e.what();

    wait();
    EXPECT_FALSE(havePing);
    if (havePing) wait();
    EXPECT_TRUE(havePong);

    havePong = havePing = false;

    pong = [&](LSMessage *m) {
        finish();
        havePong = true;
        auto response = fromJson(LSMessageGetPayload(m));
        EXPECT_EQ(JRef(true), response["returnValue"]);
        EXPECT_EQ(JRef(42), response["answer"]);
        return true;
    };

    EXPECT_TRUE(
        LSCallOneReply(
            sh_client.get(), "luna://com.palm.test/ping", "{}",
            [](LSHandle* h, LSMessage* m, void* ctx) { return pong(m); },
            this, &token,
            e.get()
        )
    ) << e.what();

    wait();
    EXPECT_TRUE(havePing);
    wait();
    EXPECT_TRUE(havePong);
}
