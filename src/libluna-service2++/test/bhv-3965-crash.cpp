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

using namespace std;

class TestEnvironment
    : public ::testing::Test
{
protected:
    LS::Error e;
    LSHandle *sh;
    GMainLoop *main_loop;

private:
    virtual void SetUp()
    {
        main_loop = g_main_loop_new(nullptr, false);

        ASSERT_TRUE(LSRegister("com.palm.test_client", &sh, e.get()));
        ASSERT_TRUE(LSGmainAttach(sh, main_loop, e.get()));
    }

    virtual void TearDown()
    {
        ASSERT_TRUE(LSUnregister(sh, e.get()));
        g_main_loop_unref(main_loop);
    }

};

namespace {

bool OnIntrospectionReply(LSHandle *, LSMessage *msg, void *)
{
    LSMessagePrint(msg, stdout);
    assert(!LSMessageIsHubErrorMessage(msg));
    return true;
}

} //namespace;

TEST_F(TestEnvironment, Unregister)
{
    LSMessageToken token;
    ASSERT_TRUE(LSCall(sh,
                       "luna://com.palm.test_service/test/foo",
                       "{}",
                       OnIntrospectionReply, nullptr, &token,
                       e.get()));

    g_main_context_iteration(g_main_loop_get_context(main_loop), true);
    g_main_context_iteration(g_main_loop_get_context(main_loop), true);
    g_main_context_iteration(g_main_loop_get_context(main_loop), true);
}

// vim: set et ts=4 sw=4:
