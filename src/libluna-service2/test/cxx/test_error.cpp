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

TEST(TestError, DefaultCtor)
{
    LS::Error e;
    ASSERT_FALSE(e.isSet());
    EXPECT_EQ(0, e->error_code);
    EXPECT_EQ(nullptr, e->message);
    EXPECT_EQ(nullptr, e->file);
    EXPECT_EQ(0, e->line);
    EXPECT_EQ(nullptr, e->func);
}

TEST(TestError, MoveCtor)
{
    LS::Error e0;
    auto error_code = e0->error_code = 13;
    auto message = e0->message = g_strdup("Hello, world!");
    auto file = e0->file = __FILE__;
    auto line = e0->line = __LINE__;
    auto func = e0->func = "MoveCtor";
    ASSERT_TRUE(e0.isSet());

    LS::Error e1{std::move(e0)};
    ASSERT_FALSE(e0.isSet());
    EXPECT_EQ(error_code, e1->error_code);
    EXPECT_EQ(message, e1->message);
    EXPECT_EQ(file, e1->file);
    EXPECT_EQ(line, e1->line);
    EXPECT_EQ(func, e1->func);
}

TEST(TestError, MoveAssignment)
{
    LS::Error e0, e1;

    auto error_code = e0->error_code = 13;
    auto message = e0->message = g_strdup("Hello, world!");
    auto file = e0->file = __FILE__;
    auto line = e0->line = __LINE__;
    auto func = e0->func = "MoveAssignment";
    ASSERT_TRUE(e0.isSet());

    e1 = std::move(e0);
    ASSERT_FALSE(e0.isSet());
    EXPECT_EQ(error_code, e1->error_code);
    EXPECT_EQ(message, e1->message);
    EXPECT_EQ(file, e1->file);
    EXPECT_EQ(line, e1->line);
    EXPECT_EQ(func, e1->func);
}

TEST(TestError, Ostream)
{
    LS::Error e;
    e->error_code = 17;
    e->message = g_strdup("Forty-two");
    e->file = "test_error.cpp";
    e->line = 1234;
    e->func = "TestOstream";

    ostringstream oss;
    oss << e;
    EXPECT_EQ("LUNASERVICE ERROR 17: Forty-two (TestOstream @ test_error.cpp:1234)", oss.str());
}
