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
#include <payload.hpp>


TEST(TestJSONPayload, JSONPayloadGetTest)
{
    std::string payload = R"json({
"nullValue":null,
"objectValue":{},
"boolValue":false,
"intValue":1234,
"stringValue":"Test string",
"doubleValue":42.5,
"arrayValue":["string", 789, true, null]
})json";

    LS::JSONPayload jp(payload);
    ASSERT_TRUE(jp.isValid());
    ASSERT_EQ(std::size_t{7}, jp.size());

    pbnjson::JValue nullTest = pbnjson::Object();
    EXPECT_TRUE(jp.get("nullValue", nullTest));
    EXPECT_TRUE(nullTest.isNull());

    pbnjson::JValue objectTest;
    EXPECT_TRUE(jp.get("objectValue", objectTest));
    EXPECT_TRUE(objectTest.isObject());
    EXPECT_FALSE(objectTest.isNull());
    EXPECT_EQ(ssize_t{0}, objectTest.objectSize());

    pbnjson::JValue arrayTest = pbnjson::Object();
    EXPECT_TRUE(jp.get("arrayValue", arrayTest));
    EXPECT_TRUE(arrayTest.isArray());
    EXPECT_EQ(ssize_t{4}, arrayTest.arraySize());

    bool boolTest = true;
    EXPECT_TRUE(jp.get("boolValue", boolTest));
    EXPECT_FALSE(boolTest);

    int32_t intTest{0};
    EXPECT_TRUE(jp.get("intValue", intTest));
    EXPECT_EQ(1234, intTest);

    double doubleTest{0.0};
    EXPECT_TRUE(jp.get("doubleValue", doubleTest));
    EXPECT_DOUBLE_EQ(42.5, doubleTest);

    std::string stringTest;
    EXPECT_TRUE(jp.get("stringValue", stringTest));
    EXPECT_EQ(std::string("Test string"), stringTest);
}

TEST(TestJSONPayload, JSONPayloadSetTest)
{
    LS::JSONPayload jp;
    ASSERT_TRUE(jp.isValid());
    ASSERT_EQ(std::size_t{0}, jp.size());

    pbnjson::JValue nullValue;
    EXPECT_TRUE(jp.set("nullValue", nullValue));
    pbnjson::JValue objValue = pbnjson::Object();
    EXPECT_TRUE(jp.set("objectValue", objValue));
    pbnjson::JValue arrayValue = pbnjson::Array();
    EXPECT_TRUE(jp.set("arrayValue", arrayValue));
    EXPECT_TRUE(jp.set("boolValue", false));
    EXPECT_TRUE(jp.set("intValue", 1234));
    EXPECT_TRUE(jp.set("doubleValue", 42.5));
    EXPECT_TRUE(jp.set("stringValue", std::string("Test string")));

    EXPECT_EQ(std::size_t{7}, jp.size());

    pbnjson::JValue nullTest = pbnjson::Object();
    EXPECT_TRUE(jp.get("nullValue", nullTest));
    EXPECT_TRUE(nullTest.isNull());

    pbnjson::JValue objectTest;
    EXPECT_TRUE(jp.get("objectValue", objectTest));
    EXPECT_TRUE(objectTest.isObject());
    EXPECT_FALSE(objectTest.isNull());
    EXPECT_EQ(ssize_t{0}, objectTest.objectSize());

    pbnjson::JValue arrayTest = pbnjson::Object();
    EXPECT_TRUE(jp.get("arrayValue", arrayTest));
    EXPECT_TRUE(arrayTest.isArray());
    EXPECT_EQ(ssize_t{0}, arrayTest.arraySize());

    bool boolTest = true;
    EXPECT_TRUE(jp.get("boolValue", boolTest));
    EXPECT_FALSE(boolTest);

    int32_t intTest{0};
    EXPECT_TRUE(jp.get("intValue", intTest));
    EXPECT_EQ(1234, intTest);

    double doubleTest{0.0};
    EXPECT_TRUE(jp.get("doubleValue", doubleTest));
    EXPECT_DOUBLE_EQ(42.5, doubleTest);

    std::string stringTest;
    EXPECT_TRUE(jp.get("stringValue", stringTest));
    EXPECT_EQ(std::string("Test string"), stringTest);
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
