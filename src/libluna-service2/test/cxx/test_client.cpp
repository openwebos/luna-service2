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
    const char *service_name = "com.palm.test_client";

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
