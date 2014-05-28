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
#include <boost/scope_exit.hpp>
#include <glib.h>
#include <thread>
#include "util.hpp"

using namespace std;
using namespace pbnjson;


TEST(CategoryNotification, First)
{
    typedef vector<string> NotificationsT;
    NotificationsT notifications;

    // Start background main loop
    auto context = mk_ptr(g_main_context_new(), g_main_context_unref);

    // Register a watch service to collect notifications
    struct Watch
    {
        static bool callback(LSHandle *sh, LSMessage *reply, void *ctx)
        {
            NotificationsT &notifications = *static_cast<NotificationsT *>(ctx);
            notifications.push_back(LSMessageGetPayload(reply));
            return true;
        }
    };

    auto watch = LS::registerService("a.b.watch");
    watch.attachToLoop(context.get());

    auto call = watch.callMultiReply("luna://com.palm.bus/signal/registerServiceCategory",
                                     "{\"serviceName\": \"com.palm.A\"}",
                                     Watch::callback, &notifications);
    BOOST_SCOPE_EXIT((&call)) {
        call.cancel();
    } BOOST_SCOPE_EXIT_END

    process_context(context.get());

    // Register and kick-off watched service
    struct A
    {
        static bool callback(LSHandle *sh, LSMessage *msg, void *ctxt)
        {
            return true;
        }
    };

    auto a = LS::registerService("com.palm.A");
    a.attachToLoop(context.get());

    // Register part of /category1
    static LSMethod methods[] =
    {
        { "bar", A::callback },
        { "baz", A::callback },
        { nullptr },
    };
    a.registerCategory("/category1", methods, nullptr, nullptr);

    // Register another part of /category1
    static LSMethod methods2[] =
    {
        { "bar2", A::callback },
        { "baz2", A::callback },
        { nullptr }
    };
    a.registerCategoryAppend("/category1", methods2, nullptr);

    // Register /category2
    static LSMethod methods3[] =
    {
        { "foo", A::callback },
        { "bar", A::callback },
        { nullptr }
    };
    a.registerCategory("/category2", methods3, nullptr, nullptr);

    process_context(context.get(), 100);

    ASSERT_EQ(4, notifications.size());

    EXPECT_EQ(JRef::object(), fromJson(notifications[0]));

    auto ref1 = JRef{{"/category1", JRef::array({"baz","bar"})}};
    EXPECT_EQ(ref1, fromJson(notifications[1]));

    auto ref2 = JRef{{"/category1", JRef::array({"baz","bar", "baz2", "bar2"})}};
    EXPECT_EQ(ref2, fromJson(notifications[2]));

    auto ref3 = JRef{{"/category1", JRef::array({"baz","bar", "baz2", "bar2"})},
                     {"/category2", JRef::array({"bar","foo"})}};
    EXPECT_EQ(ref3, fromJson(notifications[3]));
}
