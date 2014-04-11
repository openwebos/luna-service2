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

using namespace std;

template <typename T, typename D>
std::unique_ptr<T, D> mk_ptr(T *t, D d)
{
    return std::unique_ptr<T, D>(t, d);
}

TEST(CategoryNotification, First)
{
    LS::Error e;
    LSMessageToken token;

    // Start background main loop
    auto main_loop = mk_ptr(g_main_loop_new(nullptr, false), g_main_loop_unref);
    thread t([&main_loop](){ g_main_loop_run(main_loop.get()); });

    struct Watch
    {
        static bool callback(LSHandle *sh, LSMessage *reply, void *ctx)
        {
            printf("Category changed: ");
            LSMessagePrint(reply, stdout);
            return true;
        }
    };

    auto watch = LS::registerService("a.b.watch");
    watch.attachToLoop(main_loop.get());

    struct A
    {
        static bool callback(LSHandle *sh, LSMessage *msg, void *ctxt)
        {
            return true;
        }
    };

    auto a = LS::registerService("com.palm.A");
    a.attachToLoop(main_loop.get());

    static LSMethod methods[] =
    {
        { "bar", A::callback },
        { "baz", A::callback },
        { nullptr },
    };
    a.registerCategory("/category1", methods, nullptr, nullptr);

    static LSMethod methods2[] =
    {
        { "bar2", A::callback },
        { "baz2", A::callback },
        { nullptr }
    };
    a.registerCategoryAppend("/category1", methods2, nullptr);

    static LSMethod methods3[] =
    {
        { "foo", A::callback },
        { "bar", A::callback },
        { nullptr }
    };
    a.registerCategoryAppend("/category2", methods3, nullptr);

    usleep(500000);

    ASSERT_TRUE(LSCall(watch.get(), "luna://com.palm.bus/signal/registerServiceCategory",
                "{\"serviceName\": \"com.palm.A\", \"category\": \"/category1\"}",
                Watch::callback, nullptr, &token, e.get()));
    BOOST_SCOPE_EXIT((&watch)(&token)) {
        LS::Error e;
        LSCallCancel(watch.get(), token, e.get());
    } BOOST_SCOPE_EXIT_END

    usleep(500000);
    g_main_loop_quit(main_loop.get());
    t.join();
}
