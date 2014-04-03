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

#include <luna-service2/lunaservice.hpp>
#include <boost/scope_exit.hpp>
#include <memory>

using namespace std;

namespace {

static bool FooMethod(LSHandle *sh, LSMessage *msg, void *ctxt)
{
    LSMessagePrint(msg, stdout);

    LS::Error e;
    LSMessageReply(sh, msg, "{\"status\": 0}", e.get());

    GMainLoop *main_loop = static_cast<GMainLoop *>(ctxt);
    g_main_loop_quit(main_loop);
    return true;
}

template <typename T, typename D>
unique_ptr<T, D> mk_ptr(T *t, D d)
{
    return unique_ptr<T, D>(t, d);
}

} //namespace;

int main()
{
    LSHandle *sh{nullptr};
    LS::Error e;

    auto main_loop = mk_ptr(g_main_loop_new(nullptr, false), g_main_loop_unref);

    bool res = LSRegister("com.palm.test_service", &sh, e.get());
    if (!res)
        return 1;
    BOOST_SCOPE_EXIT((&sh)(&e)) {
        LSUnregister(sh, e.get());
    } BOOST_SCOPE_EXIT_END

    static LSMethod test_methods[] =
    {
        { "foo", &FooMethod },
        { nullptr }
    };

    res = LSRegisterCategory(sh, "/test",
                             test_methods, nullptr, nullptr,
                             e.get());
    if (!res)
        return 1;

    res = LSCategorySetData(sh, "/test", main_loop.get(), e.get());
    if (!res)
        return 1;

    res = LSGmainAttach(sh, main_loop.get(), e.get());
    if (!res)
        return 1;

    g_main_loop_run(main_loop.get());
    return 0;
}

// vim: set et ts=4 sw=4:
