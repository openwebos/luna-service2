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
#include <memory>
#include <functional>

class LS2Service : public LS::Handle
{
    typedef std::function<void(LSHandle *sh, LSMessage *msg)> LS2Method;
    std::vector< std::shared_ptr<LS2Method> > methods;
    std::shared_ptr<GMainLoop> loop;
    std::thread loop_thread;

    void loop_thread_func();
    static bool callback(LSHandle *sh, LSMessage *msg, void *category_context);

public:

    LS2Service(const std::string &name, bool public_service);
    ~LS2Service();
    void AddMethod(const std::string& name, const LS2Method& _method);
    void callNoReply(const char *uri, const char *payload, const char * appID = NULL);
};

inline void LS2Service::loop_thread_func()
{
    g_main_loop_run(loop.get());
}

inline bool LS2Service::callback(LSHandle *sh, LSMessage *msg, void *category_context)
{
    reinterpret_cast<LS2Method*>(category_context)->operator()(sh, msg);
    return true;
}

inline LS2Service::LS2Service(const std::string &name, bool public_service)
        : LS::Handle(LS::registerService(name.c_str(), public_service))
        , loop(g_main_loop_new(nullptr, false), g_main_loop_unref)
        , loop_thread(std::bind(&LS2Service::loop_thread_func, this))
{
    attachToLoop(loop.get());

    while(!g_main_loop_is_running(loop.get()))
        usleep(1000);
}

inline LS2Service::~LS2Service()
{
    g_main_loop_quit(loop.get());
    loop_thread.join();
}

inline void LS2Service::AddMethod(const std::string& name, const LS2Method& _method)
{
    std::shared_ptr<LS2Method> method(new LS2Method(_method));
    methods.push_back(method);
    LSMethod method_arg[] = {{"call", callback}, { nullptr, nullptr }};
    registerCategory(name.c_str(), method_arg, nullptr, nullptr);
    setCategoryData(name.c_str(), method.get());
}

inline void LS2Service::callNoReply(const char *uri, const char *payload, const char * appID)
{
    LS::Error error;
    if (!LSCallFromApplication( get(), uri, payload, appID, nullptr,nullptr, nullptr,error.get()))
        throw error;
}

class Timer
{
    std::chrono::high_resolution_clock::time_point start;
public:
    Timer()
        : start(std::chrono::high_resolution_clock::now())
    {}

    int msec()
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            (std::chrono::high_resolution_clock::now() - start)).count();
    }
};
