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

#pragma once

#include <luna-service2/lunaservice.h>
#include <luna-service2/lunaservice-meta.h>
#include "call.hpp"
#include "server_status.hpp"
#include <PmLogLib.h>
#include <cstring>
#include <iostream>
#include <memory>

namespace LS {

#define LS_CATEGORY_BEGIN(cl,name)                      \
    { typedef class cl cl_t;                            \
      const char *category_name = name;                 \
      constexpr static const LSMethod table[] = {

#define LS_CATEGORY_METHOD2(name,flags) { #name,        \
      &LS::Handle::methodWraper<cl_t, &cl_t::name>,     \
      static_cast<LSMethodFlags>(flags) },

#define LS_CATEGORY_METHOD1(name) LS_CATEGORY_METHOD2(name,0)

#define GET_METHOD_MACRO(_1,_2,NAME,...) NAME

#define LS_CATEGORY_METHOD(...)                         \
    GET_METHOD_MACRO(__VA_ARGS__,LS_CATEGORY_METHOD2,LS_CATEGORY_METHOD1)(__VA_ARGS__)

#define LS_CATEGORY_END {nullptr, nullptr}};            \
    registerCategory(category_name, table, nullptr, nullptr); \
    setCategoryData(category_name, this); \
    }

class Handle
{
    friend Handle registerService(const char *, bool);

public:
    template<typename ClassT, bool (ClassT::*MethT)(LSMessage&)>
    static bool methodWraper(LSHandle *h, LSMessage *m, void *ctx)
    {
        auto this_ = static_cast<ClassT*>(ctx);
        return (this_->*MethT)(*m);
    }


    Handle();

    Handle(const Handle &) = delete;
    Handle &operator=(const Handle &) = delete;

    Handle(Handle &&other);

    Handle(const char *name, bool public_service = false);

    Handle &operator=(Handle &&other);

    ~Handle();

    LSHandle *get() { return _handle; }
    const LSHandle *get() const { return _handle; }

    const char *getName() const;

    explicit operator bool() const { return _handle; }

    void registerCategory(const char       *category,
                          const LSMethod   *methods,
                          const LSSignal   *signal,
                          const LSProperty *properties);

    void registerCategoryAppend(const char *category,
                                LSMethod   *methods,
                                LSSignal   *signal);

    void setDisconnectHandler(LSDisconnectHandler disconnect_handler, void *user_data);

    void setCategoryData(const char *category, void *user_data);

    void setCategoryDescription(const char *category, jvalue_ref description);

    void pushRole(const char *role_path);

    void attachToLoop(GMainContext *context) const;

    void attachToLoop(GMainLoop *loop) const;

    void detach();

    void setPriority(int priority) const;

    void sendSignal(const char *uri, const char *payload, bool typecheck = true) const;

    Call callOneReply(const char *uri, const char *payload, const char *appID = NULL);

    Call callOneReply(const char *uri,
                      const char *payload,
                      LSFilterFunc func,
                      void *context,
                      const char *appID = NULL);

    Call callMultiReply(const char *uri, const char *payload, const char *appID = NULL);

    Call callMultiReply(const char *uri,
                        const char *payload,
                        LSFilterFunc func,
                        void *context,
                        const char *appID = NULL);

    Call callSignal(const char *category, const char *methodName, LSFilterFunc func, void *context);

    ServerStatus registerServerStatus(const char *service_name, const ServerStatusCallback &callback);

private:
    LSHandle *_handle;

private:
    explicit Handle(LSHandle *handle);

    LSHandle *release();

    friend std::ostream &operator<<(std::ostream &os, const Handle &service_handle);
};

Handle registerService(const char *name = nullptr, bool public_service = false);

} //namespace LS;
