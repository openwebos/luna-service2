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
#include "message.hpp"

namespace LS {

class Message;
class PalmService;

#define LS_CATEGORY_BEGIN(cl,name)                      \
    { typedef class cl cl_t;                            \
      constexpr const char* category_name = #name;      \
      constexpr static const LSMethod table[] = {

#define LS_CATEGORY_METHOD(name) { #name,               \
      &LS::Service::methodWraper<cl_t, &cl_t::name>,    \
      static_cast<LSMethodFlags>(0) },

#define LS_CATEGORY_END };                              \
    registerCategory(category_name, table, nullptr, nullptr); \
    setCategoryData(category_name, this); \
    }


class Service
{
    friend Service registerService(const char *, bool);
    friend class PalmService;

public:
    template<typename ClassT, bool (ClassT::*MethT)(LSMessage&)>
    static bool methodWraper(LSHandle* h, LSMessage* m, void* ctx)
    {
        auto this_ = static_cast<ClassT*>(ctx);
        return (this_->*MethT)(*m);
    }


    Service() : _handle(nullptr) {}

    Service(const Service &) = delete;
    Service& operator=(const Service &) = delete;

    Service(Service &&other) : _handle(other.release()) {}

    Service(const char *name, bool public_service = false)
    {
        Error error;
        LSHandle *handle;

        if (!LSRegisterPubPriv(name, &handle, public_service, error.get()))
        {
            throw error;
        }

        _handle = handle;
    }

    Service &operator=(Service &&other)
    {
        if (_handle)
        {
            Error error;

            if (!LSUnregister(_handle, error.get()))
            {
                throw error;
            }
        }
        _handle = other.release();
        return *this;
    }

    ~Service()
    {
        if (_handle)
        {
            Error error;

            if (!LSUnregister(_handle, error.get()))
            {
                error.log(PmLogGetLibContext(), "LS_FAILED_TO_UNREG");
            }
        }
    }

    LSHandle *get() { return _handle; }
    const LSHandle *get() const { return _handle; }

    const char *getName() const { return LSHandleGetName(_handle); }

    explicit operator bool() const { return _handle; }

    void registerCategory(const char*       category,
                          const LSMethod*   methods,
                          const LSSignal*   signal,
                          const LSProperty* properties)
    {
        Error error;
        if (!LSRegisterCategory(_handle,
                                category,
                                const_cast<LSMethod*>(methods),
                                const_cast<LSSignal*>(signal),
                                const_cast<LSProperty*>(properties),
                                error.get()))
        {
            throw error;
        }
    }

    void registerCategoryAppend(const char *category,
                                LSMethod      *methods,
                                LSSignal      *signal)
    {
        Error error;

        if (!LSRegisterCategoryAppend(_handle, category, methods, signal, error.get()))
        {
            throw error;
        }
    }

    void setDisconnectHandler(LSDisconnectHandler disconnect_handler, void *user_data)
    {
        Error error;

        if (!LSSetDisconnectHandler(_handle, disconnect_handler, user_data, error.get()))
        {
            throw error;
        }
    }

    void setCategoryData(const char *category, void *user_data)
    {
        Error error;

        if (!LSCategorySetData(_handle, category, user_data, error.get()))
        {
            throw error;
        }
    }

    void setCategoryDescription(const char *category, jvalue_ref description)
    {
        Error error;

        if (!LSCategorySetDescription(_handle, category, description, error.get()))
        {
            throw error;
        }
    }

    void pushRole(const char *role_path)
    {
        Error error;

        if (!LSPushRole(_handle, role_path, error.get()))
        {
            throw error;
        }
    }

    void attachToLoop(GMainContext *context) const
    {
        Error error;

        if(!LSGmainContextAttach(_handle, context, error.get()))
        {
            throw error;
        }
    }

    void attachToLoop(GMainLoop *loop) const
    {
        Error error;

        if(!LSGmainAttach(_handle, loop, error.get()))
        {
            throw error;
        }
    }

    void detach()
    {
        Error error;

        if(!LSGmainDetach(_handle, error.get()))
        {
            throw error;
        }
        release();
    }

    void setPriority(int priority) const
    {
        Error error;

        if(!LSGmainSetPriority(_handle, priority, error.get()))
        {
            throw error;
        }
    }

    void sendSignal(const char *uri, const char *payload, bool typecheck = true) const
    {
        Error error;

        if (typecheck)
        {
            if (!LSSignalSend(_handle, uri, payload, error.get()))
            {
                throw error;
            }
        }
        else
        {
            if (!LSSignalSendNoTypecheck(_handle, uri, payload, error.get()))
            {
                throw error;
            }
        }
    }

    Call callOneReply(const char *uri, const char *payload, const char * appID = NULL)
    {
        Call call;
        call.call(_handle, uri, payload, true, appID);
        return call;
    }

    Call callOneReply(const char *uri,
        const char *payload, LSFilterFunc func, void * context, const char * appID = NULL)
    {
        Call call;
        call.continueWith(func, context);
        call.call(_handle, uri, payload, true, appID);
        return call;
    }

    Call callMultiReply(const char *uri, const char *payload, const char * appID = NULL)
    {
        Call call;
        call.call(_handle, uri, payload, false, appID);
        return call;
    }

    Call callMultiReply(const char *uri,
        const char *payload, LSFilterFunc func, void * context, const char * appID = NULL)
    {
        Call call;
        call.continueWith(func, context);
        call.call(_handle, uri, payload, false, appID);
        return call;
    }

    Call callSignal(const char *category, const char *methodName, LSFilterFunc func, void * context)
    {
        Call call;
        call.continueWith(func, context);
        call.callSignal(_handle, category, methodName);
        return call;
    }

    ServerStatus registerServerStatus(const char *service_name, const ServerStatusCallback &callback)
    {
        return ServerStatus(_handle, service_name, callback);
    }

private:
    LSHandle *_handle;

private:
    explicit Service(LSHandle *handle) : _handle(handle) {}

    LSHandle *release()
    {
        LSHandle *handle = _handle;
        _handle = nullptr;

        return handle;
    }

    friend std::ostream &operator<<(std::ostream &os, const Service &service)
    {
        return os << "LUNA SERVICE '" << service.getName() << "'";
    }
};

Service registerService(const char *name = nullptr, bool public_service = false)
{
    return { name, public_service };
}

} //namespace LS;
