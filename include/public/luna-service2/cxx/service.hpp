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
#include <PmLogLib.h>
#include <cstring>
#include <iostream>
#include <memory>

namespace LS {

class PalmService;

class Service
{
    friend Service registerService(const char *, bool);
    friend class PalmService;

public:
    Service() : _handle(nullptr) {}

    Service(const Service &) = delete;
    Service& operator=(const Service &) = delete;

    Service(Service &&other) : _handle(other.release()) {}

    Service &operator=(Service &&other)
    {
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

    const char *getName() const { return LSHandleGetName(_handle); }

    void registerCategory(const char *category,
                          LSMethod      *methods,
                          LSSignal      *signal,
                          LSProperty    *properties)
    {
        Error error;

        if (!LSRegisterCategory(_handle, category, methods, signal, properties, error.get()))
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

Service registerService(const char *name, bool public_service = true)
{
    Error error;
    LSHandle *handle;

    if (!LSRegisterPubPriv(name, &handle, public_service, error.get()))
    {
        throw error;
    }

    return Service(handle);
}

} //namespace LS;
