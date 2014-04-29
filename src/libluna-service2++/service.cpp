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

#include "service.hpp"
#include "error.hpp"
#include "message.hpp"

namespace LS
{

Service::Service()
    : _handle(nullptr)
{
}

Service::Service(Service &&other)
    : _handle(other.release())
{
}

Service::Service(const char *name, bool public_service)
{
    Error error;
    LSHandle *handle;

    if (!LSRegisterPubPriv(name, &handle, public_service, error.get()))
    {
        throw error;
    }

    _handle = handle;
}

Service &Service::operator=(Service &&other)
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

Service::~Service()
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

const char *Service::getName() const
{
    return LSHandleGetName(_handle);
}

void Service::registerCategory(const char *category,
                               const LSMethod *methods,
                               const LSSignal *signal,
                               const LSProperty *properties)
{
    Error error;
    if (!LSRegisterCategory(_handle,
                            category,
                            const_cast<LSMethod *>(methods),
                            const_cast<LSSignal *>(signal),
                            const_cast<LSProperty *>(properties),
                            error.get()))
    {
        throw error;
    }
}

void Service::registerCategoryAppend(const char *category,
                                     LSMethod *methods,
                                     LSSignal *signal)
{
    Error error;

    if (!LSRegisterCategoryAppend(_handle, category, methods, signal,
        error.get()))
    {
        throw error;
    }
}

void Service::setDisconnectHandler(LSDisconnectHandler disconnect_handler,
                                   void *user_data)
{
    Error error;

    if (!LSSetDisconnectHandler(_handle, disconnect_handler, user_data,
        error.get()))
    {
        throw error;
    }
}

void Service::setCategoryData(const char *category, void *user_data)
{
    Error error;

    if (!LSCategorySetData(_handle, category, user_data, error.get()))
    {
        throw error;
    }
}

void Service::setCategoryDescription(const char *category,
                                     jvalue_ref description)
{
    Error error;

    if (!LSCategorySetDescription(_handle, category, description, error.get()))
    {
        throw error;
    }
}

void Service::pushRole(const char *role_path)
{
    Error error;

    if (!LSPushRole(_handle, role_path, error.get()))
    {
        throw error;
    }
}

void Service::attachToLoop(GMainContext *context) const
{
    Error error;

    if (!LSGmainContextAttach(_handle, context, error.get()))
    {
        throw error;
    }
}

void Service::attachToLoop(GMainLoop *loop) const
{
    Error error;

    if (!LSGmainAttach(_handle, loop, error.get()))
    {
        throw error;
    }
}

void Service::detach()
{
    Error error;

    if (!LSGmainDetach(_handle, error.get()))
    {
        throw error;
    }
    release();
}

void Service::setPriority(int priority) const
{
    Error error;

    if (!LSGmainSetPriority(_handle, priority, error.get()))
    {
        throw error;
    }
}

void Service::sendSignal(const char *uri, const char *payload, bool typecheck) const
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

Call Service::callOneReply(const char *uri,
                           const char *payload,
                           const char *appID)
{
    Call call;
    call.call(_handle, uri, payload, true, appID);
    return call;
}

Call Service::callOneReply(const char *uri,
                           const char *payload,
                           LSFilterFunc func,
                           void *context,
                           const char *appID)
{
    Call call;
    call.continueWith(func, context);
    call.call(_handle, uri, payload, true, appID);
    return call;
}

Call Service::callMultiReply(const char *uri,
                             const char *payload,
                             const char *appID)
{
    Call call;
    call.call(_handle, uri, payload, false, appID);
    return call;
}

Call Service::callMultiReply(const char *uri,
                             const char *payload,
                             LSFilterFunc func,
                             void *context,
                             const char *appID)
{
    Call call;
    call.continueWith(func, context);
    call.call(_handle, uri, payload, false, appID);
    return call;
}

Call Service::callSignal(const char *category,
                         const char *methodName,
                         LSFilterFunc func,
                         void *context)
{
    Call call;
    call.continueWith(func, context);
    call.callSignal(_handle, category, methodName);
    return call;
}

ServerStatus Service::registerServerStatus(const char *service_name,
                                           const ServerStatusCallback &callback)
{
    return ServerStatus(_handle, service_name, callback);
}

Service::Service(LSHandle *handle)
    : _handle(handle)
{
}

LSHandle *Service::release()
{
    LSHandle *handle = _handle;
    _handle = nullptr;

    return handle;
}

std::ostream &operator<<(std::ostream &os, const Service &service)
{
    return os << "LUNA SERVICE '" << service.getName() << "'";
}

Service registerService(const char *name, bool public_service)
{
    return { name, public_service };
}

}

