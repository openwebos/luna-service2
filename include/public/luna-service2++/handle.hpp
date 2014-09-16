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

#define LS_CATEGORY_METHOD1(name) LS_CATEGORY_METHOD2(name, LUNA_METHOD_FLAGS_NONE)

#define GET_METHOD_MACRO(_1,_2,NAME,...) NAME

#define LS_CATEGORY_METHOD(...)                         \
    GET_METHOD_MACRO(__VA_ARGS__,LS_CATEGORY_METHOD2,LS_CATEGORY_METHOD1)(__VA_ARGS__)

#define LS_CATEGORY_END {nullptr, nullptr}};            \
    registerCategory(category_name, table, nullptr, nullptr); \
    setCategoryData(category_name, this); \
    }

/**
 * @ingroup LunaServicePP
 * @brief Bus end-point base class
 *
 * It provides an API to control service and client end-points of luna hub.
 * You can inherit or use it to create own service.
 * However this class is planned to be less used as some low-level full functionality precise wrapper for the API.
 * Instead, additional Service and Client wrappers would be created for more comfortable use of the functionality.
 */
class Handle
{
    friend Handle registerService(const char *, bool);

public:
    /**
     * @brief Map a category method to some class method.
     * It allows to obtain LSMethod presentation of a given method.
     * This is used to create a Category method list.
     *
     * @note An object address which has the method should be passed as user_data parameter to setCategoryData method.
     *       This mean all methods of a category should be methods of one class as for now.
     *
     * @tparam ClassT class of category
     * @tparam MethT method of the class ClassT
     */
    template<typename ClassT, bool (ClassT::*MethT)(LSMessage&)>
    static bool methodWraper(LSHandle *h, LSMessage *m, void *ctx)
    {
        auto this_ = static_cast<ClassT*>(ctx);
        return (this_->*MethT)(*m);
    }

    /**
     * Does nothing. Only empty inactive instance created.
     */
    Handle();

    Handle(const Handle &) = delete;
    Handle &operator=(const Handle &) = delete;

    Handle(Handle &&other);

    /**
     * Register new service.
     * @param name the service name
     * @param public_service true if we need the service to be public
     */
    Handle(const char *name, bool public_service = false);

    Handle &operator=(Handle &&other);

    ~Handle();

    /**
     * @return service handle for libluna-service c API
     */
    LSHandle *get() { return _handle; }

    /**
     * @return service handle for libluna-service c API
     */
    const LSHandle *get() const { return _handle; }

    /**
     * @return service name
     */
    const char *getName() const;

    /**
     * Check if the end-point registration was successfully performed
     */
    explicit operator bool() const { return _handle; }

    /**
     * Register a named category with methods and signals
     * @param category category name starting from '/'
     * @param methods c API style method describing structure objects
     * @param signals
     * @param properties
     */
    void registerCategory(const char       *category,
                          const LSMethod   *methods,
                          const LSSignal   *signals,
                          const LSProperty *properties);

    /**
     * Append some methods and signals to a category by name
     * @param category name o category of this end-point
     * @param methods c-style method list. Should end with zeroed item
     * @param signals c-style signal list. Should end with zeroed item
     */
    void registerCategoryAppend(const char *category,
                                LSMethod   *methods,
                                LSSignal   *signals);

    /**
     * Set a disconnection event observer
     * @param disconnect_handler
     * @param user_data - context
     */
    void setDisconnectHandler(LSDisconnectHandler disconnect_handler, void *user_data);

    /**
     * Set context for category methods
     * @param category
     * @param user_data - context
     */
    void setCategoryData(const char *category, void *user_data);

    /**
     * Set a category description by name
     * @param category
     * @param description
     */
    void setCategoryDescription(const char *category, jvalue_ref description);

    /**
     * Push a role for the end-point
     * @param role_path
     */
    void pushRole(const char *role_path);

    /**
     * Attach to context
     * @param context
     */
    void attachToLoop(GMainContext *context) const;

    /**
     * Attach to loop
     * @param loop
     */
    void attachToLoop(GMainLoop *loop) const;

    /**
     * @brief Detach the end-point from a glib mainloop.
     * You should NEVER use this function unless you are fork()'ing without exec()'ing
     * and know what you are doing.
     * This will perform nearly all the same cleanup as LSUnregister(), with
     * the exception that it will not send out shutdown messages or flush any
     * buffers. It is intended to be used only when fork()'ing so that your child
     * process can continue without interfering with the parent's file descriptors,
     * since open file descriptors are duplicated during a fork().
     */
    void detach();

    /**
     * Set priority for the event queue.
     * See https://developer.gnome.org/glib/2.37/glib-The-Main-Event-Loop.html#g-source-set-priority for details.
     * @param priority
     */
    void setPriority(int priority) const;

    /**
     * Send signal by given URI
     * @param uri signal
     * @param payload parameter
     * @param typecheck if true then check existens of the signal point and log warning if it does not exist
     */
    void sendSignal(const char *uri, const char *payload, bool typecheck = true) const;

    /**
     * Make a call
     * @param uri
     * @param payload
     * @param appID
     * @return call control object
     */
    Call callOneReply(const char *uri, const char *payload, const char *appID = NULL);

    /**
     * Make a call with result handler callback
     * @param uri
     * @param payload
     * @param func
     * @param context
     * @param appID
     * @return call handler object
     */
    Call callOneReply(const char *uri,
                      const char *payload,
                      LSFilterFunc func,
                      void *context,
                      const char *appID = NULL);

    /**
     * @brief Multi-call
     * Returned object will collect arrived messages in internal queue.
     * Messaged can be obtained with callback or get(...) functions.
     * @param uri
     * @param payload
     * @param appID
     * @return call handler object
     */
    Call callMultiReply(const char *uri, const char *payload, const char *appID = NULL);

    /**
     * Multi-call with result processing callback
     * @param uri
     * @param payload
     * @param func
     * @param context
     * @param appID
     * @return call handler object
     */
    Call callMultiReply(const char *uri,
                        const char *payload,
                        LSFilterFunc func,
                        void *context,
                        const char *appID = NULL);

    /**
     * Call a signal
     * @param category
     * @param methodName
     * @param func
     * @param context
     * @return call handler object
     */
    Call callSignal(const char *category, const char *methodName, LSFilterFunc func, void *context);

    /**
     * Subscribes to state changes with given callback
     * @param service_name
     * @param callback
     * @return status handler object, control its lifetime to control the subscription
     */
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
