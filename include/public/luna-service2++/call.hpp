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

#include <cassert>
#include <cstring>
#include <iostream>
#include <string>
#include <chrono>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <thread>
#include <memory>

#include <luna-service2/lunaservice.h>
#include "message.hpp"


namespace LS {


/**
 * @ingroup LunaServicePP
 * @brief This class provides ability to make call to service category methods
 * Controls lifetime of the call.
 * Call is canceled on object destroy.
 */
class Call
{
    friend class Handle;

public:

    Call();

    ~Call();

    Call(Call &&other);

    Call &operator=(Call &&other);

    Call(const Call &) = delete;
    Call &operator=(const Call &) = delete;

    /**
     * @brief Send a cancel message to service to end call session and
     * unregister any callback associated with call.
     */
    void cancel();

    /**
     * @brief Set timeout for a method call.
     * The call will be canceled if no reply is received after the msTimeout milliseconds.
     * @param msTimeout
     * @return is success
     */
    bool setTimeout(int msTimeout) const;

    /**
     * @brief Set callback to continue.
     * The callback called for each message arrives.
     * Replaces previous callback if exists.
     * If internal queue already contains messages then callback
     * to be called sequentially for every message in this function.
     * @param callback
     * @param context
     */
    void continueWith(LSFilterFunc callback, void *context);

    /**
     * Retrieve top message object from its queue.
     * Waits for new messages if there is no one.
     * It blocks execution until new message arrived.
     * @note If continueWith were called then this call will wait infinitely
     * because callback from continueWith will intercept all messages and keep message queue empty.
     * @return message
     */
    Message get();

    /**
     * Get with timeout
     * @param msTimeout
     * @return message. The message could be empty. Check it by if(message) before processing.
     */
    Message get(unsigned long msTimeout);

private:

    LSMessageToken _token;
    LSHandle *_sh;
    bool _single;
    LSFilterFunc _callCB;
    void *_callCtx;
    typedef Call *CallPtr;
    std::unique_ptr<CallPtr> _context;
    std::mutex _mutex;
    std::condition_variable _cv;
    std::queue<Message> _queue;
    GMainContext *_mainloopCtx;
    volatile bool _timeoutExpired;

    void cleanup();

    bool isActive() const;

    void call(LSHandle *sh, const char *uri, const char *payload, bool oneReply, const char *appID = NULL);

    void callSignal(LSHandle *sh, const char *category, const char *methodName);

    bool isMainLoopThread() const;

    Message tryGet();

    Message waitOnMainLoop();

    Message waitTimeoutOnMainLoop(unsigned long msTimeout);

    Message wait();

    Message waitTimeout(unsigned long msTimeout);

    bool handleReply(LSHandle *sh, LSMessage *reply);

    static bool replyCallback(LSHandle *sh, LSMessage *reply, void *context);

    static gboolean onWaitCB(gpointer context);

};

} //namespace LS;
