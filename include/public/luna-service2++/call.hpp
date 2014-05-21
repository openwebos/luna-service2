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

    void cancel();

    bool setTimeout(int msTimeout) const;

    void continueWith(LSFilterFunc callback, void *context);

    Message get();

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
