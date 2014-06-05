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

#include "call.hpp"
#include "error.hpp"

namespace LS
{

Call::Call()
    : _token { LSMESSAGE_TOKEN_INVALID },
      _sh { nullptr },
      _single { false },
      _callCB { nullptr },
      _callCtx { nullptr },
      _context { new CallPtr(this) }
{
}

Call::~Call()
{
    cleanup();
}

Call::Call(LS::Call &&other)
    : _token { other._token },
      _sh { other._sh },
      _single { other._single },
      _callCB { other._callCB },
      _callCtx { other._callCtx },
      _context { std::move(other._context) }
{
    *_context = this;
    std::lock_guard < std::mutex > lockg { other._mutex };
    other._token = LSMESSAGE_TOKEN_INVALID;
    other._sh = nullptr;
    other._callCB = nullptr;
    other._callCtx = nullptr;
    _queue = std::move(other._queue);
}

LS::Call &Call::operator=(LS::Call &&other)
{
    if (this != &other)
    {
        std::unique_lock < std::mutex > thisLock { _mutex, std::defer_lock };
        std::unique_lock < std::mutex > thatLock { other._mutex, std::defer_lock };
        std::lock(thisLock, thatLock);
        cleanup();
        _token = other._token;
        _sh = other._sh;
        _callCB = other._callCB;
        _callCtx = other._callCtx;
        _context = std::move(other._context);
        *_context = this;
        _queue = std::move(other._queue);
        other._token = LSMESSAGE_TOKEN_INVALID;
        other._sh = nullptr;
        other._callCB = nullptr;
        other._callCtx = nullptr;
    }
    return *this;
}

void Call::cancel()
{
    if (isActive())
    {
        ::LS::Error error;
        if (LSCallCancel(_sh, _token, error.get()))
        {
            _token = LSMESSAGE_TOKEN_INVALID;
        }
        else
        {
            error.log(PmLogGetLibContext(), "LS_CANC_METH");
        }
    }
}

bool Call::setTimeout(int msTimeout) const
{
    if (isActive())
    {
        LS::Error error;
        return LSCallSetTimeout(_sh, _token, msTimeout, error.get());
    }
    return false;
}

void Call::continueWith(LSFilterFunc callback, void *context)
{
    std::lock_guard < std::mutex > lockg { _mutex };
    _callCB = callback;
    _callCtx = context;
    if (!_callCB)
    {
        return;
    }

    while (!_queue.empty())
    {
        (_callCB)(_sh, _queue.front().get(), _callCtx);
        _queue.pop();
    }
}

Message Call::get()
{
    auto result = tryGet();
    if (result)
        return result;

    if (!isMainLoopThread())
    {
        return wait();
    }
    else
    {
        return waitOnMainLoop();
    }
}

Message Call::get(unsigned long msTimeout)
{
    Message result = tryGet();
    if (result)
        return result;

    if (!isMainLoopThread())
    {
        return waitTimeout(msTimeout);
    }
    else
    {
        return waitTimeoutOnMainLoop(msTimeout);
    }
}

void Call::cleanup()
{
    cancel();
}

bool Call::isActive() const
{
    if (LSMESSAGE_TOKEN_INVALID != _token && _sh)
    {
        return true;
    }
    return false;
}

void Call::call(LSHandle *sh, const char *uri, const char *payload, bool oneReply, const char *appID)
{
    LS::Error error;
    typedef bool (*CallFuncType)(LSHandle *,
                                 const char *,
                                 const char *,
                                 const char *,
                                 LSFilterFunc,
                                 void *,
                                 LSMessageToken *,
                                 LSError *);
    _sh = sh;
    _single = oneReply;
    CallFuncType callFunc = _single ? LSCallFromApplicationOneReply : LSCallFromApplication;

    if (!callFunc(_sh,
                  uri,
                  payload,
                  appID,
                  &replyCallback,
                  _context.get(),
                  &_token,
                  error.get()))
    {
        throw error;
    }
}

void Call::callSignal(LSHandle *sh, const char *category, const char *methodName)
{
    LS::Error error;
    _sh = sh;
    _single = false;

    if (!LSSignalCall(_sh,
                      category,
                      methodName,
                      &replyCallback,
                      _context.get(),
                      &_token,
                      error.get()))
    {
        throw error;
    }
}

bool Call::isMainLoopThread() const
{
    if (!_sh)
        return false;
    LS::Error error;
    if (FALSE != g_main_context_is_owner(LSGmainGetContext(_sh, error.get())))
        return true;
    else
    {
        //Check if we can acquire context - probably main loop is not running
        if (FALSE != g_main_context_acquire(LSGmainGetContext(_sh, error.get())))
        {
            g_main_context_release(LSGmainGetContext(_sh, error.get()));
            return true;
        }
    }

    return false;
}

Message Call::tryGet()
{
    std::lock_guard < std::mutex > lockg { _mutex };
    Message result;
    if (!_queue.empty())
    {
        result = std::move(_queue.front());
        _queue.pop();
    }
    return result;
}

Message Call::waitOnMainLoop()
{
    LS::Error error;
    _mainloopCtx = LSGmainGetContext(_sh, error.get());
    if (!_mainloopCtx)
        return nullptr;

    Message reply;
    while (true)
    {
        g_main_context_iteration(_mainloopCtx, TRUE);
        if (_queue.empty())
            continue;
        std::lock_guard < std::mutex > lockg { _mutex };
        if (!_queue.empty())
        {
            reply = std::move(_queue.front());
            _queue.pop();
            break;
        }
    }
    return reply;
}

Message Call::waitTimeoutOnMainLoop(long unsigned int msTimeout)
{
    ::LS::Error error;
    _mainloopCtx = LSGmainGetContext(_sh, error.get());

    if (!_mainloopCtx)
        return nullptr;

    Message reply;
    _timeoutExpired = false;
    GSource *timeoutSrc = g_timeout_source_new(msTimeout);
    g_source_set_callback(timeoutSrc, (GSourceFunc)onWaitCB, this, nullptr);
    g_source_attach(timeoutSrc, _mainloopCtx);
    while (!_timeoutExpired)
    {
        if (FALSE == g_main_context_iteration(_mainloopCtx, TRUE))
            continue;

        if (_queue.empty())
            continue;

        std::lock_guard < std::mutex > lockg { _mutex };
        if (!_queue.empty())
        {
            reply = std::move(_queue.front());
            _queue.pop();
            break;
        }
    }
    g_source_destroy(timeoutSrc);
    g_source_unref(timeoutSrc);
    return reply;
}

Message Call::wait()
{
    std::unique_lock < std::mutex > ul{_mutex};
    _cv.wait(ul, [this] { return !_queue.empty(); });
    Message result = std::move(_queue.front());
    _queue.pop();
    return result;
}

Message Call::waitTimeout(long unsigned int msTimeout)
{
    std::unique_lock < std::mutex > ul { _mutex };
    bool gotMessage = _cv.wait_for(ul,
                                   std::chrono::milliseconds(msTimeout),
                                   [this] { return !_queue.empty();});
    if (gotMessage)
    {
        Message result = std::move(_queue.front());
        _queue.pop();
        return result;
    }
    return {};
}

bool Call::handleReply(LSHandle* sh, LSMessage* reply)
{
    std::lock_guard < std::mutex > lockg { _mutex };
    if (LSMESSAGE_TOKEN_INVALID == _token)
        return false;

    if (_single)
        _token = LSMESSAGE_TOKEN_INVALID;

    if (_callCB)
    {
        (_callCB)(sh, reply, _callCtx);
    }
    else
    {
        _queue.push(reply);
        _cv.notify_one();
    }
    return true;
}

bool Call::replyCallback(LSHandle* sh, LSMessage* reply, void* context)
{
    if (context)
    {
        CallPtr * call = static_cast<CallPtr *>(context);
        (*call)->handleReply(sh, reply);
    }
    return true;
}

gboolean Call::onWaitCB(gpointer context)
{
    (static_cast<Call *>(context))->_timeoutExpired = true;
    /* FIXME -- investigate GMainLoop internal work if this call is really nesessary */
    g_main_context_wakeup((static_cast<Call *>(context))->_mainloopCtx);
    return G_SOURCE_REMOVE;
}

}
