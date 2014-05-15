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
#include <cassert>
#include <iostream>

namespace LS {

class Handle;

/**
 * @ingroup LunaServicePP
 * @brief LSMessage wrapper
 */
class Message
{
public:
    Message() : _message(nullptr) {}

    Message(const Message &);
    Message& operator=(const Message &);

    Message(Message &&other) : _message(other._message)
    {
        other._message = nullptr;
    }

    Message(LSMessage *message)
        : _message(message)
    {
        LSMessageRef(_message);
    }


    Message &operator=(Message &&other);

    ~Message()
    {
        if (_message)
        {
            LSMessageUnref(_message);
        }
    }

    /**
     * @return underlying LSMessage object
     */
    LSMessage *get() { return _message; }

    /**
     * @return underlying LSMessage object
     */
    const LSMessage *get() const { return _message; }

    /**
     * @return true if there is a message
     */
    explicit operator bool() const { return _message; }

    void print(FILE *out) const
    {
        LSMessagePrint(_message, out);
    }

    bool isHubError() const
    {
        return LSMessageIsHubErrorMessage(_message);
    }

    const char *getUniqueToken() const
    {
        return LSMessageGetUniqueToken(_message);
    }

    const char *getKind() const
    {
        return LSMessageGetKind(_message);
    }

    const char *getApplicationID() const
    {
        return LSMessageGetApplicationID(_message);
    }

    const char *getSender() const
    {
        return LSMessageGetSender(_message);
    }

    const char *getSenderServiceName() const
    {
        return LSMessageGetSenderServiceName(_message);
    }

    const char *getCategory() const
    {
        return LSMessageGetCategory(_message);
    }

    const char *getMethod() const
    {
        return LSMessageGetMethod(_message);
    }

    const char *getPayload() const
    {
        return LSMessageGetPayload(_message);
    }

    LSMessageToken getMessageToken() const
    {
        return LSMessageGetToken(_message);
    }

    LSMessageToken getResponseToken() const
    {
        return LSMessageGetResponseToken(_message);
    }

    bool isSubscription() const
    {
        return LSMessageIsSubscription(_message);
    }

    void respond(const char *reply_payload);

    void reply(Handle &service_handle, const char *reply_payload);

private:
    LSMessage *_message;

private:

    friend std::ostream &operator<<(std::ostream &os, const Message &message);
};

} //namespace LS;
