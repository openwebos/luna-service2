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

#include "message.hpp"
#include "error.hpp"
#include "handle.hpp"

namespace LS
{

Message::Message(const Message &o)
{
    _message = o._message;
    if (_message) LSMessageRef(_message);
}

Message& Message::operator=(const Message &o)
{
    if (this == &o)
        return *this;
    if (_message) LSMessageUnref(_message);
    _message = o._message;
    if (_message) LSMessageRef(_message);
    return *this;
}

Message &Message::operator=(Message &&other)
{
    if (_message)
    {
        LSMessageUnref(_message);
    }
    _message = other._message;
    other._message = nullptr;
    return *this;
}

std::ostream &operator<<(std::ostream &os, const Message &message)
{
    return os << "LS MESSAGE from service '" << message.getSenderServiceName()
        << "'" << ", category: '" << message.getCategory() << "'"
        << ", method: '" << message.getMethod() << "'" << ", payload: "
        << message.getPayload();
}

void Message::reply(Handle &service_handle, const char *reply_payload)
{
    Error error;

    if (!LSMessageReply(service_handle.get(), _message, reply_payload, error.get()))
    {
        throw error;
    }
}

void Message::respond(const char *reply_payload)
{
    Error error;

    if (!LSMessageRespond(_message, reply_payload, error.get()))
    {
        throw error;
    }
}

}
