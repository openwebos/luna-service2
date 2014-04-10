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
#include <cstring>
#include <iostream>

namespace LS {

class Service;

class Call
{
    friend class Service;

public:
    Call() : _service_handle(nullptr), _token(LSMESSAGE_TOKEN_INVALID) {}

    Call(const Call &) = delete;
    Call& operator=(const Call &) = delete;

    Call(Call &&other)
        : _service_handle(other._service_handle)
        , _token(other._token)
    {
        other._service_handle = nullptr;
        other._token = LSMESSAGE_TOKEN_INVALID;
    }

    Call &operator=(Call &&other)
    {
        _service_handle = other._service_handle;
        _token = other._token;

        other._service_handle = nullptr;
        other._token = LSMESSAGE_TOKEN_INVALID;
        return *this;
    }

    ~Call()
    {
        if (LSMESSAGE_TOKEN_INVALID != _token)
        {
            Error error;

            if (!LSSignalCallCancel(_service_handle, _token, error.get()))
            {
                error.log(PmLogGetLibContext(), "LS_FAILED_TO_CANC_SIGNAL");
            }
        }
    }

    void cancel()
    {
        Error error;

        if (!LSSignalCallCancel(_service_handle, _token, error.get()))
        {
            error.log(PmLogGetLibContext(), "LS_FAILED_TO_CANC_SIGNAL");
        }
    }

private:
    LSHandle *_service_handle;
    LSMessageToken _token;

private:
    explicit Call(LSHandle *service_handle, LSMessageToken token)
        : _service_handle(service_handle)
        , _token(token) {}

    friend std::ostream &operator<<(std::ostream &os, const Call &signal)
    {
        return os << "LUNA SIGNAL CALL '" << signal._token << "'";
    }
};
} //namespace LS;
