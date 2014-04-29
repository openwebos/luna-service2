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

#include "server_status.hpp"
#include "error.hpp"

namespace LS
{

ServerStatus::ServerStatus(LSHandle *_handle,
                           const char *service_name,
                           const ServerStatusCallback &callback)
    : _handle(_handle),
      _cookie(nullptr),
      _callback(new ServerStatusCallback(callback))
{
    Error error;
    if (!LSRegisterServerStatusEx(_handle,
                                  service_name,
                                  ServerStatus::callbackFunc,
                                  _callback.get(),
                                  &_cookie,
                                  error.get()))
    {
        throw error;
    }
}

ServerStatus::~ServerStatus()
{
    if (_cookie)
    {
        Error error;

        if (!LSCancelServerStatus(_handle, _cookie, error.get()))
        {
            error.log(PmLogGetLibContext(), "LS_FAILED_TO_UNREG_SRV_STAT");
        }
    }
}

bool ServerStatus::callbackFunc(LSHandle *,
                                const char *,
                                bool connected,
                                void *ctx)
{
    ServerStatusCallback callback = *(static_cast<ServerStatusCallback *>(ctx));

    return callback(connected);
}

}

