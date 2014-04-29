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
#include "service.hpp"
#include <cstring>
#include <iostream>

namespace LS {

class PalmService
{
    friend PalmService registerPalmService(const char *);

public:
    PalmService();

    PalmService(const PalmService &) = delete;
    PalmService &operator=(const PalmService &) = delete;

    PalmService(PalmService &&) = default;
    PalmService &operator=(PalmService &&) = default;

    void registerCategory(const char *category, LSMethod *methods_public,
                          LSMethod *methods_private, LSSignal *langis);

    Service &getPublicConnection() { return _public_service; }
    const Service &getPublicConnection() const { return _public_service; }

    Service &getPrivateConnection() { return _private_service; }
    const Service &getPrivateConnection() const { return _private_service; }


    void pushRole(const char *role_path);

    void attachToLoop(GMainLoop *loop) const;

    void attachToLoop(GMainContext *context) const;

    void setPriority(int priority) const;

private:
    Service _private_service, _public_service;

private:
    explicit PalmService(Service &&private_handle, Service &&public_handle);

    friend std::ostream &operator<<(std::ostream &os, const PalmService &service);
};

PalmService registerPalmService(const char *name);

} //namespace LS;
