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
#include "handle.hpp"
#include <cstring>
#include <iostream>

namespace LS {

/**
 * @ingroup LunaServicePP
 * @brief This class is wrapper for service that have both public and private representations
 */
class PalmService
{
    friend PalmService registerPalmService(const char *);

public:
    PalmService();

    PalmService(const PalmService &) = delete;
    PalmService &operator=(const PalmService &) = delete;

    PalmService(PalmService &&) = default;
    PalmService &operator=(PalmService &&) = default;

    /**
     * Register public and private methods
     * @param category name
     * @param methods_public LSMethod array that should end with {0}
     * @param methods_private LSMethod array that should end with {0}
     * @param signals LSSignal array that should end with {0}
     */
    void registerCategory(const char *category, LSMethod *methods_public,
                          LSMethod *methods_private, LSSignal *signals);

    /**
     * @return public service handle
     */
    Handle &getPublicHandle() { return _public_handle; }

    /**
     * @return public service handle
     */
    const Handle &getPublicHandle() const { return _public_handle; }

    /**
     * @return private service handle
     */
    Handle &getPrivateHandle() { return _private_handle; }
    /**
     * @return private service handle
     */
    const Handle &getPrivateHandle() const { return _private_handle; }

    void pushRole(const char *role_path);

    void attachToLoop(GMainLoop *loop) const;

    void attachToLoop(GMainContext *context) const;

    void setPriority(int priority) const;

private:
    Handle _private_handle, _public_handle;

private:
    explicit PalmService(Handle &&private_handle, Handle &&public_handle);

    friend std::ostream &operator<<(std::ostream &os, const PalmService &service);
};

PalmService registerPalmService(const char *name);

} //namespace LS;
