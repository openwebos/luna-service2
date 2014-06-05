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

#include "palm_service.hpp"

namespace LS
{

PalmService::PalmService()
    : _private_handle(),
      _public_handle()
{
}

void PalmService::registerCategory(const char *category,
                                   LSMethod *methods_public,
                                   LSMethod *methods_private,
                                   LSSignal *signals)
{
    _public_handle.registerCategory(category, methods_public, signals, NULL);

    _private_handle.registerCategory(category, methods_private, signals, NULL);
    _private_handle.registerCategoryAppend(category, methods_public, signals);
}

void PalmService::pushRole(const char *role_path)
{
    _public_handle.pushRole(role_path);
    _private_handle.pushRole(role_path);
}

void PalmService::attachToLoop(GMainLoop *loop) const
{
    _public_handle.attachToLoop(loop);
    _private_handle.attachToLoop(loop);
}

void PalmService::attachToLoop(GMainContext *context) const
{
    _public_handle.attachToLoop(context);
    _private_handle.attachToLoop(context);
}

void PalmService::setPriority(int priority) const
{
    _public_handle.setPriority(priority);
    _private_handle.setPriority(priority);
}

PalmService::PalmService(Handle &&private_handle, Handle &&public_handle)
    : _private_handle(std::move(private_handle)),
      _public_handle(std::move(public_handle))
{
}

std::ostream &operator<<(std::ostream &os, const PalmService &service)
{
    return os << "LUNA PALM SERVICE '" << service.getPrivateHandle().getName() << "'";

}

PalmService registerPalmService(const char *name)
{
    Handle public_handle = registerService(name, true);
    Handle private_handle = registerService(name, false);

    return PalmService(std::move(private_handle), std::move(public_handle));
}

}

