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

#include "luna-service2++/error.hpp"
#include "luna-service2++/message.hpp"
#include "luna-service2++/handle.hpp"
#include "luna-service2++/palm_service.hpp"
#include "luna-service2++/call.hpp"
#include "luna-service2++/subscription.hpp"


/// @defgroup LunaServicePP LunaService++
/// @ingroup Luna
/// @brief Luna Services C++ API.

/// @defgroup LunaServicePPExample Luna C++ Wrapper Usage Example
/// @ingroup LunaServicePP
/// @brief Luna Services C++ API examples.
///
/// <h1>LunaService++</h1>
///
/// <em>Example synchronous client usage:</em>
///
/// @snippet test_example++.cpp synchronous client call
///
/// <em>Example asynchronous client usage:</em>
///
/// @snippet test_example++.cpp asynchronous client call
///
/// <em>Example service usage:</em>
///
/// @snippet test_example++.cpp method implementation
/// @snippet test_example++.cpp service registration
///
/// <em>Example C++ service usage:</em>
///
/// @snippet test_example++.cpp memfun service registration
/// @snippet test_example++.cpp memfun service initialization
