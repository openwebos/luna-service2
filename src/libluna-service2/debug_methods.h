/* @@@LICENSE
*
*      Copyright (c) 2008-2013 LG Electronics, Inc.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* LICENSE@@@ */


#ifndef _DEBUG_METHODS_H_
#define _DEBUG_METHODS_H_

#include <stdbool.h>
#include "base.h"

#define SUBSCRIPTION_DEBUG
#define MALLOC_DEBUG
#define INTROSPECTION_DEBUG

#ifdef SUBSCRIPTION_DEBUG
bool _LSPrivateGetSubscriptions(LSHandle* sh, LSMessage *message, void *ctx);
#endif
#ifdef MALLOC_DEBUG
bool _LSPrivateGetMallinfo(LSHandle* sh, LSMessage *message, void *ctx);
bool _LSPrivateDoMallocTrim(LSHandle* sh, LSMessage *message, void *ctx);
#endif
#ifdef INTROSPECTION_DEBUG
bool _LSPrivateInrospection(LSHandle* sh, LSMessage *message, void *ctx);
#endif

#endif // _DEBUG_METHODS_H_
