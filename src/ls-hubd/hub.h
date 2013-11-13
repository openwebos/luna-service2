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
#ifndef _HUB_H
#define _HUB_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <signal.h>
#include <stdbool.h>
#include "error.h"

bool ServiceInitMap(LSError *lserror, bool volatile_dirs);
bool ParseServiceDirectory(const char *path, LSError *lserror, bool isVolatileDir);
bool SetupSignalHandler(int signal, void (*handler)(int));
bool LSHubSendConfScanCompleteSignal(void);

typedef struct _Service _Service;
_Service* ServiceMapLookup(const char *service_name);

#endif  /* _HUB_H */
