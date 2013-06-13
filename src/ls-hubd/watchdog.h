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


#ifndef _WATCHDOG_H
#define _WATCHDOG_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include "error.h"

typedef enum
{
    LSHubWatchdogFailureModeInvalid = -1,
    LSHubWatchdogFailureModeNoop,           /**< don't do anything */
    LSHubWatchdogFailureModeCrash,          /**< crash */
    LSHubWatchdogFailureModeRdx,            /**< generate rdx report */
} LSHubWatchdogFailureMode;

bool SetupWatchdog(LSError *lserror);
LSHubWatchdogFailureMode LSHubWatchdogProcessFailureMode(const char *mode_str);

#endif  /* _WATCHDOG_H */
