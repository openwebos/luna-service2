/* @@@LICENSE
*
*      Copyright (c) 2014 LG Electronics, Inc.
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


#include <glib.h>

#include "log.h"

static PmLogContext pm_log_context = kPmLogDefaultContext;

void LSLogSetContext(const char* context_name)
{
    PmLogGetContext(context_name, &pm_log_context);
}

inline PmLogContext LSLogGetContext(void)
{
    return pm_log_context;
}

void LSLogSetDebugLevel(bool debug)
{
    PmLogSetContextLevel(LSLogGetContext(), debug ? kPmLogLevel_Debug : kPmLogLevel_Info);
}
