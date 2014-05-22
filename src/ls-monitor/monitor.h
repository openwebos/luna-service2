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


#ifndef _MONITOR_H
#define _MONITOR_H

#include <sys/time.h>
#include <stdbool.h>

#include "transport.h"

void _LSMonitorGetTime(struct timespec *time);
void _LSMonitorMessagePrint(_LSTransportMessage *message, bool public_bus);
double _LSMonitorTimeDiff(const struct timespec const *time1, const struct timespec const *time2);

#endif  /* _MONITOR_H */
