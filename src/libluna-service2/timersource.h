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


#include <stdbool.h>

typedef struct _GTimerSource GTimerSource;

GTimerSource * g_timer_source_new(guint interval_ms, guint granularity_ms);

GTimerSource *g_timer_source_new_seconds(guint interval_seconds);

void g_timer_source_set_interval_seconds(GTimerSource *tsource, guint interval_sec, gboolean from_poll);

void g_timer_source_set_interval(GTimerSource *tsource, guint interval, gboolean from_poll);

guint g_timer_source_get_interval_ms(GTimerSource *tsource);

