/* @@@LICENSE
*
*      Copyright (c) 2013 LG Electronics, Inc.
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

#ifndef __PMTRACE_LS2_H__
#define __PMTRACE_LS2_H__

#if defined(HAS_LTTNG) && ! defined(LUNA_SERVICE_UNIT_TEST)

#include "pmtrace_ls2_provider.h"

#define CHECK_NULL(A) (A)?(A):"NULL"

#define PMTRACE_CLIENT_PREPARE(sender, receiver, method) \
    tracepoint(pmtrace_lunaservice2, client_prepare, CHECK_NULL(sender), CHECK_NULL(receiver), CHECK_NULL(method))

#define PMTRACE_CLIENT_CALL(sender, receiver, method, token) \
    tracepoint(pmtrace_lunaservice2, client_call, CHECK_NULL(sender), CHECK_NULL(receiver), CHECK_NULL(method), token)

#define PMTRACE_SERVER_RECEIVE(sender, receiver, method, token) \
    tracepoint(pmtrace_lunaservice2, service_receive, CHECK_NULL(sender), CHECK_NULL(receiver), CHECK_NULL(method), token)

#define PMTRACE_SERVER_REPLY(sender, receiver, method, token) \
    tracepoint(pmtrace_lunaservice2, service_reply, CHECK_NULL(sender), CHECK_NULL(receiver), CHECK_NULL(method), token)

#define PMTRACE_CLIENT_CALLBACK(sender, receiver, method, token) \
    tracepoint(pmtrace_lunaservice2, client_callback, CHECK_NULL(sender), CHECK_NULL(receiver), CHECK_NULL(method), token)

#else // HAS_LTTNG && !LUNA_SERVICE_UNIT_TEST

#define PMTRACE_CLIENT_PREPARE(sender, receiver, method)
#define PMTRACE_CLIENT_CALL(sender, receiver, method, token)
#define PMTRACE_SERVER_RECEIVE(sender, receiver, method, token)
#define PMTRACE_SERVER_REPLY(sender, receiver, method, token)
#define PMTRACE_CLIENT_CALLBACK(sender, receiver, method, token)

#endif // HAS_LTTNG && !LUNA_SERVICE_UNIT_TEST

#endif // __PMTRACE_LS2_H__
