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

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER pmtrace_lunaservice2

#undef TRACEPOINT_INCLUDE_FILE
#define TRACEPOINT_INCLUDE_FILE ./pmtrace_ls2_provider.h

#ifdef __cplusplus
extern "C"{
#endif /*__cplusplus */

#if !defined(_PMTRACE_LS2_PROVIDER_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _PMTRACE_LS2_PROVIDER_H

#include <lttng/tracepoint.h>

/* client is ready to send a call*/
TRACEPOINT_EVENT(
    TRACEPOINT_PROVIDER,
    client_prepare,
    TP_ARGS(char*, sender, char*, receiver, char*, method),
    TP_FIELDS(ctf_string(sender, sender))
    TP_FIELDS(ctf_string(receiver, receiver))
    TP_FIELDS(ctf_string(method, method)))

/* client has sent the call*/
TRACEPOINT_EVENT(
    TRACEPOINT_PROVIDER,
    client_call,
    TP_ARGS(char*, sender, char*, receiver, char*, method, long, token),
    TP_FIELDS(ctf_string(sender, sender))
    TP_FIELDS(ctf_string(receiver, receiver))
    TP_FIELDS(ctf_string(method, method))
    TP_FIELDS(ctf_integer(long, token, token)))

/* service is ready to call a handler for the method */
TRACEPOINT_EVENT(
    TRACEPOINT_PROVIDER,
    service_receive,
    TP_ARGS(char*, sender, char*, receiver, char*, method, long, token),
    TP_FIELDS(ctf_string(sender, sender))
    TP_FIELDS(ctf_string(receiver, receiver))
    TP_FIELDS(ctf_string(method, method))
    TP_FIELDS(ctf_integer(long, token, token)))

/* handler has been called, sending reply to the client */
TRACEPOINT_EVENT(
    TRACEPOINT_PROVIDER,
    service_reply,
    TP_ARGS(char*, sender, char*, receiver, char*, method, long, token),
    TP_FIELDS(ctf_string(sender, sender))
    TP_FIELDS(ctf_string(receiver, receiver))
    TP_FIELDS(ctf_string(method, method))
    TP_FIELDS(ctf_integer(long, token, token)))

/* client has received reply and ready to pass it to callback*/
TRACEPOINT_EVENT(
    TRACEPOINT_PROVIDER,
    client_callback,
    TP_ARGS(char*, sender, char*, receiver, char*, method, long, token),
    TP_FIELDS(ctf_string(sender, sender))
    TP_FIELDS(ctf_string(receiver, receiver))
    TP_FIELDS(ctf_string(method, method))
    TP_FIELDS(ctf_integer(long, token, token)))


#endif /* _PMTRACE_LS2_PROVIDER_H */

#include <lttng/tracepoint-event.h>

#ifdef __cplusplus
}
#endif /*__cplusplus */

