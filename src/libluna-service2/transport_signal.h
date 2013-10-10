/* @@@LICENSE
*
*      Copyright (c) 2008-2014 LG Electronics, Inc.
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


#ifndef _TRANSPORT_SIGNAL_H_
#define _TRANSPORT_SIGNAL_H_

#include <luna-service2/lunaservice.h>
#include "transport.h"

#define SERVICE_STATUS_CATEGORY  "_private_service_status"    /**< category used for special service status signal registration */
#define SERVICE_STATUS_DOWN_PAYLOAD  "{\"connected\":false, \"serviceName\":\"%s\", \"uniqueName\":\"%s\", \"returnValue\":true}"
#define SERVICE_STATUS_UP_PAYLOAD    "{\"connected\":true, \"serviceName\":\"%s\", \"uniqueName\":\"%s\", \"pid\":%d, \"allNames\":[%s], \"returnValue\":true}"

#define SERVICE_STATUS_SERVICE_NAME     "serviceName"

bool LSTransportRegisterSignal(_LSTransport *transport, const char *category, const char *method, LSMessageToken *token, LSError *lserror);
bool LSTransportUnregisterSignal(_LSTransport *transport, const char *category, const char *method, LSMessageToken *token, LSError *lserror);
bool LSTransportSendSignal(_LSTransport *transport, const char *category, const char *method, const char *payload, LSError *lserror);

bool LSTransportRegisterSignalServiceStatus(_LSTransport *transport, const char *service_name,  LSMessageToken *token, LSError *lserror);
bool LSTransportUnregisterSignalServiceStatus(_LSTransport *transport, const char *service_name,  LSMessageToken *token, LSError *lserror);

char* LSTransportServiceStatusSignalGetServiceName(_LSTransportMessage *message);
_LSTransportMessage* LSTransportMessageSignalNewRef(const char *category, const char *method, const char *payload);

#endif      // _TRANSPORT_SIGNAL_H_
