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


#ifndef _TRANSPORT_INCOMING_H_
#define _TRANSPORT_INCOMING_H_

#include <pthread.h>
#include <glib.h>
#include <luna-service2/lunaservice.h>
#include "transport_message.h"

struct LSTransportIncoming {
    pthread_mutex_t lock;
    LSMessageToken last_serial_processed;   /**< last reply processed -- see LSTransportSerial */
    _LSTransportHeader tmp_header;          /**< temp location when reading in the header */
    unsigned long tmp_header_offset;        /**< end of valid data in temp header */
    _LSTransportMessage *tmp_msg;           /**< temp location when building up a message */
    unsigned long tmp_msg_offset;           /**< end of data in temp message */
    GQueue *complete_messages;              /**< completed messages; ready for processing */
};

typedef struct LSTransportIncoming _LSTransportIncoming;

_LSTransportIncoming* _LSTransportIncomingNew(void);
void _LSTransportIncomingFree(_LSTransportIncoming *incoming);

#endif      // _TRANSPORT_INCOMING_H_
