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


#ifndef _TRANSPORT_OUTGOING_H_
#define _TRANSPORT_OUTGOING_H_

#include <pthread.h>
#include <glib.h>
#include "transport_serial.h"

struct LSTransportOutgoing {
    pthread_mutex_t lock;           /**< protects queue */
    GQueue *queue;                  /**< queue of LSTransportMessages that need to be sent */
    _LSTransportSerial *serial;     /**< keeps track of clean shutdown state */
};

typedef struct LSTransportOutgoing _LSTransportOutgoing;

_LSTransportOutgoing* _LSTransportOutgoingNew(void);
void _LSTransportOutgoingFree(_LSTransportOutgoing *outgoing);

#endif      // _TRANSPORT_OUTGOING_H_
