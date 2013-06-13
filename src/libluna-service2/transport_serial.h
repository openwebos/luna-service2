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


#ifndef _TRANSPORT_SERIAL_H_
#define _TRANSPORT_SERIAL_H_

#include <pthread.h>
#include <glib.h>
#include <luna-service2/lunaservice.h>

typedef struct LSTransportSerialMapEntry {
    LSMessageToken serial;  /**< global serial */
    GList *serial_list_item;
} _LSTransportSerialMapEntry;

typedef struct LSTransportSerialListItem {
    LSMessageToken serial;  /**< global */
    _LSTransportMessage *message;
} _LSTransportSerialListItem;

/**
 * In order to handle clean shutdown (i.e., making sure that we know which
 * method calls have been received and/or processed on the far end), we keep
 * a queue of @LSTransportSerialListItem that saves the serial number for
 * each method call that we make. In additon, we save a pointer to the
 * actual item on the queue as a @LSTransportSerialMapEntry in the @map,
 * which allows us to do a fast lookup and remove from the list when
 * receive a method call reply.
 *
 * When a client shuts down cleanly, it will send the serial number of the
 * last method call that it has processed. We then look up that serial
 * number in the map and get the pointer to the item on the queue that
 * represents that message. We know that every serial in the list beyond
 * this one has not been processed and can iterate over that list and call
 * a failure callback with the serial number of each message that didn't
 * get processed.
 *
 * Example:
 * 3 Method calls on com.palm.foo:
 *  Serial numbers: 1, 3, 4
 *
 *
 * 4 Method calls on com.palm.bar:
 *  Serial numbers: 2, 5, 6
 *
 * com.palm.bar shuts down and sends 5 as the last serial number processed
 *
 * We then call the failure handler on serial 6.
 *
 * Note that we also remove serial numbers from the queue when we receive
 * a reply, since that indicates that the far side has processed the
 * message as well.
 */
typedef struct LSTransportSerial {
    pthread_mutex_t lock;           /**< protects the queue and map */
    GQueue *queue;                  /**< ordered linked list of serial #s */
    GHashTable *map;                /**< map of serial number to ll item */
} _LSTransportSerial;

_LSTransportSerialMapEntry* _LSTransportSerialMapEntryNew(LSMessageToken serial, GList *list_item);
void _LSTransportSerialMapEntryFree(_LSTransportSerialMapEntry *entry);
_LSTransportSerialListItem* _LSTransportSerialListItemNew(LSMessageToken serial, _LSTransportMessage *message);
void _LSTransportSerialListItemFree(_LSTransportSerialListItem *list_item);
_LSTransportSerial* _LSTransportSerialNew(void);
void _LSTransportSerialFree(_LSTransportSerial *serial_info);
bool _LSTransportSerialSave(_LSTransportSerial *serial_info, _LSTransportMessage *message, LSError *lserror);
void _LSTransportSerialRemove(_LSTransportSerial *serial_info, LSMessageToken serial);
_LSTransportMessage *_LSTransportSerialPopHead(_LSTransportSerial *serial_info);

#endif      // _TRANSPORT_SERIAL_H_
