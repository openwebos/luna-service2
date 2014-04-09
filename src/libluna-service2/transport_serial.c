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


#include <string.h>

#include <errno.h>
#include "error.h"
#include "transport_utils.h"
#include "transport_message.h"
#include "transport_serial.h"

/**
 * @defgroup LunaServiceTransportSerial
 * @ingroup LunaServiceTransport
 * @brief Transport serial
 */

/**
 * @addtogroup LunaServiceTransportSerial
 * @{
 */

/**
 *******************************************************************************
 * @brief Allocate a new serial map entry.
 *
 * @param  serial       IN  serial
 * @param  list_item    IN  pointer to item in list
 *
 * @retval  entry on success
 * @retval  NULL on failure
 *******************************************************************************
 */
_LSTransportSerialMapEntry*
_LSTransportSerialMapEntryNew(LSMessageToken serial, GList *list_item)
{
    _LSTransportSerialMapEntry* entry = g_slice_new0(_LSTransportSerialMapEntry);

    entry->serial = serial;
    entry->serial_list_item = list_item;

    return entry;
}

/**
 *******************************************************************************
 * @brief Free a serial map entry.
 *
 * @param  entry    IN  entry
 *******************************************************************************
 */
void
_LSTransportSerialMapEntryFree(_LSTransportSerialMapEntry *entry)
{
    LS_ASSERT(entry != NULL);

#ifdef MEMCHECK
    memset(entry, 0xFF, sizeof(_LSTransportSerialMapEntry));
#endif

    g_slice_free(_LSTransportSerialMapEntry, entry);
}

/**
 *******************************************************************************
 * @brief Allocate a new serial list item.
 *
 * @param  serial   IN  serial (token)
 *
 * @retval  item on success
 * @retval  NULL on failure
 *******************************************************************************
 */
_LSTransportSerialListItem*
_LSTransportSerialListItemNew(LSMessageToken serial, _LSTransportMessage *message)
{
    _LSTransportSerialListItem *item = g_slice_new0(_LSTransportSerialListItem);

    item->serial = serial;
    _LSTransportMessageRef(message);
    item->message = message;

    return item;
}

/**
 *******************************************************************************
 * @brief Free a serial list item.
 *
 * @param  list_item    IN serial list item to free
 *******************************************************************************
 */
void
_LSTransportSerialListItemFree(_LSTransportSerialListItem *list_item)
{
    LS_ASSERT(list_item != NULL);

    _LSTransportMessageUnref(list_item->message);

#ifdef MEMCHECK
    memset(list_item, 0xFF, sizeof(_LSTransportSerialListItem));
#endif

    g_slice_free(_LSTransportSerialListItem, list_item);
}

/**
 *******************************************************************************
 * @brief Allocate a new transport serial.
 *
 * @retval  transport serial on success
 * @retval  NULL on failure
 *******************************************************************************
 */
_LSTransportSerial*
_LSTransportSerialNew(void)
{
    _LSTransportSerial *serial_info = g_slice_new0(_LSTransportSerial);

    if (pthread_mutex_init(&serial_info->lock, NULL))
    {
        LOG_LS_ERROR(MSGID_LS_MUTEX_ERR, 0, "Could not initialize mutex");
        goto error;
    }

    serial_info->queue = g_queue_new();

    /* TODO: make custom 64-bit int hash function since we may need to
     * increase the size of LSMessageToken */
    serial_info->map = g_hash_table_new_full(g_int_hash, g_int_equal, NULL, (GDestroyNotify)_LSTransportSerialMapEntryFree);

    return serial_info;

error:
    _LSTransportSerialFree(serial_info);
    return NULL;
}

/**
 *******************************************************************************
 * @brief Free transport serial info
 *
 * @param  serial_info  IN  serial info
 *******************************************************************************
 */
void
_LSTransportSerialFree(_LSTransportSerial *serial_info)
{
    LS_ASSERT(serial_info != NULL);

    SERIAL_INFO_LOCK(&serial_info->lock);

    while (!g_queue_is_empty(serial_info->queue))
    {
         _LSTransportSerialListItem *item = g_queue_pop_head(serial_info->queue);
        _LSTransportSerialListItemFree(item);
    }

    g_queue_free(serial_info->queue);
    g_hash_table_destroy(serial_info->map); /* key and value destroy functions clean this up */

    SERIAL_INFO_UNLOCK(&serial_info->lock);

#ifdef MEMCHECK
    memset(serial_info, 0xFF, sizeof(_LSTransportSerial));
#endif

    g_slice_free(_LSTransportSerial, serial_info);
}

/**
 *******************************************************************************
 * @brief Save a serial (token) in the queue and map.
 *
 * @attention locks the serial lock
 *
 * @param  serial_info  IN  serial info
 * @param  serial       IN  message serial (token) to save
 * @param  lserror      OUT set on error
 *
 * @retval  true on success
 * @retval  false on failure
 *******************************************************************************
 */
bool
_LSTransportSerialSave(_LSTransportSerial *serial_info, _LSTransportMessage *message, LSError *lserror)
{
    LSMessageToken serial = _LSTransportMessageGetToken(message);
    _LSTransportSerialListItem *item = _LSTransportSerialListItemNew(serial, message);

    SERIAL_INFO_LOCK(&serial_info->lock);

    g_queue_push_tail(serial_info->queue, item);
    GList *list = g_queue_peek_tail_link(serial_info->queue);

    LS_ASSERT(list != NULL);

    _LSTransportSerialMapEntry *map_entry = _LSTransportSerialMapEntryNew(serial, list);

    LS_ASSERT(NULL == g_hash_table_lookup(serial_info->map, &map_entry->serial));

    g_hash_table_insert(serial_info->map, &map_entry->serial, map_entry);

    SERIAL_INFO_UNLOCK(&serial_info->lock);

    return true;
}

/**
 *******************************************************************************
 * @brief Remove a serial (token) from the queue and map.
 *
 * @attention locks the serial info lock
 *
 * @param  serial_info  IN  serial info
 * @param  serial       IN  serial (token) to remove
 *******************************************************************************
 */
void
_LSTransportSerialRemove(_LSTransportSerial *serial_info, LSMessageToken serial)
{
    SERIAL_INFO_LOCK(&serial_info->lock);

    _LSTransportSerialMapEntry *map_entry = g_hash_table_lookup(serial_info->map, &serial);

    if (map_entry)
    {
        _LSTransportSerialListItem *item = (_LSTransportSerialListItem*)map_entry->serial_list_item->data;
        g_queue_delete_link(serial_info->queue, map_entry->serial_list_item);
        _LSTransportSerialListItemFree(item);
        g_hash_table_remove(serial_info->map, &serial);
    }

    SERIAL_INFO_UNLOCK(&serial_info->lock);
}

/**
 *******************************************************************************
 * @brief Pops a message from the serial queue and removes it from the serial map.
 *
 * @attention locks the serial info lock
 *
 * @param  serial_info  IN  serial info
 *
 * @retval message on success
 * @retval NULL on empty serial queue
 *******************************************************************************
 */
_LSTransportMessage*
_LSTransportSerialPopHead(_LSTransportSerial *serial_info)
{
    _LSTransportMessage *message = NULL;
    SERIAL_INFO_LOCK(&serial_info->lock);

    _LSTransportSerialListItem *item = g_queue_pop_head(serial_info->queue);
    if (item)
    {
        message = item->message;
        _LSTransportMessageRef(message);
        g_hash_table_remove(serial_info->map, &item->serial);
        _LSTransportSerialListItemFree(item);
    }

    SERIAL_INFO_UNLOCK(&serial_info->lock);

    return message;
}

/* @} END OF LunaServiceTransportSerial */
