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


#include <string.h>

#include "error.h"
#include "transport_message.h"
#include "transport_outgoing.h"

/**
 * @defgroup LunaServiceTransportOutgoing
 * @ingroup LunaServiceTransport
 * @brief Transport outgoing queue
 */

/**
 * @addtogroup LunaServiceTransportOutgoing
 * @{
 */

/**
 *******************************************************************************
 * @brief Allocate a new outgoing queue.
 *
 * @retval  queue on success
 * @retval  NULL on failure
 *******************************************************************************
 */
_LSTransportOutgoing*
_LSTransportOutgoingNew(void)
{
    _LSTransportOutgoing *outgoing = g_slice_new0(_LSTransportOutgoing);

    if (pthread_mutex_init(&outgoing->lock, NULL))
    {
        LOG_LS_ERROR(MSGID_LS_MUTEX_ERR, 0, "Could not initialize mutex");
        goto error_before_mutex;
    }

    outgoing->queue = g_queue_new();
    outgoing->serial = _LSTransportSerialNew();
    if (!outgoing->serial)
    {
        LOG_LS_ERROR(MSGID_LS_SERIAL_ERROR, 0, "Could not initialize serial map");
        goto error;
    }

    return outgoing;

error:
    pthread_mutex_destroy(&outgoing->lock);

error_before_mutex:
    _LSTransportOutgoingFree(outgoing);
    return NULL;
}

/**
 *******************************************************************************
 * @brief Free an outgoing queue.
 *
 * @param  outgoing     IN  outgoing queue
 *******************************************************************************
 */
void
_LSTransportOutgoingFree(_LSTransportOutgoing *outgoing)
{
    LS_ASSERT(outgoing != NULL);
    LS_ASSERT(outgoing->queue != NULL);
    LS_ASSERT(outgoing->serial != NULL);

    while (!g_queue_is_empty(outgoing->queue))
    {
        _LSTransportMessage *message = g_queue_pop_head(outgoing->queue);
        _LSTransportMessageUnref(message);
    }
    g_queue_free(outgoing->queue);

    _LSTransportSerialFree(outgoing->serial);

#ifdef MEMCHECK
    memset(outgoing, 0xFF, sizeof(_LSTransportOutgoing));
#endif

    g_slice_free(_LSTransportOutgoing, outgoing);
}

/* @} END OF LunaServiceTransportOutgoing */
