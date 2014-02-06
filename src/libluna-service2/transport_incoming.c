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
#include "transport_incoming.h"

/**
 * @defgroup LunaServiceTransportIncoming
 * @ingroup LunaServiceTransport
 * @brief Transport incoming queue
 */

/**
 * @addtogroup LunaServiceTransportIncoming
 * @{
 */

/**
 *******************************************************************************
 * @brief Allocate a new incoming queue.
 *
 * @retval  incoming queue on success
 * @retval  NULL on failure
 *******************************************************************************
 */
_LSTransportIncoming* _LSTransportIncomingNew(void)
{
    _LSTransportIncoming *incoming = g_slice_new0(_LSTransportIncoming);

    /* This cannot fail when using eglibc (2.15) */
    if (pthread_mutex_init(&incoming->lock, NULL))
    {
        LOG_LS_ERROR(MSGID_LS_MUTEX_ERR, 0, "Could not initialize mutex");
        goto error;
    }
    incoming->complete_messages = g_queue_new();

    return incoming;

error:
    _LSTransportIncomingFree(incoming);
    return NULL;
}

/**
 *******************************************************************************
 * @brief Free an incoming queue.
 *
 * @param  incoming IN incoming
 *******************************************************************************
 */
void _LSTransportIncomingFree(_LSTransportIncoming *incoming)
{
    LS_ASSERT(incoming != NULL);

    /* want to have processed all incoming messages so we don't lose any */
    LS_ASSERT(incoming->tmp_msg == NULL);
    LS_ASSERT(g_queue_is_empty(incoming->complete_messages));
    g_queue_free(incoming->complete_messages);

#ifdef MEMCHECK
    memset(incoming, 0xFF, sizeof(_LSTransportIncoming));
#endif

    g_slice_free(_LSTransportIncoming, incoming);
}

/* @} END OF LunaServiceTransportIncoming */
