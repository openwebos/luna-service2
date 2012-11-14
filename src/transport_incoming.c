/* @@@LICENSE
*
*      Copyright (c) 2008-2012 Hewlett-Packard Development Company, L.P.
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

    if (incoming)
    {
        /* This cannot fail when using eglibc (2.15) */
        if (!pthread_mutex_init(&incoming->lock, NULL)) {
            g_slice_free(_LSTransportIncoming, incoming);
            return NULL;
        }
        incoming->complete_messages = g_queue_new();
        LS_ASSERT(incoming->complete_messages != 0);
    }
    return incoming;
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
