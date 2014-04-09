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

#include "transport.h"
#include "transport_priv.h"
#include "transport_utils.h"
#include "log.h"
//#include "transport_client.h"

/**
 * @defgroup LunaServiceTransportClient
 * @ingroup LunaServiceTransport
 * @brief Transport client
 */

/**
 * @addtogroup LunaServiceTransportClient
 * @{
 */

/**
 *******************************************************************************
 * @brief Allocate a new client.
 *
 * @param  transport        IN  transport
 * @param  fd               IN  fd
 * @param  service_name     IN  client service name
 * @param  unique_name      IN  client unique name
 * @param  outgoing         IN  outgoing queue (NULL means allocate)
 * @param  initiator        IN  true if this is the end of the connection that initiated the connection
 *
 * @retval client on success
 * @retval NULL on failure
 *******************************************************************************
 */
_LSTransportClient*
_LSTransportClientNew(_LSTransport* transport, int fd, const char *service_name, const char *unique_name, _LSTransportOutgoing *outgoing, bool initiator)
{
    _LSTransportClient *new_client = g_slice_new0(_LSTransportClient);

    //new_client->sh = sh;
    new_client->service_name = g_strdup(service_name);
    new_client->unique_name = g_strdup(unique_name);
    new_client->transport = transport;
    new_client->state = _LSTransportClientStateInvalid;
    new_client->is_sysmgr_app_proxy = false;
    new_client->is_dynamic = false;
    new_client->initiator = initiator;

    _LSTransportChannelInit(transport, &new_client->channel, fd, transport->source_priority);

    new_client->cred = _LSTransportCredNew();

    /* Get pid, gid, and uid of client if we're local. It won't work for obvious
     * reasons if it's a TCP/IP connection */
    if (_LSTransportGetTransportType(transport) == _LSTransportTypeLocal)
    {
        LSError lserror;
        LSErrorInit(&lserror);

        if (!_LSTransportGetCredentials(fd, new_client->cred, &lserror))
        {
            LOG_LSERROR(MSGID_LS_TRANSPORT_NETWORK_ERR, &lserror);
            LSErrorFree(&lserror);
        }
    }

    if (outgoing)
    {
        new_client->outgoing = outgoing;
    }
    else
    {
        new_client->outgoing = _LSTransportOutgoingNew();
        if (!new_client->outgoing)
        {
            LOG_LS_ERROR(MSGID_LS_TRANSPORT_INIT_ERR, 0, "Could not allocate outgoing queue");
            goto error;
        }
    }

    new_client->incoming = _LSTransportIncomingNew();
    if (!new_client->incoming)
    {
        LOG_LS_ERROR(MSGID_LS_TRANSPORT_INIT_ERR, 0, "Could not allocate incoming queue");
        goto error;
    }

    return new_client;

error:

    g_free(new_client->service_name);
    g_free(new_client->unique_name);

    if (new_client->outgoing && !outgoing)
    {
        _LSTransportOutgoingFree(new_client->outgoing);
    }
    if (new_client->incoming)
    {
        _LSTransportIncomingFree(new_client->incoming);
    }
    g_slice_free(_LSTransportClient, new_client);

    return NULL;
}

/**
 *******************************************************************************
 * @brief Free a client.
 *
 * @param  client   IN  client
 *******************************************************************************
 */
void
_LSTransportClientFree(_LSTransportClient* client)
{
    g_free(client->unique_name);
    g_free(client->service_name);
    _LSTransportCredFree(client->cred);
    _LSTransportOutgoingFree(client->outgoing);
    _LSTransportIncomingFree(client->incoming);
    _LSTransportChannelClose(&client->channel, true);
    _LSTransportChannelDeinit(&client->channel);

#ifdef MEMCHECK
    memset(client, 0xFF, sizeof(_LSTransportClient));
#endif

    g_slice_free(_LSTransportClient, client);
}

/**
 *******************************************************************************
 * @brief Allocate a new client with a ref count of 1.
 *
 * @param  transport        IN  transport
 * @param  fd               IN  fd
 * @param  service_name     IN  client service name
 * @param  unique_name      IN  client unique name
 * @param  outgoing         IN  outgoing queue (NULL means allocate)
 * @param  initiator        IN  true if this is the end of the connection that initiated the connection
 *
 * @retval client on success
 * @retval NULL on failure
 *******************************************************************************
 */
_LSTransportClient*
_LSTransportClientNewRef(_LSTransport* transport, int fd, const char *service_name, const char *unique_name, _LSTransportOutgoing *outgoing, bool initiator)
{
    _LSTransportClient *client = _LSTransportClientNew(transport, fd, service_name, unique_name, outgoing, initiator);
    if (client)
    {
        client->ref = 1;
        LOG_LS_DEBUG("%s: %d (%p)\n", __func__, client->ref, client);
    }


    return client;
}

/**
 *******************************************************************************
 * @brief Increment the ref count of a client.
 *
 * @param  client   IN  client
 *******************************************************************************
 */
void
_LSTransportClientRef(_LSTransportClient *client)
{
    LS_ASSERT(client != NULL);
    LS_ASSERT(g_atomic_int_get(&client->ref) > 0);

    g_atomic_int_inc(&client->ref);

    LOG_LS_DEBUG("%s: %d (%p)\n", __func__, client->ref, client);
}

/**
 *******************************************************************************
 * @brief Decrement the ref count of a client.
 *
 * @param  client   IN  client
 *******************************************************************************
 */
void
_LSTransportClientUnref(_LSTransportClient *client)
{
    LS_ASSERT(client != NULL);
    LS_ASSERT(g_atomic_int_get(&client->ref) > 0);

    if (g_atomic_int_dec_and_test(&client->ref))
    {
        LOG_LS_DEBUG("%s: %d (%p)\n", __func__, client->ref, client);
        _LSTransportClientFree(client);
    }
    else
    {
        LOG_LS_DEBUG("%s: %d (%p)\n", __func__, client->ref, client);
    }
}

/**
 *******************************************************************************
 * @brief Get a client's unique name.
 *
 * @param  client   IN  client
 *
 * @retval  name on success
 * @retval  NULL on failure
 *******************************************************************************
 */
const char*
_LSTransportClientGetUniqueName(const _LSTransportClient *client)
{
    LS_ASSERT(client != NULL);
    return client->unique_name;
}

/**
 *******************************************************************************
 * @brief Get a client's service name.
 *
 * @param  client   IN  client
 *
 * @retval name on success
 * @retval NULL on failure
 *******************************************************************************
 */
const char*
_LSTransportClientGetServiceName(const _LSTransportClient *client)
{
    LS_ASSERT(client != NULL);
    return client->service_name;
}

/**
 *******************************************************************************
 * @brief Get the channel associated with this client. Does not ref count the
 * channel.
 *
 * @param  client   IN  client
 *
 * @retval  channel
 *******************************************************************************
 */
_LSTransportChannel*
_LSTransportClientGetChannel(_LSTransportClient *client)
{
    LS_ASSERT(client != NULL);
    return &client->channel;
}

_LSTransport*
_LSTransportClientGetTransport(const _LSTransportClient *client)
{
    LS_ASSERT(client != NULL);
    return client->transport;
}

/**
 *******************************************************************************
 * @brief Get credentials for the client.
 *
 * @param  client   IN  client
 *
 * @retval  credentials on success
 * @retval  NULL on failure
 *******************************************************************************
 */
const _LSTransportCred*
_LSTransportClientGetCred(const _LSTransportClient *client)
{
    LS_ASSERT(client != NULL);
    return client->cred;
}

/* @} END OF LunaServiceTransportClient */
