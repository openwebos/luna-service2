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


#include <glib.h>

#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>

#include <luna-service2/lunaservice.h>
#include "lunaservice-custom-priv.h"

#include "base.h"
#include "message.h"
#include "transport_priv.h"

struct LSFetchQueue {
    GSList *sh_list;
    GSList *dispatch_iter;
    GMainContext *main_context;
};

struct LSCustomMessageQueue {
    pthread_mutex_t lock;
    GQueue *queue;
};

void LSCustomMessageQueuePush(LSCustomMessageQueue *q, _LSTransportMessage *message);
_LSTransportMessage* LSCustomMessageQueuePop(LSCustomMessageQueue *q);
bool LSCustomMessageQueueIsEmpty(LSCustomMessageQueue *q);

/**
 * @addtogroup LunaServiceMainloop
 *
 * @{
 */

/**
* @brief Get a glib mainloop context for service
*
* @param sh
* @param lserror
*
* @retval
*/
GMainContext * LSGmainGetContext(LSHandle *sh, LSError *lserror)
{
    _LSErrorIfFail(sh != NULL, lserror, MSGID_LS_INVALID_HANDLE);
    LSHANDLE_VALIDATE(sh);

    return sh->context;
}

/**
* @brief Attach a service to a glib mainloop
*
* @param sh
* @param mainContext
* @param lserror
*
* @retval
*/
bool LSGmainContextAttach(LSHandle *sh, GMainContext *mainContext, LSError *lserror)
{
    _LSErrorIfFail(sh != NULL, lserror, MSGID_LS_INVALID_HANDLE);
    LSHANDLE_VALIDATE(sh);

    _LSErrorIfFailMsg(mainContext != NULL, lserror, MSGID_LS_MAINCONTEXT_ERROR, -1,
                   "%s: %s", __FUNCTION__, ": No maincontext.");

    _LSTransportGmainAttach(sh->transport, mainContext);
    sh->context = g_main_context_ref(mainContext);

    return true;
}

/**
* @brief Attach a service to a glib mainloop.
*
* @param  sh
* @param  mainLoop
* @param  lserror
*
* @retval
*/
bool
LSGmainAttach(LSHandle *sh, GMainLoop *mainLoop, LSError *lserror)
{
    _LSErrorIfFail(mainLoop != NULL, lserror, MSGID_LS_MAINLOOP_ERROR);
    GMainContext *context = g_main_loop_get_context(mainLoop);
    return LSGmainContextAttach(sh, context, lserror);
}

bool LSGmainContextAttachPalmService(LSPalmService *psh, GMainContext *mainContext, LSError *lserror)
{
    _LSErrorIfFail(psh != NULL, lserror, MSGID_LS_INVALID_HANDLE);
    _LSErrorIfFail(mainContext != NULL, lserror, MSGID_LS_MAINCONTEXT_ERROR);

    bool retVal;
    retVal = LSGmainContextAttach(psh->public_sh, mainContext, lserror);
    if (!retVal) return retVal;
    retVal = LSGmainContextAttach(psh->private_sh, mainContext, lserror);
    if (!retVal) return retVal;

    return retVal;
}

bool
LSGmainAttachPalmService(LSPalmService *psh, GMainLoop *mainLoop, LSError *lserror)
{
    _LSErrorIfFail(mainLoop != NULL, lserror, MSGID_LS_MAINLOOP_ERROR);
    GMainContext *context = g_main_loop_get_context(mainLoop);
    return LSGmainContextAttachPalmService(psh, context, lserror);
}

/**
 * @brief Detach a service from a glib mainloop. You should NEVER use this
 * function unless you are fork()'ing without exec()'ing and know what you are
 * doing. This will perform nearly all the same cleanup as LSUnregister(), with
 * the exception that it will not send out shutdown messages or flush any
 * buffers. It is intended to be used only when fork()'ing so that your child
 * process can continue without interfering with the parent's file descriptors,
 * since open file descriptors are duplicated during a fork().
 *
 * @param  sh
 * @param  lserror
 *
 * @retval
 */
bool
LSGmainDetach(LSHandle *sh, LSError *lserror)
{
    _LSErrorIfFail(sh != NULL, lserror, MSGID_LS_INVALID_HANDLE);
    _LSErrorIfFailMsg(sh->context != NULL, lserror, MSGID_LS_MAINCONTEXT_ERROR, -1,
                      "%s: %s", __FUNCTION__, ": No maincontext.");

    /* We "unregister" without actually flushing or sending shutdown messages */
    return _LSUnregisterCommon(sh, false, LSHANDLE_GET_RETURN_ADDR(), lserror);
}

/**
 * @brief See LSGmainDetach(). This is the equivalent for a "PalmService"
 * handle.
 *
 * @param  psh          IN      PalmService handle
 * @param  lserror      OUT     set on error
 *
 * @retval  true on success
 * @retval  false on failure
 */
bool
LSGmainDetachPalmService(LSPalmService *psh, LSError *lserror)
{
    bool retVal;

    retVal = LSGmainDetach(psh->public_sh, lserror);
    if (!retVal) return retVal;
    retVal = LSGmainDetach(psh->private_sh, lserror);
    if (!retVal) return retVal;

    return retVal;
}

/**
* @brief Sets the priority level on the associated GSources for
*        the service connection.
*
*        This should be called after LSGmainAttach().
*
*        See glib documentation for GSource priority levels.
*
* @param  sh
* @param  lserror
*
* @retval
*/
bool
LSGmainSetPriority(LSHandle *sh, int priority, LSError *lserror)
{
    _LSErrorIfFail(sh != NULL, lserror, MSGID_LS_INVALID_HANDLE);

    LSHANDLE_VALIDATE(sh);

    return _LSTransportGmainSetPriority(sh->transport, priority, lserror);
}

bool
LSGmainSetPriorityPalmService(LSPalmService *psh, int priority, LSError *lserror)
{
    bool retVal;
    _LSErrorIfFail(psh != NULL, lserror, MSGID_LS_INVALID_HANDLE);

    if (psh->public_sh)
    {
        retVal = LSGmainSetPriority(psh->public_sh, priority, lserror);
        if (!retVal) return false;
    }
    if (psh->private_sh)
    {
        retVal = LSGmainSetPriority(psh->private_sh, priority, lserror);
        if (!retVal) return false;
    }
    return true;
}

/* @} END OF LunaServiceMainloop */

/**
 * @addtogroup LunaServiceCustomInternals
 * @{
 */

LSMessageHandlerResult
_LSCustomMessageHandler(_LSTransportMessage *message, void *context)
{
    /* add the messages to our internal queue */
    LSHandle *sh = (LSHandle*)context;
    _LSTransportMessageRef(message);
    LSCustomMessageQueuePush(sh->custom_message_queue, message);
    return LSMessageHandlerResultHandled;
}

/* @} END OF LunaServiceCustomInternals */

/**
 * @addtogroup LunaServiceCustom
 * @{
 */

/**
* @brief Wake up the user's custom mainloop.  Only works if you've
*        implented a custom mainloop via LSCustomGetFds()
*
* @param  sh
* @param  lserror
*
* @retval
*/
bool
LSCustomWakeUp(LSHandle *sh, LSError *lserror)
{
    LSHANDLE_VALIDATE(sh);

    g_main_context_wakeup(sh->transport->mainloop_context);

    return true;
}

LSCustomMessageQueue*
LSCustomMessageQueueNew(void)
{
    LSCustomMessageQueue *ret = g_new0(LSCustomMessageQueue, 1);

    if (pthread_mutex_init(&ret->lock, NULL))
    {
        LOG_LS_ERROR(MSGID_LS_MUTEX_ERR, 0, "Could not initialize mutex.");
        goto error;
    }
    ret->queue = g_queue_new();

    return ret;

error:
    LSCustomMessageQueueFree(ret);
    return NULL;
}

void
LSCustomMessageQueueFree(LSCustomMessageQueue *q)
{
    /* clean up any remaining messages on the queue */
    while (!g_queue_is_empty(q->queue))
    {
        _LSTransportMessage *message = g_queue_pop_head(q->queue);
        _LSTransportMessageUnref(message);
    }

    g_queue_free(q->queue);

#ifdef MEMCHECK
    memset(q, 0xFF, sizeof(LSCustomMessageQueue));
#endif

    g_free(q);
}

bool
LSCustomMessageQueueIsEmpty(LSCustomMessageQueue *q)
{
    bool ret;

    pthread_mutex_lock(&q->lock);
    ret = g_queue_is_empty(q->queue);
    pthread_mutex_unlock(&q->lock);

    return ret;
}

_LSTransportMessage*
LSCustomMessageQueuePop(LSCustomMessageQueue *q)
{
    /* lock queue */
    pthread_mutex_lock(&q->lock);

    _LSTransportMessage *ret = g_queue_pop_head(q->queue);

    /* unlock queue */
    pthread_mutex_unlock(&q->lock);

    if (ret) _LSTransportMessageUnref(ret);

    return ret;
}

void
LSCustomMessageQueuePush(LSCustomMessageQueue *q, _LSTransportMessage *message)
{
    _LSTransportMessageRef(message);

    /* lock queue */
    pthread_mutex_lock(&q->lock);

    g_queue_push_tail(q->queue, message);

    /* unlock queue */
    pthread_mutex_unlock(&q->lock);

}

/**
* @brief Block till incoming message is ready.  This should only be
*        called by custom mainloops.
*
* @param  sh
* @param  *message  allocated store of next message from queue, NULL if queue is empty.
*                   You MUST call LSMessageUnref() to free this message.
* @param  lserror
*
* @retval
*/
bool
LSCustomWaitForMessage(LSHandle *sh, LSMessage **message,
                               LSError *lserror)
{
    _LSErrorIfFail(sh != NULL, lserror, MSGID_LS_INVALID_HANDLE);
    _LSErrorIfFail(message != NULL, lserror, MSGID_LS_MSG_ERR);

    LSHANDLE_VALIDATE(sh);

    bool retVal;

    /* If the incoming queue contains messages, return immediately */
    retVal = LSCustomFetchMessage(sh, message, lserror);
    if (!retVal)
        return false;
    if (*message)
        return true;

    /* install custom message callback if not done already */
    if (G_UNLIKELY(sh->transport->msg_handler != _LSCustomMessageHandler))
    {
        sh->transport->msg_handler = _LSCustomMessageHandler;
        sh->transport->msg_context = sh;

        sh->transport->mainloop_context = g_main_context_new();

        _LSTransportAddInitialWatches(sh->transport, sh->transport->mainloop_context);
    }

    /*
     * Run an interation of the context: g_main_context_iteration, which
     * will call our special custom message callback and add to the queue of
     * messages
     */
    g_main_context_iteration(sh->transport->mainloop_context, TRUE);

    /* Fetch 1 message off incoming queue. */
    retVal = LSCustomFetchMessage(sh, message, lserror);
    if (!retVal) return false;

    return true;
}

bool
LSFetchQueueNew(LSFetchQueue **ret_fetch_queue)
{
    if (!ret_fetch_queue) return false;

    *ret_fetch_queue = g_new0(LSFetchQueue, 1);
    (*ret_fetch_queue)->main_context = g_main_context_new();

    return true;
}

// TODO
bool
LSFetchQueueWakeUp(LSFetchQueue *fq, LSError *lserror)
{
    if (!fq || !fq->sh_list)
    {
        _LSErrorSet(lserror, MSGID_LS_QUEUE_ERROR, -1, "LSFetchQueue not initialized.");
        return false;
    }

    LSHandle *sh = (LSHandle*)fq->sh_list->data;

    if (!sh)
    {
        _LSErrorSet(lserror, MSGID_LS_QUEUE_ERROR, -1, "No servers associated with FetchQueue.");
        return false;
    }

    g_main_context_wakeup(sh->transport->mainloop_context);
    return true;
}

void
LSFetchQueueFree(LSFetchQueue *fq)
{
    if (fq)
    {
        g_slist_free(fq->sh_list);
        g_main_context_unref(fq->main_context);

#ifdef MEMCHECK
        memset(fq, 0xFF, sizeof(LSFetchQueue));
#endif

        g_free(fq);
    }
}

void
LSFetchQueueAddConnection(LSFetchQueue *fq, LSHandle *sh)
{
    /* FIXME -- why is this getting called with NULL LSHandle? */
    if (fq && sh)
    {
        fq->sh_list = g_slist_prepend(fq->sh_list, sh);

        /* use custom message handler and attach context */
        if ((sh->transport->msg_handler != _LSCustomMessageHandler))
        {
            sh->transport->msg_handler = _LSCustomMessageHandler;
            sh->transport->msg_context = sh;
        }
        _LSTransportGmainAttach(sh->transport, fq->main_context);
    }
}

/*
 * This returns NULL or a ref'd message which you must unref when finished
 * with
 */
bool
LSFetchQueueWaitForMessage(LSFetchQueue *fq, LSMessage **ret_message,
                                 LSError *lserror)
{
    _LSErrorIfFail(fq != NULL, lserror, MSGID_LS_INVALID_HANDLE);
    _LSErrorIfFail(ret_message != NULL, lserror, MSGID_LS_MSG_ERR);

    GSList *iter;
    //int nfd = -1;
    bool do_iteration = true;

    /* If we have already pending data we don't want to block on the iteration
     * since there may not be any more data coming */
    for (iter = fq->sh_list; iter != NULL; iter = iter->next)
    {
        LSHandle *sh = (LSHandle*)iter->data;

        if (_FetchMessageQueueSize(sh) > 0 || !LSCustomMessageQueueIsEmpty(sh->custom_message_queue))
        {
            do_iteration = false;
            break;
        }
    }

    /*
     * Run an interation of the context: g_main_context_iteration, which
     * will call our special custom message callback and add to the queue of
     * messages
     */
    if (do_iteration)
    {
        g_main_context_iteration(fq->main_context, TRUE);
    }


    /**********
     * Dispatch
     **********/

    /* We treat the dispatch list like a circular list.  Stop when we see
     * the first message, or if we see the first element.
     *
     * This avoids starvation of any single connection.
     */
    if (!fq->dispatch_iter)
    {
        fq->dispatch_iter = fq->sh_list;
    }

    GSList *first = fq->dispatch_iter;
    LSMessage *message = NULL;

    while (fq->dispatch_iter != NULL)
    {
        LSHandle *sh = (LSHandle*)fq->dispatch_iter->data;

        /* Fetch 1 message off incoming queue. */
        if (!LSCustomFetchMessage(sh, &message, lserror))
        {
            LOG_LS_WARNING(MSGID_LS_MSG_ERR, 0, "LSCustomFetchMessage returned false.");
            return false;
        }

        /* Get next connection. */
        fq->dispatch_iter = fq->dispatch_iter->next;
        if (!fq->dispatch_iter)
        {
            fq->dispatch_iter = fq->sh_list;
        }

        if (fq->dispatch_iter == first)
        {
            fq->dispatch_iter = NULL;
        }

        /* Found a message! return it to user */
        if (message != NULL) break;
    }

    *ret_message = message;

    return true;
}

/**
* @brief Pop a message from the incoming queue, non blocking.  This should
*        only be called by custom mainloops.  Do NOT call this if you intend
*        to use callback tables registered by LSRegisterCategory().
*
*        To dispatch to callback tables use LSCustomDispatchMessage()
*        instead.
*
* @param  sh
* @param  *ret_message  allocated store of next message from queue, NULL if queue is empty.
*                   You MUST call LSMessageUnref() to free this message.
* @param  lserror
*
* @retval
*/
bool
LSCustomFetchMessage(LSHandle *sh, LSMessage **ret_message,
               LSError *lserror)
{
    LSHANDLE_VALIDATE(sh);

    return _FetchMessageQueueGet(sh, ret_message, lserror);
}

/* @} END OF LunaServiceCustom */
