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
#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>
#include <glib.h>
#include <cjson/json.h>

#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#define NOGDI
#include <winsock2.h>
#else
#include <sys/select.h>
#endif

#include "lunaservice-errors.h"

#ifndef _LUNASERVICE_H_
#define _LUNASERVICE_H_

#define LS_DEPRECATED   __attribute__ ((deprecated))

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @page
 * @addtogroup LunaServiceExample
 *
 * <h1>LunaService</h1>
 *
 * <em>Example client usage:</em>
 *
@code
bool retVal;
LSError lserror;
LSErrorInit(&lserror);

LSHandle *serviceHandle;
retVal = LSRegister(NULL, &serviceHandle, &lserror);
if (!retVal) goto error;

retVal = LSCall(serviceHandle, "luna://com.palm.contacts/category/listContacts",
        "{ \"json payload\" }", listContactsHandler, user_data, &token, &lserror);
if (!retVal) goto error;

LSGmainAttach(serviceHandle, gmainLoop, &lserror); 
g_main_loop_run(gmainLoop);
@endcode


<em>Example service usage.</em>

@code
// callback
static bool
listContacts(LSHandle *sh, LSMessage *message)
{
     LSMessage *reply = NULL;

     bool retVal;
     LSError lserror;
     LSErrorInit(&lserror);

     retVal = LSMessageReply(sh, message, "{ JSON REPLY PAYLOAD }", &lserror);
     if (!retVal)
     {
         LSErrorPrint(&lserror, stderr);
         LSErrorFree(&lserror);
     }

     return retVal;
}

static LSMethod ipcMethods[] = {
   { "listContacts", listContacts },
   { },
};
...

// Service registration thread
bool retVal;
LSError lserror;
LSErrorInit(&lserror);

LSHandle *serviceHandle;
retVal = LSRegister("com.palm.contacts", &serviceHandle, &lserror);
if (!retVal) goto error;

retVal = LSRegisterCategory(serviceHandle, "/category",  ipcMethods, NULL, NULL, &lserror);
if (!retVal) goto error;

retVal = LSGmainAttach(serviceHandle, gmainLoop, &lserror); 
if (!retVal) goto error;

g_main_loop_run(gmainLoop);
@endcode

<em>Storing a message for replying in another thread.</em>
@code

Queue messageQueue;
...

static bool
listContacts(LSHandle *sh, LSMessage *message)
{
     bool retVal;

     LSError lserror;
     LSErrorInit(&lserror);

     LSMessageRef(message);

     queue(messageQueue, message);
}

...

void
SomeOtherThread()
{
    LSError lserror;
    LSErrorInit(&lserror);

    LSMessage *message = dequeue(messageQueue);
    ...
    if (!LSMessageReply(sh, message, "{PAYLOAD IN JSON}", lserror))
    {
        LSErrorPrint(&lserror);
        LSErrorFree(&lserror);
    }

    ....
}

@endcode

<em>Example run loop via select.  See LSCustomSelectExample() for
latest example.</em>

@code

bool retVal;

do
{
    int nfd = -1;
    fd_set rdfds, wrfds, exfds;

    FD_ZERO(&rdfds);
    FD_ZERO(&wrfds);
    FD_ZERO(&exfds);

    retVal = LSCustomGetFds(sh, &nfd, &rdfds, &wrfds, &exfds, lserror);
    if (!retVal) return -1;

    int ret = select(nfd, &rdfds, &wrfds, &exfds, NULL);
    if (ret < 0) 
    {
        perror("select");
        break;
    }

    // Pull incoming bytes off socket and push outgoing bytes onto it.
    retVal = LSCustomSendRecvBytes(sh, &rdfds, &wrfds, &exfds, lserror);
    if (!retVal)
    {
        break;
    }

    // Transmit byte and Dispatch incomming at most 1 message
    retVal = LSCustomDispatchMessage(sh, NULL, lserror); 
    if (!retVal)
    {
        break;
    }

} while (true);

@endcode

<em>Example run loop via select if you want to handle messages directly.</em>

@code

while (serviceRunning)
{
    fd_set rdfds, wrfds, exfds;
    FD_ZERO(&rdfds);
    FD_ZERO(&wrfds);
    FD_ZERO(&exfds);

    LSGetFd(serviceHandle, &maxfd, &rdfds, &wrfds, &exfds, &lserror);

    ret = select(maxfd, &rdfds, &wrfds, &exfds, NULL);
    if (ret > 0)
    {
        LSMessage *message;
        char *reply = NULL;

        LSMessageFetch(serviceHandle, &message, &lserror);

        if (strcmp(LSMessageGetName(message), "listContacts"))
        {
            char *payload;
            payload = LSMessageGetPayload(message);
            ...
            reply = "{ JSON PAYLOAD }";
            LSMessageReply(serviceHandle, message, reply, &lserror);
        }
    }
}

@endcode
 */

/**
 * @addtogroup LunaService
 * @{
 */

/**
 * @brief Signal category for control messages from the hub
 */
#define HUB_CONTROL_CATEGORY            "/com/palm/hub/control"

/**
 * @brief Signal method that hub emits when the config files scanning
 * has been completed
 */
#define HUB_CONF_SCAN_COMPLETE_METHOD    "configScanComplete"

typedef unsigned long LSMessageToken;

/**
 * @brief Invalid token number.
 *
 * This is seen if you do LSMessageGetResponseToken() on a message that is not
 * a reply.  It is also a good neutral value to initialize an array of
 * unitialized message tokens.
 */
#define LSMESSAGE_TOKEN_INVALID 0

/** 
* @brief Error object which contains information about first
*        error since it was initialized via LSErrorInit. 
*/
struct LSError {
    int   error_code;  /**< public error code */
    char *message;     /**< public error message */

    const char *file;  /**< file in which error happened. */
    int         line;  /**< line on which error happened. */
    const char *func;  /**< function on which error happened. */

    void       *padding;  /**< Reserved for future use */
    unsigned long magic;  /**< use as cookie to detect invalid LSErrors  */
};

typedef struct LSError  LSError;

/** 
* @brief Handle to service.
*/
typedef struct LSHandle LSHandle;

/** 
* @brief Handle to public service.
*/
typedef struct LSPalmService LSPalmService;

/** 
* @brief Message object.
*/
typedef struct LSMessage        LSMessage;

/**
 * Table registration of callbacks.
 */

/** 
* @brief Type for method callbacks.
* 
* @param  *LSMethodFunction 
* @param  sh 
* @param  msg 
* 
* @retval true if message successfully processed.
* @retval false if some error occurred and you would like the callback to
*               be called again later.
*/
typedef bool (*LSMethodFunction) (LSHandle *sh, LSMessage *msg, void *category_context);


/** 
* @brief Type for property get callback.
* 
* @param  *LSPropertyGetFunction 
* @param  sh 
* @param  msg 
* 
* @retval Same as LSMethodFunction()
*/
typedef bool (*LSPropertyGetFunction) (LSHandle *sh, LSMessage *msg, void *category_context);

/** 
* @brief Type for property set callback.
* 
* @param  *LSPropertySetFunction 
* @param  sh 
* @param  msg 
* 
* @retval Same as LSMethodFunction()
*/
typedef bool (*LSPropertySetFunction) (LSHandle *sh, LSMessage *msg, void *category_context);

/** 
* @brief Method flags
*/
typedef enum {
	LUNA_METHOD_FLAG_DEPRECATED = (1 << 0),
} LSMethodFlags;

/**
 * @brief Signal flags
 */
typedef enum {
	LUNA_SIGNAL_FLAG_DEPRECATED = (1 << 0),
} LSSignalFlags;

/**
 * @brief Property flags
 */
typedef enum {
	LUNA_PROPERTY_FLAG_DEPRECATED = (1 << 0),
} LSPropertyFlags;

typedef struct {
    const char *name;		      /**< Method name */
	LSMethodFunction function;  /**< Method function */
	LSMethodFlags flags;		  /**< Method flags */
} LSMethod;

typedef struct {
	const char *name;		    /**<Signal name */
	LSSignalFlags flags;		/**<Signal flags */
} LSSignal;

typedef struct {
	const char *name;		/**<Property name */
	const char *type;		/**<Property value type */
	LSPropertyGetFunction get;	/**<Property get function */
	LSPropertySetFunction set;	/**<Property set function */
	LSPropertyFlags flags;	/**<Property flags */
} LSProperty;

/* @} END OF LunaService */

/**
 * @addtogroup LunaServiceError
 * @{
 */

/* LSError exception style functions */

bool LSErrorInit(LSError *error);
void LSErrorFree(LSError *error);

bool LSErrorIsSet(LSError *lserror);

void LSErrorPrint(LSError *lserror, FILE *out);

/* @} END OF LunaServiceError */

/**
 * @addtogroup LunaServiceRegistration
 * @{
 */

/* Luna Service general functions */

bool LSRegister(const char *name, LSHandle **sh,
                  LSError *lserror);

bool LSRegisterPubPriv(const char *name, LSHandle **sh,
                  bool public_bus,
                  LSError *lserror);

typedef void (*LSDisconnectHandler)(LSHandle *sh, void *user_data);
bool LSSetDisconnectHandler(LSHandle *sh, LSDisconnectHandler disconnect_handler,
                    void *user_data, LSError *lserror);

bool LSRegisterCategory(LSHandle *sh, const char *category,
                   LSMethod      *methods,
                   LSSignal      *langis,
                   LSProperty    *properties, LSError *lserror);

bool LSRegisterCategoryAppend(LSHandle *sh, const char *category,
                   LSMethod      *methods,
                   LSSignal      *langis,
                   LSError *lserror);

bool LSCategorySetData(LSHandle *sh, const char *category,
                       void *user_data, LSError *lserror);

bool LSUnregister(LSHandle *service, LSError *lserror);

const char * LSHandleGetName(LSHandle *sh);

/* Palm Services */

bool LSRegisterPalmService(const char *name,
                  LSPalmService **ret_palm_service,
                  LSError *lserror);

bool LSUnregisterPalmService(LSPalmService *psh, LSError *lserror);

bool LSPalmServiceRegisterCategory(LSPalmService *psh,
    const char *category,
    LSMethod *methods_public, LSMethod *methods_private,
    LSSignal *langis, void *category_user_data, LSError *lserror);

LSHandle * LSPalmServiceGetPrivateConnection(LSPalmService *psh);
LSHandle * LSPalmServiceGetPublicConnection(LSPalmService *psh);

bool LSPushRole(LSHandle *sh, const char *role_path, LSError *lserror);
bool LSPushRolePalmService(LSPalmService *psh, const char *role_path, LSError *lserror);

/* @} END OF LunaServiceRegistration */

/**
 * @addtogroup LunaServiceMessage
 * @{
 */

/* LSMessage (Luna Service Message) functions */

LSHandle * LSMessageGetConnection(LSMessage *message);
bool LSMessageIsPublic(LSPalmService *psh, LSMessage *message);

void LSMessageRef(LSMessage *message);
void LSMessageUnref(LSMessage *message);

bool LSMessagePrint(LSMessage *lmsg, FILE *out);
bool LSMessageIsHubErrorMessage(LSMessage *message);

const char * LSMessageGetUniqueToken(LSMessage *message);
const char * LSMessageGetKind(LSMessage *message);

const char * LSMessageGetApplicationID(LSMessage *message);

const char * LSMessageGetSender(LSMessage *message);
const char * LSMessageGetSenderServiceName(LSMessage *message);
const char * LSMessageGetCategory(LSMessage *message);
const char * LSMessageGetMethod(LSMessage *message);

const char * LSMessageGetPayload(LSMessage *message);

bool LSMessageIsSubscription(LSMessage *lsmgs);

LSMessageToken LSMessageGetToken(LSMessage *call);
LSMessageToken LSMessageGetResponseToken(LSMessage *reply);

bool LSMessageRespond(LSMessage *message, const char *reply_payload,
                LSError *lserror);

bool LSMessageReply(LSHandle *sh, LSMessage *lsmsg, const char *replyPayload,
                LSError *lserror);

/* @} END OF LunaServiceMessage */

/**
 * @addtogroup LunaServiceMainloop
 * @{
 */

/* Mainloop integration functions. */

bool LSGmainAttach(LSHandle *sh, GMainLoop *mainLoop, LSError *lserror);

bool LSGmainAttachPalmService(LSPalmService *psh,
                           GMainLoop *mainLoop, LSError *lserror);

bool LSGmainDetach(LSHandle *sh, LSError *lserror);

bool LSGmainSetPriority(LSHandle *sh, int priority, LSError *lserror);

bool LSGmainSetPriorityPalmService(LSPalmService *psh, int priority, LSError *lserror);

/* @} END OF LunaServiceMainloop */

/**
 * @addtogroup LunaServiceClient
 * @{
 */


/** 
* @brief Function callback to be called when serviceName connects/disconnects.
* 
* @param  sh             service handle
* @param  serviceName    name of service that was brought up/down.
* @param  connected      service was brought up if true.
* 
* @retval
*/
typedef bool (*LSServerStatusFunc) (LSHandle *sh, const char *serviceName,
                                  bool connected,
                                  void *ctx);

/** 
* @brief Callback function called on incomming message.
* 
* @param  sh             service handle
* @param  reply          reply message
* @param  void *         context 
* 
* @retval true if message is handled.
*/
typedef bool (*LSFilterFunc) (LSHandle *sh, LSMessage *reply, void *ctx);

bool LSCall(LSHandle *sh, const char *uri, const char *payload,
       LSFilterFunc callback, void *user_data,
       LSMessageToken *ret_token, LSError *lserror);

bool LSCallOneReply(LSHandle *sh, const char *uri, const char *payload,
       LSFilterFunc callback, void *ctx,
       LSMessageToken *ret_token, LSError *lserror);

bool LSCallFromApplication(LSHandle *sh, const char *uri, const char *payload,
       const char *applicationID,
       LSFilterFunc callback, void *ctx,
       LSMessageToken *ret_token, LSError *lserror);

bool LSCallFromApplicationOneReply(
       LSHandle *sh, const char *uri, const char *payload,
       const char *applicationID,
       LSFilterFunc callback, void *ctx,
       LSMessageToken *ret_token, LSError *lserror);

bool LSCallCancel(LSHandle *sh, LSMessageToken token, LSError *lserror);

/* @} END OF LunaServiceClient */

/**
 * @addtogroup LunaServiceSubscription
 * @{
 */
typedef struct LSSubscriptionIter LSSubscriptionIter;

bool LSSubscriptionProcess (LSHandle *sh, LSMessage *message, bool *subscribed,
                LSError *lserror);

bool LSSubscriptionSetCancelFunction(LSHandle *sh,
                                LSFilterFunc cancelFunction,
                                void *ctx, LSError *lserror);

bool LSSubscriptionAdd(LSHandle *sh, const char *key,
                  LSMessage *message, LSError *lserror);

bool LSSubscriptionAcquire(LSHandle *sh, const char *key,
                  LSSubscriptionIter **ret_iter, LSError *lserror);

void LSSubscriptionRelease(LSSubscriptionIter *iter);

bool LSSubscriptionHasNext(LSSubscriptionIter *iter);

LSMessage *LSSubscriptionNext(LSSubscriptionIter *iter);

void LSSubscriptionRemove(LSSubscriptionIter *iter);

bool LSSubscriptionReply(LSHandle *sh, const char *key,
                    const char *payload, LSError *lserror);

bool LSSubscriptionRespond(LSPalmService *psh, const char *key,
                      const char *payload, LSError *lserror);

bool LSSubscriptionPost(LSHandle *sh, const char *category,
        const char *method,
        const char *payload, LSError *lserror);

/* @} END OF LunaServiceSubscription */

/**
 * @addtogroup LunaServiceSignals
 * @{
 */

bool LSSignalSend(LSHandle *sh, const char *uri, const char *payload,
             LSError *lserror);

bool LSSignalSendNoTypecheck(LSHandle *sh,
            const char *uri, const char *payload, LSError *lserror);

bool LSSignalCall(LSHandle *sh,
         const char *category, const char *methodName, 
         LSFilterFunc filterFunc, void *ctx,
         LSMessageToken *ret_token,
         LSError *lserror);

bool LSSignalCallCancel(LSHandle *sh, LSMessageToken token, LSError *lserror);


bool LSRegisterServerStatus(LSHandle *sh, const char *serviceName,
              LSServerStatusFunc func, void *ctx, LSError *lserror);


/* @} END OF LunaServiceSignals */



#ifdef __cplusplus
} // extern "C"
#endif

#endif //_LUNASERVICE_H_
