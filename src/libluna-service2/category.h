/****************************************************************
 * @@@LICENSE
 *
 * Copyright (c) 2014 LG Electronics, Inc.
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
 * LICENSE@@@
 ****************************************************************/

/**
 *  @file category.h
 */

#ifndef __CATEGORY_H
#define __CATEGORY_H

#include <pbnjson.h>

#include "base.h"
#include "error.h"
#include "clock.h"

#include <pmtrace_ls2.h>

/**
 * @addtogroup LunaServiceInternals
 * @{
 */

/**
* @brief
*/
struct LSCategoryTable {

    LSHandle       *sh;

    GHashTable     *methods;
    GHashTable     *signals;
    GHashTable     *properties;

    void           *category_user_data;
    jvalue_ref     description;
};

typedef struct LSCategoryTable LSCategoryTable;

typedef struct {
    LSMethodFunction function;  /**< Method function */
    LSMethodFlags flags;        /**< Method flags */
    jschema_ref schema_call;
    jschema_ref schema_firstReply;
    jschema_ref schema_reply;
} LSMethodEntry;

bool LSCategoryValidateCall(LSMethodEntry *entry, LSMessage *message);

static inline LSMessageHandlerResult LSCategoryMethodCall(
    LSHandle *sh,
    LSCategoryTable *category,
    const char *service_name,
    LSMessage *message
)
{
    const char* method_name = LSMessageGetMethod(message);

    /* find the method in the tableHandlers->methods hash */
    LSMethodEntry *method = g_hash_table_lookup(category->methods, method_name);

    if (!method)
    {
        LOG_LS_ERROR(MSGID_LS_NO_METHOD, 1,
                     PMLOGKS("METHOD", method_name),
                     "Couldn't find method: %s", method_name);
        return LSMessageHandlerResultUnknownMethod;
    }
    bool validateCall = method->flags & LUNA_METHOD_FLAG_VALIDATE_IN;

    /* XXX: work-around clients that puts garbage in method flags */
    if (unlikely(validateCall && method->schema_call == NULL))
    {
        validateCall = false;
        LOG_LS_ERROR(MSGID_LS_BAD_VALIDATION_FLAG, 5,
                     PMLOGKS("SENDER", LSMessageGetSenderServiceName(message)),
                     PMLOGKS("SERVICE", service_name),
                     PMLOGKS("CATEGORY", LSMessageGetCategory(message)),
                     PMLOGKS("METHOD", method_name),
                     PMLOGKFV("FLAGS", "%d", method->flags),
                     "Called for method that was declared for validation but wasn't supplied with schema");
    }

    bool validCall = !validateCall || LSCategoryValidateCall(method, message);

    // pmtrace point before call a handler
    PMTRACE_SERVER_RECEIVE(service_name, sh->name, (char*)method_name, LSMessageGetToken(message));

    struct timespec start_time, end_time, gap_time;
    if (DEBUG_TRACING)
    {
        ClockGetTime(&start_time);
    }
    bool handled;

    if (!validCall) /* validation error were sent */
    { handled = true; }
    else if (method->function == NULL) /* no callback were set? */
    { handled = false; }
    else
    { handled = method->function(sh, message, category->category_user_data); }

    if (DEBUG_TRACING)
    {
        ClockGetTime(&end_time);
        ClockDiff(&gap_time, &end_time, &start_time);
        LOG_LS_DEBUG("TYPE=service handler execution time | TIME=%ld | SERVICE=%s | CATEGORY=%s | METHOD=%s",
                ClockGetMs(&gap_time), sh->name, LSMessageGetCategory(message), method_name);
    }

    // pmtrace point after handler
    PMTRACE_SERVER_REPLY(service_name, sh->name, (char*)method_name, LSMessageGetToken(message));

    if (!handled)
    {
        LOG_LS_WARNING(MSGID_LS_MSG_NOT_HANDLED, 1,
                       PMLOGKS("METHOD", method_name),
                       "Method wasn't handled!");
        return LSMessageHandlerResultNotHandled;
    }

    return LSMessageHandlerResultHandled;
}

/* @} END OF LunaServiceInternals */

#endif
