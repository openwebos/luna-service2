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


#include "debug_methods.h"
#include "subscription.h"
#include "base.h"

#ifdef MALLOC_DEBUG
#include <malloc.h>
#define __USE_GNU
#include <dlfcn.h>
#endif

#include <string.h>

#ifdef SUBSCRIPTION_DEBUG
bool
_LSPrivateGetSubscriptions(LSHandle* sh, LSMessage *message, void *ctx)
{
    LSError lserror;
    LSErrorInit(&lserror);

    const char *sender = LSMessageGetSenderServiceName(message);

    if (!sender || strcmp(sender, MONITOR_NAME) != 0)
    {
        g_critical("WARNING: subscription debug method not called by monitor;"
                   " ignoring (service name: %s, unique_name: %s)",
                   sender, LSMessageGetSender(message));
        return true;
    }

    struct json_object *ret_obj = NULL;
    bool json_ret = _LSSubscriptionGetJson(sh, &ret_obj, &lserror);
    if (!json_ret)
    {
        LSErrorPrint(&lserror, stderr);
        LSErrorFree(&lserror);
        return true;
    }

    bool reply_ret = LSMessageReply(sh, message, json_object_to_json_string(ret_obj), &lserror);
    if (!reply_ret)
    {
        g_critical("%s: sending subscription info failed", __FUNCTION__);
        LSErrorPrint(&lserror, stderr);
        LSErrorFree(&lserror);
    }

    json_object_put(ret_obj);
    
    return true;

}
#endif  /* SUBSCRIPTION_DEBUG */

#ifdef MALLOC_DEBUG
bool
_LSPrivateGetMallinfo(LSHandle* sh, LSMessage *message, void *ctx)
{
    LSError lserror;
    LSErrorInit(&lserror);

    struct json_object *ret_obj = NULL;
    struct json_object *true_obj = NULL;
    struct json_object *mallinfo_obj = NULL;
    struct json_object *allocator_name_obj = NULL;
    struct json_object *slot_a_obj = NULL;
    struct json_object *slot_d_obj = NULL;
    struct json_object *slot_e_obj = NULL;
    struct json_object *slot_f_obj = NULL;
    struct json_object *slot_h_obj = NULL;
    struct json_object *slot_i_obj = NULL;
    struct json_object *slot_j_obj = NULL;

    const char *sender = LSMessageGetSenderServiceName(message);

    if (!sender || strcmp(sender, MONITOR_NAME) != 0)
    {
        g_critical("WARNING: mallinfo debug method not called by monitor;"
                   " ignoring (service name: %s, unique_name: %s)",
                   sender, LSMessageGetSender(message));
        return true;
    }

    ret_obj = json_object_new_object();
    if (JSON_ERROR(ret_obj)) goto error;
       
    true_obj = json_object_new_boolean(true);
    if (JSON_ERROR(true_obj)) goto error;
 
    mallinfo_obj = json_object_new_object();
    if (JSON_ERROR(mallinfo_obj)) goto error;

    /* returnValue: true,
     * mallinfo: {key: int,...}
     */

    typedef struct mallinfo (*mallinfo_t)();
    static mallinfo_t mallinfo_p = NULL;

    if (mallinfo_p == NULL) {
        mallinfo_p = (mallinfo_t)dlsym(RTLD_DEFAULT, "mallinfo");
        if (mallinfo_p == NULL)
            mallinfo_p = (mallinfo_t)-1;
    }
    struct mallinfo mi;
    if (mallinfo_p != (mallinfo_t)-1) {
        mi = mallinfo_p();
    } else {
        memset(&mi, '\0', sizeof(mi));
    }
    
    allocator_name_obj = json_object_new_string("ptmalloc");
    if (JSON_ERROR(allocator_name_obj)) goto error;

    slot_a_obj = json_object_new_int(mi.arena);
    if (JSON_ERROR(slot_a_obj)) goto error;

    slot_d_obj = json_object_new_int(mi.hblks);
    if (JSON_ERROR(slot_d_obj)) goto error;

    slot_e_obj = json_object_new_int(mi.hblkhd);
    if (JSON_ERROR(slot_e_obj)) goto error;

    slot_f_obj = json_object_new_int(mi.usmblks);
    if (JSON_ERROR(slot_f_obj)) goto error;

    slot_h_obj = json_object_new_int(mi.uordblks);
    if (JSON_ERROR(slot_h_obj)) goto error;

    slot_i_obj = json_object_new_int(mi.fordblks);
    if (JSON_ERROR(slot_i_obj)) goto error;
    
    slot_j_obj = json_object_new_int(mi.keepcost);
    if (JSON_ERROR(slot_j_obj)) goto error;

    json_object_object_add(mallinfo_obj, "allocator", allocator_name_obj);
    json_object_object_add(mallinfo_obj, "sbrk_bytes", slot_a_obj);
    json_object_object_add(mallinfo_obj, "mmap_count", slot_d_obj);
    json_object_object_add(mallinfo_obj, "mmap_bytes", slot_e_obj);
    json_object_object_add(mallinfo_obj, "max_malloc_bytes", slot_f_obj);
    json_object_object_add(mallinfo_obj, "malloc_bytes", slot_h_obj);
    json_object_object_add(mallinfo_obj, "slack_bytes", slot_i_obj);
    json_object_object_add(mallinfo_obj, "trimmable_slack_bytes", slot_j_obj);
        
    json_object_object_add(ret_obj, "returnValue", true_obj);
    json_object_object_add(ret_obj, "mallinfo", mallinfo_obj);

    bool reply_ret = LSMessageReply(sh, message, json_object_to_json_string(ret_obj), &lserror);
    if (!reply_ret)
    {
        g_critical("%s: sending malloc info failed", __FUNCTION__);
        LSErrorPrint(&lserror, stderr);
        LSErrorFree(&lserror);
    }

    json_object_put(ret_obj);
    
    return true;

error:
    
    if (!JSON_ERROR(ret_obj)) json_object_put(ret_obj);
    if (!JSON_ERROR(true_obj)) json_object_put(true_obj);
    if (!JSON_ERROR(mallinfo_obj)) json_object_put(mallinfo_obj);
    
    if (!JSON_ERROR(allocator_name_obj)) json_object_put(allocator_name_obj);
    if (!JSON_ERROR(slot_a_obj)) json_object_put(slot_a_obj);
    if (!JSON_ERROR(slot_d_obj)) json_object_put(slot_d_obj);
    if (!JSON_ERROR(slot_e_obj)) json_object_put(slot_e_obj);
    if (!JSON_ERROR(slot_f_obj)) json_object_put(slot_f_obj);
    if (!JSON_ERROR(slot_h_obj)) json_object_put(slot_h_obj);
    if (!JSON_ERROR(slot_i_obj)) json_object_put(slot_i_obj);
    if (!JSON_ERROR(slot_j_obj)) json_object_put(slot_j_obj);
    
    return true;
}

bool
_LSPrivateDoMallocTrim(LSHandle* sh, LSMessage *message, void *ctx)
{
    LSError lserror;
    LSErrorInit(&lserror);

    struct json_object *ret_obj = NULL;
    struct json_object *true_obj = NULL;
    struct json_object *malloc_trim_obj = NULL;

    ret_obj = json_object_new_object();
    if (JSON_ERROR(ret_obj)) goto error;
       
    true_obj = json_object_new_boolean(true);
    if (JSON_ERROR(true_obj)) goto error;
 

    /* returnValue: true,
     * malloc_trim: int
     */

    typedef int (*malloc_trim_t)(size_t);
    static malloc_trim_t malloc_trim_p = NULL;

    if (malloc_trim_p == NULL) {
        malloc_trim_p = (malloc_trim_t)dlsym(RTLD_DEFAULT, "malloc_trim");
        if (malloc_trim_p == NULL)
            malloc_trim_p = (malloc_trim_t)-1;
    }
    
    int result;
    if (malloc_trim_p != (malloc_trim_t)-1) {
        result = malloc_trim_p(0);
    } else {
        result = -1;
    }

    malloc_trim_obj = json_object_new_int(result);
    if (JSON_ERROR(malloc_trim_obj)) goto error;
        
    json_object_object_add(ret_obj, "returnValue", true_obj);
    json_object_object_add(ret_obj, "malloc_trim", malloc_trim_obj);

    bool reply_ret = LSMessageReply(sh, message, json_object_to_json_string(ret_obj), &lserror);
    if (!reply_ret)
    {
        g_critical("%s: sending malloc trim result failed", __FUNCTION__);
        LSErrorPrint(&lserror, stderr);
        LSErrorFree(&lserror);
    }

    json_object_put(ret_obj);
    
    return true;

error:
    
    if (!JSON_ERROR(ret_obj)) json_object_put(ret_obj);
    if (!JSON_ERROR(true_obj)) json_object_put(true_obj);
    if (!JSON_ERROR(malloc_trim_obj)) json_object_put(malloc_trim_obj);
    
    return true;
}
#endif  /* MALLOC_DEBUG */

#ifdef INTROSPECTION_DEBUG
bool
_LSPrivateInrospection(LSHandle* sh, LSMessage *message, void *ctx)
{
    LSError lserror;
    LSErrorInit(&lserror);

    GHashTableIter iter_category, iter_element;
    gpointer name_category, table_category, name_element, callback;
    struct LSCategoryTable *pTable = NULL;

    struct json_object *ret_obj = NULL;
    struct json_object *category_obj = NULL;
    struct json_object *element_obj = NULL;

    ret_obj = json_object_new_object();

    g_hash_table_iter_init(&iter_category, sh->tableHandlers);
    while (g_hash_table_iter_next(&iter_category, &name_category, &table_category))
    {
        // skip hidden method
        if (strcmp("/com/palm/luna/private", name_category) == 0)
            continue;

        pTable = (struct LSCategoryTable *)table_category;
        category_obj = json_object_new_object();

        // methods
        g_hash_table_iter_init(&iter_element, pTable->methods);
        while (g_hash_table_iter_next(&iter_element, &name_element, &callback))
        {
            element_obj = json_object_new_string("METHOD");
            json_object_object_add(category_obj, name_element, element_obj);
        }

        // signals
        g_hash_table_iter_init(&iter_element, pTable->signals);
        while (g_hash_table_iter_next(&iter_element, &name_element, &callback))
        {
            element_obj = json_object_new_string("SIGNAL");
            json_object_object_add(category_obj, name_element, element_obj);
        }

        json_object_object_add(ret_obj, name_category, category_obj);
    }

    bool reply_ret = LSMessageReply(sh, message, json_object_to_json_string(ret_obj), &lserror);
    if (!reply_ret)
    {
        g_critical("%s: sending introspection data failed", __FUNCTION__);
        LSErrorPrint(&lserror, stderr);
        LSErrorFree(&lserror);
        goto error;
    }

    json_object_put(ret_obj);

    return true;

error:

    if (!JSON_ERROR(ret_obj)) json_object_put(ret_obj);
    if (!JSON_ERROR(category_obj)) json_object_put(category_obj);
    if (!JSON_ERROR(element_obj)) json_object_put(element_obj);

    return false;
}
#endif  /* INTROSPECTION_DEBUG */
