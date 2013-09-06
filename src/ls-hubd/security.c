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


#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <cjson/json.h>

#include "transport.h"
#include "transport_utils.h"

#include "hub.h"
#include "conf.h"
#include "security.h"

#define ROLE_FILE_SUFFIX    ".json"

#define ROLE_TYPE_REGULAR       "regular"
#define ROLE_TYPE_PRIVILEGED    "privileged"

#define ROLE_KEY            "role"
#define PERMISSION_KEY      "permissions"
#define EXE_NAME_KEY        "exeName"
#define TYPE_KEY            "type"
#define ALLOWED_NAMES_KEY   "allowedNames"
#define SERVICE_KEY         "service"
#define INBOUND_KEY         "inbound"
#define OUTBOUND_KEY        "outbound"

#define PERMISSION_ANY_STRING   "*"

#define TRITON_SERVICE_EXE_PATH     "js"    /**< special "path" for triton services */

#define PALM_SERVICE_PREFIX     "com.palm."
#define PALM_WEBOS_PREFIX       "com.webos."
#define PALM_LGE_PREFIX         "com.lge."

static inline bool _LSTransportSupportsSecurityFeatures(const _LSTransport *transport);
static inline bool _LSHubClientExePathMatches(const _LSTransportClient *client, const char *path);

struct _LSHubPatternQueue {
    int ref;
    GQueue *q;
};

typedef struct _LSHubPatternQueue _LSHubPatternQueue;

struct _LSHubPatternSpec {
    int ref;
    const char *pattern_str;
    GPatternSpec *pattern_spec;
};

typedef struct _LSHubPatternSpec _LSHubPatternSpec;

struct LSHubRole {
    int ref;
    const char *exe_path;
    LSHubRoleType type;
    _LSHubPatternQueue *allowed_names;
};

struct LSHubPermission {
    int ref;
    const char *service_name;
    _LSHubPatternQueue *inbound;
    _LSHubPatternQueue *outbound;
};


/**
 * Hash of pid to LSHubRole.
 * 
 * These are roles that are currently in use by processes
 */
static GHashTable *active_role_map = NULL;

/**
 * Hash of exe path to LSHubRole
 */
static GHashTable *role_map = NULL;

/**
 * Hash of service name to LSHubPermissions
 */
static GHashTable *permission_map = NULL;

static _LSHubPatternSpec*
_LSHubPatternSpecNew(const char *pattern)
{
    LS_ASSERT(pattern != NULL);

    _LSHubPatternSpec *ret = g_slice_new0(_LSHubPatternSpec);

    if (ret)
    {
        ret->pattern_str = g_strdup(pattern);

        if (!ret->pattern_str) goto error;

        ret->pattern_spec = g_pattern_spec_new(pattern);

        if (!ret->pattern_spec) goto error;
    }

    return ret;

error:
    if (ret->pattern_str) g_free((char*)ret->pattern_str);
    if (ret->pattern_spec) g_pattern_spec_free(ret->pattern_spec);
    return NULL;
}

static _LSHubPatternSpec*
_LSHubPatternSpecNewRef(const char *pattern)
{
    LS_ASSERT(pattern != NULL);

    _LSHubPatternSpec *ret = _LSHubPatternSpecNew(pattern);

    if (ret)
    {
        ret->ref = 1;
    }

    return ret;
}

static void
_LSHubPatternSpecRef(_LSHubPatternSpec *pattern)
{
    LS_ASSERT(pattern != NULL);
    LS_ASSERT(g_atomic_int_get(&pattern->ref) > 0);

    g_atomic_int_inc(&pattern->ref);
}

static void
_LSHubPatternSpecFree(_LSHubPatternSpec *pattern)
{
    LS_ASSERT(pattern != NULL);

    g_free((char*)pattern->pattern_str);
    g_pattern_spec_free(pattern->pattern_spec);
    g_slice_free(_LSHubPatternSpec, pattern);
}

/* returns true if the ref count went to 0 and the role was freed */
static bool
_LSHubPatternSpecUnref(_LSHubPatternSpec *pattern)
{
    LS_ASSERT(pattern != NULL);
    LS_ASSERT(g_atomic_int_get(&pattern->ref) > 0);

    if (g_atomic_int_dec_and_test(&pattern->ref))
    {
        _LSHubPatternSpecFree(pattern);
        return true;
    }

    return false;
}

static _LSHubPatternQueue*
_LSHubPatternQueueNew(void)
{
    _LSHubPatternQueue *q = g_slice_new0(_LSHubPatternQueue);

    if (q)
    {
        q->q = g_queue_new();
    }
    
    return q;
}

static _LSHubPatternQueue*
_LSHubPatternQueueNewRef(void)
{
    _LSHubPatternQueue *q = _LSHubPatternQueueNew();

    if (q)
    {
        q->ref = 1;
    }

    return q;
}

#if 0
static void
_LSHubPatternQueueRef(_LSHubPatternQueue *q)
{
    LS_ASSERT(q != NULL);
    LS_ASSERT(g_atomic_int_get(&q->ref) > 0);

    g_atomic_int_inc(&q->ref);
}
#endif

static void
_LSHubPatternQueueFree(_LSHubPatternQueue *q)
{
    LS_ASSERT(q != NULL);

    /* free each pattern spec */
    while (!g_queue_is_empty(q->q))
    {
        _LSHubPatternSpec *pattern = (_LSHubPatternSpec*)g_queue_pop_head(q->q);
        _LSHubPatternSpecUnref(pattern);
    }

    g_queue_free(q->q);
    g_slice_free(_LSHubPatternQueue, q);
}

/* returns true if the ref count went to 0 and the queue was freed */
static bool
_LSHubPatternQueueUnref(_LSHubPatternQueue *q)
{
    LS_ASSERT(q != NULL);
    LS_ASSERT(g_atomic_int_get(&q->ref) > 0);

    if (g_atomic_int_dec_and_test(&q->ref))
    {
        _LSHubPatternQueueFree(q);
        return true;
    }

    return false;
}

static void
_LSHubPatternQueuePushTail(_LSHubPatternQueue *q, _LSHubPatternSpec *pattern)
{
    LS_ASSERT(q != NULL);
    LS_ASSERT(pattern != NULL);

    _LSHubPatternSpecRef(pattern);
    g_queue_push_tail(q->q, pattern);
}

void
_LSHubPatternQueueShallowCopy(_LSHubPatternSpec *pattern, _LSHubPatternQueue *q)
{
    LS_ASSERT(pattern != NULL);
    LS_ASSERT(q != NULL);

    _LSHubPatternSpecRef(pattern);
    _LSHubPatternQueuePushTail(q, pattern);
}

/* creates a shallow copy with ref count of 1 */
static _LSHubPatternQueue*
_LSHubPatternQueueCopyRef(const _LSHubPatternQueue *q)
{
    LS_ASSERT(q != NULL);

    _LSHubPatternQueue *new_q = _LSHubPatternQueueNew();

    if (new_q)
    {
        new_q->ref = 1;
        g_queue_foreach(q->q, (GFunc)_LSHubPatternQueueShallowCopy, new_q);
    }

    return new_q;
}

static bool
_LSHubPatternQueueHasMatch(const _LSHubPatternQueue *q, const char *str)
{
    LS_ASSERT(q != NULL);
    LS_ASSERT(str != NULL);

    GList *list = NULL;
    char *rev_str = NULL;
    bool ret = false;

    list = q->q->head;

    if (!g_utf8_validate(str, -1, NULL))
    {
        ret = false;
        goto Exit;
    }

    rev_str = g_utf8_strreverse(str, -1);

    if (!rev_str)
    {
        ret = false;
        goto Exit;
    }

    while (list)
    {
        _LSHubPatternSpec *pattern = (_LSHubPatternSpec*)list->data;
        if (g_pattern_match(pattern->pattern_spec, strlen(str), str, rev_str))
        {
            ret = true;
            goto Exit;
        }

        list = list->next;
    }

    ret = false;

Exit:
    if (rev_str) g_free(rev_str);

    return ret;
}

static void
_LSHubPatternQueuePrint(const _LSHubPatternQueue *q, FILE *file)
{
    LS_ASSERT(q != NULL);
    LS_ASSERT(file != NULL);

    GList *list = NULL;

    list = q->q->head; 

    while (list)
    {
        _LSHubPatternSpec *pattern = (_LSHubPatternSpec*)list->data;
        fprintf(file, "%s ", pattern->pattern_str);
        list = list->next;
    }
}

GHashTable*
LSHubGetRoleMap(void)
{
    return role_map;
}

GHashTable*
LSHubGetPermissionMap(void)
{
    return permission_map;
}

GHashTable*
LSHubGetActiveRoleMap(void)
{
    return active_role_map;
}

LSHubRole*
LSHubRoleNew(const char *exe_path, LSHubRoleType type)
{
    _ls_verbose("%s: exe_path: \"%s\", type: %d\n", __func__, exe_path, type);
    
    LSHubRole *role = g_slice_new0(LSHubRole);

    if (role)
    {
        role->exe_path = g_strdup(exe_path);

        if (!role->exe_path)
        {
            goto error;
        }

        role->type = type;

        role->allowed_names = _LSHubPatternQueueNewRef();

        if (!role->allowed_names)
        {
            goto error;
        }
    }
    return role;

error:
    if (role->exe_path) g_free((char*)role->exe_path);

    if (role->allowed_names) _LSHubPatternQueueUnref(role->allowed_names);
    if (role) g_slice_free(LSHubRole, role);

    return NULL;
}

void
LSHubRoleFree(LSHubRole *role)
{
    LS_ASSERT(role != NULL);
    
    _ls_verbose("%s\n", __func__);

    g_free((char*)role->exe_path);

    _LSHubPatternQueueUnref(role->allowed_names);

#ifdef MEMCHECK
    memset(role, 0xFF, sizeof(LSHubRole));
#endif

    g_slice_free(LSHubRole, role);
}

LSHubRole*
LSHubRoleNewRef(const char *exe_path, LSHubRoleType type)
{
    _ls_verbose("%s: exe_path: \"%s\", type: %d\n", __func__, exe_path, type);
    
    LSHubRole *role = LSHubRoleNew(exe_path, type);
    
    if (role)
    {
        role->ref = 1;
    }

    return role;
}

void
LSHubRoleRef(LSHubRole *role)
{
    LS_ASSERT(role != NULL);
    LS_ASSERT(g_atomic_int_get(&role->ref) > 0);
    
    _ls_verbose("%s\n", __func__);

    g_atomic_int_inc(&role->ref);
}

/* returns true if the ref count went to 0 and the role was freed */
bool
LSHubRoleUnref(LSHubRole *role)
{
    LS_ASSERT(role != NULL);
    LS_ASSERT(g_atomic_int_get(&role->ref) > 0);
    
    _ls_verbose("%s\n", __func__);

    if (g_atomic_int_dec_and_test(&role->ref))
    {
        LSHubRoleFree(role);
        return true;
    }

    return false;
}

/* creates a copy of a HubRole with refcount of 1 */
LSHubRole*
LSHubRoleCopyRef(const LSHubRole *role)
{
    _ls_verbose("%s\n", __func__);

    LSHubRole *new_role = LSHubRoleNew(role->exe_path, role->type);

    if (new_role)
    {
        new_role->ref = 1;

        /* Unref the queue allocated in LSHubRoleNew */
        _LSHubPatternQueueUnref(new_role->allowed_names);
        
        /* shallow copy */
        new_role->allowed_names = _LSHubPatternQueueCopyRef(role->allowed_names);
    }

    return new_role; 
}

void
LSHubGHashTablePrint(const GHashTable *hash,
                     const char *key_format, const char *value_format,
                     const char *separator, FILE *file)
{
    gpointer key = NULL;
    gpointer value = NULL;
    bool first = true;

    GHashTableIter iter;
    g_hash_table_iter_init(&iter, (GHashTable*)hash);

    char *format_str = g_strconcat("[", key_format, " => ", value_format, "]", NULL);

    while (g_hash_table_iter_next(&iter, &key, &value))
    {
        if (!first)
        {
            fprintf(file, "%s", separator);
        }
        else
        {
            first = false;    
        }

        fprintf(file, format_str, key, value); 
    }
    
    g_free(format_str); 
}

gchar *
LSHubRoleAllowedNamesForExe(const char * exe_path)
{
    LSHubRole * role = NULL;

    if (!exe_path)
        return NULL;
    
    role = g_hash_table_lookup(LSHubGetRoleMap(), exe_path);
    
    if (!role)
      return NULL;
    
    GString * str = g_string_new("");
    const _LSHubPatternQueue * q = role->allowed_names;
    bool sep = false;
    
    LS_ASSERT(q != NULL);

    GList *list = NULL;

    list = q->q->head; 

    while (list)
    {
        _LSHubPatternSpec *pattern = (_LSHubPatternSpec*)list->data;
        if (sep)
          g_string_append_c(str, ',');
        // FIXME: this doesn't attempt to escape characters, despite being used as JSON
        g_string_append_printf(str, "\"%s\"", pattern->pattern_str);
        sep = true;
        list = list->next;
    }
    
    return g_string_free(str, FALSE);
}

void
LSHubRolePrint(const LSHubRole *role, FILE *file)
{
    fprintf(file, "Role: ref: %d, exe_path: \"%s\", type: %d, ",
                   role->ref, role->exe_path, role->type);
    fprintf(file, "allowed_names: ");
    _LSHubPatternQueuePrint(role->allowed_names, file);
    fprintf(file, "\n"); 
}

void
LSHubPermissionPrint(const LSHubPermission *perm, FILE *file)
{
    fprintf(file, "Permission: ref: %d, service_name: \"%s\" ",
                   perm->ref, perm->service_name);
    fprintf(file, "inbound: ");
    _LSHubPatternQueuePrint(perm->inbound, file);
    fprintf(file, " outbound: ");
    _LSHubPatternQueuePrint(perm->outbound, file);
    fprintf(file, "\n"); 
}

bool
LSHubRoleAddAllowedName(LSHubRole *role, const char *name, LSError *lserror)
{
    LS_ASSERT(role != NULL);
    LS_ASSERT(name != NULL);

    _ls_verbose("%s: add name: \"%s\"\n", __func__, name);

    _LSHubPatternSpec *pattern = _LSHubPatternSpecNewRef(name);

    if (pattern)
    {
        _LSHubPatternQueuePushTail(role->allowed_names, pattern); /* increments ref count */
        _LSHubPatternSpecUnref(pattern);
        return true;
    }

    return false;
}

static LSHubRoleType
_LSHubRoleTypeStringToType(const char *type)
{
    _ls_verbose("%s: type: \"%s\"\n", __func__, type);
    
    if (strcmp(ROLE_TYPE_REGULAR, type) == 0)
    {
        return LSHubRoleTypeRegular;
    }
    else if (strcmp(ROLE_TYPE_PRIVILEGED, type) == 0)
    {
        return LSHubRoleTypePrivileged;
    }
    else
    {
        return LSHubRoleTypeInvalid;
    }
}

LSHubPermission*
LSHubPermissionNew(const char *service_name)
{
    _ls_verbose("%s\n", __func__);
    
    LSHubPermission *perm = g_slice_new0(LSHubPermission);

    if (perm)
    {
        perm->service_name = g_strdup(service_name);

        if (!perm->service_name) goto error;

        perm->inbound = _LSHubPatternQueueNewRef();

        if (!perm->inbound) goto error;

        perm->outbound = _LSHubPatternQueueNewRef();

        if (!perm->outbound) goto error;
    }

    return perm;

error:
    if (perm->service_name) g_free((char*)perm->service_name);
    if (perm->inbound) _LSHubPatternQueueUnref(perm->inbound);
    if (perm->outbound) _LSHubPatternQueueUnref(perm->outbound);
    if (perm) g_slice_free(LSHubPermission, perm);

    return NULL;
}

LSHubPermission*
LSHubPermissionNewRef(const char *service_name)
{
    _ls_verbose("%s\n", __func__);

    LSHubPermission *perm = LSHubPermissionNew(service_name);

    if (perm)
    {
        perm->ref = 1;
    }

    return perm;
}

void
LSHubPermissionFree(LSHubPermission *perm)
{
    LS_ASSERT(perm != NULL);

    _ls_verbose("%s: free permission\n", __func__);

    g_free((char*)perm->service_name);

    _LSHubPatternQueueUnref(perm->inbound);
    _LSHubPatternQueueUnref(perm->outbound);

#ifdef MEMCHECK
    memset(perm, 0xFF, sizeof(LSHubPermission));
#endif

    g_slice_free(LSHubPermission, perm);
}

void
LSHubPermissionRef(LSHubPermission *perm)
{
    LS_ASSERT(perm != NULL);
    LS_ASSERT(g_atomic_int_get(&perm->ref) > 0);

    _ls_verbose("%s: ref permission\n", __func__);

    g_atomic_int_inc(&perm->ref);
}

bool
LSHubPermissionUnref(LSHubPermission *perm)
{
    LS_ASSERT(perm != NULL);
    LS_ASSERT(g_atomic_int_get(&perm->ref) > 0);

    _ls_verbose("%s: unref permission\n", __func__);

    if (g_atomic_int_dec_and_test(&perm->ref))
    {
        LSHubPermissionFree(perm);
        return true;
    }
    return false;
}

bool
LSHubPermissionAddAllowedInbound(LSHubPermission *perm, const char *name, LSError *lserror)
{
    LS_ASSERT(perm != NULL);
    LS_ASSERT(name != NULL);
    
    _ls_verbose("%s: add name: \"%s\" as allowed inbound\n", __func__, name);

    _LSHubPatternSpec *pattern = _LSHubPatternSpecNewRef(name);

    if (pattern)
    {
        _LSHubPatternQueuePushTail(perm->inbound, pattern); /* increments ref count */
        _LSHubPatternSpecUnref(pattern);
        return true;
    }

    return false;
}

bool
LSHubPermissionAddAllowedOutbound(LSHubPermission *perm, const char *name, LSError *lserror)
{
    LS_ASSERT(perm != NULL);
    LS_ASSERT(name != NULL);

    _ls_verbose("%s: add name: \"%s\" as allowed outbound\n", __func__, name);

    _LSHubPatternSpec *pattern = _LSHubPatternSpecNewRef(name);

    if (pattern)
    {
        _LSHubPatternQueuePushTail(perm->outbound, pattern); /* increments ref count */
        _LSHubPatternSpecUnref(pattern);
        return true;
    }

    return false;
}


/***************************** ROLE MAP ****************************/

LSHubRole*
LSHubRoleMapLookup(const char *exe_path)
{
    _ls_verbose("%s: look up exe_path: \"%s\" in role map\n", __func__, exe_path);
    
    if (exe_path)
    {
        return g_hash_table_lookup(LSHubGetRoleMap(), exe_path);
    }
    
    return NULL;
}

/* Add role to hash table */
bool
LSHubRoleMapAddRef(LSHubRole *role, LSError *lserror)
{
    LS_ASSERT(role != NULL);

    _ls_verbose("%s: ref role: %p in role map...\n", __func__, role);

    /* check to see if it already exists -- we don't want duplicates */
    if (LSHubRoleMapLookup(role->exe_path))
    {
        _ls_verbose("%s: ...failure\n", __func__);
        _LSErrorSet(lserror, -1, "Role already exists for exe_path: \"%s\"", role->exe_path);
        return false;
    }

    LSHubRoleRef(role);
    g_hash_table_insert(LSHubGetRoleMap(), g_strdup(role->exe_path), role);
    
    _ls_verbose("%s: ...success\n", __func__);

    return true;
}

/* returns true if ref count went down to 0 and we removed from the hash table
 */
bool
LSHubRoleMapUnref(const char *exe_path)
{
    LS_ASSERT(exe_path != NULL);

    _ls_verbose("%s: unref'ing exe_path: \"%s\" from role map... ", __func__, exe_path);

    LSHubRole *role = LSHubRoleMapLookup(exe_path);
   
    LS_ASSERT(role != NULL);

    if (LSHubRoleUnref(role))
    {
        bool removed = g_hash_table_remove(LSHubGetRoleMap(), exe_path);
        LS_ASSERT(removed == true);
        _ls_verbose("removed\n");
        return true;
    }
    
    _ls_verbose("unref'ed\n");

    return false;
}

/************************* ACTIVE ROLE MAP *******************************/

LSHubRole*
LSHubActiveRoleMapLookup(pid_t pid)
{
    _ls_verbose("%s: look up pid: "LS_PID_PRINTF_FORMAT" in role map\n", __func__, LS_PID_PRINTF_CAST(pid));
    return g_hash_table_lookup(LSHubGetActiveRoleMap(), &pid);
}

bool
LSHubActiveRoleMapAddRef(pid_t pid, LSHubRole *role, LSError *lserror)
{
    _ls_verbose("%s: attempting to ref pid: "LS_PID_PRINTF_FORMAT" in role map...\n", __func__, LS_PID_PRINTF_CAST(pid));

    /* if it already exists in hash table then bump up its ref count */
    LSHubRole *hashed_role = LSHubActiveRoleMapLookup(pid);

    if (hashed_role)
    {
        /* active role already exists for this pid, so bump ref count */
        LSHubRoleRef(hashed_role);
        _ls_verbose("%s: bump ref count...\n", __func__);
    }
    else
    {
        /* ref and insert new role */
        gint *key = g_malloc(sizeof(key));
        *key = pid;
        LSHubRoleRef(role);
        g_hash_table_insert(LSHubGetActiveRoleMap(), key, role);
        _ls_verbose("%s: ref and insert...\n", __func__);
    }

    _ls_verbose("%s: success\n", __func__);
    
    return true;
}

bool
LSHubActiveRoleMapUnref(pid_t pid)
{
    _ls_verbose("%s: attempting to unref pid: "LS_PID_PRINTF_FORMAT" from role map...\n", __func__, LS_PID_PRINTF_CAST(pid));
    
    /* if the role ref count goes to 0, we remove it from the hash table */
    LSHubRole *role = LSHubActiveRoleMapLookup(pid);

    if (role)
    {
        if (LSHubRoleUnref(role))
        {
            /* ref count for this role went to 0, so remove the reference to
             * it in the hash table */
            g_hash_table_remove(LSHubGetActiveRoleMap(), &pid);
            _ls_verbose("%s: removed...\n", __func__);
            return true;
        }
    
        _ls_verbose("unref'ed\n");
    }

    return false;
}


/***************************** PERMISSION MAP *****************************/

LSHubPermission*
LSHubPermissionMapLookup(const char *service_name)
{
    _ls_verbose("%s: looking up service name: \"%s\" in permission map\n", __func__, service_name);

    LSHubPermission *perm = NULL;

    if (service_name)
    {
        perm = g_hash_table_lookup(LSHubGetPermissionMap(), service_name);

        /* FIXME - unfortunate hack since mediaserver dynamically registers
         * names on the bus */
        if (!perm)
        {
            const char *media_service_name = IsMediaService(service_name);

            if (media_service_name)
            {
                perm = g_hash_table_lookup(LSHubGetPermissionMap(), media_service_name);
            }
        } 
    }
    
    return perm;
}

/* Add permission to hash table */
bool
LSHubPermissionMapAddRef(LSHubPermission *perm, LSError *lserror)
{
    _ls_verbose("%s: attempting to add permission %p to permission map...\n", __func__, perm);

     LSHubPermission *lookup_perm = LSHubPermissionMapLookup(perm->service_name);

     if (lookup_perm)
     {
         _LSErrorSet(lserror, -1, "Attempting to add duplicate service name to permission map: \"%s\"", perm->service_name);
         _ls_verbose("%s: failure\n", __func__);
         return false;
     }

     LSHubPermissionRef(perm);
     g_hash_table_insert(LSHubGetPermissionMap(), g_strdup(perm->service_name), perm);
    _ls_verbose("%s: success\n", __func__);
     return true;
}

bool
LSHubPermissionMapUnref(const char *service_name, LSError *lserror)
{
    _ls_verbose("%s: attempting to remove \"%s\" from permission map...\n", __func__, service_name);

    LSHubPermission *perm = LSHubPermissionMapLookup(service_name);

    if (perm)
    {
        g_hash_table_remove(LSHubGetPermissionMap(), service_name);
        LSHubPermissionUnref(perm);
        _ls_verbose("%s: success\n", __func__);
        return true;
    }
    else
    {
        _LSErrorSet(lserror, -1, "Expected to find a permission to unref");
        _ls_verbose("%s: failure\n", __func__);
        return false;
    }
}

bool
LSHubRoleMapClear(LSError *lserror)
{
    // TODO: use g_hash_table_remove_all()
    gpointer key = NULL;
    gpointer value = NULL;
    GHashTableIter iter;

    _ls_verbose("%s: clearing role map\n", __func__);

    g_hash_table_iter_init(&iter, LSHubGetRoleMap());

    while (g_hash_table_iter_next(&iter, &key, &value))
    {
        LSHubRoleUnref((LSHubRole*)value);
        g_hash_table_iter_remove(&iter);    /* this frees the key due to the
                                             * key_destroy_func set in
                                             * g_hash_table_new_full */
    }
    return true;
}

bool
LSHubPermissionMapClear(LSError *lserror)
{
    // TODO: use g_hash_table_remove_all()
    gpointer key = NULL;
    gpointer value = NULL;
    GHashTableIter iter;

    _ls_verbose("%s: clearing permission map\n", __func__);

    g_hash_table_iter_init(&iter, LSHubGetPermissionMap());

    while (g_hash_table_iter_next(&iter, &key, &value))
    {
        LSHubPermissionUnref((LSHubPermission*)value);
        g_hash_table_iter_remove(&iter);    /* this frees the key due to the
                                             * key_destroy_func set in
                                             * g_hash_table_new_full */

    }
    return true;
}


bool
ParseJSONFile(const char *path, struct json_object **json, LSError *lserror)
{
    bool ret = false;
    GIOChannel *file_channel = NULL;
    char *file_text = NULL;
    gsize file_text_len = 0;
    GError *error = NULL;
    GIOStatus status;
    struct json_object *ret_json = NULL;

    _ls_verbose("%s: parsing JSON from file: \"%s\"", __func__, path);

    int fd = open(path, O_RDONLY);

    if (fd == -1)
    {
        _LSErrorSetFromErrno(lserror, errno);
        goto exit;
    }

    file_channel = g_io_channel_unix_new(fd);
    
    g_io_channel_set_close_on_unref(file_channel, true); 

    /* The role files are small, so it should be ok to parse them in one shot */
    status = g_io_channel_read_to_end(file_channel, &file_text, &file_text_len, &error);

    if (status != G_IO_STATUS_NORMAL)
    {
        _LSErrorSetFromGError(lserror, error);
        goto exit;
    }

    ret_json = json_tokener_parse(file_text);

    if (is_error(ret_json))
    {
        _LSErrorSet(lserror, -1, "Error parsing JSON");
        goto exit;
    }

    *json = ret_json;

    ret = true;

    _ls_verbose("%s: successfully parsed JSON\n", __func__);

exit:

    /* unref and close */
    if (file_channel) g_io_channel_unref(file_channel);
    if (file_text) g_free(file_text);

    if (!ret)
    {
        _ls_verbose("%s: error parsing JSON\n", __func__);
        if (ret_json && !is_error(ret_json)) json_object_put(ret_json);
    }

    return ret;
} 

bool
ParseJSONGetRole(struct json_object *json, const char *json_file_path, LSHubRole **role,
                 LSError *lserror)
{
    bool ret = false;
    struct json_object *role_obj = NULL;
    struct json_object *exe_obj = NULL;
    struct json_object *type_obj = NULL;
    struct json_object *allowed_names_obj = NULL;
    int allowed_names_arr_len = 0;
    LSHubRole *ret_role = NULL;
    int i = 0;

    _ls_verbose("%s: parsing role from file: %s\n", __func__, json_file_path);

    if (!json_object_object_get_ex(json, ROLE_KEY, &role_obj))
    {
        _LSErrorSet(lserror, -1, "Unable to get role from JSON (%s)", json_file_path);
        goto exit;
    }
    
    if (!json_object_object_get_ex(role_obj, EXE_NAME_KEY, &exe_obj))
    {
        _LSErrorSet(lserror, -1, "Unable to get exeName from JSON (%s)", json_file_path);
        goto exit;
    }
    
    if (!json_object_object_get_ex(role_obj, TYPE_KEY, &type_obj))
    {
        _LSErrorSet(lserror, -1, "Unable to get type from JSON (%s)", json_file_path);
        goto exit;
    }
    
    if (!json_object_object_get_ex(role_obj, ALLOWED_NAMES_KEY, &allowed_names_obj))
    {
        _LSErrorSet(lserror, -1, "Unable to get allowedNames from JSON (%s)", json_file_path);
        goto exit;
    }

    allowed_names_arr_len = json_object_array_length(allowed_names_obj);
    
    /* exeName */
    const char *exe_name = json_object_get_string(exe_obj);

    /* type */
    const char *type_str = json_object_get_string(type_obj);

    LSHubRoleType type = _LSHubRoleTypeStringToType(type_str);

    _ls_verbose("%s: creating new role with exe_name: \"%s\", type: %d\n", __func__, exe_name, type);

    ret_role = LSHubRoleNewRef(exe_name, type);

    if (!ret_role)
    {
        _LSErrorSetOOM(lserror);
        goto exit;
    }

    /* allowedNames */
    for (i = 0; i < allowed_names_arr_len; i++)
    {
        struct json_object *tmp_obj = json_object_array_get_idx(allowed_names_obj, i);
        if (!LSHubRoleAddAllowedName(ret_role, json_object_get_string(tmp_obj), lserror))
        {
            goto exit;
        }
    }

    *role = ret_role;
    
    ret = true;

exit:
    if (!ret && ret_role)
    {
        /* cleanup on error */
        LSHubRoleUnref(ret_role);
    }

    return ret;
}

bool
ParseJSONGetPermissions(struct json_object *json, const char *json_file_path, GSList **perm_list, 
                        LSError *lserror)
{
    bool ret = false;
    struct json_object *perm_obj = NULL;
    int perm_arr_len = 0;
    struct json_object *service_obj = NULL;
    struct json_object *inbound_obj = NULL;
    struct json_object *outbound_obj = NULL;
    LSHubPermission *new_perm = NULL;
    int i = 0;
    int j = 0;
    int k = 0;

    _ls_verbose("%s: parsing permissions from %s\n", __func__, json_file_path);

    if (!json_object_object_get_ex(json, PERMISSION_KEY, &perm_obj))
    {
        _LSErrorSet(lserror, -1, "Unable to get permission from JSON (%s)", json_file_path);
        goto exit;
    }

    perm_arr_len = json_object_array_length(perm_obj);

    for (i = 0; i < perm_arr_len; i++)
    {
        struct json_object *cur_perm_obj = json_object_array_get_idx(perm_obj, i);

        if (!json_object_object_get_ex(cur_perm_obj, SERVICE_KEY, &service_obj))
        {
            _LSErrorSet(lserror, -1, "Unable to get service from JSON (%s)", json_file_path);
            goto exit;
        }
        
        if (!json_object_object_get_ex(cur_perm_obj, INBOUND_KEY, &inbound_obj))
        {
            _LSErrorSet(lserror, -1, "Unable to get inbound from JSON (%s)", json_file_path);
            goto exit;
        }
        
        if (!json_object_object_get_ex(cur_perm_obj, OUTBOUND_KEY, &outbound_obj))
        {
            _LSErrorSet(lserror, -1, "Unable to get outbound from JSON (%s)", json_file_path);
            goto exit;
        }
       
        _ls_verbose("%s: creating new permission\n", __func__);

        new_perm = LSHubPermissionNewRef(json_object_get_string(service_obj));
        
        for (j = 0; j < json_object_array_length(inbound_obj); j++)
        {
            struct json_object *cur_inbound_obj = json_object_array_get_idx(inbound_obj, j);

            if (!LSHubPermissionAddAllowedInbound(new_perm, json_object_get_string(cur_inbound_obj), lserror))
            {
                goto exit;
            }
        }

        for (k = 0; k < json_object_array_length(outbound_obj); k++)
        {
            struct json_object *cur_outbound_obj = json_object_array_get_idx(outbound_obj, k);
            if (!LSHubPermissionAddAllowedOutbound(new_perm, json_object_get_string(cur_outbound_obj), lserror))
            {
                goto exit;
            }
        } 
        
        *perm_list = g_slist_prepend(*perm_list, new_perm);
    }

    ret = true;

exit:

    if (!ret)
    {
        for (; *perm_list != NULL; *perm_list = g_slist_next(*perm_list))
        {
            LSHubPermission *perm = (*perm_list)->data;
            if (perm) LSHubPermissionUnref(perm);
            *perm_list = g_slist_delete_link(*perm_list, *perm_list);
        }
    }

    return ret;
}

bool
ParseRoleDirectory(const char *path, GHashTable *role_hash, GHashTable *perm_hash, LSError *lserror)
{
    GError *gerror = NULL;
    const char *filename = NULL;

    _ls_verbose("%s: parsing role directory: \"%s\"\n", __func__, path);

    GDir *dir = g_dir_open(path, 0, &gerror);

    if (!dir)
    {
        _LSErrorSetFromGError(lserror, gerror);
        return false;
    }

    while ((filename = g_dir_read_name(dir)) != NULL)
    {
        /* check file extension */
        if (g_str_has_suffix(filename, ROLE_FILE_SUFFIX))
        {
            char *full_path = g_strconcat(path, "/", filename, NULL);

            LSHubRole *role = NULL;
            GSList *perm_list = NULL;

            /* Create role and permission objects */
            struct json_object *json = NULL;
            if (!ParseJSONFile(full_path, &json, lserror))
            {
                LSErrorPrint(lserror, stderr);
                LSErrorFree(lserror);
                goto next;
            }

            if (!ParseJSONGetRole(json, full_path, &role, lserror))
            {
                LSErrorPrint(lserror, stderr);
                LSErrorFree(lserror);
            }


            if (!ParseJSONGetPermissions(json, full_path, &perm_list, lserror))
            {
                LSErrorPrint(lserror, stderr);
                LSErrorFree(lserror);
            }

            /* Add role object to hash table */
            if (role)
            {
                /* Don't add the role (but do add permissions) for a triton
                 * service, since triton will push the role file when it wants to
                 * use it
                 *
                 * Similarly, don't add the role for a mojo app, since they
                 * do not register for a service name (sysmgr just sets the
                 * appId and we do the check on that */
                if (strcmp(role->exe_path, g_conf_triton_service_exe_path) != 0 &&
                    strcmp(role->exe_path, g_conf_mojo_app_exe_path) != 0)
                {
                    if (!LSHubRoleMapAddRef(role, lserror))
                    {
                        LSErrorPrint(lserror, stderr);
                        LSErrorFree(lserror);
                    }
                }
            }
                
            /* Add permission object to hash table */
            for (; perm_list != NULL; perm_list = g_slist_delete_link(perm_list, perm_list)/*perm_list = g_slist_next(perm_list)*/)
            {
                LSHubPermission *perm = perm_list->data;

                if (!LSHubPermissionMapAddRef(perm, lserror))
                {
                    LSErrorPrint(lserror, stderr);
                    LSErrorFree(lserror);
                }
                LSHubPermissionUnref(perm);
            }
           
next: 
            if (role) LSHubRoleUnref(role);
            if (json && !is_error(json)) json_object_put(json);
            g_free(full_path);
        }
    }

    g_dir_close(dir);

    return true;
}

bool
LSHubPushRole(const _LSTransportClient *client, const char *path, LSError *lserror)
{
    bool ret = false;
    struct json_object *json = NULL;
    LSHubRole *role = NULL;

    /* Remove current role from active role map if there is one */
    const _LSTransportCred *cred = _LSTransportClientGetCred(client);

    if (!cred)
    {
        _LSErrorSet(lserror, LS_TRANSPORT_PUSH_ROLE_PERMISSION_DENIED, LS_TRANSPORT_PUSH_ROLE_PERMISSION_DENIED_TEXT);
        goto exit;
    }

    /* DFISH-23679: Only root users can push a role */
    uid_t uid = _LSTransportCredGetUid(cred);

    if (uid != 0)
    {
        _LSErrorSet(lserror, LS_TRANSPORT_PUSH_ROLE_PERMISSION_DENIED, LS_TRANSPORT_PUSH_ROLE_PERMISSION_DENIED_TEXT);
        goto exit;
    }

    pid_t pid = _LSTransportCredGetPid(cred);

    /* Unref the existing role for this pid if there is one. */
    if ((role = LSHubActiveRoleMapLookup(pid)) != NULL)
    {
        /* Check that this client is allowed to push a role */
        if (!LSHubClientGetPrivileged(client))
        {
            _LSErrorSet(lserror, LS_TRANSPORT_PUSH_ROLE_PERMISSION_DENIED, LS_TRANSPORT_PUSH_ROLE_PERMISSION_DENIED_TEXT);
            goto exit;
        }

        /* Verify that there should only be a single ref and the role is freed */
        if (!LSHubActiveRoleMapUnref(pid))
        {
            _LSErrorSet(lserror, LS_TRANSPORT_PUSH_ROLE_DUPLICATE, LS_TRANSPORT_PUSH_ROLE_DUPLICATE_TEXT);
            goto exit;
        }
    }
    else
    {
        /* Couldn't verify that this pid is allowed to push a role */
        _LSErrorSet(lserror, LS_TRANSPORT_PUSH_ROLE_PERMISSION_DENIED, LS_TRANSPORT_PUSH_ROLE_PERMISSION_DENIED_TEXT);
        goto exit;
    }

    /* create the new role from the file */
    if (!ParseJSONFile(path, &json, lserror))
    {
        LSErrorPrint(lserror, stderr);
        LSErrorFree(lserror);
        _LSErrorSet(lserror, LS_TRANSPORT_PUSH_ROLE_FILE_ERROR, LS_TRANSPORT_PUSH_ROLE_FILE_ERROR_TEXT, path);
        goto exit;
    }

    if (!ParseJSONGetRole(json, path, &role, lserror))
    {
        LSErrorPrint(lserror, stderr);
        LSErrorFree(lserror);
        _LSErrorSet(lserror, LS_TRANSPORT_PUSH_ROLE_FILE_ERROR, LS_TRANSPORT_PUSH_ROLE_FILE_ERROR_TEXT, path);
        goto exit;
    }

    /* ignore any permissions in the file */

    if (!LSHubActiveRoleMapAddRef(pid, role, lserror))
    {
        LSErrorPrint(lserror, stderr);
        LSErrorFree(lserror);
        _LSErrorSet(lserror, LS_TRANSPORT_PUSH_ROLE_UNKNOWN_ERROR, LS_TRANSPORT_PUSH_ROLE_UNKNOWN_ERROR_TEXT);
        LSHubRoleUnref(role);
        goto exit;
    }

    LSHubRoleUnref(role);

    ret = true;

exit:
    if (json && !is_error(json)) json_object_put(json);

    return ret;
}

bool
LSHubClientGetPrivileged(const _LSTransportClient *client)
{
    bool privileged = false;

    if (!g_conf_security_enabled || !_LSTransportSupportsSecurityFeatures(_LSTransportClientGetTransport(client)))
    {
        // if security is not enabled or the transport doesn't
        // support security then just say that the client is privileged
        privileged = true;
        goto done;
    }

    /* look up the role in active role map */
    const _LSTransportCred *cred = _LSTransportClientGetCred(client);

    if (cred)
    {
        pid_t pid = _LSTransportCredGetPid(cred);
        LSHubRole *role;
    
        if ((role = LSHubActiveRoleMapLookup(pid)) != NULL)
        {
            privileged = LSHubRoleTypePrivileged == role->type;
        }
    }

done:
    return privileged;
}

/* call this when a client disconnects so that the active role map can be kept
 * accurate */
bool
LSHubActiveRoleMapClientRemove(const _LSTransportClient *client, LSError *lserror)
{
    if (!g_conf_security_enabled)
    {
        return true;
    }

    /* look up the role in active role map and unref it */
    const _LSTransportCred *cred = _LSTransportClientGetCred(client);

    if (!cred)
    {
        _LSErrorSet(lserror, -1, "Unable to get client credentials");
        return false;
    }

    pid_t pid = _LSTransportCredGetPid(cred);

    LSHubActiveRoleMapUnref(pid);

    return true;
}

static bool
_LSHubSecurityPatternQueueAllowServiceName(_LSHubPatternQueue *q, const char *service_name)
{
    LS_ASSERT(q != NULL);

    /* un-named services are represented as empty strings in the map */
    if (service_name == NULL)
    {
        service_name = "";
    }
    else if (service_name[0] == '\0')
    {
        /* empty strings are not allowed as service names */
        return false;
    }

    if (_LSHubPatternQueueHasMatch(q, service_name))
    {
        return true;
    }

    return false;
}

static inline bool
_LSTransportSupportsSecurityFeatures(const _LSTransport *transport)
{
    switch (_LSTransportGetTransportType(transport))
    {
    case _LSTransportTypeLocal:
        return true;
    case _LSTransportTypeInet:
    default:
        return false;
    }
}

/* true if the client is allowed to register the requested service name */
bool
LSHubIsClientAllowedToRequestName(const _LSTransportClient *client, const char *service_name)
{
    LS_ASSERT(client != NULL);

    LSError lserror;
    LSErrorInit(&lserror);
        
    const char *exe_path = NULL;

    if (!_LSTransportSupportsSecurityFeatures(_LSTransportClientGetTransport(client)))
    {
        return true;
    }

    /* Use exe_path in client credentials to look up role file and allowed service names */
    const _LSTransportCred *cred = _LSTransportClientGetCred(client);

    if (!cred)
    {
        return false;
    }

    /* first check the active role map to see if this process already has a role
     * associated with it */
    pid_t pid = _LSTransportCredGetPid(cred);
    LSHubRole *role = g_hash_table_lookup(LSHubGetActiveRoleMap(), &pid);

    if (role)
    {
        /* increment role ref count -- this function is called once per LSRegister()
         * and we will clean up on LSUnregister() or disconnect */
        LSHubRoleRef(role);
    }
    else
    {
        /* Check the role map from disk based on exe path */

        exe_path = _LSTransportCredGetExePath(cred);

        if (!exe_path)
        {
            return false;
        } 

        role = LSHubRoleMapLookup(exe_path);

        if (!role)
        {
            if (g_conf_security_enabled)
            {
                /* service name is not in role file set, so deny request */
                g_critical("ERROR: No role file for executable: \"%s\" (cmdline: \"%s\")",
                           exe_path, _LSTransportCredGetCmdLine(cred));
                return false;
            }
            else
            {
                g_critical("WARNING: Missing role file for executable: \"%s\" (cmdline: \"%s\")",
                           exe_path, _LSTransportCredGetCmdLine(cred));
                return true;
            } 
        }

        /* create copy, ref, and add to active role map */
        LSHubRole *copy = LSHubRoleCopyRef(role);               /* ref count = 1 */
        if (!LSHubActiveRoleMapAddRef(pid, copy, &lserror))     /* ref count = 2 */
        {
            LSErrorPrint(&lserror, stderr);
            LSErrorFree(&lserror);
        }
        LSHubRoleUnref(copy);                                   /* ref count is 1 */
    }

    /* check to see if role allows this name */
    if (role->allowed_names && _LSHubSecurityPatternQueueAllowServiceName(role->allowed_names, service_name))
    {
        return true; 
    }
  
    if (g_conf_security_enabled)
    {
        g_critical("ERROR: executable: \"%s\" (cmdline: \"%s\") "
                   "does not have permission to register name: \"%s\"",
                    _LSTransportCredGetExePath(cred),
                    _LSTransportCredGetCmdLine(cred),
                    service_name);

        return false;
    }
    else
    {
        g_critical("WARNING: executable: \"%s\" (cmdline: \"%s\") "
                   "does not have permission to register name: \"%s\"",
                    _LSTransportCredGetExePath(cred),
                    _LSTransportCredGetCmdLine(cred),
                    service_name);
        return true;
    } 
}

/** 
 *******************************************************************************
 * @brief Returns true if the specified client is the monitor binary. If the
 * transport does not support security features this will always return true.
 * 
 * @param  client   IN  client to check 
 * 
 * @retval  true if specified client is monitor binary
 * @retval  false otherwise
 *******************************************************************************
 */
bool
LSHubIsClientMonitor(const _LSTransportClient *client)
{
    LS_ASSERT(client != NULL);

    if (!_LSTransportSupportsSecurityFeatures(_LSTransportClientGetTransport(client)))
    {
        return true;
    }

    return ( _LSHubClientExePathMatches(client, g_conf_monitor_exe_path) ||
             _LSHubClientExePathMatches(client, g_conf_monitor_pub_exe_path) );
}

/** 
 *******************************************************************************
 * @brief Returns true if the client's exe path matches the given path.
 * 
 * @param  client   IN  client 
 * @param  path     IN  path to compare
 * 
 * @retval true if client's exe path matches given path
 * @retval false otherwise
 *******************************************************************************
 */
static inline bool
_LSHubClientExePathMatches(const _LSTransportClient *client, const char *path)
{
    const _LSTransportCred *cred = _LSTransportClientGetCred(client);

    if (!cred)
    {
        return false;
    }

    const char *exe_path = _LSTransportCredGetExePath(cred);

    if (!exe_path)
    {
        return false;
    }

    if (strcmp(_LSTransportCredGetExePath(cred), path) == 0)
    {
        return true;
    }

    return false;
}

/** 
 *******************************************************************************
 * @brief Returns true if the client is LunaSysMgr.
 * 
 * @param  client   IN      client 
 * 
 * @retval  true if client is LunaSysMgr
 * @retval  false otherwise (including failure to get permissions)
 *******************************************************************************
 */
static bool
_LSHubIsClientSysMgr(const _LSTransportClient *client)
{
    return (_LSHubClientExePathMatches(client, g_conf_sysmgr_exe_path) ||
           _LSHubClientExePathMatches(client, g_conf_webappmgr_exe_path) ||
           _LSHubClientExePathMatches(client, g_conf_webappmgr2_exe_path));
}

/** 
 *******************************************************************************
 * @brief Returns true if the client is a special connection used by
 * LunaSysMgr for proxying app requests.
 * 
 * @param  client   IN  client 
 * 
 * @retval  true if client is LunaSysMgr app proxy
 * @retval  false otherwise
 *******************************************************************************
 */
static inline bool
_LSHubIsClientSysMgrAppProxy(const _LSTransportClient *client)
{
    LS_ASSERT(client != NULL);
    return client->is_sysmgr_app_proxy;
}

static inline void
_LSHubPrintPermissionsMessage(const _LSTransportClient *client, const char *sender_service_name,
                              const char *dest_service_name, bool inbound, bool is_error)
{
    const _LSTransportCred *cred  = _LSTransportClientGetCred(client);
    
    if (inbound)
    {
        g_critical("%s: \"%s\" permissions does not allow inbound "
                   "connections from \"%s\" "
                   "(requester pid: "LS_PID_PRINTF_FORMAT", requester exe: \"%s\" "
                   "requester cmdline: \"%s\")",
                   is_error ? "ERROR" : "WARNING",
                    dest_service_name, sender_service_name,
                   LS_PID_PRINTF_CAST(_LSTransportCredGetPid(cred)),
                   _LSTransportCredGetExePath(cred),
                   _LSTransportCredGetCmdLine(cred));
    }
    else
    {
        /* outbound */
        g_critical("%s: \"%s\" does not have sufficient outbound permissions "
                   "to communicate with \"%s\" "
                   "(requester pid: "LS_PID_PRINTF_FORMAT", requester exe: \"%s\" "
                   "requester cmdline: \"%s\")",
                   is_error ? "ERROR": "WARNING",
                   sender_service_name, dest_service_name,
                   LS_PID_PRINTF_CAST(_LSTransportCredGetPid(cred)),
                   _LSTransportCredGetExePath(cred),
                   _LSTransportCredGetCmdLine(cred));
    }
}

static inline void
_LSHubPrintSignalPermissionsMessage(const _LSTransportClient *client)
{
    const char *service_name = _LSTransportClientGetServiceName(client);
    const _LSTransportCred *cred = _LSTransportClientGetCred(client);

    g_critical("%s: \"%s\" is not allowed to send signals "
               "(requester pid: "LS_PID_PRINTF_FORMAT", requester exe: \"%s\" "
               "requester cmdline: \"%s\")",
               g_conf_security_enabled ? "ERROR": "WARNING",
               service_name,
               LS_PID_PRINTF_CAST(_LSTransportCredGetPid(cred)),
               _LSTransportCredGetExePath(cred),
               _LSTransportCredGetCmdLine(cred));
}

/** 
 *******************************************************************************
 * @brief LunaSysMgr sets the appId to be "com.palm.app.foo PID", where PID
 * is a numeric value that is unique to each instance of the app (but
 * it's not a real PID in the OS -- it's generated and tracked by
 * LunaSysMgr. This strips off the PID and leaves only the app name.
 * 
 * @param  app_id   app id with PID 
 * 
 * @retval  stripped app id on success
 * @retval  NULL on failure
 *******************************************************************************
 */
static inline char*
_LSHubAppIdStripPidAndDup(const char *app_id)
{
    char *modified_app_id = NULL;

    modified_app_id = g_strdup(app_id);

    if (modified_app_id)
    {
        char *space = strstr(modified_app_id, " ");

        if (space)
        {
            *space = '\0';
        }
    }

    return modified_app_id;
}

static bool
_LSHubIsClientAllowedOutbound(_LSTransportClient *client, const char *dest_service_name, const char *sender_app_id)
{
    LS_ASSERT(client != NULL);
    LS_ASSERT(dest_service_name != NULL);

    bool ret = false;
    char *modified_app_id = NULL;
    const char *sender_service_name = _LSTransportClientGetServiceName(client);
   
    /* (1)
     * If the sender is LunaSysMgr, then we need to base the permissions on
     * the sender's appId because sysmgr uses a single connection to the hub
     * for all the messages that it sends.
     *
     * (2)
     * However, rather than force all of the apps to also install a role file
     * with their outbound permissions (which would probably all be set to
     * allow them to talk to anything), we will just allow them outbound and
     * rely on the incoming permissions of the services that they are talking
     * to to block them.
     *
     * (3)
     * NOV-112468: We cache the result from (2).
     */

    /* See (3) */
    if (_LSHubIsClientSysMgrAppProxy(client))
    {
        return true;
    }
    else if (_LSHubIsClientSysMgr(client))
    {
        /* See (2) */
        if (g_conf_mojo_apps_allow_all_outbound_by_default)
        {
            if (sender_app_id != NULL)
            {
                /* Since the app_id is non-null, sysmgr is making a
                 * request on behalf of an app */
                client->is_sysmgr_app_proxy = true;
                return true;
            }
        }
        else
        {
            /* See (1).
             * 
             * If we ever decide to require role files for apps, we'll run this code */
            modified_app_id = _LSHubAppIdStripPidAndDup(sender_app_id);
            sender_service_name = modified_app_id;
        }
    }

    if ((sender_service_name == NULL) && g_conf_allow_null_outbound_by_default)
    {
        ret = true;
        goto Exit;
    }
    
    LSHubPermission *perm = LSHubPermissionMapLookup(sender_service_name);

    if (!perm)
    {
        if (g_conf_security_enabled)
        {
            _LSHubPrintPermissionsMessage(client, sender_service_name, dest_service_name, false, true);
            ret = false;
            goto Exit;
        }
        else
        {
            _LSHubPrintPermissionsMessage(client, sender_service_name, dest_service_name, false, false);
            ret = true;
            goto Exit;
        }
    }

    if (perm->outbound && _LSHubSecurityPatternQueueAllowServiceName(perm->outbound, dest_service_name))
    {
        ret = true;
        goto Exit;
    }
   
    if (g_conf_security_enabled)
    {
        _LSHubPrintPermissionsMessage(client, sender_service_name, dest_service_name, false, true);
        ret = false;
        goto Exit;
    }
    else
    {
        _LSHubPrintPermissionsMessage(client, sender_service_name, dest_service_name, false, false);
        ret = false;
        goto Exit;
    }

Exit:
    if (modified_app_id) g_free(modified_app_id);

    return ret;
}

static bool
_LSHubIsClientAllowedInbound(const _LSTransportClient *client, const char *dest_service_name, const char *sender_app_id)
{
    LS_ASSERT(client != NULL);
    LS_ASSERT(dest_service_name != NULL);

    bool ret = false;
    const char *sender_service_name = _LSTransportClientGetServiceName(client);
    char *modified_app_id = NULL;

    /* Always allow the monitor to send messages to everyone without explicitly adding
     * it to each role file */
    if (LSHubIsClientMonitor(client))
    {
        return true;
    }

    /* If the sender is LunaSysMgr, then we need to base the permissions on
     * the sender's appId because sysmgr uses a single connection to the hub
     * for all the messages that it sends */
    if (_LSHubIsClientSysMgr(client))
    {
        /* see _LSHubAppIdStripPidAndDup() for why this is necessary */
        modified_app_id = _LSHubAppIdStripPidAndDup(sender_app_id);
        sender_service_name = modified_app_id;
    }

    LSHubPermission *perm = LSHubPermissionMapLookup(dest_service_name);

    if (!perm)
    {
        if (g_conf_security_enabled)
        {
            _LSHubPrintPermissionsMessage(client, sender_service_name, dest_service_name, true, true);
            ret = false;
            goto Exit;
        }
        else
        {
            _LSHubPrintPermissionsMessage(client, sender_service_name, dest_service_name, true, false);
            ret = true;
            goto Exit;
        }
    }

    if (perm->inbound && _LSHubSecurityPatternQueueAllowServiceName(perm->inbound, sender_service_name))
    {
        ret = true;
        goto Exit;
    }

    if (g_conf_security_enabled)
    {
        _LSHubPrintPermissionsMessage(client, sender_service_name, dest_service_name, true, true);
    
        ret = false;
        goto Exit;
    }
    else
    {
        _LSHubPrintPermissionsMessage(client, sender_service_name, dest_service_name, true, false);
        ret = true;
        goto Exit;
    }

Exit:
    if (modified_app_id) g_free(modified_app_id);

    return ret;
}

bool
LSHubIsClientAllowedToQueryName(_LSTransportClient *client, const char *dest_service_name, const char *sender_app_id)
{
    LS_ASSERT(client != NULL);
    LS_ASSERT(dest_service_name != NULL);

    if (!_LSTransportSupportsSecurityFeatures(_LSTransportClientGetTransport(client)))
    {
        return true;
    }

    if (_LSHubIsClientAllowedOutbound(client, dest_service_name, sender_app_id) && _LSHubIsClientAllowedInbound(client, dest_service_name, sender_app_id))
    {
        return true;
    }

    return false;
}

bool
LSHubIsClientAllowedToSendSignal(_LSTransportClient *client)
{
    LS_ASSERT(client != NULL);

    if (!g_conf_security_enabled || !_LSTransportSupportsSecurityFeatures(_LSTransportClientGetTransport(client)))
    {
        return true;
    }

    const char *service_name = _LSTransportClientGetServiceName(client);

    /* Only Palm services are allowed to send signals */
    if (service_name &&
            (g_str_has_prefix(service_name, PALM_WEBOS_PREFIX) ||
             g_str_has_prefix(service_name, PALM_SERVICE_PREFIX) ||
             g_str_has_prefix(service_name, PALM_LGE_PREFIX)
            )
       )
    {
        return true;
    }

    _LSHubPrintSignalPermissionsMessage(client);
    return false;
}

static bool
_PermissionsAndRolesInit(LSError *lserror)
{
    if (role_map)
    {
        if (!LSHubRoleMapClear(lserror))
        {
            LSErrorPrint(lserror, stderr);
            LSErrorFree(lserror);
        }
    }
    else
    {
        role_map = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, /*TODO: unref */NULL);

        if (!role_map)
        {
            _LSErrorSetOOM(lserror);
            return false;
        }
    }

    if (!active_role_map)
    {
        /* NOTE: Don't set the value destroy function to unref or it will break
         * the ref counting scheme used */
        active_role_map = g_hash_table_new_full(g_int_hash, g_int_equal, g_free, NULL);

        if (!active_role_map)
        {
            _LSErrorSetOOM(lserror);
            return false;
        }
    }

    if (permission_map)
    {
        if (!LSHubPermissionMapClear(lserror))
        {
            LSErrorPrint(lserror, stderr);
            LSErrorFree(lserror);
        }
    }
    else
    {
        permission_map = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, /*TODO: unref */NULL);

        if (!permission_map)
        {
            _LSErrorSetOOM(lserror);
            return false;
        }
    }

    return true;
}

bool
ProcessRoleDirectories(const char **dirs, void *ctxt, LSError *lserror)
{
    /* process all the role files in the specified directories */
    LS_ASSERT(dirs != NULL);

    const char **cur_dir = NULL;

    printf("%s called\n", __func__);

    if (!_PermissionsAndRolesInit(lserror))
    {
        return false;
    }

    for (cur_dir = dirs; *cur_dir != NULL; cur_dir++)
    {
        if (!ParseRoleDirectory(*cur_dir, LSHubGetRoleMap(), LSHubGetPermissionMap(), lserror))
        {
            LSErrorPrint(lserror, stderr);
            LSErrorFree(lserror);
        }
    }
    
    fprintf(stderr, "Done parsing role directories\n");

    GHashTableIter iter;
    g_hash_table_iter_init(&iter, LSHubGetRoleMap());

    gpointer key = NULL;
    gpointer value = NULL;

    while (g_hash_table_iter_next(&iter, &key, &value))
    {
        LSHubRole *role = value;
        LSHubRolePrint(role, stderr);
    }
    
    g_hash_table_iter_init(&iter, LSHubGetPermissionMap());

    while (g_hash_table_iter_next(&iter, &key, &value))
    {
        LSHubPermission *perm = value;
        LSHubPermissionPrint(perm, stderr);
    }

    return true;
}
