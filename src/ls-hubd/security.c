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


#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <pbnjson.h>

#include "simple_pbnjson.h"

#include "transport.h"
#include "transport_utils.h"

#include "hub.h"
#include "conf.h"
#include "log.h"
#include "security.h"
#include "pattern.h"

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

/*
 * Handy function to obtain a string property from object
 * @param obj where to lookup for property
 * @param key what name of property we are looking for
 * @param value optional output for property string value (assumed uninitialized)
 * @param lserror optional output for errors
 * @param msgid optional id for message to set if error met
 * @param json optional reference to json document
 */
static inline bool
jobject_get_string(jvalue_ref obj, raw_buffer key, raw_buffer *value, LSError *lserror, const char *msgid, const char *json)
{
    LS_ASSERT( obj != NULL && key.m_str != NULL && value != NULL );

    const char *jsonDesc = json ? json : "<no-source>";

    jvalue_ref prop;
    if (!jobject_get_exists(obj, key, &prop))
    {
        _LSErrorSet(lserror, msgid, -1, "Unable to get %.*s from JSON (%s)", (int)key.m_len, key.m_str, jsonDesc);
        return false;
    }

    if (!jis_string(prop))
    {
        _LSErrorSet(lserror, msgid, -1, "Property %.*s isn't a string inside JSON (%s)", (int)key.m_len, key.m_str, jsonDesc);
        return false;
    }

    *value = jstring_get_fast(prop);

    return true;
}

/*
 * Handy function to obtain a string property from array
 * @param array where our item located
 * @param index where inside of array our item located
 * @param value optional output for string value (assumed uninitialized)
 * @param lserror optional output for errors
 * @param msgid optional id for message to set if error met
 * @param json optional reference to json document
 */
static inline bool
jarray_get_string(jvalue_ref array, ssize_t index, raw_buffer *value, LSError *lserror, const char *msgid, const char *json)
{
    assert( array != NULL );
    assert( 0 <= index && index < jarray_size(array) );

    const char *jsonDesc = json ? json : "<no-source>";

    jvalue_ref prop = jarray_get( array, index );

    if (!jis_string(prop))
    {
        _LSErrorSet(lserror, msgid, -1, "Item #%zd isn't a string inside JSON (%s)", index, jsonDesc);
        return false;
    }

    *value = jstring_get_fast(prop);

    return true;
}

struct _LSHubPatternQueue {
    int ref;
    GSList *q;
};

typedef struct _LSHubPatternQueue _LSHubPatternQueue;

struct LSHubRole {
    int ref;
    const char *exe_path;
    LSHubRoleType type;
    _LSHubPatternQueue *allowed_names;
    bool from_volatile_dir;
};

struct LSHubPermission {
    int ref;
    const char *service_name;
    _LSHubPatternQueue *inbound;
    _LSHubPatternQueue *outbound;
    bool from_volatile_dir;
};

gchar **roles_volatile_dirs = NULL;        /**< volatile directories with service description files*/

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

/**
 * @brief Tree of service name pattern to LSHubPermissions.
 *
 * Patterns are ordered by comparing prefixes up to the first '?' or '*'.
 */
static GTree *permission_wildcard_map = NULL;


static _LSHubPatternQueue*
_LSHubPatternQueueNew(void)
{
    _LSHubPatternQueue *q = g_slice_new0(_LSHubPatternQueue);

    return q;
}

static _LSHubPatternQueue*
_LSHubPatternQueueNewRef(void)
{
    _LSHubPatternQueue *q = _LSHubPatternQueueNew();

    q->ref = 1;

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

static void FreePatternSpec(gpointer data)
{
    _LSHubPatternSpecUnref((_LSHubPatternSpec *) data);
}

static void
_LSHubPatternQueueFree(_LSHubPatternQueue *q)
{
    LS_ASSERT(q != NULL);

    g_slist_free_full(q->q, &FreePatternSpec);

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
    q->q = g_slist_prepend(q->q, pattern);
}

static int
PatternSpecStringCompare(const _LSHubPatternSpec *a, const _LSHubPatternSpec *b)
{
    return strcmp(a->pattern_str, b->pattern_str);
}

static void
_LSHubPatternQueueInsertSorted(_LSHubPatternQueue *q, _LSHubPatternSpec *pattern)
{
    LS_ASSERT(q != NULL);
    LS_ASSERT(pattern != NULL);

    _LSHubPatternSpecRef(pattern);
    q->q = g_slist_insert_sorted(q->q, pattern, (GCompareFunc) &PatternSpecStringCompare);
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
        g_slist_foreach(q->q, (GFunc)_LSHubPatternQueueShallowCopy, new_q);
    }

    return new_q;
}

static bool
_LSHubPatternQueueHasMatch(const _LSHubPatternQueue *q, const char *str)
{
    LS_ASSERT(q != NULL);
    LS_ASSERT(str != NULL);

    GSList *list = q->q;
    char *rev_str = NULL;
    bool ret = false;

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

        list = g_slist_next(list);
    }

    ret = false;

Exit:
    g_free(rev_str);

    return ret;
}

static void
_LSHubPatternQueuePrint(const _LSHubPatternQueue *q, FILE *file)
{
    LS_ASSERT(q != NULL);
    LS_ASSERT(file != NULL);

    GSList *list = q->q;

    while (list)
    {
        _LSHubPatternSpec *pattern = (_LSHubPatternSpec*)list->data;
        fprintf(file, "%s ", pattern->pattern_str);
        list = g_slist_next(list);
    }
}

static gchar*
_LSHubPatternQueueDump(const _LSHubPatternQueue *q)
{
    LS_ASSERT(q != NULL);

    GString *str = g_string_new("[");

    const GSList *list = q->q;

    while (list)
    {
        const _LSHubPatternSpec *pattern = (const _LSHubPatternSpec *) list->data;
        if (list != q->q)
            str = g_string_append(str, ", ");
        str = g_string_append(str, pattern->pattern_str);
        list = g_slist_next(list);
    }

    str = g_string_append(str, "]");
    return g_string_free(str, FALSE);
}

static bool
_LSHubPatternQueueIsEqual(const _LSHubPatternQueue *a, const _LSHubPatternQueue *b)
{
    LS_ASSERT(a != NULL);
    LS_ASSERT(b != NULL);

    // Iterate over two sorted lists simultaneously.
    // If a difference is spotted, they aren't equal.

    GSList *i = a->q;
    GSList *j = b->q;

    while (i && j)
    {
        const _LSHubPatternSpec *pa = (const _LSHubPatternSpec *) i->data;
        const _LSHubPatternSpec *pb = (const _LSHubPatternSpec *) j->data;

        if (strcmp(pa->pattern_str, pb->pattern_str))
            return false;

        i = g_slist_next(i);
        j = g_slist_next(j);
    }

    // Finally, both iterators should be NULL.
    return i == j;
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

GTree*
LSHubGetPermissionWildcardMap(void)
{
   return permission_wildcard_map;
}

GHashTable*
LSHubGetActiveRoleMap(void)
{
    return active_role_map;
}

static LSHubRole*
LSHubRoleNew(raw_buffer exe_path, LSHubRoleType type)
{
    LS_ASSERT(exe_path.m_str != NULL);

    LOG_LS_DEBUG("%s: exe_path: \"%.*s\", type: %d\n", __func__, (int)exe_path.m_len, exe_path.m_str, type);
    LSHubRole *role = g_slice_new0(LSHubRole);

    role->exe_path = g_strndup(exe_path.m_str, exe_path.m_len);
    role->type = type;
    role->allowed_names = _LSHubPatternQueueNewRef();

    return role;
}

static void
LSHubRoleFree(LSHubRole *role)
{
    LS_ASSERT(role != NULL);
    LOG_LS_DEBUG("%s\n", __func__);

    g_free((char*)role->exe_path);

    _LSHubPatternQueueUnref(role->allowed_names);

#ifdef MEMCHECK
    memset(role, 0xFF, sizeof(LSHubRole));
#endif

    g_slice_free(LSHubRole, role);
}

static LSHubRole*
LSHubRoleNewRef(raw_buffer exe_path, LSHubRoleType type)
{
    LOG_LS_DEBUG("%s: exe_path: \"%.*s\", type: %d\n", __func__, (int)exe_path.m_len, exe_path.m_str, type);
    LSHubRole *role = LSHubRoleNew(exe_path, type);

    role->ref = 1;

    return role;
}

static void
LSHubRoleRef(LSHubRole *role)
{
    LS_ASSERT(role != NULL);
    LS_ASSERT(g_atomic_int_get(&role->ref) > 0);

    LOG_LS_DEBUG("%s\n", __func__);

    g_atomic_int_inc(&role->ref);
}

/* returns true if the ref count went to 0 and the role was freed */
static bool
LSHubRoleUnref(LSHubRole *role)
{
    LS_ASSERT(role != NULL);
    LS_ASSERT(g_atomic_int_get(&role->ref) > 0);

    LOG_LS_DEBUG("%s\n", __func__);

    if (g_atomic_int_dec_and_test(&role->ref))
    {
        LSHubRoleFree(role);
        return true;
    }

    return false;
}

/* creates a copy of a HubRole with refcount of 1 */
static LSHubRole*
LSHubRoleCopyRef(const LSHubRole *role)
{
    LOG_LS_DEBUG("%s\n", __func__);

    raw_buffer exe_path = {
        .m_str = role->exe_path,
        .m_len = strlen(role->exe_path)
    };

    LSHubRole *new_role = LSHubRoleNew(exe_path, role->type);

    new_role->ref = 1;

    /* Unref the queue allocated in LSHubRoleNew */
    _LSHubPatternQueueUnref(new_role->allowed_names);

    /* shallow copy */
    new_role->allowed_names = _LSHubPatternQueueCopyRef(role->allowed_names);

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

    GSList *list = q->q;

    while (list)
    {
        _LSHubPatternSpec *pattern = (_LSHubPatternSpec*)list->data;
        if (sep)
          g_string_append_c(str, ',');
        // FIXME: this doesn't attempt to escape characters, despite being used as JSON
        g_string_append_printf(str, "\"%s\"", pattern->pattern_str);
        sep = true;
        list = g_slist_next(list);
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

gchar*
LSHubPermissionDump(const LSHubPermission *perm)
{
    GString *str = g_string_new("{service: ");
    str = g_string_append(str, perm->service_name);
    str = g_string_append(str, ", inbound: ");

    gchar *inbound = _LSHubPatternQueueDump(perm->inbound);
    str = g_string_append(str, inbound);
    g_free(inbound);

    str = g_string_append(str, ", outbound: ");

    gchar *outbound = _LSHubPatternQueueDump(perm->outbound);
    str = g_string_append(str, outbound);
    g_free(outbound);

    str = g_string_append(str, "}");
    return g_string_free(str, FALSE);
}

bool
LSHubRoleAddAllowedName(LSHubRole *role, const char *name, LSError *lserror)
{
    LS_ASSERT(role != NULL);
    LS_ASSERT(name != NULL);

    LOG_LS_DEBUG("%s: add name: \"%s\"\n", __func__, name);

    _LSHubPatternSpec *pattern = _LSHubPatternSpecNewRef(name);

    _LSHubPatternQueuePushTail(role->allowed_names, pattern); /* increments ref count */
    _LSHubPatternSpecUnref(pattern);
    return true;
}

static LSHubRoleType
_LSHubRoleTypeStringToType(raw_buffer type)
{
    LOG_LS_DEBUG("%s: type: \"%.*s\"\n", __func__, (int)type.m_len, type.m_str);

    if (buffer_eq_cstr(type, ROLE_TYPE_REGULAR))
    {
        return LSHubRoleTypeRegular;
    }
    else if (buffer_eq_cstr(type, ROLE_TYPE_PRIVILEGED))
    {
        return LSHubRoleTypePrivileged;
    }
    else
    {
        return LSHubRoleTypeInvalid;
    }
}

#ifndef UNIT_TESTS
static
#endif
LSHubPermission*
LSHubPermissionNew(raw_buffer service_name)
{
    LS_ASSERT(service_name.m_str != NULL);

    LOG_LS_DEBUG("%s\n", __func__);

    LSHubPermission *perm = g_slice_new0(LSHubPermission);

    perm->service_name = g_strndup(service_name.m_str, service_name.m_len);
    perm->inbound = _LSHubPatternQueueNewRef();
    perm->outbound = _LSHubPatternQueueNewRef();

    return perm;
}

static LSHubPermission*
LSHubPermissionNewRef(raw_buffer service_name)
{
    LOG_LS_DEBUG("%s\n", __func__);

    LSHubPermission *perm = LSHubPermissionNew(service_name);

    if (perm)
    {
        perm->ref = 1;
    }

    return perm;
}

#ifndef UNIT_TESTS
static
#endif
void
LSHubPermissionFree(LSHubPermission *perm)
{
    LS_ASSERT(perm != NULL);

    LOG_LS_DEBUG("%s: free permission\n", __func__);

    g_free((char*)perm->service_name);

    _LSHubPatternQueueUnref(perm->inbound);
    _LSHubPatternQueueUnref(perm->outbound);

#ifdef MEMCHECK
    memset(perm, 0xFF, sizeof(LSHubPermission));
#endif

    g_slice_free(LSHubPermission, perm);
}

static void
LSHubPermissionRef(LSHubPermission *perm)
{
    LS_ASSERT(perm != NULL);
    LS_ASSERT(g_atomic_int_get(&perm->ref) > 0);

    LOG_LS_DEBUG("%s: ref permission\n", __func__);

    g_atomic_int_inc(&perm->ref);
}

static bool
LSHubPermissionUnref(LSHubPermission *perm)
{
    LS_ASSERT(perm != NULL);
    LS_ASSERT(g_atomic_int_get(&perm->ref) > 0);

    LOG_LS_DEBUG("%s: unref permission\n", __func__);

    if (g_atomic_int_dec_and_test(&perm->ref))
    {
        LSHubPermissionFree(perm);
        return true;
    }
    return false;
}

#ifndef UNIT_TESTS
static
#endif
bool
LSHubPermissionAddAllowedInbound(LSHubPermission *perm, const char *name, LSError *lserror)
{
    LS_ASSERT(perm != NULL);
    LS_ASSERT(name != NULL);

    LOG_LS_DEBUG("%s: add name: \"%s\" as allowed inbound\n", __func__, name);

    _LSHubPatternSpec *pattern = _LSHubPatternSpecNewRef(name);

    _LSHubPatternQueueInsertSorted(perm->inbound, pattern); /* increments ref count */
    _LSHubPatternSpecUnref(pattern);
    return true;
}

#ifndef UNIT_TESTS
static
#endif
bool
LSHubPermissionAddAllowedOutbound(LSHubPermission *perm, const char *name, LSError *lserror)
{
    LS_ASSERT(perm != NULL);
    LS_ASSERT(name != NULL);

    LOG_LS_DEBUG("%s: add name: \"%s\" as allowed outbound\n", __func__, name);

    _LSHubPatternSpec *pattern = _LSHubPatternSpecNewRef(name);

    _LSHubPatternQueueInsertSorted(perm->outbound, pattern); /* increments ref count */
    _LSHubPatternSpecUnref(pattern);
    return true;
}

#ifndef UNIT_TESTS
static
#endif
bool
LSHubPermissionIsEqual(const LSHubPermission *a, const LSHubPermission *b)
{
    LS_ASSERT(a != NULL);
    LS_ASSERT(b != NULL);

    if (a == b)
        return true;

    return !strcmp(a->service_name, b->service_name) &&
           _LSHubPatternQueueIsEqual(a->inbound, b->inbound) &&
           _LSHubPatternQueueIsEqual(a->outbound, b->outbound);
}

/***************************** ROLE MAP ****************************/

LSHubRole*
LSHubRoleMapLookup(const char *exe_path)
{
    LOG_LS_DEBUG("%s: look up exe_path: \"%s\" in role map\n", __func__, exe_path);

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

    LOG_LS_DEBUG("%s: ref role: %p in role map...\n", __func__, role);

    /* check to see if it already exists -- we don't want duplicates */
    if (LSHubRoleMapLookup(role->exe_path))
    {
        LOG_LS_DEBUG("%s: ...failure\n", __func__);
        _LSErrorSet(lserror, MSGID_LSHUB_ROLE_EXISTS, -1, "Role already exists for exe_path: \"%s\"", role->exe_path);
        return false;
    }

    LSHubRoleRef(role);
    g_hash_table_insert(LSHubGetRoleMap(), g_strdup(role->exe_path), role);

    LOG_LS_DEBUG("%s: ...success\n", __func__);

    return true;
}

/* returns true if ref count went down to 0 and we removed from the hash table
 */
bool
LSHubRoleMapUnref(const char *exe_path)
{
    LS_ASSERT(exe_path != NULL);

    LOG_LS_DEBUG("%s: unref'ing exe_path: \"%s\" from role map... ", __func__, exe_path);

    LSHubRole *role = LSHubRoleMapLookup(exe_path);

    LS_ASSERT(role != NULL);

    if (LSHubRoleUnref(role))
    {
        bool removed = g_hash_table_remove(LSHubGetRoleMap(), exe_path);
        LS_ASSERT(removed == true);
        LOG_LS_DEBUG("removed\n");
        return true;
    }

    LOG_LS_DEBUG("unref'ed\n");

    return false;
}

/************************* ACTIVE ROLE MAP *******************************/

LSHubRole*
LSHubActiveRoleMapLookup(pid_t pid)
{
    LOG_LS_DEBUG("%s: look up pid: "LS_PID_PRINTF_FORMAT" in role map\n", __func__, LS_PID_PRINTF_CAST(pid));
    return g_hash_table_lookup(LSHubGetActiveRoleMap(), &pid);
}

bool
LSHubActiveRoleMapAddRef(pid_t pid, LSHubRole *role, LSError *lserror)
{
    LOG_LS_DEBUG("%s: attempting to ref pid: "LS_PID_PRINTF_FORMAT" in role map...\n", __func__, LS_PID_PRINTF_CAST(pid));

    /* if it already exists in hash table then bump up its ref count */
    LSHubRole *hashed_role = LSHubActiveRoleMapLookup(pid);

    if (hashed_role)
    {
        /* active role already exists for this pid, so bump ref count */
        LSHubRoleRef(hashed_role);
        LOG_LS_DEBUG("%s: bump ref count...\n", __func__);
    }
    else
    {
        /* ref and insert new role */
        gint *key = g_malloc(sizeof(*key));
        *key = pid;
        LSHubRoleRef(role);
        g_hash_table_insert(LSHubGetActiveRoleMap(), key, role);
        LOG_LS_DEBUG("%s: ref and insert...\n", __func__);
    }

    LOG_LS_DEBUG("%s: success\n", __func__);

    return true;
}

bool
LSHubActiveRoleMapUnref(pid_t pid)
{
    LOG_LS_DEBUG("%s: attempting to unref pid: "LS_PID_PRINTF_FORMAT" from role map...\n", __func__, LS_PID_PRINTF_CAST(pid));

    /* if the role ref count goes to 0, we remove it from the hash table */
    LSHubRole *role = LSHubActiveRoleMapLookup(pid);

    if (role)
    {
        if (LSHubRoleUnref(role))
        {
            /* ref count for this role went to 0, so remove the reference to
             * it in the hash table */
            g_hash_table_remove(LSHubGetActiveRoleMap(), &pid);
            LOG_LS_DEBUG("%s: removed...\n", __func__);
            return true;
        }

        LOG_LS_DEBUG("unref'ed\n");
    }

    return false;
}


/***************************** PERMISSION MAP *****************************/

LSHubPermission*
LSHubPermissionMapLookup(const char *service_name)
{
    LOG_LS_DEBUG("%s: looking up service name: \"%s\" in permission map\n", __func__, service_name);

    LSHubPermission *perm = NULL;

    if (service_name)
    {
        perm = g_hash_table_lookup(LSHubGetPermissionMap(), service_name);

        if (!perm)
        {
            _LSHubPatternSpec key = _LSHubPatternSpecNoPattern(service_name);
            perm = g_tree_lookup(LSHubGetPermissionWildcardMap(), &key);
        }
    }

    return perm;
}

/* Add permission to hash table */
bool
LSHubPermissionMapAddRef(LSHubPermission *perm, LSError *lserror)
{
    LOG_LS_DEBUG("%s: attempting to add permission %p to permission map...\n", __func__, perm);

    LSHubPermission *lookup_perm = LSHubPermissionMapLookup(perm->service_name);

    if (lookup_perm)
    {
        /* Services widely use name "" for anonymouse call, but it's in fact one instance,
         * which is shared among all them. So we register empty name only once,
         * hoping that it has enough permissions for all them
         */
        if (!perm->service_name[0])
            return true;

        /* Permissions are global, so they can't be duplicated.
         * However, there's no point to complain on *equal* duplicates.
         */
        if (LSHubPermissionIsEqual(perm, lookup_perm))
        {
            LOG_LS_DEBUG("Allowing duplicate service name in permission map: \"%s\"", perm->service_name);
            return true;
        }

        gchar *perm_str = LSHubPermissionDump(perm);
        gchar *lookup_perm_str = LSHubPermissionDump(lookup_perm);

        _LSErrorSet(lserror, MSGID_LSHUB_SERVICE_EXISTS, -1,
                    "Skipping duplicate service name to permission map: %s (already there %s)",
                    perm_str, lookup_perm_str);

        g_free(perm_str);
        g_free(lookup_perm_str);

        LOG_LS_DEBUG("%s: failure\n", __func__);
        return false;
    }

    // See if perm->service_name is a wildcard. If so, it must be compiled and stored
    // in the tree instead of the hash map.
    size_t prefix = strcspn(perm->service_name, "*?");
    if (!perm->service_name[prefix])
    {
        // The service name doesn't contain wildcard characters, treat verbatim.
        LSHubPermissionRef(perm);
        g_hash_table_insert(LSHubGetPermissionMap(), g_strdup(perm->service_name), perm);
    }
    else
    {
        _LSHubPatternSpec *pattern = _LSHubPatternSpecNewRef(perm->service_name);

        LSHubPermissionRef(perm);
        g_tree_insert(LSHubGetPermissionWildcardMap(), pattern, perm);
    }

    LOG_LS_DEBUG("%s: success\n", __func__);
    return true;
}


gboolean RoleMapRemoveSpecDirectory (gpointer key, gpointer value, gpointer user_data)
{
    LSHubRole const *role = value;
    return GPOINTER_TO_INT(user_data) == role->from_volatile_dir;
}

bool
LSHubRoleMapClear(LSError *lserror, bool from_volatile_dir)
{
    LOG_LS_DEBUG("%s: clearing role map\n", __func__);

    g_hash_table_foreach_remove(LSHubGetRoleMap(), &RoleMapRemoveSpecDirectory, GINT_TO_POINTER(from_volatile_dir));

    return true;
}

gboolean PermissionMapRemoveSpecDirectory (gpointer key, gpointer value, gpointer user_data)
{
    LSHubPermission* service = value;
    bool from_volatile_dir = *(bool*)user_data;
    return from_volatile_dir == service->from_volatile_dir;
}

bool
LSHubPermissionMapClear(LSError *lserror, bool from_volatile_dir)
{
    LOG_LS_DEBUG("%s: clearing permission map\n", __func__);

    g_hash_table_foreach_remove(LSHubGetPermissionMap(), &PermissionMapRemoveSpecDirectory, &from_volatile_dir);

    return true;
}

struct PermTreeTraverseData
{
    GSList* list_to_remove;
    bool from_volatile_dir;
};
typedef struct PermTreeTraverseData PermTreeTraverseData;

static gboolean PermTreeTraverse(gpointer key, gpointer value, gpointer data)
{
    PermTreeTraverseData* arg = (PermTreeTraverseData*)data;
    LSHubPermission* perm = (LSHubPermission*)value;
    if (arg->from_volatile_dir == perm->from_volatile_dir)
    {
        arg->list_to_remove = g_slist_prepend(arg->list_to_remove, key);
    }

    return false;
}

void
LSHubWildcardPermissionTreeClear(bool from_volatile_dir)
{
    LOG_LS_DEBUG("%s: clearing wildcard permission tree\n", __func__);

    PermTreeTraverseData traverse_data;
    traverse_data.from_volatile_dir = from_volatile_dir;
    traverse_data.list_to_remove = NULL;

    g_tree_foreach(permission_wildcard_map, PermTreeTraverse, &traverse_data);

    for (; traverse_data.list_to_remove != NULL;
         traverse_data.list_to_remove = g_slist_delete_link(traverse_data.list_to_remove,
                                                            traverse_data.list_to_remove))
    {
        LSHubPermission* perm = (LSHubPermission*)traverse_data.list_to_remove->data;
        g_tree_remove(permission_wildcard_map, perm);
    }
}

static bool
ParseJSONFile(const char *path, jvalue_ref *json, LSError *lserror)
{
    struct JErrorCallbacks errorCallbacks;
    JSchemaInfo schemaInfo;
    jvalue_ref dom;

    SetLSErrorCallbacks(&errorCallbacks, lserror);

    jschema_info_init(&schemaInfo, jschema_all(), NULL, &errorCallbacks);

    LOG_LS_DEBUG("%s: parsing JSON from file: \"%s\"", __func__, path);

    dom = jdom_parse_file(path, &schemaInfo, JFileOptMMap);

    if (!jis_valid(dom)) /* error? */
    {
        j_release(&dom);
        return false;
    }

    *json = dom;

    LOG_LS_DEBUG("%s: successfully parsed JSON\n", __func__);

    return true;
}

static bool
ParseJSONGetRole(jvalue_ref json, const char *json_file_path, LSHubRole **role,
                 LSError *lserror)
{
    bool ret = false;
    jvalue_ref role_obj = NULL;
    jvalue_ref allowed_names_obj = NULL;
    LSHubRole *ret_role = NULL;

    LOG_LS_DEBUG("%s: parsing role from file: %s\n", __func__, json_file_path);

    if (!jobject_get_exists(json, J_CSTR_TO_BUF(ROLE_KEY), &role_obj))
    {
        _LSErrorSet(lserror, MSGID_LSHUB_ROLE_FILE_ERR, -1, "Unable to get %s from JSON (%s)", ROLE_KEY, json_file_path);
        goto exit;
    }

    /* exeName */
    raw_buffer exe_buf;
    if (!jobject_get_string(role_obj, J_CSTR_TO_BUF(EXE_NAME_KEY), &exe_buf, lserror, MSGID_LSHUB_ROLE_FILE_ERR, json_file_path))
    {
        goto exit;
    }

    /* type */
    raw_buffer type_buf;
    if (!jobject_get_string(role_obj, J_CSTR_TO_BUF(TYPE_KEY), &type_buf, lserror, MSGID_LSHUB_ROLE_FILE_ERR, json_file_path))
    {
        goto exit;
    }

    if (!jobject_get_exists(role_obj, J_CSTR_TO_BUF(ALLOWED_NAMES_KEY), &allowed_names_obj))
    {
        _LSErrorSet(lserror, MSGID_LSHUB_ROLE_FILE_ERR, -1, "Unable to get %s from JSON (%s)", ALLOWED_NAMES_KEY, json_file_path);
        goto exit;
    }

    if (!jis_array(allowed_names_obj))
    {
        _LSErrorSet(lserror, MSGID_LSHUB_ROLE_FILE_ERR, -1, "Property %s isn't an array inside JSON (%s)", ALLOWED_NAMES_KEY, json_file_path);
        goto exit;
    }

    ssize_t allowed_names_arr_len = jarray_size(allowed_names_obj);

    LSHubRoleType type = _LSHubRoleTypeStringToType(type_buf);

    LOG_LS_DEBUG("%s: creating new role with exe_name: \"%.*s\", type: %d\n", __func__, (int)exe_buf.m_len, exe_buf.m_str, type);

    ret_role = LSHubRoleNewRef(exe_buf, type);

    /* allowedNames */
    ssize_t i;
    for (i = 0; i < allowed_names_arr_len; i++)
    {
        jvalue_ref tmp_obj = jarray_get(allowed_names_obj, i);
        raw_buffer tmp_buf = jstring_get_fast(tmp_obj);

        /* Work-around to get C-string.
         * We would pass raw_buffer but there is an external (to this module)
         * code around patterns that expects C-string used in
         * LSHubRoleAddAllowedName.
         */
        LOCAL_CSTR_FROM_BUF( tmp, tmp_buf );

        if (!LSHubRoleAddAllowedName(ret_role, tmp, lserror))
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

static bool
ParseJSONGetPermissions(jvalue_ref json, const char *json_file_path, GSList **perm_list,
                        LSError *lserror)
{
    bool ret = false;
    jvalue_ref perm_obj;

    LOG_LS_DEBUG("%s: parsing permissions from %s\n", __func__, json_file_path);

    if (!jobject_get_exists(json, J_CSTR_TO_BUF(PERMISSION_KEY), &perm_obj))
    {
        _LSErrorSet(lserror, MSGID_LSHUB_ROLE_FILE_ERR, -1, "Unable to get permission from JSON (%s)", json_file_path);
        goto exit;
    }

    ssize_t perm_arr_len = jarray_size(perm_obj);

    ssize_t i;
    for (i = 0; i < perm_arr_len; i++)
    {
        jvalue_ref cur_perm_obj = jarray_get(perm_obj, i);

        raw_buffer service_buf;
        if (!jobject_get_string(cur_perm_obj, J_CSTR_TO_BUF(SERVICE_KEY), &service_buf, lserror, MSGID_LSHUB_ROLE_FILE_ERR, json_file_path))
        {
            goto exit;
        }

        jvalue_ref inbound_obj;
        if (!jobject_get_exists(cur_perm_obj, J_CSTR_TO_BUF(INBOUND_KEY), &inbound_obj))
        {
            _LSErrorSet(lserror, MSGID_LSHUB_ROLE_FILE_ERR, -1, "Unable to get %s from JSON (%s)", INBOUND_KEY, json_file_path);
            goto exit;
        }

        jvalue_ref outbound_obj;
        if (!jobject_get_exists(cur_perm_obj, J_CSTR_TO_BUF(OUTBOUND_KEY), &outbound_obj))
        {
            _LSErrorSet(lserror, MSGID_LSHUB_ROLE_FILE_ERR, -1, "Unable to get %s from JSON (%s)", OUTBOUND_KEY, json_file_path);
            goto exit;
        }
        LOG_LS_DEBUG("%s: creating new permission\n", __func__);

        LSHubPermission *new_perm = LSHubPermissionNewRef(service_buf);

        *perm_list = g_slist_prepend(*perm_list, new_perm);

        ssize_t inbound_size = jarray_size(inbound_obj);
        ssize_t j;
        for (j = 0; j < inbound_size; j++)
        {
            raw_buffer cur_inbound_buf;
            if (!jarray_get_string(inbound_obj, j, &cur_inbound_buf, lserror, MSGID_LSHUB_ROLE_FILE_ERR, json_file_path))
            {
                goto exit;
            }

            LOCAL_CSTR_FROM_BUF( cur_inbound, cur_inbound_buf );
            if (!LSHubPermissionAddAllowedInbound(new_perm, cur_inbound, lserror))
            {
                goto exit;
            }
        }

        ssize_t outbound_size = jarray_size(outbound_obj);
        ssize_t k;
        for (k = 0; k < outbound_size; k++)
        {
            raw_buffer cur_outbound_buf;
            if (!jarray_get_string(outbound_obj, k, &cur_outbound_buf, lserror, MSGID_LSHUB_ROLE_FILE_ERR, json_file_path))
            {
                goto exit;
            }

            LOCAL_CSTR_FROM_BUF( cur_outbound, cur_outbound_buf );
            if (!LSHubPermissionAddAllowedOutbound(new_perm, cur_outbound, lserror))
            {
                goto exit;
            }
        }
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
ParseRoleDirectory(const char *path, LSError *lserror, bool is_volatile_dir)
{
    GError *gerror = NULL;
    const char *filename = NULL;

    LOG_LS_DEBUG("%s: parsing role directory: \"%s\"\n", __func__, path);

    GDir *dir = g_dir_open(path, 0, &gerror);

    if (!dir)
    {
        if (gerror->code == G_FILE_ERROR_NOENT)
        {
            LOG_LS_DEBUG("Skipping missing roles directory %s", path);
            return true;
        }
        _LSErrorSetFromGError(lserror, MSGID_LSHUB_NO_ROLE_DIR, gerror);
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
            jvalue_ref json = NULL;
            if (!ParseJSONFile(full_path, &json, lserror))
            {
                LOG_LSERROR(MSGID_LSHUB_ROLE_FILE_ERR, lserror);
                LSErrorFree(lserror);
                goto next;
            }

            if (!ParseJSONGetRole(json, full_path, &role, lserror))
            {
                LOG_LSERROR(MSGID_LSHUB_ROLE_FILE_ERR, lserror);
                LSErrorFree(lserror);
            }


            if (!ParseJSONGetPermissions(json, full_path, &perm_list, lserror))
            {
                LOG_LSERROR(MSGID_LSHUB_ROLE_FILE_ERR, lserror);
                LSErrorFree(lserror);
            }

            /* Add role object to hash table */
            if (role)
            {
                role->from_volatile_dir = is_volatile_dir;

                /* Don't add the role (but do add permissions) for a triton
                 * service, since triton will push the role file when it wants to
                 * use it
                 *
                 * Similarly, don't add the role for a mojo app, since they
                 * do not register for a service name (sysmgr just sets the
                 * appId and we do the check on that */
                if (g_strcmp0(role->exe_path, g_conf_triton_service_exe_path) != 0 &&
                    g_strcmp0(role->exe_path, g_conf_mojo_app_exe_path) != 0)
                {
                    if (!LSHubRoleMapAddRef(role, lserror))
                    {
                        LOG_LSERROR(MSGID_LSHUB_DATA_ERROR, lserror);
                        LSErrorFree(lserror);
                    }
                }
            }

            /* Add permission object to hash table */
            for (; perm_list != NULL; perm_list = g_slist_delete_link(perm_list, perm_list)/*perm_list = g_slist_next(perm_list)*/)
            {
                LSHubPermission *perm = perm_list->data;
                perm->from_volatile_dir = is_volatile_dir;

                if (!LSHubPermissionMapAddRef(perm, lserror))
                {
                    LOG_LSERROR(MSGID_LSHUB_DATA_ERROR, lserror);
                    LSErrorFree(lserror);
                }
                LSHubPermissionUnref(perm);
            }

next:
            if (role) LSHubRoleUnref(role);
            j_release(&json);
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
    jvalue_ref json = NULL;
    LSHubRole *role = NULL;

    /* Remove current role from active role map if there is one */
    const _LSTransportCred *cred = _LSTransportClientGetCred(client);

    if (!cred)
    {
        _LSErrorSet(lserror, MSGID_LSHUB_PUSH_ROLE_ERR, LS_TRANSPORT_PUSH_ROLE_PERMISSION_DENIED, LS_TRANSPORT_PUSH_ROLE_PERMISSION_DENIED_TEXT);
        goto exit;
    }

    /* DFISH-23679: Only root users can push a role */
    uid_t uid = _LSTransportCredGetUid(cred);

    if (uid != 0)
    {
        _LSErrorSet(lserror, MSGID_LSHUB_PUSH_ROLE_ERR, LS_TRANSPORT_PUSH_ROLE_PERMISSION_DENIED, LS_TRANSPORT_PUSH_ROLE_PERMISSION_DENIED_TEXT);
        goto exit;
    }

    pid_t pid = _LSTransportCredGetPid(cred);

    /* Unref the existing role for this pid if there is one. */
    if ((role = LSHubActiveRoleMapLookup(pid)) != NULL)
    {
        /* Check that this client is allowed to push a role */
        if (!LSHubClientGetPrivileged(client))
        {
            _LSErrorSet(lserror, MSGID_LSHUB_PUSH_ROLE_ERR, LS_TRANSPORT_PUSH_ROLE_PERMISSION_DENIED, LS_TRANSPORT_PUSH_ROLE_PERMISSION_DENIED_TEXT);
            goto exit;
        }

        /* Verify that there should only be a single ref and the role is freed */
        if (!LSHubActiveRoleMapUnref(pid))
        {
            _LSErrorSet(lserror, MSGID_LSHUB_PUSH_ROLE_ERR, LS_TRANSPORT_PUSH_ROLE_DUPLICATE, LS_TRANSPORT_PUSH_ROLE_DUPLICATE_TEXT);
            goto exit;
        }
    }
    else
    {
        /* Couldn't verify that this pid is allowed to push a role */
        _LSErrorSet(lserror, MSGID_LSHUB_PUSH_ROLE_ERR, LS_TRANSPORT_PUSH_ROLE_PERMISSION_DENIED, LS_TRANSPORT_PUSH_ROLE_PERMISSION_DENIED_TEXT);
        goto exit;
    }

    /* create the new role from the file */
    if (!ParseJSONFile(path, &json, lserror))
    {
        LOG_LSERROR(MSGID_LSHUB_ROLE_FILE_ERR, lserror);
        LSErrorFree(lserror);
        _LSErrorSet(lserror, MSGID_LSHUB_PUSH_ROLE_ERR, LS_TRANSPORT_PUSH_ROLE_FILE_ERROR, LS_TRANSPORT_PUSH_ROLE_FILE_ERROR_TEXT, path);
        goto exit;
    }

    if (!ParseJSONGetRole(json, path, &role, lserror))
    {
        LOG_LSERROR(MSGID_LSHUB_ROLE_FILE_ERR, lserror);
        LSErrorFree(lserror);
        _LSErrorSet(lserror, MSGID_LSHUB_PUSH_ROLE_ERR, LS_TRANSPORT_PUSH_ROLE_FILE_ERROR, LS_TRANSPORT_PUSH_ROLE_FILE_ERROR_TEXT, path);
        goto exit;
    }

    /* ignore any permissions in the file */

    if (!LSHubActiveRoleMapAddRef(pid, role, lserror))
    {
        LOG_LSERROR(MSGID_LSHUB_ROLE_FILE_ERR, lserror);
        LSErrorFree(lserror);
        _LSErrorSet(lserror, MSGID_LSHUB_PUSH_ROLE_ERR, LS_TRANSPORT_PUSH_ROLE_UNKNOWN_ERROR, LS_TRANSPORT_PUSH_ROLE_UNKNOWN_ERROR_TEXT);
        LSHubRoleUnref(role);
        goto exit;
    }

    LSHubRoleUnref(role);

    ret = true;

exit:
    j_release(&json);

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
        _LSErrorSet(lserror, MSGID_LSHUB_NO_CLIENT, -1, "Unable to get client credentials");
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

        const char *exe_path = _LSTransportCredGetExePath(cred);

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
                LOG_LS_ERROR(MSGID_LSHUB_NO_ROLE_FILE, 1,
                             PMLOGKS("EXE", exe_path),
                             "No role file for executable: \"%s\" (cmdline: %s)",
                             exe_path, _LSTransportCredGetCmdLine(cred));
                return false;
            }
            else
            {
                LOG_LS_WARNING(MSGID_LSHUB_NO_ROLE_FILE, 1,
                               PMLOGKS("EXE", exe_path),
                               "Missing role file for executable: \"%s\" (cmdline: %s)",
                               exe_path, _LSTransportCredGetCmdLine(cred));
                return true;
            }
        }

        /* create copy, ref, and add to active role map */
        LSHubRole *copy = LSHubRoleCopyRef(role);               /* ref count = 1 */
        if (!LSHubActiveRoleMapAddRef(pid, copy, &lserror))     /* ref count = 2 */
        {
            LOG_LSERROR(MSGID_LSHUB_DATA_ERROR, &lserror);
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
        LOG_LS_ERROR(MSGID_LSHUB_NO_PERMISSION_FOR_NAME, 2,
                     PMLOGKS("APP_ID", service_name),
                     PMLOGKS("EXE", _LSTransportCredGetExePath(cred)),
                     "Executable: \"%s\" (cmdline: %s) "
                     "does not have permission to register name: \"%s\"",
                     _LSTransportCredGetExePath(cred),
                     _LSTransportCredGetCmdLine(cred),
                     service_name);

        return false;
    }
    else
    {
        LOG_LS_WARNING(MSGID_LSHUB_NO_PERMISSION_FOR_NAME, 2,
                       PMLOGKS("APP_ID", service_name),
                       PMLOGKS("EXE", _LSTransportCredGetExePath(cred)),
                       "Executable: \"%s\" (cmdline: %s) "
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
    if (!path)
        return false;

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
        LOG_LS_ERROR(MSGID_LSHUB_NO_INBOUND_PERMS, 4,
                     PMLOGKS("DEST_APP_ID", dest_service_name),
                     PMLOGKS("SRC_APP_ID", sender_service_name),
                     PMLOGKS("EXE", _LSTransportCredGetExePath(cred)),
                     PMLOGKFV("PID", LS_PID_PRINTF_FORMAT, LS_PID_PRINTF_CAST(_LSTransportCredGetPid(cred))),
                     "Permissions does not allow inbound connections from \"%s\" to \"%s\" (cmdline: %s)",
                     sender_service_name, dest_service_name, _LSTransportCredGetCmdLine(cred));
    }
    else
    {
        /* outbound */
        LOG_LS_ERROR(MSGID_LSHUB_NO_OUTBOUND_PERMS, 4,
                     PMLOGKS("DEST_APP_ID", dest_service_name),
                     PMLOGKS("SRC_APP_ID", sender_service_name),
                     PMLOGKS("EXE", _LSTransportCredGetExePath(cred)),
                     PMLOGKFV("PID", LS_PID_PRINTF_FORMAT, LS_PID_PRINTF_CAST(_LSTransportCredGetPid(cred))),
                     "\"%s\" does not have sufficient outbound permissions to communicate with \"%s\" (cmdline: %s)",
                     sender_service_name, dest_service_name, _LSTransportCredGetCmdLine(cred));
    }
}

static inline void
_LSHubPrintSignalPermissionsMessage(const _LSTransportClient *client)
{
    const char *service_name = _LSTransportClientGetServiceName(client);
    const _LSTransportCred *cred = _LSTransportClientGetCred(client);

    LOG_LS_ERROR(MSGID_LSHUB_NO_SIGNAL_PERMS, 3,
                 PMLOGKS("APP_ID", service_name),
                 PMLOGKS("EXE", _LSTransportCredGetExePath(cred)),
                 PMLOGKFV("PID", LS_PID_PRINTF_FORMAT, LS_PID_PRINTF_CAST(_LSTransportCredGetPid(cred))),
                 "\"%s\" is not allowed to send signals (cmdline: %s)", service_name,
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
    char *modified_app_id = g_strdup(app_id);

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
    g_free(modified_app_id);

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
    g_free(modified_app_id);

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

bool
PermissionsAndRolesInit(LSError *lserror, bool from_volatile_dir)
{
    if (role_map)
    {
        if (!LSHubRoleMapClear(lserror, from_volatile_dir))
        {
            LOG_LSERROR(MSGID_LSHUB_DATA_ERROR, lserror);
            LSErrorFree(lserror);
        }
    }
    else
    {
        role_map = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, (GDestroyNotify) LSHubRoleUnref);
    }

    if (!active_role_map)
    {
        /* NOTE: Don't set the value destroy function to unref or it will break
         * the ref counting scheme used */
        active_role_map = g_hash_table_new_full(g_int_hash, g_int_equal, g_free, NULL);
    }

    if (permission_map)
    {
        if (!LSHubPermissionMapClear(lserror, from_volatile_dir))
        {
            LOG_LSERROR(MSGID_LSHUB_DATA_ERROR, lserror);
            LSErrorFree(lserror);
        }
    }
    else
    {
        permission_map = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, (GDestroyNotify) LSHubPermissionUnref);
    }

    if (permission_wildcard_map)
    {
        LSHubWildcardPermissionTreeClear(from_volatile_dir);
    }
    else
    {
        permission_wildcard_map = g_tree_new_full((GCompareDataFunc) _LSHubPatternSpecCompare, NULL,
                                                  (GDestroyNotify) _LSHubPatternSpecUnref,
                                                  (GDestroyNotify) LSHubPermissionUnref);
        if (!permission_wildcard_map)
        {
            LOG_LS_ERROR(MSGID_LSHUB_ARGUMENT_ERR, 0, "Invalid cannot create Glib tree");
            return false;
        }
    }

    return true;
}


static void
_PermissionsAndRolesDeinit()
{
    if (role_map) g_hash_table_destroy(role_map);
    if (active_role_map) g_hash_table_destroy(active_role_map);
    if (permission_map) g_hash_table_destroy(permission_map);
    if (permission_wildcard_map) g_tree_destroy(permission_wildcard_map);
}

static gboolean
print_wildcard_permissions(gpointer key, gpointer value, gpointer data)
{
    LSHubPermissionPrint((LSHubPermission *) value, stderr);
    return false;
}

bool
ProcessRoleDirectories(const char **dirs, void *ctxt, LSError *lserror)
{
    /* process all the role files in the specified directories */
    LS_ASSERT(dirs != NULL);

    const char **cur_dir = NULL;

    bool is_volatile_dir = (GPOINTER_TO_INT(ctxt) == VOLATILE_DIRS);

    printf("%s called\n", __func__);

    if (!PermissionsAndRolesInit(lserror, is_volatile_dir))
    {
        return false;
    }

    for (cur_dir = dirs; cur_dir != NULL && *cur_dir != NULL; cur_dir++)
    {
        if (!ParseRoleDirectory(*cur_dir, lserror, is_volatile_dir))
        {
            LOG_LSERROR(MSGID_LSHUB_ROLE_FILE_ERR, lserror);
            LSErrorFree(lserror);
        }
    }

    if (is_volatile_dir)
    {
        if (roles_volatile_dirs != (gchar**)dirs)
        {
            g_strfreev(roles_volatile_dirs);
            roles_volatile_dirs = g_strdupv((gchar**)dirs);
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

    g_tree_foreach(LSHubGetPermissionWildcardMap(), print_wildcard_permissions, NULL);

    return true;
}

void RolesCleanup()
{
    _PermissionsAndRolesDeinit();
}
