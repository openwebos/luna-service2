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
 *  @file category.c
 */

#include "category.h"

#include "luna-service2/lunaservice.h"
#include "luna-service2/lunaservice-meta.h"
#include "log.h"

/**
 * @addtogroup LunaServiceInternals
 * @{
 */

static void
_LSCategoryTableFree(LSCategoryTable *table)
{
    if (table->methods)
        g_hash_table_unref(table->methods);
    if (table->signals)
        g_hash_table_unref(table->signals);
    if (table->properties)
        g_hash_table_unref(table->properties);

    j_release(&table->description);

#ifdef MEMCHECK
    memset(table, 0xFF, sizeof(LSCategoryTable));
#endif

    g_free(table);
}

static char*
_category_to_object_path_alloc(const char *category)
{
    char *category_path;

    if (NULL == category)
    {
        category_path = g_strdup("/"); // default category
    }
    else if ('/' == category[0])
    {
        category_path = g_strdup(category);
    }
    else
    {
        category_path = g_strdup_printf("/%s", category);
    }

    return category_path;
}

static bool
_category_exists(LSHandle *sh, const char *category)
{
    if (!sh->tableHandlers) return false;

    char *category_path = _category_to_object_path_alloc(category);
    bool exists = false;

    if (g_hash_table_lookup(sh->tableHandlers, category_path))
    {
        exists = true;
    }

    g_free(category_path);

    return exists;
}

static LSCategoryTable *
LSHandleGetCategory(LSHandle *sh, const char *category, LSError *error)
{
    LSCategoryTable *table;
    char *categoryPath = _category_to_object_path_alloc(category);

    _LSGlobalLock();

    _LSErrorGotoIfFail(fail, sh->tableHandlers != NULL, error, MSGID_LS_NO_CATEGORY_TABLE,
        -1, "%s: %s not registered.", __FUNCTION__, category);

    table = g_hash_table_lookup(sh->tableHandlers, category);
    _LSErrorGotoIfFail(fail, table != NULL, error, MSGID_LS_NO_CATEGORY,
        -1, "%s: %s not registered.", __FUNCTION__, category);

    _LSGlobalUnlock();
    g_free(categoryPath);
    return table;

fail:
    _LSGlobalUnlock();
    g_free(categoryPath);

    return NULL;
}

static LSMethodEntry *LSMethodEntryCreate(LSMethod *method)
{
    LS_ASSERT(method);
    LS_ASSERT(method->function);

    LSMethodEntry *entry = g_slice_new(LSMethodEntry);
    entry->function = method->function;
    entry->flags = method->flags;

    return entry;
}

static void LSMethodEntryFree(void *methodEntry)
{
    LS_ASSERT(methodEntry);

    g_slice_free(LSMethodEntry, methodEntry);
}

/* @} END OF LunaServiceInternals */

/**
* @brief Append methods to the category.
*        Creates a category if needed.
*
* @param  sh
* @param  category
* @param  methods
* @param  signals
* @param  category_user_data
* @param  lserror
*
* @retval
*/
bool
LSRegisterCategoryAppend(LSHandle *sh, const char *category,
                   LSMethod      *methods,
                   LSSignal      *signals,
                   LSError *lserror)
{
    LSHANDLE_VALIDATE(sh);

    LSCategoryTable *table = NULL;

    if (!sh->tableHandlers)
    {
        sh->tableHandlers = g_hash_table_new_full(g_str_hash, g_str_equal,
            /*key*/ (GDestroyNotify)g_free,
            /*value*/ (GDestroyNotify)_LSCategoryTableFree);
    }

    char *category_path = _category_to_object_path_alloc(category);

    table =  g_hash_table_lookup(sh->tableHandlers, category_path);
    if (!table)
    {
        table = g_new0(LSCategoryTable, 1);

        table->sh = sh;
        table->methods    = g_hash_table_new_full(g_str_hash, g_str_equal, free, LSMethodEntryFree);
        table->signals    = g_hash_table_new(g_str_hash, g_str_equal);
        table->category_user_data = NULL;
        table->description = NULL;

        g_hash_table_replace(sh->tableHandlers, category_path, table);

    }
    else
    {
        /*
         * We've already registered the category, so free the unneeded
         * category_path. This will happen when we call
         * LSRegisterCategoryAppend multiple times with the same category
         * (i.e., LSPalmServiceRegisterCategory)
         */
        g_free(category_path);
        category_path = NULL;
    }

    /* Add methods to table. */

    if (methods)
    {
        LSMethod *m;
        for (m = methods; m->name && m->function; m++)
        {
            g_hash_table_replace(table->methods, strdup(m->name), LSMethodEntryCreate(m));
        }
    }

    if (signals)
    {
        LSSignal *s;
        for (s = signals; s->name; s++)
        {
            g_hash_table_replace(table->signals, (gpointer)s->name, s);
        }
    }

    return true;
}

/**
* @brief Register public methods and private methods.
*
* @param  psh
* @param  category
* @param  methods_public
* @param  methods_private
* @param  signals
* @param  category_user_data
* @param  lserror
*
* @retval
*/
bool
LSPalmServiceRegisterCategory(LSPalmService *psh,
    const char *category, LSMethod *methods_public, LSMethod *methods_private,
    LSSignal *signals, void *category_user_data, LSError *lserror)
{
    bool retVal;

    retVal = LSRegisterCategoryAppend(psh->public_sh,
        category, methods_public, signals, lserror);
    if (!retVal) goto error;

    retVal = LSCategorySetData(psh->public_sh, category,
                      category_user_data, lserror);
    if (!retVal) goto error;

    /* Private bus is union of public and private methods. */

    retVal = LSRegisterCategoryAppend(psh->private_sh,
        category, methods_private, signals, lserror);
    if (!retVal) goto error;

    retVal = LSRegisterCategoryAppend(psh->private_sh,
        category, methods_public, NULL, lserror);
    if (!retVal) goto error;

    retVal = LSCategorySetData(psh->private_sh, category,
                      category_user_data, lserror);
    if (!retVal) goto error;
error:
    return retVal;
}

/**
* @brief Set the userdata that is delivered to each callback registered
*        to the category.
*
* @param  sh
* @param  category
* @param  user_data
* @param  lserror
*
* @retval
*/
bool
LSCategorySetData(LSHandle *sh, const char *category, void *user_data, LSError *lserror)
{
    LSHANDLE_VALIDATE(sh);

    LSCategoryTable *table = LSHandleGetCategory(sh, category, lserror);
    if (table == NULL) return false;

    table->category_user_data = user_data;

    return true;
}

bool LSCategorySetDescription(
    LSHandle *sh, const char *category,
    jvalue_ref description,
    LSError *error
)
{
    LSHANDLE_VALIDATE(sh);

    LSCategoryTable *table = LSHandleGetCategory(sh, category, error);
    if (table == NULL) return false;

    j_release(&table->description);
    table->description = jvalue_copy(description);

    return true;
}

/**
* @brief Register tables of callbacks associated with the message category.
*
* @param  category    - May be NULL for default '/' category.
* @param  methods     - table of methods.
* @param  signals     - table of signals.
* @param  properties  - table of properties.
* @param  lserror
*
* @retval
*/
bool
LSRegisterCategory(LSHandle *sh, const char *category,
                   LSMethod      *methods,
                   LSSignal      *signals,
                   LSProperty    *properties, LSError *lserror)
{
    _LSErrorIfFail(sh != NULL, lserror, MSGID_LS_INVALID_HANDLE);

    LSHANDLE_VALIDATE(sh);

    if (_category_exists(sh, category))
    {
        _LSErrorSet(lserror, MSGID_LS_CATEGORY_REGISTERED, -1,
                    "Category %s already registered.", category);
        return false;
    }

    return LSRegisterCategoryAppend(sh, category, methods, signals, lserror);
}
