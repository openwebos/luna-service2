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
 *  @file simple_pbnjson.c
 */

#include "error.h"
#include "simple_pbnjson.h"

static bool
LSError_parser(void *ctx, JSAXContextRef parseCtxt)
{
    LSError *lserror = (LSError *)ctx;
    _LSErrorSetNoPrint(lserror, -1, "JSON parser error");
    return false;
}

static bool
LSError_schema(void *ctx, JSAXContextRef parseCtxt)
{
    LSError *lserror = (LSError *)ctx;
    _LSErrorSetNoPrint(lserror, -1, "JSON schema validation error");
    return false;
}

static bool
LSError_misc(void *ctx, JSAXContextRef parseCtxt)
{
    LSError *lserror = (LSError *)ctx;
    _LSErrorSetNoPrint(lserror, -1, "JSON misc error");
    return false;
}

void
SetLSErrorCallbacks(struct JErrorCallbacks *callbacks, LSError *lserror)
{
    *callbacks = (struct JErrorCallbacks){
        .m_parser = LSError_parser,
        .m_schema = LSError_schema,
        .m_unknown = LSError_misc,
        .m_ctxt = lserror
    };
}

jvalue_ref jvalue_shallow(jvalue_ref value)
{
    if (jis_array(value))
    {
        jvalue_ref array = jarray_create_hint(NULL, jarray_size(value));
        jarray_splice_append(array, value, SPLICE_COPY);
        return array;
    }
    else if (jis_object(value))
    {
        jobject_iter iter;
        if (!jobject_iter_init(&iter, value))
        { return jinvalid(); }

        jvalue_ref object = jobject_create();

        jobject_key_value keyval;
        while (jobject_iter_next(&iter, &keyval))
        {
            jobject_set2(object, keyval.key, keyval.value);
        }
        return object;
    }
    else
    { return jvalue_duplicate(value); }
}
