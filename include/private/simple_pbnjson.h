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
 *  @file simple_pbnjson.h
 */

#ifndef __SIMPLE_PBNJSON_H
#define __SIMPLE_PBNJSON_H

#include <stdbool.h>
#include <string.h>
#include <pbnjson.h>

#include "luna-service2/lunaservice.h"

/**
 * Handy macro to define local C-string from raw_buffer
 * @param name specifies which identifier to use for variable
 * @param buf says from which variable to get raw_buffer
 */
#define LOCAL_CSTR_FROM_BUF(name, buf) \
    char name[buf.m_len+1]; \
    { \
        raw_buffer __buf_value = (buf); \
        (void) memcpy(name, __buf_value.m_str, __buf_value.m_len); \
        name[buf.m_len] = '\0'; \
    }

/**
 * Test raw_buffer string representation with C-string representation for equivalence
 */
static inline bool
buffer_eq_cstr(raw_buffer buf, const char *cstr)
{
	return strlen(cstr) == buf.m_len
		&& memcmp(cstr, buf.m_str, buf.m_len) == 0;
}

/**
 * Test jstring representation with C-string representation for equivalence
 */
static inline bool
jstr_eq_cstr(jvalue_ref jstr, const char *cstr)
{ return buffer_eq_cstr(jstring_get_fast(jstr), cstr); }

/**
 * Create shallow copy of jvalue
 */
jvalue_ref jvalue_shallow(jvalue_ref value);

/*
 * Setup JErrorCallbacks to fillup LSError on any error event
 */
void
SetLSErrorCallbacks(struct JErrorCallbacks *callbacks, LSError *lserror);

#endif
