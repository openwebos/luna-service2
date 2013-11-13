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


#ifndef _PATTERN_H
#define _PATTERN_H

#include <stdbool.h>
#include <glib.h>

/** @brief Glob-style patterns for matching against "com.palm.foo*" and alike. */
struct _LSHubPatternSpec {
    int ref;                    /**< Reference counter */
    const char *pattern_str;    /**< Original pattern string. Is used for prefix-based ordering. */
    GPatternSpec *pattern_spec; /**< Compiled pattern ready for matching. */
};

typedef struct _LSHubPatternSpec _LSHubPatternSpec;


/** @brief Return a structure allocated on stack with pattern_str initialized,
 * but without compiling it into pattern_spec. This is useful for lookups.
 */
_LSHubPatternSpec _LSHubPatternSpecNoPattern(const char *pattern);

/** @brief Allocate, initialize and compile a pattern with zero reference count. */
_LSHubPatternSpec* _LSHubPatternSpecNew(const char *pattern);

/** @brief Allocate, initialize and compile a pattern with reference count one. */
_LSHubPatternSpec* _LSHubPatternSpecNewRef(const char *pattern);

/** @brief Increment reference count. */
void _LSHubPatternSpecRef(_LSHubPatternSpec *pattern);

/** @brief Destroy the object and free the memory. */
void _LSHubPatternSpecFree(_LSHubPatternSpec *pattern);

/** @brief Decrement reference count. Once it drops to zero, destroy the object and free the memory. */
bool _LSHubPatternSpecUnref(_LSHubPatternSpec *pattern);

/** @brief Compare two patterns and order them.
 *
 * Only pattern_str is used for relative ordering. If no pattern_spec is supplied
 * with either operand, string matching is used. Otherwise, match against pattern
 * is returned.
 */
int _LSHubPatternSpecCompare(_LSHubPatternSpec const *pa, _LSHubPatternSpec const *pb,
                             gpointer user_data);

#endif  /*_PATTERN_H */
