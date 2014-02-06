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


#include "pattern.h"
#include "error.h"


_LSHubPatternSpec _LSHubPatternSpecNoPattern(const char *pattern)
{
    LS_ASSERT(pattern != NULL);

    _LSHubPatternSpec ret =
    {
        .pattern_str = pattern,
    };
    return ret;
}

_LSHubPatternSpec* _LSHubPatternSpecNew(const char *pattern)
{
    LS_ASSERT(pattern != NULL);

    _LSHubPatternSpec *ret = g_slice_new0(_LSHubPatternSpec);

    ret->pattern_str = g_strdup(pattern);
    ret->pattern_spec = g_pattern_spec_new(pattern);

    return ret;
}

_LSHubPatternSpec* _LSHubPatternSpecNewRef(const char *pattern)
{
    LS_ASSERT(pattern != NULL);

    _LSHubPatternSpec *ret = _LSHubPatternSpecNew(pattern);

    ret->ref = 1;

    return ret;
}

void _LSHubPatternSpecRef(_LSHubPatternSpec *pattern)
{
    LS_ASSERT(pattern != NULL);
    LS_ASSERT(g_atomic_int_get(&pattern->ref) > 0);

    g_atomic_int_inc(&pattern->ref);
}

void _LSHubPatternSpecFree(_LSHubPatternSpec *pattern)
{
    LS_ASSERT(pattern != NULL && pattern->pattern_spec);

    g_free((char*)pattern->pattern_str);
    g_pattern_spec_free(pattern->pattern_spec);
    g_slice_free(_LSHubPatternSpec, pattern);
}

/* returns true if the ref count went to 0 and the role was freed */
bool _LSHubPatternSpecUnref(_LSHubPatternSpec *pattern)
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

int _LSHubPatternSpecCompare(_LSHubPatternSpec const *pa, _LSHubPatternSpec const *pb,
                             gpointer user_data)
{
    /* Always called against at least one pattern */
    LS_ASSERT(pa->pattern_spec || pb->pattern_spec);

    /* We order patterns by their prefixes:
     *  asdf* < bcd*
     */
    size_t pref_a = strcspn(pa->pattern_str, "*?");
    size_t pref_b = strcspn(pb->pattern_str, "*?");

    int res = strncmp(pa->pattern_str, pb->pattern_str, MIN(pref_a, pref_b));
    if (res)
        return res;

    /* Now, if both keys to comare are patterns, there's no way to order them any more.
     * Thus we consider they're equal (it's impossible to add them to the tree simultaneously).
     */
    if (pa->pattern_spec && pb->pattern_spec)
        return 0;

    /* For lookup, it only matters if the key is matched against the pattern. */
    if ( (pa->pattern_spec && g_pattern_match(pa->pattern_spec, strlen(pb->pattern_str), pb->pattern_str, NULL)) ||
         (pb->pattern_spec && g_pattern_match(pb->pattern_spec, strlen(pa->pattern_str), pa->pattern_str, NULL)) )
    {
        return 0;
    }

    /* We don't care about other case (undefined match), the lookup will fail. */
    return 1;
}
