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


/**
 * GTimerSource - a source needed because the typical GSources do not have necessary features.
 * I write this utility with the intention that this might be contributed back to glib
 * in the future.
 *
 * GTimerSource
 * 1) Can be forced to expire.
 * 2) The expiration interval may be changed.
 * 3) Uses a montonic clock.
 */

#include <glib.h>

#include "timersource.h"
#include "clock.h"
#include "log.h"

struct _GTimerSource
{
    GSource  source;
    GTimeVal expiration;   /* Should I just make this use Clock* API? */
    guint    interval_ms;     /* In milisecs */
    guint    granularity;
};

static gboolean g_timer_source_prepare(GSource *source, gint *timeout_ms);
static gboolean g_timer_source_check(GSource *source);
static gboolean g_timer_source_dispatch(GSource *source, GSourceFunc callback, gpointer user_data);

GSourceFuncs g_timer_source_funcs= {
    .prepare  = g_timer_source_prepare,
    .check    = g_timer_source_check,
    .dispatch = g_timer_source_dispatch,
    .finalize = NULL,
};

#define USECS_PER_SEC 1000000
#define USECS_PER_MSEC 1000
static void
g_timer_set_expiration(GTimerSource *rsource, GTimeVal *now)
{
    guint interval_secs = rsource->interval_ms / 1000;
    glong interval_usecs = (rsource->interval_ms - interval_secs * 1000) * 1000;

    rsource->expiration.tv_sec = now->tv_sec + interval_secs;
    rsource->expiration.tv_usec = now->tv_usec + interval_usecs;

    if (rsource->expiration.tv_usec >= USECS_PER_SEC)
    {
        rsource->expiration.tv_usec -= USECS_PER_SEC;
        rsource->expiration.tv_sec++;
    }

    if (rsource->granularity)
    {
        gint gran;
        gint remainder;

        gran = rsource->granularity * USECS_PER_MSEC;
        remainder = rsource->expiration.tv_usec % gran;

        if (remainder >= gran / 4)
            rsource->expiration.tv_usec += gran;

        rsource->expiration.tv_usec -= remainder;

        while (rsource->expiration.tv_usec > USECS_PER_SEC)
        {
            rsource->expiration.tv_usec -= USECS_PER_SEC;
            rsource->expiration.tv_sec++;
        }
    }
}

static void
g_timer_get_current_time(GTimerSource *tsource, GTimeVal *now)
{
    g_return_if_fail (now != NULL);

    // TODO: We should do a time_is_current and skip syscalls
    struct timespec tv;
    ClockGetTime(&tv);

    now->tv_sec = tv.tv_sec;
    now->tv_usec = tv.tv_nsec / 1000;
}

static gboolean
g_timer_source_prepare(GSource    *source,
                     gint       *timeout_ms)
{
    GTimeVal now;

    GTimerSource *tsource = (GTimerSource*)source;

    g_timer_get_current_time (tsource, &now);

    // assume monotic clock

    glong msec = (tsource->expiration.tv_sec - now.tv_sec) * 1000;
    if (msec < 0)
    {
        msec = 0;
    }
    else
    {
        msec += (tsource->expiration.tv_usec - now.tv_usec)/1000;
        if (msec < 0)
        {
            msec = 0;
        }
    }

    *timeout_ms = (gint)msec;

    return (msec == 0);
}

static gboolean
g_timer_source_check(GSource *source)
{
    GTimeVal now;
    GTimerSource *tsource = (GTimerSource*)source;

    g_timer_get_current_time(tsource, &now);

    return (tsource->expiration.tv_sec < now.tv_sec) ||
        ((tsource->expiration.tv_sec == now.tv_sec) &&
         (tsource->expiration.tv_usec <= now.tv_usec));
}

static gboolean
g_timer_source_dispatch(GSource *source,
                        GSourceFunc callback, gpointer user_data)
{
    GTimerSource *tsource = (GTimerSource*)source;

    if (!callback)
    {
        LOG_LS_WARNING(MSGID_LS_TIMER_NO_CALLBACK, 0,
                       "Timeout source dispatched without callback\n"
                       "Call g_source_set_callback().");
        return FALSE;
    }

    if (callback(user_data))
    {
        GTimeVal now;
        g_timer_get_current_time(tsource, &now);
        g_timer_set_expiration(tsource, &now);
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

/** Public Functions */

/**
* @brief A create a timer with 100 ms resolution.
*
* @param  interval_ms
*
* @retval
*/
GTimerSource *
g_timer_source_new(guint interval_ms, guint granularity_ms)
{
    GSource *source;
    GTimerSource *tsource;

    source = g_source_new(&g_timer_source_funcs, sizeof(GTimerSource));
    tsource = (GTimerSource*)source;

    GTimeVal now;

    tsource->interval_ms = interval_ms;
    tsource->granularity = granularity_ms;

    g_timer_get_current_time(tsource, &now);

    g_timer_set_expiration(tsource, &now);

    return tsource;
}

GTimerSource *
g_timer_source_new_seconds(guint interval_sec)
{
    GSource *source;
    GTimerSource *tsource;

    source = g_source_new(&g_timer_source_funcs, sizeof(GTimerSource));
    tsource = (GTimerSource*)source;

    GTimeVal now;

    tsource->interval_ms = 1000*interval_sec;
    tsource->granularity = 1000;

    g_timer_get_current_time(tsource, &now);

    g_timer_set_expiration(tsource, &now);

    return tsource;
}

void
g_timer_source_set_interval_seconds(GTimerSource *tsource, guint interval_sec, gboolean from_poll)
{
    g_timer_source_set_interval(tsource, interval_sec * 1000, from_poll);
}

void
g_timer_source_set_interval(GTimerSource *tsource, guint interval_ms, gboolean from_poll)
{
    GTimeVal now;

    g_timer_get_current_time(tsource, &now);

    tsource->interval_ms = interval_ms;
    g_timer_set_expiration(tsource, &now);

    if (!from_poll)
    {
        GMainContext *context =  g_source_get_context((GSource*)tsource);
        if (!context)
        {
            LOG_LS_ERROR(MSGID_LS_TIMER_NO_CONTEXT, 0,
                         "Cannot get context for timer_source.\n"
                         "Maybe you didn't call g_source_attach()\n");
            return;
        }
        g_main_context_wakeup(context);
    }
}

guint
g_timer_source_get_interval_ms(GTimerSource *tsource)
{
    return tsource->interval_ms;
}


