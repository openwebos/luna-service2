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
 * Clock Helper.
 * Attempts to use monotonic clock as default clock source.
 */

#include "clock.h"
#include "log.h"

#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <glib.h>

// #include "debug.h" - removed for use in luna-service2, apparently not needed

#define NSEC_PER_SEC 1000000000L
#define NSEC_PER_MSEC 1000000L

#if (_POSIX_C_SOURCE - 0) >= 200112L
    #define HAVE_PTHREAD_CONDATTR_SETCLOCK
#else
    //#error Powerd requires pthread extensions for using monotonic clock.
    //#error warn Please use glibc >= 2.5
#endif

void
ClockGetTime(struct timespec *time)
{
    int ret = 1;

#ifdef HAVE_PTHREAD_CONDATTR_SETCLOCK
    ret = clock_gettime(CLOCK_MONOTONIC, time);
#endif
    if (ret)
    {
        LOG_LS_ERROR(MSGID_LS_CLOCK_ERROR, 0, "Could not obtain monotonic clock");

        struct timeval tv;
        gettimeofday(&tv, NULL);

        time->tv_sec = tv.tv_sec;
        time->tv_nsec = tv.tv_usec * 1000;
    }
}

/**
 * returns true if a > b
 */
bool
ClockTimeIsGreater(struct timespec *a, struct timespec *b)
{
    return (a->tv_sec > b->tv_sec) ||
        (a->tv_sec == b->tv_sec && a->tv_nsec > b->tv_nsec);
}

void
ClockPrintTime(struct timespec *time)
{
    g_message("%lds.%ldms ", time->tv_sec, time->tv_nsec / NSEC_PER_MSEC);
}

void
ClockStr(GString *str, struct timespec *time)
{
    g_string_append_printf(str, "%lds.%ldms ",
        time->tv_sec, time->tv_nsec / NSEC_PER_MSEC);
}

/**
 * Pretty print the current time.
 */
void
ClockPrint(void)
{
    struct timespec time;
    ClockGetTime(&time);

    ClockPrintTime(&time);
}

/**
 * result = x - y
 */
bool
ClockDiff(struct timespec *result, const struct timespec *x, const struct timespec *_y)
{
    struct timespec y = *_y;

    /* Perform the carry for the later subtraction by updating y. */
    if (x->tv_nsec < y.tv_nsec)
    {
        int sec = (y.tv_nsec - x->tv_nsec) / NSEC_PER_SEC + 1;
        y.tv_nsec -= NSEC_PER_SEC * sec;
        y.tv_sec += sec;
    }
    else if (x->tv_nsec - y.tv_nsec > NSEC_PER_SEC)
    {
        int sec = (x->tv_nsec - y.tv_nsec) / NSEC_PER_SEC;
        y.tv_nsec += NSEC_PER_SEC * sec;
        y.tv_sec -= sec;
    }

    /* Compute the time remaining to wait.
    tv_usec is certainly positive. */
    result->tv_sec = x->tv_sec - y.tv_sec;
    result->tv_nsec = x->tv_nsec - y.tv_nsec;

    /* Return true if result is negative. */
    return x->tv_sec < y.tv_sec;
}

/**
 * sum += b
 */
void
ClockAccum (struct timespec *sum, const struct timespec *b)
{
    sum->tv_sec += b->tv_sec;
    sum->tv_nsec += b->tv_nsec;

    if (sum->tv_nsec > NSEC_PER_SEC)
    {
        sum->tv_sec += sum->tv_nsec / NSEC_PER_SEC;
        sum->tv_nsec %= NSEC_PER_SEC;
    }
}

void
ClockAccumMs (struct timespec *sum, int duration_ms)
{
    int sec = duration_ms / 1000;
    int nsec = (duration_ms - (sec * 1000)) * NSEC_PER_MSEC;

    sum->tv_sec += sec;
    sum->tv_nsec += nsec;
    if (sum->tv_nsec > NSEC_PER_SEC)
    {
        sum->tv_sec += sum->tv_nsec / NSEC_PER_SEC;
        sum->tv_nsec %= NSEC_PER_SEC;
    }
}

long
ClockGetMs(struct timespec *ts)
{
    if (!ts) return 0;
    return ts->tv_sec * 1000 + ts->tv_nsec / NSEC_PER_MSEC;
}

/**
 * a = 0
 */
void
ClockClear(struct timespec *a)
{
    a->tv_sec = 0;
    a->tv_nsec = 0;
}
