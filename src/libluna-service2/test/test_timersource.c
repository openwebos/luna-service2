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

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <glib.h>
#include <timersource.h>
#include <PmLogLib.h>

/* PmLogLib ******************************************************************/
PmLogErr _PmLogMsgKV(PmLogContext context, PmLogLevel level, unsigned int flags,
                     const char *msgid, size_t kv_count, const char *check_keywords,
                     const char *check_formats, const char *fmt, ...)
{
    if (level == kPmLogLevel_Debug) return kPmLogErr_None;

    va_list args;

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    putc('\n', stderr);

    return kPmLogErr_None;
}

/* Test utils *****************************************************************/

static gboolean
test_on_timeout(gpointer user_data)
{
    g_assert(NULL != user_data);

    gboolean *flag = (gboolean *)user_data;
    *flag = TRUE;

    return true;
}

static void
test_iterate_main_loop(int ms)
{
    g_test_timer_start();
    while (true)
    {
        g_main_context_iteration(NULL, FALSE);
        if (g_test_timer_elapsed() * 1000 > ms)
            break;
        g_usleep(500);
    }
}

/* Test cases *****************************************************************/

static void
test_timer_source_new()
{
    gboolean fired = FALSE;

    GMainLoop *main_loop = g_main_loop_new(NULL, false);
    GTimerSource *source = g_timer_source_new(250, 1);
    g_assert(NULL != source);

    // note that in this test we expect that scattering is +/- 50ms which is
    // probably fine for most systems

    g_source_set_callback ((GSource*)source, test_on_timeout, &fired, NULL);
    g_source_attach ((GSource*)source, NULL);

    // so we've started a timer that fires each 250ms

    // wait 350 ms and see if it were fired
    test_iterate_main_loop(350);
    g_assert(fired);

    // looks good. next fire in 150.
    // lets check that during next 100ms it will not fire
    fired = FALSE;
    test_iterate_main_loop(100);
    g_assert(!fired);

    // fine. 50ms to next fire. will see if it will made up for next 100ms
    test_iterate_main_loop(100);
    g_assert(fired);

    g_source_unref((GSource*)source);
    g_main_loop_unref(main_loop);
}

static void
test_timer_source_set_interval()
{
    // 2s interval
    GTimerSource *source = g_timer_source_new_seconds(2);

    // 1s interval
    g_timer_source_set_interval(source, 1000, true);

    g_assert_cmpint(g_timer_source_get_interval_ms(source), ==, 1000);

    g_source_unref((GSource*)source);
}

static void
test_timer_source_set_interval_seconds()
{
    // 2s interval
    GTimerSource *source = g_timer_source_new_seconds(2);

    // 1s interval
    g_timer_source_set_interval_seconds(source, 1, true);

    g_assert_cmpint(g_timer_source_get_interval_ms(source), ==, 1000);

    // no main loop, no main context, cannot wakeup context, expect warning
    if (g_test_trap_fork(0, G_TEST_TRAP_SILENCE_STDERR))
    {
        g_timer_source_set_interval_seconds(source, 2, false);
        exit(0);
    }
    g_test_trap_assert_stderr("*Cannot get context for timer_source*");

    // valid main loop/context, source attached, expect no warning
    if (g_test_trap_fork(0, G_TEST_TRAP_SILENCE_STDERR))
    {
        GMainLoop *main_loop = g_main_loop_new(NULL, false);

        g_source_attach ((GSource*)source, NULL);

        g_timer_source_set_interval_seconds(source, 1, false);

        g_main_loop_unref(main_loop);
        g_source_unref((GSource*)source);

        exit(0);
    }
    g_test_trap_assert_stderr_unmatched("*Cannot get context for timer_source*");

    g_source_unref((GSource*)source);
}

/* Test suite *****************************************************************/

int
main(int argc, char *argv[])
{
    g_test_init(&argc, &argv, NULL);

    g_log_set_always_fatal (G_LOG_LEVEL_ERROR);
    g_log_set_fatal_mask ("LunaService", G_LOG_LEVEL_ERROR);

    g_test_add_func("/luna-service2/g_timer_source_new", test_timer_source_new);
    g_test_add_func("/luna-service2/g_timer_source_set_interval", test_timer_source_set_interval);
    g_test_add_func("/luna-service2/g_timer_source_set_interval_seconds", test_timer_source_set_interval_seconds);

    return g_test_run();
}

