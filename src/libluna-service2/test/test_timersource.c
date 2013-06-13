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


#include <stdlib.h>
#include <glib.h>
#include <timersource.h>

/* Test utils *****************************************************************/

static gboolean
test_quit_mainloop(gpointer user_data)
{
    g_assert(NULL != user_data);

    GMainLoop *main_loop = (GMainLoop*)user_data;
    g_main_loop_quit(main_loop);

    return true;
}

static void
test_fork_timer_process(GTimerSource *source, guint64 usec_fork_timeout, GSourceFunc callback)
{
    if (g_test_trap_fork(usec_fork_timeout, G_TEST_TRAP_SILENCE_STDOUT))
    {
        GMainLoop *main_loop = g_main_loop_new(NULL, false);

        g_source_set_callback ((GSource*)source, callback, main_loop, NULL);
        g_source_attach ((GSource*)source, NULL);

        g_main_loop_run(main_loop);
        g_main_loop_unref(main_loop);

        g_source_unref((GSource*)source);

        exit(0);
    }
}

/* Test cases *****************************************************************/

static void
test_timer_source_new()
{
    GTimerSource *source = NULL;

    // test timer of 1000ms in fork process with 2000ms timeout
    // (timer expires, fork does not reach timeout)
    source = g_timer_source_new(1000, 1);
    g_assert(NULL != source);
    test_fork_timer_process(source, 2000000, test_quit_mainloop);
    g_source_unref((GSource*)source);
    g_assert(!g_test_trap_reached_timeout());

    // test timer of 1000ms in fork process with 500ms timeout
    // (timer does not expire, fork reaches timeout)
    source = g_timer_source_new(1000, 1);
    g_assert(NULL != source);
    test_fork_timer_process(source, 500000, test_quit_mainloop);
    g_source_unref((GSource*)source);
    g_assert(g_test_trap_reached_timeout());
}

static void
test_timer_source_new_seconds()
{
    GTimerSource *source = NULL;

    // test timer of 1000ms in fork process with 2000ms timeout
    // (timer expires, fork does not reach timeout)
    source = g_timer_source_new_seconds(1);
    g_assert(NULL != source);
    test_fork_timer_process(source, 2000000, test_quit_mainloop);
    g_source_unref((GSource*)source);
    g_assert(!g_test_trap_reached_timeout());

    // test timer of 1000ms in fork process with 500ms timeout
    // (timer does not expire, fork reaches timeout)
    source = g_timer_source_new_seconds(1);
    g_assert(NULL != source);
    test_fork_timer_process(source, 500000, test_quit_mainloop);
    g_source_unref((GSource*)source);
    g_assert(g_test_trap_reached_timeout());
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
    g_test_add_func("/luna-service2/g_timer_source_new_seconds", test_timer_source_new_seconds);
    g_test_add_func("/luna-service2/g_timer_source_set_interval", test_timer_source_set_interval);
    g_test_add_func("/luna-service2/g_timer_source_set_interval_seconds", test_timer_source_set_interval_seconds);

    return g_test_run();
}

