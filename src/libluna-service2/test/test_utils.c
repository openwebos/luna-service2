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
#include <glib/gstdio.h>
#include <utils.h>

/* Test cases *****************************************************************/

static void
test_LSIsRunning()
{
    const char *pid_dir = "/tmp";
    const char *pid_file_name = "test_lsisrunning.lock";
    const char *pid_path = "/tmp/test_lsisrunning.lock";

    // remove lock file from previous test run
    g_remove(pid_path);
    g_assert(!g_file_test(pid_path, G_FILE_TEST_EXISTS|G_FILE_TEST_IS_REGULAR));

    // initial call, not running, LSIsRunning should return false
    g_assert(!LSIsRunning(pid_dir, pid_file_name));

    // verify that lock file exists
    g_assert(g_file_test(pid_path, G_FILE_TEST_EXISTS|G_FILE_TEST_IS_REGULAR));

    int i;
    for (i=0; i < 10; ++i)
    {
        // trailing calls to LSIsRunning in same process should also return false
        // (lunaservice is running for this process)
        g_assert(!LSIsRunning(pid_dir, pid_file_name));
    }

    if (g_test_trap_fork(1000000, 0))
    {
        // forked process, lunaservice already running at parent process
        // LSIsRunning should return true
        bool running = LSIsRunning(pid_dir, pid_file_name);
        exit(running ? 0 : 1);
    }
    g_test_trap_assert_passed();
}

/* Test suite *****************************************************************/

int
main(int argc, char *argv[])
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/luna-service2/LSIsRunning", test_LSIsRunning);

    return g_test_run();
}

