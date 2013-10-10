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
#include <glib.h>
#include <unistd.h>
#include <transport_utils.h>

/* Test data ******************************************************************/

static bool test_sigusr1_handled = false;

static void
test_sigusr1_handler(int signum)
{
    g_assert(signum == SIGUSR1);

    test_sigusr1_handled = true;
}

/* Test cases *****************************************************************/
static void
test_strlen_safe()
{
    g_assert_cmpint(strlen_safe("key"), ==, 3);
    g_assert_cmpint(strlen_safe(""), ==, 0);
    g_assert_cmpint(strlen_safe(NULL), ==, 0);
}

static void
test_DumpHashItem()
{
    if (g_test_trap_fork(0, G_TEST_TRAP_SILENCE_STDOUT))
    {
        DumpHashItem("key", GINT_TO_POINTER(1), 0);
        exit(0);
    }
    g_test_trap_assert_stdout("key: key, value: 0x1\n");
}

static void
test_DumpHashItemTable()
{
    GHashTable *table = g_hash_table_new(g_str_hash, g_str_equal);

    g_hash_table_insert(table, "key1", GINT_TO_POINTER(1));
    g_hash_table_insert(table, "key2", GINT_TO_POINTER(2));

    if (g_test_trap_fork(0, G_TEST_TRAP_SILENCE_STDOUT))
    {
        DumpHashTable(table);
        exit(0);
    }
    const char *expected_stdout =
            "key: key1, value: 0x1\n" \
            "key: key2, value: 0x2\n" \
            "\n";
    g_test_trap_assert_stdout(expected_stdout);

    g_hash_table_unref(table);
}

static void
test_LSTransportSetupSignalHandler()
{
    if (g_test_trap_fork(10000000, 0))
    {
        g_assert(_LSTransportSetupSignalHandler(SIGUSR1, test_sigusr1_handler));

        test_sigusr1_handled = false;

        // block SIGUSR1 and suspend process until signal arrived and handled
        sigset_t mask, oldmask;
        sigemptyset(&mask);
        sigemptyset(&oldmask);
        sigaddset(&mask, SIGUSR1);
        sigprocmask(SIG_BLOCK, &mask, &oldmask);
        raise(SIGUSR1);
        while(!test_sigusr1_handled)
            sigsuspend(&oldmask);
        sigprocmask(SIG_UNBLOCK, &mask, NULL);

        exit(0);
    }
    g_test_trap_assert_passed();
}

static void
test_LSTransportFdSetBlockAndNonBlock()
{
    gchar templ[] = "XXXXXX";
    int fd = g_mkstemp(templ);
    bool prev_state_blocking = false;

    // file should be in block mode by default
    _LSTransportFdSetBlock(fd, &prev_state_blocking);
    g_assert(prev_state_blocking);
    // second call to make sure that block mode is currently active
    _LSTransportFdSetBlock(fd, &prev_state_blocking);
    g_assert(prev_state_blocking);

    // change to non-block mode
    _LSTransportFdSetNonBlock(fd, &prev_state_blocking);
    g_assert(prev_state_blocking);
    // make sure that non-block mode is active
    _LSTransportFdSetNonBlock(fd, &prev_state_blocking);
    g_assert(!prev_state_blocking);

    close(fd);

    unlink(templ);
}

/* Test suite *****************************************************************/

int
main(int argc, char *argv[])
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/luna-service2/strlen_safe", test_strlen_safe);
    g_test_add_func("/luna-service2/DumpHashItem", test_DumpHashItem);
    g_test_add_func("/luna-service2/DumpHashItemTable", test_DumpHashItemTable);
    g_test_add_func("/luna-service2/test_LSTransportSetupSignalHandler", test_LSTransportSetupSignalHandler);
    g_test_add_func("/luna-service2/LSTransportFdSetBlockAndNonBlock", test_LSTransportFdSetBlockAndNonBlock);

    return g_test_run();
}

