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


#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <transport.h>

/* Mock variables *************************************************************/

static _LSTransportCred* mvar_transport_cred = NULL;

/* Test cases *****************************************************************/

static void
test_LSTransportSecurityPositive(void)
{
    /* Test creation, getters and deletion .*/
    mvar_transport_cred = _LSTransportCredNew();
    g_assert(NULL != mvar_transport_cred);
    g_assert_cmpint(_LSTransportCredGetPid(mvar_transport_cred),
                     ==,
                     (pid_t)LS_PID_INVALID);
    g_assert_cmpint(_LSTransportCredGetUid(mvar_transport_cred),
                     ==,
                     (uid_t)LS_UID_INVALID);
    g_assert_cmpint(_LSTransportCredGetGid(mvar_transport_cred),
                     ==,
                     (gid_t)LS_GID_INVALID);
    g_assert(!_LSTransportCredGetExePath(mvar_transport_cred));
    g_assert(!_LSTransportCredGetCmdLine(mvar_transport_cred));
    _LSTransportCredFree(mvar_transport_cred);
    mvar_transport_cred = NULL;

    /* Credentials of a socket.  */
    mvar_transport_cred = _LSTransportCredNew();
    struct sockaddr_un socketaddress;
    int socketfd = socket(AF_LOCAL, SOCK_STREAM, 0);
    g_assert_cmpint(socketfd, !=, -1);
    memset(&socketaddress, 0, sizeof(struct sockaddr_un));
    socketaddress.sun_family = AF_LOCAL;
    strncpy(socketaddress.sun_path,
             "/tmp/testsocket",
             sizeof(socketaddress.sun_path) - 1);
    unlink("/tmp/testsocket");
    bind(socketfd,
          (struct sockaddr*) &socketaddress,
          sizeof(struct sockaddr_un));
    listen(socketfd, 3);
    if (g_test_trap_fork(300, G_TEST_TRAP_SILENCE_STDOUT))
    {
        while(1)
        {
            accept(socketfd, NULL, NULL);
        }
    }
    else
    {
        int socketfd2 = socket(AF_LOCAL, SOCK_STREAM, 0);
        while (connect(socketfd2,
                         (struct sockaddr*) &socketaddress,
                         sizeof(struct sockaddr_un)) != 0);
        LSError error;
        LSErrorInit(&error);
        _LSTransportGetCredentials(socketfd, mvar_transport_cred, &error);
        g_assert(NULL != mvar_transport_cred);
        g_assert_cmpint(_LSTransportCredGetPid(mvar_transport_cred),
                         ==,
                         getpid());
        g_assert_cmpint(_LSTransportCredGetUid(mvar_transport_cred),
                         ==,
                         getuid());
        g_assert_cmpint(_LSTransportCredGetGid(mvar_transport_cred),
                         ==,
                         getgid());
        g_assert(_LSTransportCredGetExePath(mvar_transport_cred));
        g_assert(_LSTransportCredGetCmdLine(mvar_transport_cred));

        close(socketfd2);
    }
    g_test_trap_has_passed();

    close(socketfd);
}

/* Mocks **********************************************************************/

bool
_LSTransportIsHub(void)
{
    return true;
}

/* Test suite *****************************************************************/

int
main(int argc, char *argv[])
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/luna-service2/LSTransportSecurityPositive",
                     test_LSTransportSecurityPositive);

    return g_test_run();
}

