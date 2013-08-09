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
#include <string.h>
#include <glib.h>
#include <base.h>
#include "../security.c"
#define main mocked_main
#include "../hub.c"
#undef main
#include "../watchdog.c"
#include "../conf.c"
#include "transport_priv.h"
#include "transport_security_internal.h"

///////////////////////////////////// UNDEFINED FUNCTIONS /////////////////////////////////////////////////////////

void SetLoggingPmLogLib(bool public_hub)
{
}

void SetLoggingSyslog(void)
{
}

///////////////////////////////////// TESTS /////////////////////////////////////////////////////////

static void test_LSHubIsClientAllowedToSendSignal()
{
    _LSTransportCred defaultCred = {0, 0, 0, "", ""};
    _LSTransport localTransport = {.type = _LSTransportTypeLocal};

    _LSTransportClient client;
    client.transport = &localTransport;
    client.cred = &defaultCred;

    client.service_name = "com.webos.";
    g_assert(LSHubIsClientAllowedToSendSignal(&client));

    client.service_name = "com.palm.";
    g_assert(LSHubIsClientAllowedToSendSignal(&client));

    client.service_name = "com.lge.";
    g_assert(LSHubIsClientAllowedToSendSignal(&client));

    client.service_name = "com.name.";
    g_assert(!LSHubIsClientAllowedToSendSignal(&client));

}

///////////////////////////////////// MAIN /////////////////////////////////////////////////////////

int
main(int argc, char *argv[])
{
    g_test_init(&argc, &argv, NULL);

    g_log_set_always_fatal (G_LOG_LEVEL_ERROR);
    g_log_set_fatal_mask ("LunaService", G_LOG_LEVEL_ERROR);

    // Enable security
    g_conf_security_enabled = true;

    g_test_add_func("/ls-hub/LSHubIsClientAllowedToSendSignal", test_LSHubIsClientAllowedToSendSignal);

    return g_test_run();
}

