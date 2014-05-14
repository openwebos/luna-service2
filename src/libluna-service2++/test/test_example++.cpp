// @@@LICENSE
//
//      Copyright (c) 2014 LG Electronics, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// LICENSE@@@

#include <glib.h>
#include <luna-service2/lunaservice.hpp>
#include <memory>
#include <atomic>
#include <boost/scope_exit.hpp>

using namespace std;

namespace {

atomic_bool hit_reply{false};

gboolean OnTimeout(gpointer user_data)
{
    g_main_loop_quit((GMainLoop *) user_data);
    return FALSE;
}

void ClientProc(GMainLoop *serviceLoop)
{
    unique_ptr<GMainLoop, std::function<void(GMainLoop*)>> main_loop{g_main_loop_new(NULL, FALSE), g_main_loop_unref};
    GMainLoop *mainLoop = main_loop.get();

    BOOST_SCOPE_EXIT((serviceLoop)) {
        g_main_loop_quit(serviceLoop);
    } BOOST_SCOPE_EXIT_END

    //! [synchronous client call]
    try
    {
        auto client = LS::registerService(nullptr);
        client.attachToLoop(mainLoop);  // Main loop is necessary!
        auto call = client.callOneReply("luna://com.palm.contacts/category/listContacts",
                                        "{ \"json payload\" }");
        auto reply = call.get(1000);
        if (!reply)
        {
            cerr << "No reply in 1 second" << endl;
            return;
        }
        if (reply.isHubError())
        {
            cerr << "Error occured: " << reply.getPayload() << endl;
            return;
        }

        cout << reply.getPayload() << endl;
    }
    catch (const LS::Error &e)
    {
        cerr << e << endl;
        return;
    }
    //! [synchronous client call]
    hit_reply = true;
}

} //namespace

//! [method implementation]
namespace {

// callback
bool listContacts(LSHandle *sh, LSMessage *raw_message, void *categoryContext)
{
    LS::Message message{raw_message};

    try
    {
        message.respond("{ JSON REPLY PAYLOAD }");
    }
    catch (const LS::Error &e)
    {
        cerr << e << endl;
        return false;
    }
    return true;
}

static LSMethod ipcMethods[] = {
   { "listContacts", listContacts },
   { },
};

} //namespace
//! [method implementation]

int main()
{
    unique_ptr<GMainLoop, std::function<void(GMainLoop*)>> main_loop{g_main_loop_new(NULL, FALSE), g_main_loop_unref};
    GMainLoop *mainLoop = main_loop.get();
    g_timeout_add(10000, &OnTimeout, mainLoop);
    gpointer userData = mainLoop;

    thread t(bind(&ClientProc, mainLoop));

    //! [service registration]
    try
    {
        auto service = LS::registerService("com.palm.contacts");

        service.registerCategory("/category", ipcMethods, nullptr, nullptr);
        service.setCategoryData("/category", userData);

        service.attachToLoop(mainLoop);

        g_main_loop_run(mainLoop);
    }
    catch (const LS::Error &e)
    {
        cerr << e << endl;
        return 1;
    }
    //! [service registration]

    t.join();
    if (hit_reply)
    {
        cout << "PASS" << endl;
        return 0;
    }
    cerr << "FAILED" << endl;
    return 1;
}
