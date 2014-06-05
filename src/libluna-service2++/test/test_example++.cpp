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

atomic_bool hit_reply1{false};
atomic_bool hit_reply2{false};

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
    hit_reply1 = true;
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

namespace {

void Test1()
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
        throw;
    }
    //! [service registration]

    t.join();
}

//! [memfun service registration]
class Category
    : private LS::Handle
{
public:
    Category(GMainLoop *mainLoop)
        : LS::Handle(LS::registerService("com.palm.contacts"))
    {
        attachToLoop(mainLoop);

        LS_CATEGORY_BEGIN(Category, "/category")
            LS_CATEGORY_METHOD(listContacts)
        LS_CATEGORY_END
    }

private:
    bool listContacts(LSMessage &message)
    {
        LS::Message request(&message);
        request.respond("{ JSON REPLY PAYLOAD }");
        return true;
    }
};
//! [memfun service registration]

bool listContactsHandler(LSHandle *sh, LSMessage *message, void *ctx)
{
    LS::Message reply{message};
    cout << "Got reply: " << reply.getPayload() << endl;
    if (!reply.isHubError())
        hit_reply2 = true;
    g_main_loop_quit((GMainLoop *) ctx);
    return true;
}

void AsyncClientProc(GMainLoop *serviceMainLoop)
{
    unique_ptr<GMainLoop, std::function<void(GMainLoop*)>> main_loop{g_main_loop_new(NULL, FALSE), g_main_loop_unref};
    GMainLoop *mainLoop = main_loop.get();
    void *userData = mainLoop;

    //! [asynchronous client call]
    try
    {
        auto client = LS::registerService(nullptr);
        client.attachToLoop(mainLoop);
        auto call = client.callOneReply("luna://com.palm.contacts/category/listContacts",
                                        "{ \"json payload\" }");
        call.setTimeout(1000);
        call.continueWith(listContactsHandler, userData);

        g_main_loop_run(mainLoop);
    }
    catch (const LS::Error &e)
    {
        cerr << e << endl;
        throw;
    }
    //! [asynchronous client call]

    g_main_loop_quit(serviceMainLoop);
}

void Test2()
{
    unique_ptr<GMainLoop, std::function<void(GMainLoop*)>> main_loop{g_main_loop_new(NULL, FALSE), g_main_loop_unref};
    GMainLoop *mainLoop = main_loop.get();
    g_timeout_add(10000, &OnTimeout, mainLoop);

    thread t(bind(&AsyncClientProc, mainLoop));

    //! [memfun service initialization]
    try
    {
        Category category(mainLoop);

        g_main_loop_run(mainLoop);
    }
    catch (const LS::Error &e)
    {
        cerr << e << endl;
        throw;
    }
    //! [memfun service initialization]

    t.join();
}

} //namespace;

int main()
{
    try
    {
        Test1();
        Test2();
    }
    catch (const std::exception &e)
    {
    }

    if (hit_reply1 && hit_reply2)
    {
        cout << "PASS" << endl;
        return 0;
    }
    cerr << "FAILED" << endl;
    return 1;
}
