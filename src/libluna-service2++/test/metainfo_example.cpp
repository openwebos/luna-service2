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

#include <pbnjson.hpp>

#include "luna-service2/lunaservice.hpp"
#include "luna-service2/lunaservice-meta.h"

#include "util.hpp"

#include <iostream>
#include <thread>
#include <string>
#include <cassert>

// Service class which uses schemas for category methods
class TestMetaInfoService: public LS::Handle
{

public:
    TestMetaInfoService()
    : LS::Handle{LS::registerService("com.palm.metainfo_example")},
      _mainCtx{g_main_context_new()},
      _mainLoop{g_main_loop_new(_mainCtx, false)},
      _thread{[this](){g_main_loop_run(_mainLoop);}},
      _category{"/testMethods"}
    {
        LS_CATEGORY_BEGIN(TestMetaInfoService, _category.c_str())
            LS_CATEGORY_METHOD(testCall,LUNA_METHOD_FLAG_VALIDATE_IN)
        LS_CATEGORY_END

        attachToLoop(_mainLoop);
    }

    ~TestMetaInfoService()
    {
        g_main_loop_quit(_mainLoop);
        _thread.join();
        detach();
        g_main_loop_unref(_mainLoop);
        g_main_context_unref(_mainCtx);
    }

    bool testCall(LSMessage &message)
    {
        LS::Error error;
        LSMessageRespond(&message, R"({"returnValue":true})", error.get());
        return true;
    }

    void setCategorySchema(const std::string &schema)
    {
        setCategoryDescription(_category.c_str(), fromJson(schema).get());
    }

private:
    GMainContext *_mainCtx;
    GMainLoop *_mainLoop;
    std::thread _thread;
    std::string _category;

};

namespace
{

std::string basicSchema = R"json(
{
"definitions": {
    "successResponse": {
        "type": "object",
        "description": "general successful response schema",
        "properties": {
            "returnValue": {
                "type": "boolean",
                "description": "call successful result indicator",
                "enum": [true]
            }
        },
        "required": ["returnValue"]
    },
    "errorResponse": {
        "type": "object",
        "description": "general error response schema",
        "properties": {
            "returnValue": {
                "type": "boolean",
                "description": "call unsuccessful result indicator",
                "enum": [false]
            },
            "errorCode": {
                "type": "integer",
                "description": "type of error indicator for client service"
            },
            "errorText": {
                "type": "string",
                "description": "human-readable error description"
            }
        },
        "required": ["returnValue"]
    }
},
"methods": {
    "testCall": {
        "call": {
            "type": "object",
            "description": "test call basic schema",
            "properties": {
                "id": { "type": "integer", "minimum": 0, "exclusiveMinimum": true }
            },
            "required": ["id"],
            "additionalProperties": true
        },
        "reply": {
            "oneOf": [
                { "$ref": "#/definitions/successResponse" },
                { "$ref": "#/definitions/errorResponse" }
            ]
        }
    }
}
}
)json";

std::string extSchema = R"json(
{
"definitions": {
    "client": {
        "description": "schema for client object",
        "type": "object",
        "properties": {
            "name": { "type": "string", "minLength": 2, "maxLength": 10 },
            "organization": { "type": "string" }
        },
        "required": ["name"],
        "additionalProperties": false
    },
    "successResponse": {
        "type": "object",
        "description": "general successful response schema",
        "properties": {
            "returnValue": {
                "type": "boolean",
                "description": "call successful result indicator",
                "enum": [true]
            }
        },
        "required": ["returnValue"]
    },
    "errorResponse": {
        "type": "object",
        "description": "general error response schema",
        "properties": {
            "returnValue": {
                "type": "boolean",
                "description": "call unsuccessful result indicator",
                "enum": [false]
            },
            "errorCode": {
                "type": "integer",
                "description": "type of error indicator for client service"
            },
            "errorText": {
                "type": "string",
                "description": "human-readable error description"
            }
        },
        "required": ["returnValue"]
    }
},
"methods": {
    "testCall": {
        "call": {
            "type": "object",
            "description": "test call request schema",
            "properties": {
                "id": { "type": "integer", "minimum": 0, "exclusiveMinimum": true },
                "sender": { "$ref": "#/definitions/client" }
            },
            "required": ["id", "sender"],
            "additionalProperties": true
        },
        "firstReply": {
            "oneOf": [
                { "$ref": "#/definitions/successResponse" },
                { "$ref": "#/definitions/errorResponse" }
            ]
        },
        "reply": {
            "type": "object",
            "description": "test call reply schema",
            "properties": {
                "timestamp": { "type": "string" }
            },
            "additionalProperties": true
        }
    }
}
}
)json";

} // anonymous

static bool returnValue(const LS::Message &message)
{
    return fromJson(message.getPayload())["returnValue"].asBool();
}

// Example how to use JSON schema for call validation
static void validationExample()
{
    TestMetaInfoService service;

    GMainContext * mainCtx = g_main_context_new();
    GMainLoop * mainLoop = g_main_loop_new(mainCtx, false);
    LS::Handle client = LS::registerService();
    client.attachToLoop(mainLoop);

    LS::Message resp;
    LS::Call call;

    // No validation schema for testCall
    // Call with empty payload - success
    call = client.callOneReply("palm://com.palm.metainfo_example/testMethods/testCall", "{}");
    resp = call.get();
    assert(returnValue(resp));

//! [call validation]
    // Set schema for testCall
    // Mandatory parameters:
    //  numeric "id" > 0
    service.setCategorySchema(basicSchema);

    // Call with empty payload - fail call validation
    call = client.callOneReply("palm://com.palm.metainfo_example/testMethods/testCall", "{}");
    resp = call.get();
    assert(!returnValue(resp));

    // Call with invalid "id" value - fail call validation
    call = client.callOneReply("palm://com.palm.metainfo_example/testMethods/testCall", R"({"id":-1})");
    resp = call.get();
    assert(!returnValue(resp));

    // Call with valid "id" value - success call validation
    call = client.callOneReply("palm://com.palm.metainfo_example/testMethods/testCall", R"({"id":1})");
    resp = call.get();
    assert(returnValue(resp));

    // Set new schema for testCall
    // Mandatory parameters:
    //  numeric "id" > 0
    //  object "sender" with properties:
    //   "name" - mandatory string from 2 to 10 characters
    //   "organization" - optional string
    //   no additional properties allowed
    service.setCategorySchema(extSchema);

    // Call without "sender" object - fail call validation
    call = client.callOneReply("palm://com.palm.metainfo_example/testMethods/testCall", R"({"id":1})");
    resp = call.get();
    assert(!returnValue(resp));

    // Call testCall with invalid "sender" object - "name" is missing - fail call validation
    call = client.callOneReply("palm://com.palm.metainfo_example/testMethods/testCall",
        R"({"id":1, "sender": {"organization": "LGE"}})");
    resp = call.get();
    assert(!returnValue(resp));

    // Call testCall with invalid "sender" object - added additional property - fail call validation
    call = client.callOneReply("palm://com.palm.metainfo_example/testMethods/testCall",
        R"({"id":1, "sender": {"name": "Test service", "addKey": "addValue"}})");
    resp = call.get();
    assert(!returnValue(resp));

    // Call testCall with valid "sender" object - success call validation
    call = client.callOneReply("palm://com.palm.metainfo_example/testMethods/testCall",
        R"({"id":1, "sender": {"name": "test", "organization": "LGE"}})");
    resp = call.get();
    assert(returnValue(resp));
//! [call validation]
}

// Example how to use JSON schema for category introspection
static void introspectionExample()
{
    TestMetaInfoService service;

    GMainContext * mainCtx = g_main_context_new();
    GMainLoop * mainLoop = g_main_loop_new(mainCtx, false);
    LS::Handle client = LS::registerService();
    client.attachToLoop(mainLoop);

//! [category introspection]
    // Set schema for category
    service.setCategorySchema(extSchema);

    // Call category introspection information
    auto call = client.callOneReply("palm://com.palm.metainfo_example/com/palm/luna/private/introspection",
        R"({"type":"description"})");
    auto resp = call.get();
    assert(returnValue(resp));
    JRef reply = fromJson(resp.getPayload());
    assert(reply.hasKey("categories"));
    // Retrieve categories
    JRef cats = reply["categories"];
    std::cout<<"Category: "<<(*cats.begin()).first.asString()<<std::endl;
    // Retrieve methods for first category
    JRef methods{(*cats.begin()).second["methods"]};
    // Iterate through methods and print assigned schemas
    for (auto it = methods.begin(); it != methods.end(); ++it)
    {
        std::cout<<" Method: "<<(*it).first.asString()<<std::endl;
        JRef method{(*it).second};
        assert(method.hasKey("call"));
        std::cout<<"  Call schema: "<<toJson(method["call"])<<std::endl;

        if (method.hasKey("firstReply"))
        {
            std::cout<<"  First reply schema: "<<toJson(method["firstReply"])<<std::endl;
        }
        if (method.hasKey("reply"))
        {
            std::cout<<"  Reply schema: "<<toJson(method["reply"])<<std::endl;
        }

    }
//! [category introspection]
}

int main(int argc, char ** argv)
{
    validationExample();
    introspectionExample();
    return 0;
}

