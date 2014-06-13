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

#include "util.hpp"

using namespace std;

void process_context(GMainContext *context, int timeout_ms)
{
    auto main_loop = mk_ptr(g_main_loop_new(context, FALSE), g_main_loop_unref);

    GTimeout timeout(timeout_ms, [&]() -> gboolean { g_main_loop_quit(main_loop.get()); return FALSE; });
    timeout.attach(context);

    g_main_loop_run(main_loop.get());
}

JRef fromJson(const std::string &s)
{
    static pbnjson::JDomParser parser(nullptr);
    static pbnjson::JSchemaFragment schema("{}");
    if (parser.parse(s, schema))
        return JRef(parser.getDom());
    else
        return JRef::invalid();
}

std::string toJson(const JRef &x)
{
    static pbnjson::JSchemaFragment schema("{}");
    static pbnjson::JGenerator gen(nullptr);
    static std::string invalid = "(invalid)";
    std::string s;
    // we'll work-around pbnjson inability to serialize primitives
    if (!gen.toString(JRef::array({ x }), schema, s))
        return invalid;

    return s.substr(1, s.size() - 2);
}
