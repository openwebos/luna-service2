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

#include "payload.hpp"

namespace LS {

//! @cond

template <>
bool JSONPayload::set(const std::string &name, const pbnjson::JValue &value)
{
    return _root.put(name, value);
}

JSONPayload::JSONPayload(const std::string &payload)
{
    pbnjson::JDomParser parser {nullptr};
    if (parser.parse(payload, pbnjson::JSchema::AllSchema()))
    {
        _root = parser.getDom();
    }
    else
    {
        throw std::invalid_argument {"Invalid JSON payload"};
    }
}

bool JSONPayload::get(const std::string &name, pbnjson::JValue &value) const
{
    if (_root.hasKey(name))
    {
        value = pbnjson::JValue {_root[name]};
        return true;
    }
    return false;
}

bool JSONPayload::get(const std::string &name, int32_t &value) const
{
    pbnjson::JValue jvalue;
    if (!get(name, jvalue) || !jvalue.isNumber())
        return false;
    value = jvalue.asNumber<int32_t>();
    return true;
}

bool JSONPayload::get(const std::string &name, int64_t &value) const
{
    pbnjson::JValue jvalue;
    if (!get(name, jvalue) || !jvalue.isNumber())
        return false;
    value = jvalue.asNumber<int64_t>();
    return true;
}

bool JSONPayload::get(const std::string &name, double &value) const
{
    pbnjson::JValue jvalue;
    if (!get(name, jvalue) || !jvalue.isNumber())
        return false;
    value = jvalue.asNumber<double>();
    return true;
}

bool JSONPayload::get(const std::string &name, bool &value) const
{
    pbnjson::JValue jvalue;
    if (!get(name, jvalue) || !jvalue.isBoolean())
        return false;
    value = jvalue.asBool();
    return true;
}

bool JSONPayload::get(const std::string &name, std::string &value) const
{
    pbnjson::JValue jvalue;
    if (!get(name, jvalue) || !jvalue.isString())
        return false;
    value = jvalue.asString();
    return true;
}

std::string JSONPayload::getJSONString() const
{
    std::string jsonStr;
    pbnjson::JGenerator {} .toString(_root, pbnjson::JSchema::AllSchema(), jsonStr);
    return jsonStr;
}

//! @endcond

} // namespace LS;
