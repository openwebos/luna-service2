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

#pragma once

#include <string>

#include <pbnjson.hpp>

namespace LS {

//! @cond
class JSONPayload
{
public:
    JSONPayload() : _root{pbnjson::Object()} {}

    explicit JSONPayload(const std::string &payload);

    ~JSONPayload() {}

    JSONPayload(const JSONPayload &) = delete;
    JSONPayload &operator=(const JSONPayload &) = delete;


    JSONPayload(JSONPayload &&other) : _root{other._root}
    {
        other._root = pbnjson::JValue{};
    }

    JSONPayload &operator=(JSONPayload &&other)
    {
        if (this != &other)
        {
            _root = other._root;
            other._root = pbnjson::JValue{};
        }
        return *this;
    }

    bool isValid()
    {
        return _root.isValid();
    }

    std::size_t size()
    {
        return _root.objectSize();
    }

    template <typename T>
    bool set(const std::string &name, const T &value)
    {
        pbnjson::JValue jvalue(value);
        return _root.put(name, jvalue);
    }

    bool get(const std::string &name, pbnjson::JValue &value) const;

    bool get(const std::string &name, int32_t &value) const;

    bool get(const std::string &name, int64_t &value) const;

    bool get(const std::string &name, double &value) const;

    bool get(const std::string &name, bool &value) const;

    bool get(const std::string &name, std::string &value) const;


    std::string getJSONString() const;

private:
    pbnjson::JValue _root;

};

template <>
bool JSONPayload::set(const std::string &name, const pbnjson::JValue &value);

//! @endcond
} // namespace LS;
