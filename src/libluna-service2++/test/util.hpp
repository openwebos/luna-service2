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

/**
 *  @file util.hpp
 */

#pragma once

#include <pbnjson.hpp>

#include <gtest/gtest.h>

#include <memory>

class JRef : public pbnjson::JValue
{
public:
    JRef() : pbnjson::JValue()
    {}

    template<typename T>
    JRef(const T &origin) : pbnjson::JValue(origin) {}

    JRef(const std::initializer_list<std::pair<std::string,JRef>> &props) : pbnjson::JValue(pbnjson::Object())
    { for(const auto &prop : props) put(prop.first, prop.second); }

    jvalue_ref get() const { return peekRaw(); }

    jvalue_ref release() { return grabOwnership(); }

    JRef clone() const { return JRef(duplicate()); }

    static JRef object() { return JRef(pbnjson::Object()); }

    static JRef array() { return JRef(pbnjson::Array()); }

    static JRef array(const std::initializer_list<JRef> &items)
    {
        auto xs = array();
        for(const auto &item : items) xs << item;
        return xs;
    }

    static const JRef invalid()
    {
        static const JRef invalid = JRef(JRef()[0]);
        return invalid;
    }
};

JRef fromJson(const std::string &s);

std::string toJson(const JRef &x);

inline void PrintTo(const JRef &x, ::std::ostream *os)
{ *os << toJson(x); }

namespace pbnjson {
    inline void PrintTo(const JValue &x, ::std::ostream *os)
    { *os << toJson(JRef(x)); }
    inline void PrintTo(const JValueArrayElement &x, ::std::ostream *os)
    { *os << toJson(JRef(x)); }
}

/// Run something on exit from scope
class OnDescope {
    std::function<void()> func;
public:
    template <typename T>
    OnDescope(T &&action) : func { std::forward<T>(action) }
    {}
    ~OnDescope()
    { func(); }
};

/// Wrap to call any callable object passed as context
template <typename F>
typename std::result_of<F()>::type wrap(void *ctx)
{ return (*static_cast<F*>(ctx))(); }

/// scope-living glib timeout with possibility to attach to custom context
class GTimeout {
    std::function<gboolean()> cb;
    GSource *s;
public:
    template <typename T>
    GTimeout(guint interval, T &&func) :
        cb(std::forward<T>(func)),
        s(g_timeout_source_new(interval))
    { g_source_set_callback(s, &wrap<decltype(cb)>, &cb, nullptr); }

    ~GTimeout()
    {
        g_source_destroy(s);
        g_source_unref(s);
    }

    void attach(GMainContext *context = nullptr)
    { (void)g_source_attach(s, context); }
};

template <typename T, typename D>
std::unique_ptr<T, D> mk_ptr(T *t, D d)
{
    return std::unique_ptr<T, D>(t, d);
}

// Process events from Glib context for specified amount of time.
void process_context(GMainContext *context, int timeout_ms = 2);
