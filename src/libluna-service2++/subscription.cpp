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

#include "subscription.hpp"
#include "error.hpp"
#include "handle.hpp"
#include "payload.hpp"

namespace LS {

inline SubscriptionPoint::SubscriptionItem::SubscriptionItem(LS::Message _message,
                                                             LS::SubscriptionPoint *_parent)
    : message{ std::move(_message) },
      parent{ _parent },
      statusToken{ LSMESSAGE_TOKEN_INVALID }
{
}

SubscriptionPoint::SubscriptionItem::~SubscriptionItem()
{
    if (statusToken != LSMESSAGE_TOKEN_INVALID)
    {
        parent->cleanItem(this);
    }
}

SubscriptionPoint::SubscriptionPoint(LS::Handle *service_handle): _service_handle {service_handle}
{
    setCancelNotificationCallback();
}

SubscriptionPoint::~SubscriptionPoint()
{
    unsetCancelNotificationCallback();
    cleanup();
}

bool SubscriptionPoint::subscribe(LS::Message &message)
{
    if (!_service_handle)
        return false;
    bool retVal {false};
    try
    {
        std::unique_ptr<SubscriptionItem> item
        {new SubscriptionItem(message, this)};

        LS::Error error;
        LS::JSONPayload payload;
        payload.set("serviceName", message.getSender());
        retVal = LSCall(_service_handle->get(), "palm://com.palm.bus/signal/registerServerStatus",
                        payload.getJSONString().c_str(), subscriberDownCB, item.get(),
                        &item->statusToken, error.get());
        if (retVal)
        {
            _subs.push_back(item.release());
        }
    }
    catch (...)
    {
        return false;
    }
    return retVal;
}

void SubscriptionPoint::setServiceHandle(LS::Handle *service_handle)
{
    _service_handle = service_handle;
    setCancelNotificationCallback();
}

bool SubscriptionPoint::post(const char *payload)
{
    if (!_service_handle)
        return false;

    try
    {
        for (auto subscriber: _subs)
        {
            subscriber->message.reply(*_service_handle, payload);
        }
    }
    catch(LS::Error &e)
    {
        e.log(PmLogGetLibContext(), "LS_SUBS_POST_FAIL");
        return false;
    }
    catch(...)
    {
        return false;
    }
    return true;
}

void SubscriptionPoint::setCancelNotificationCallback()
{
    if (_service_handle)
        LSCallCancelNotificationAdd(_service_handle->get(), subscriberCancelCB, this, LS::Error().get());
}

void SubscriptionPoint::unsetCancelNotificationCallback()
{
    if (_service_handle)
        LSCallCancelNotificationRemove(_service_handle->get(), subscriberCancelCB, this, LS::Error().get());
}

bool SubscriptionPoint::subscriberCancelCB(LSHandle *sh, const char *uniqueToken, void *context)
{
    SubscriptionPoint *self = static_cast<SubscriptionPoint *>(context);
    self->removeItem(uniqueToken);
    return true;
}

bool SubscriptionPoint::subscriberDownCB(LSHandle *sh, LSMessage *message, void *context)
{
    SubscriptionItem *item = static_cast<SubscriptionItem *>(context);
    SubscriptionPoint *self = item->parent;
    self->removeItem(item, message);
    return true;
}

void SubscriptionPoint::removeItem(const char *uniqueToken)
{
    SubscriptionItem *item {nullptr};
    auto it = std::find_if(_subs.begin(), _subs.end(),
                           [uniqueToken, &item](SubscriptionItem *_item)
    {
        if (!strcmp(uniqueToken, _item->message.getUniqueToken()))
        {
            item = _item;
            return true;
        }
        return false;
    }
                          );
    if (it != _subs.end())
    {
        _subs.erase(it);
        delete item;
    }
}

void SubscriptionPoint::removeItem(LS::SubscriptionPoint::SubscriptionItem *item, LSMessage *message)
{
    LS::JSONPayload reply(LSMessageGetPayload(message));
    if (!reply.isValid())
        return;
    bool isConnected {true};
    if (!reply.get("connected", isConnected) || isConnected)
        return;

    auto it = std::find_if(_subs.begin(), _subs.end(),
                           [item](SubscriptionItem *_item)
    {
        return (_item == item);
    }
                          );
    if (it != _subs.end())
    {
        _subs.erase(it);
        delete item;
    }
}

void SubscriptionPoint::cleanItem(LS::SubscriptionPoint::SubscriptionItem *item)
{
    if (item->statusToken != LSMESSAGE_TOKEN_INVALID)
    {
        LS::Error error;
        LSCallCancel(_service_handle->get(), item->statusToken, error.get());
        item->statusToken = LSMESSAGE_TOKEN_INVALID;
    }
}

void SubscriptionPoint::cleanup()
{
    for (auto subscriber: _subs)
    {
        delete subscriber;
    }
}

} // namespace LS;
