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
#include <vector>
#include <algorithm>

#include "message.hpp"

namespace LS {

/**
 * @ingroup LunaServicePP
 * @brief Represent publishing point for a sender service
 */
class SubscriptionPoint
{

    struct SubscriptionItem
    {

    friend class SubscriptionPoint;

    private:
        SubscriptionItem(LS::Message _message,
                         LS::SubscriptionPoint *_parent);

    public:
        ~SubscriptionItem();

        SubscriptionItem(const SubscriptionItem &) = delete;
        SubscriptionItem &operator=(const SubscriptionItem &) = delete;
        SubscriptionItem(const SubscriptionItem &&) = delete;
        SubscriptionItem &operator=(const SubscriptionItem &&) = delete;

    private:
        LS::Message message;
        LS::SubscriptionPoint *parent;
        LSMessageToken statusToken;

    };

friend struct SubscriptionItem;

public:
    SubscriptionPoint() : SubscriptionPoint{nullptr} {}

    explicit SubscriptionPoint(Handle *service_handle);

    ~SubscriptionPoint();

    SubscriptionPoint(const SubscriptionPoint &) = delete;
    SubscriptionPoint &operator=(const SubscriptionPoint &) = delete;
    SubscriptionPoint(SubscriptionPoint &&) = delete;
    SubscriptionPoint &operator=(SubscriptionPoint &&) = delete;

    /**
     * Assign a publisher service
     */
    void setServiceHandle(Handle *service_handle);

    /**
     * Process subscription message. Subscribe sender of the given message.
     * @param message
     * @return true if succeed to add the subscriber the sent the message
     */
    bool subscribe(LS::Message &message);

    /**
     * Post to subscribers
     * @param payload - posted data
     * @return true replies were posted successfully
     */
    bool post(const char *payload);

private:
    Handle *_service_handle;
    std::vector<SubscriptionItem *> _subs;

    void setCancelNotificationCallback();

    void unsetCancelNotificationCallback();


    static bool subscriberCancelCB(LSHandle *sh, const char *uniqueToken, void *context);

    static bool subscriberDownCB(LSHandle *sh, LSMessage *message, void *context);

    void removeItem(const char *uniqueToken);

    void removeItem(SubscriptionItem *item, LSMessage *message);

    void cleanItem(SubscriptionItem *item);

    void cleanup();

};

} // namespace LS;
