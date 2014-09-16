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


#ifndef _SUBSCRIPTION_H_
#define _SUBSCRIPTION_H_

#include "transport_message.h"

typedef struct LSSubscriptionList LSSubscriptionList;
typedef struct _Catalog _Catalog;

_Catalog * _CatalogNew(LSHandle *sh);
void _CatalogFree(_Catalog *catalog);

bool _CatalogHandleCancel(_Catalog *catalog, LSMessage *cancelMsg,
                          LSError *lserror);

void _LSCatalogRemoveClientSubscriptions(_Catalog *catalog, _LSTransportClient *client);

bool _LSSubscriptionGetJson(LSHandle *sh, jvalue_ref *ret_obj,
                            LSError *lserror);

#endif // _SUBSCRIPTION_H_
