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


#ifndef _SECURITY_H
#define _SECURITY_H

#include <stdbool.h>
#include <luna-service2/lunaservice.h>
#include "transport_message.h"

typedef enum {
    LSHubRoleTypeInvalid = -1,
    LSHubRoleTypeRegular,
    LSHubRoleTypePrivileged,
} LSHubRoleType;

typedef struct LSHubRole LSHubRole;
typedef struct LSHubPermission LSHubPermission;

bool ProcessRoleDirectories(const char **dirs, void *ctxt, LSError *lserror);
bool LSHubIsClientAllowedToQueryName(_LSTransportClient *client, const char *dest_service_name, const char *sender_app_id);
bool LSHubIsClientAllowedToRequestName(const _LSTransportClient *client, const char *service_name);
bool LSHubIsClientAllowedToSendSignal(_LSTransportClient *client);
bool LSHubIsClientMonitor(const _LSTransportClient *client);
bool LSHubPushRole(const _LSTransportClient *client, const char *path, LSError *lserror);
bool LSHubActiveRoleMapClientRemove(const _LSTransportClient *client, LSError *lserror);
gchar * LSHubRoleAllowedNamesForExe(const char * exe_path);
bool LSHubClientGetPrivileged(const _LSTransportClient *client);
const char* IsMediaService(const char *service_name);
LSHubRole* LSHubRoleMapLookup(const char *exe_path);
bool PermissionsAndRolesInit(LSError *lserror, bool from_volatile_dir);
LSHubPermission* LSHubPermissionMapLookup(const char *service_name);
void RolesCleanup();


#ifdef UNIT_TESTS
#include <pbnjson.h>
LSHubPermission* LSHubPermissionNew(raw_buffer service_name);
void LSHubPermissionFree(LSHubPermission *perm);
bool LSHubPermissionIsEqual(const LSHubPermission *a, const LSHubPermission *b);
bool LSHubPermissionAddAllowedInbound(LSHubPermission *perm, const char *name, LSError *lserror);
bool LSHubPermissionAddAllowedOutbound(LSHubPermission *perm, const char *name, LSError *lserror);
gchar* LSHubPermissionDump(const LSHubPermission *perm);
#endif //UNIT_TESTS

#endif  /* _SECURITY_H */
