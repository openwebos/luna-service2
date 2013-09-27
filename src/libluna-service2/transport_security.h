/* @@@LICENSE
*
*      Copyright (c) 2010-2013 LG Electronics, Inc.
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

#ifndef _TRANSPORT_SECURITY_H_
#define _TRANSPORT_SECURITY_H_

#include <stdbool.h>
#include "error.h"

#define LS_PID_INVALID      -1
#define LS_GID_INVALID      -1
#define LS_UID_INVALID      -1

#define LS_PID_PRINTF_CAST(X)      ((long)(X))
#define LS_PID_PRINTF_FORMAT       "%ld"

#define LS_GID_PRINTF_CAST(X)      ((unsigned long)(X))
#define LS_GID_PRINTF_FORMAT       "%lu"

#define LS_UID_PRINTF_CAST(X)      ((unsigned long)(X))
#define LS_UID_PRINTF_FORMAT       "%lu"

typedef struct _LSTransportCred _LSTransportCred;

_LSTransportCred* _LSTransportCredNew(void);
void _LSTransportCredFree(_LSTransportCred* cred);
bool _LSTransportGetCredentials(int fd, _LSTransportCred *cred, LSError *lserror);

pid_t _LSTransportCredGetPid(const _LSTransportCred *cred);
uid_t _LSTransportCredGetUid(const _LSTransportCred *cred);
gid_t _LSTransportCredGetGid(const _LSTransportCred *cred);
const char* _LSTransportCredGetExePath(const _LSTransportCred *cred);
const char* _LSTransportCredGetCmdLine(const _LSTransportCred *cred);

#ifdef UNIT_TESTS
void _LSTransportCredSetExePath(_LSTransportCred *cred, char const *exe_path);
void _LSTransportCredSetPid(_LSTransportCred *cred, pid_t pid);
#endif //UNIT_TESTS

#endif  /* _TRANSPORT_SECURITY_H_ */
