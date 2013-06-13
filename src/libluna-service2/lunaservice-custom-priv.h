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
#ifndef _LUNASERVICE_CUSTOM_H_
#define _LUNASERVICE_CUSTOM_H_

#ifdef __cplusplus
extern "C" {
#endif

#define LS_DEPRECATED   __attribute__ ((deprecated))

typedef struct LSFetchQueue LSFetchQueue;

bool LSFetchQueueNew(LSFetchQueue **ret_fetch_queue) LS_DEPRECATED;
void LSFetchQueueFree(LSFetchQueue *fq) LS_DEPRECATED;
void LSFetchQueueAddConnection(LSFetchQueue *fq, LSHandle *sh) LS_DEPRECATED;
bool LSFetchQueueWaitForMessage(LSFetchQueue *fq, LSMessage **message,
                                 LSError *lserror) LS_DEPRECATED;
bool LSFetchQueueWakeUp(LSFetchQueue *fq, LSError *lserror) LS_DEPRECATED;


bool LSCustomWaitForMessage(LSHandle *sh, LSMessage **message,
                               LSError *lserror) LS_DEPRECATED;

bool LSCustomFetchMessage(LSHandle *sh, LSMessage **message,
               LSError *lserror) LS_DEPRECATED;

bool LSCustomWakeUp(LSHandle *sh, LSError *lserror) LS_DEPRECATED;

#ifdef __cplusplus
} // extern "C"
#endif

#endif //_LUNASERVICE_CUSTOM_H_
