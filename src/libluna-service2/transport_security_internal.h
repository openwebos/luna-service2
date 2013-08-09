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

#ifndef _TRANSPORT_SECURITY_INTERNAL_H_
#define _TRANSPORT_SECURITY_INTERNAL_H_

/**
 * Represents credentials for a client
 */
struct _LSTransportCred {
    pid_t pid;              /**< process pid */
    uid_t uid;              /**< process uid */
    gid_t gid;              /**< process gid */
    const char *exe_path;   /**< full path to process' executable */
    const char *cmd_line;   /**< process' cmdline */
};

#endif  /* _TRANSPORT_SECURITY_INTERNAL_H_ */
