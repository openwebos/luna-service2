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
#ifndef _CONF_H
#define _CONF_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include "error.h"
#include "watchdog.h"

bool ConfigParseFile(const char *path, LSError *lserror);
bool ConfigSetupInotify(const char* conf_file, LSError *lserror);
bool ConfigKeyProcessDynamicServiceDirs(const char **dirs, void *ctxt, LSError *lserror);
void ConfigSetDefaults(void);
void ConfigCleanup();

extern int g_conf_watchdog_timeout_sec;
extern LSHubWatchdogFailureMode g_conf_watchdog_failure_mode;
extern int g_conf_query_name_timeout_ms;
extern char* g_conf_dynamic_service_exec_prefix;
extern bool g_conf_security_enabled;
extern bool g_conf_log_service_status;
extern int g_conf_connect_timeout_ms;
extern char* g_conf_monitor_exe_path;
extern char* g_conf_monitor_pub_exe_path;
extern char* g_conf_sysmgr_exe_path;
extern char* g_conf_webappmgr_exe_path;
extern char* g_conf_webappmgr2_exe_path;
extern char* g_conf_triton_service_exe_path;
extern char* g_conf_mojo_app_exe_path;
extern bool g_conf_mojo_apps_allow_all_outbound_by_default;
extern bool g_conf_allow_null_outbound_by_default;
extern char *g_conf_pid_dir;
extern char *g_conf_local_socket_path;

enum ScanDirectoriesContext {STEADY_DIRS = 0, VOLATILE_DIRS};

#endif
