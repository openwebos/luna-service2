# @@@LICENSE
#
#      Copyright (c) 2008-2012 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# LICENSE@@@

#
# luna-service2/conf/CMakeLists.txt
#

# Default settings used for device. Target-specific overrides are done below.
# If you change a value here, check to see if the overrides below are still necessary.
set(CONF_GENERAL_LOCAL_SOCKET_DIRECTORY "/var/run/ls2")
set(CONF_GENERAL_PID_DIRECTORY "/var/run/ls2")
set(CONF_GENERAL_LOG_SERVICE_STATUS "false")
set(CONF_GENERAL_CONNECT_TIMEOUT "20000")

set(CONF_WATCHDOG_TIMEOUT "60")
set(CONF_FAILURE_MODE "noop")

set(CONF_DYNAMIC_SERVICES_DIRECTORIES_PRV "/usr/share/dbus-1/system-services;/var/palm/system-services;/var/mft/palm/system-services;/var/palm/ls2/services/prv")
set(CONF_DYNAMIC_SERVICES_DIRECTORIES_PUB "/usr/share/dbus-1/services;/var/palm/system-services;/var/palm/ls2/services/pub")
set(CONF_DYNAMIC_SERVICES_EXEC_PREFIX "/usr/sbin/setcpushares-ls2")
set(CONF_DYNAMIC_SERVICES_LAUNCH_TIMEOUT "300000")

set(CONF_SECURITY_ENABLED "true")
set(CONF_SECURITY_DIRECTORIES_PRV "/usr/share/ls2/roles/prv;/var/palm/ls2/roles/prv;/var/mft/palm/ls2/roles/prv")
set(CONF_SECURITY_DIRECTORIES_PUB "/usr/share/ls2/roles/pub;/var/palm/ls2/roles/pub;/var/mft/palm/ls2/roles/pub")
set(CONF_SECURITY_MONITOR_EXE_PATH "/usr/bin/ls-monitor")
set(CONF_SECURITY_SYSMGR_EXE_PATH "/usr/bin/LunaSysMgr")
set(CONF_SECURITY_JS_SERVICE_EXE_PATH "js")
set(CONF_SECURITY_MOJO_APP_EXE_PATH "mojo-app")
set(CONF_SECURITY_MOJO_APPS_ALLOW_OUTBOUND_BY_DEFAULT "true")
set(CONF_SECURITY_ALLOW_NULL_OUTBOUND_BY_DEFAULT "true")
    
set(CONF_BINARY_DIR "${PROJECT_BINARY_DIR}/conf")

# Target-specific settings
if (TARGET_DESKTOP)
    set(CONF_GENERAL_LOCAL_SOCKET_DIRECTORY "/tmp/ls2")
    set(CONF_GENERAL_PID_DIRECTORY "/tmp/ls2")
    set(CONF_SECURITY_ENABLED "false")

    # Desktop binaries build settings
    if (NOT ${LS_TESTS})
        set(CONF_DYNAMIC_SERVICES_DIRECTORIES_PRV "/var/opt/luna/dbus-1/system-services")
        set(CONF_DYNAMIC_SERVICES_DIRECTORIES_PUB "/var/opt/luna/dbus-1/services")
        set(CONF_DYNAMIC_SERVICES_EXEC_PREFIX "")
        set(CONF_DYNAMIC_SERVICES_LAUNCH_TIMEOUT "20000")

        set(CONF_SECURITY_DIRECTORIES_PRV "/usr/share/ls2/roles")
        set(CONF_SECURITY_DIRECTORIES_PUB "/usr/share/ls2/roles")
    else ()
        # Settings overrides for running a local build for testing
        set(CONF_WATCHDOG_TIMEOUT "10")
        set(CONF_FAILURE_MODE "crash")

        set(CONF_DYNAMIC_SERVICES_DIRECTORIES_PRV "${PROJECT_BINARY_DIR}/tests/services/")
        set(CONF_DYNAMIC_SERVICES_DIRECTORIES_PUB "${CONF_DYNAMIC_SERVICES_DIRECTORIES_PRV}")
        set(CONF_DYNAMIC_SERVICES_EXEC_PREFIX "")
        set(CONF_DYNAMIC_SERVICES_LAUNCH_TIMEOUT "20000")

        set(CONF_SECURITY_DIRECTORIES_PRV "${PROJECT_BINARY_DIR}/tests/roles/")
        set(CONF_SECURITY_DIRECTORIES_PUB "${CONF_SECURITY_DIRECTORIES_PRV}")    
        set(CONF_SECURITY_SYSMGR_EXE_PATH "${PROJECT_BINARY_DIR}/tests/app-id-security")
    endif ()
endif ()

configure_file(ls-private.conf.in ${CONF_BINARY_DIR}/ls-private.conf)
configure_file(ls-public.conf.in ${CONF_BINARY_DIR}/ls-public.conf)

install(FILES ${CONF_BINARY_DIR}/ls-private.conf DESTINATION ${CONF_INSTALL_PATH})
install(FILES ${CONF_BINARY_DIR}/ls-public.conf DESTINATION ${CONF_INSTALL_PATH})
