# @@@LICENSE
#
#      Copyright (c) 2008-2013 LG Electronics, Inc.
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

# Default settings used for device. Target-specific overrides are done below.
# If you change a value here, check to see if the overrides below are still necessary.
set(CONF_GENERAL_LOCAL_SOCKET_DIRECTORY "${WEBOS_INSTALL_RUNTIMEINFODIR}/ls2")
set(CONF_GENERAL_PID_DIRECTORY "${WEBOS_INSTALL_RUNTIMEINFODIR}/ls2")
set(CONF_GENERAL_LOG_SERVICE_STATUS "false")
set(CONF_GENERAL_CONNECT_TIMEOUT "20000")

set(CONF_WATCHDOG_TIMEOUT "60")
set(CONF_FAILURE_MODE "noop")

set(CONF_DYNAMIC_SERVICES_DIRECTORIES_PRV "${WEBOS_INSTALL_SYSBUS_PRVSERVICESDIR}")
set(CONF_DYNAMIC_SERVICES_VOLATILE_DIRECTORIES_PRV "${WEBOS_INSTALL_SYSBUS_DYNPRVSERVICESDIR};${WEBOS_INSTALL_SYSBUS_DEVPRVSERVICESDIR}")
set(CONF_DYNAMIC_SERVICES_DIRECTORIES_PUB "${WEBOS_INSTALL_SYSBUS_PUBSERVICESDIR}")
set(CONF_DYNAMIC_SERVICES_VOLATILE_DIRECTORIES_PUB "${WEBOS_INSTALL_SYSBUS_DYNPUBSERVICESDIR};${WEBOS_INSTALL_SYSBUS_DEVPUBSERVICESDIR}")
set(CONF_DYNAMIC_SERVICES_EXEC_PREFIX "${WEBOS_INSTALL_SBINDIR}/setcpushares-ls2")
set(CONF_DYNAMIC_SERVICES_LAUNCH_TIMEOUT "300000")

if (${WEBOS_LS2_SECURE})
    set(CONF_SECURITY_ENABLED "true")
else()
    set(CONF_SECURITY_ENABLED "false")
endif()

set(CONF_SECURITY_DIRECTORIES_PRV "${WEBOS_INSTALL_SYSBUS_PRVROLESDIR}")
set(CONF_SECURITY_VOLATILE_DIRECTORIES_PRV "${WEBOS_INSTALL_SYSBUS_DYNPRVROLESDIR};${WEBOS_INSTALL_SYSBUS_DEVPRVROLESDIR}")
set(CONF_SECURITY_DIRECTORIES_PUB "${WEBOS_INSTALL_SYSBUS_PUBROLESDIR}")
set(CONF_SECURITY_VOLATILE_DIRECTORIES_PUB "${WEBOS_INSTALL_SYSBUS_DYNPUBROLESDIR};${WEBOS_INSTALL_SYSBUS_DEVPUBROLESDIR}")
set(CONF_SECURITY_MONITOR_EXE_PATH "${WEBOS_INSTALL_SBINDIR}/ls-monitor")
set(CONF_SECURITY_MONITOR_PUB_EXE_PATH "${WEBOS_INSTALL_BINDIR}/ls-monitor-pub")
set(CONF_SECURITY_SYSMGR_EXE_PATH "${WEBOS_INSTALL_BINDIR}/LunaSysMgr")
set(CONF_SECURITY_WEBAPPMGR_EXE_PATH "${WEBOS_INSTALL_BINDIR}/WebAppMgr")
set(CONF_SECURITY_WEBAPPMGR2_EXE_PATH "${WEBOS_INSTALL_BINDIR}/QtWebProcess")
set(CONF_SECURITY_JS_SERVICE_EXE_PATH "js")
set(CONF_SECURITY_MOJO_APP_EXE_PATH "mojo-app")
set(CONF_SECURITY_MOJO_APPS_ALLOW_OUTBOUND_BY_DEFAULT "true")
set(CONF_SECURITY_ALLOW_NULL_OUTBOUND_BY_DEFAULT "true")

webos_machine_impl_dep()
# Target-specific settings
if(WEBOS_TARGET_MACHINE_IMPL_SIMULATOR)
    set(CONF_GENERAL_LOCAL_SOCKET_DIRECTORY "/tmp/ls2")
    set(CONF_GENERAL_PID_DIRECTORY "/tmp/ls2")
    set(CONF_SECURITY_ENABLED "false")

    # Desktop binaries build settings
    if(NOT ${LS_TESTS})
        set(CONF_DYNAMIC_SERVICES_DIRECTORIES_PRV "${WEBOS_INSTALL_LOCALSTATEDIR}/opt/luna/dbus-1/system-services")
        set(CONF_DYNAMIC_SERVICES_DIRECTORIES_PUB "${WEBOS_INSTALL_LOCALSTATEDIR}/opt/luna/dbus-1/services")
        set(CONF_DYNAMIC_SERVICES_EXEC_PREFIX "")
        set(CONF_DYNAMIC_SERVICES_LAUNCH_TIMEOUT "20000")

        set(CONF_SECURITY_DIRECTORIES_PRV "${WEBOS_INSTALL_DATADIR}/ls2/roles")
        set(CONF_SECURITY_DIRECTORIES_PUB "${WEBOS_INSTALL_DATADIR}/ls2/roles")
    else()
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
    endif()
endif()

webos_build_configured_file(files/conf/ls-private.conf SYSCONFDIR luna-service2)
webos_build_configured_file(files/conf/ls-public.conf SYSCONFDIR luna-service2)

webos_build_configured_file(files/conf/pmlog/ls-hub.conf SYSCONFDIR pmlog.d)
