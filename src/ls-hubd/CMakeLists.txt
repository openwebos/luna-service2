# @@@LICENSE
#
#      Copyright (c) 2008-2014 LG Electronics, Inc.
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

set(HUB_SOURCE_FILES
    conf.c
    pattern.c
    hub.c
    security.c
    watchdog.c
    )

# The following definitions avoid the need to configure any source files
add_definitions(-DDEFAULT_SYSMGR_EXE_PATH="${WEBOS_INSTALL_BINDIR}/LunaSysMgr")
add_definitions(-DDEFAULT_WEBAPPMGR_EXE_PATH="${WEBOS_INSTALL_BINDIR}/WebAppMgr")
add_definitions(-DDEFAULT_WEBAPPMGR2_EXE_PATH="${WEBOS_INSTALL_BINDIR}/QtWebProcess")
add_definitions(-DDEFAULT_MONITOR_EXE_PATH="${WEBOS_INSTALL_SBINDIR}/ls-monitor")
add_definitions(-DDEFAULT_PID_DIR="${WEBOS_INSTALL_RUNTIMEINFODIR}/ls2")
add_definitions(-DDEFAULT_LOCAL_SOCKET_DIR="${WEBOS_INSTALL_RUNTIMEINFODIR}/ls2")

add_library(ls-hublib STATIC ${HUB_SOURCE_FILES})

add_executable(ls-hubd hub.c)
target_link_libraries(ls-hubd ls-hublib ${CMAKE_PROJECT_NAME} ${PMLOGLIB_LDFLAGS})
webos_build_daemon(NAME ls-hubd LAUNCH ${CMAKE_SOURCE_DIR}/files/launch/ ${LS2_RESTRICTED})

if (WEBOS_CONFIG_BUILD_TESTS)
    add_subdirectory(test)
else()
    message(STATUS "ls-hubd: skipping automatic tests")
endif()
