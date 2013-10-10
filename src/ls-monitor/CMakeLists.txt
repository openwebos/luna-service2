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

set(MONITOR_SOURCE_FILES
    monitor.c
    monitor_queue.c
    )

if(TARGET_DESKTOP)
	add_definitions(-DPID_DIR="/tmp")
else()
	add_definitions(-DPID_DIR="${WEBOS_INSTALL_RUNTIMEINFODIR}/ls2")
endif()

add_executable(ls-monitor ${MONITOR_SOURCE_FILES})
target_link_libraries(ls-monitor ${CMAKE_PROJECT_NAME})
webos_build_program(NAME ls-monitor ADMIN ${LS2_RESTRICTED})

add_executable(ls-monitor-pub ${MONITOR_SOURCE_FILES})
target_link_libraries(ls-monitor-pub ${CMAKE_PROJECT_NAME})
webos_build_program(NAME ls-monitor-pub)
set_target_properties(ls-monitor-pub PROPERTIES COMPILE_DEFINITIONS "PUBLIC_ONLY")
