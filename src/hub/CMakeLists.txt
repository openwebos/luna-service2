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
# luna-service2/src/hub/CMakeLists.txt
#

set(HUB_SRCS
    conf.c
    hub.c
    log.c
    security.c
    watchdog.c
    )

add_definitions(-DG_LOG_DOMAIN="LunaServiceHub")

add_executable(ls-hubd ${HUB_SRCS})
target_link_libraries(ls-hubd ${LS2_LIBRARY_NAME} ${PMLOGLIB_LDFLAGS} ${MEMCPY_LIBRARIES})

install(TARGETS ls-hubd DESTINATION bin ${RESTRICTED_PERMS})
