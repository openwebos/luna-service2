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

set(SOURCE
    base.c
    callmap.c
    category.c
    clock.c
    simple_pbnjson.c
    debug_methods.c
    mainloop.c
    message.c
    subscription.c
    timersource.c
    transport.c
    transport_channel.c
    transport_client.c
    transport_incoming.c
    transport_message.c
    transport_outgoing.c
    transport_security.c
    transport_serial.c
    transport_shm.c
    transport_signal.c
    transport_utils.c
    utils.c
    )

set(SOURCE_TEST ${SOURCE})

set(LIBRARIES
    ${GLIB2_LDFLAGS}
    ${GTHREAD2_LDFLAGS}
    ${CJSON_LDFLAGS}
    ${PBNJSON_C_LDFLAGS}
    ${PMLOGLIB_LDFLAGS}
    dl
    pthread
    rt
    )

add_definitions(-DDEFAULT_HUB_LOCAL_SOCKET_DIRECTORY="${WEBOS_INSTALL_RUNTIMEINFODIR}/luna-service2")

# Enable LLtng
if(WEBOS_LTTNG_ENABLED)
    add_definitions(-DHAS_LTTNG)
    set(SOURCE ${SOURCE} pmtrace_ls2_provider.c)
    set(LIBRARIES ${LIBRARIES} urcu-bp lttng-ust)
endif()

add_library(${CMAKE_PROJECT_NAME} SHARED ${SOURCE})
target_link_libraries(${CMAKE_PROJECT_NAME} ${LIBRARIES})

if (WEBOS_CONFIG_BUILD_TESTS)
    set(TESTLIB_PREFIX "_test")
    set(TESTLIBNAME ${CMAKE_PROJECT_NAME}${TESTLIB_PREFIX})
    add_library(${TESTLIBNAME} SHARED ${SOURCE_TEST})
    target_link_libraries(${TESTLIBNAME} ${LIBRARIES})
    SET_TARGET_PROPERTIES(${TESTLIBNAME} PROPERTIES COMPILE_FLAGS "-DLUNA_SERVICE_UNIT_TEST")
    add_subdirectory(test)
else()
    message(STATUS "libluna-service2: skipping automatic tests")
endif()

webos_build_library()
