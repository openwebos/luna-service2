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
# luna-service2/src/CMakeLists.txt
#

set(SOURCE
    base.c
    callmap.c
    clock.c
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

add_definitions(-DG_LOG_DOMAIN="LunaService")

set(LIBRARIES
    ${GLIB2_LDFLAGS}
    ${GTHREAD2_LDFLAGS}
    ${CJSON_LDFLAGS}
    dl
    pthread
    )

add_library(${LS2_LIBRARY_NAME} SHARED ${SOURCE})
target_link_libraries(${LS2_LIBRARY_NAME} ${LIBRARIES})

set_target_properties(${LS2_LIBRARY_NAME} PROPERTIES VERSION ${LS2_LIBRARY_VERSION} SOVERSION ${LS2_API_VERSION_MAJOR})

install(TARGETS ${LS2_LIBRARY_NAME} DESTINATION lib)
install(FILES ${CMAKE_SOURCE_DIR}/include/lunaservice-errors.h DESTINATION include/${LS2_LIBRARY_NAME})
install(FILES ${CMAKE_SOURCE_DIR}/include/lunaservice.h DESTINATION include/${LS2_LIBRARY_NAME})

configure_file (${LS2_LIBRARY_NAME}.pc.in
                ${PROJECT_BINARY_DIR}/config/${LS2_LIBRARY_NAME}.pc @ONLY)
install (FILES "${PROJECT_BINARY_DIR}/config/${LS2_LIBRARY_NAME}.pc" DESTINATION "lib/pkgconfig")
