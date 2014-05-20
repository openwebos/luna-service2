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
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# LICENSE@@@

set(UNIT_TEST_SOURCES
    test_base
    test_callmap
    test_clock
    test_debug_methods
    test_mainloop
    test_message
    test_subscription
    test_timersource
    test_transport_channel
    test_transport_client
    test_transport_incoming
    test_transport_message
    test_transport_outgoing
    test_transport_security
    test_transport_serial
    test_transport_shm
    test_transport_signal
    test_transport_utils
    test_transport
    test_utils
    )

foreach (TEST ${UNIT_TEST_SOURCES})
    add_executable(${TEST} ${TEST}.c)
    target_link_libraries(${TEST} ${LIBRARIES} ${TESTLIBNAME})
    add_test(${TEST} ${TEST})
endforeach ()

set(INTEGRATION_TEST_SOURCES
    "test_example"
    )

foreach(SOURCES ${INTEGRATION_TEST_SOURCES})
    foreach(SOURCE ${SOURCES})
        add_executable(${SOURCE} ${SOURCE}.c)
        target_link_libraries(${SOURCES} ${PROJECT_NAME} ${TESTLIBNAME})
    endforeach()
    list(GET SOURCES 0 TEST)
    add_test(
        NAME integration.c.${TEST}
        COMMAND ${CMAKE_SOURCE_DIR}/src/libluna-service2/test/run_with_hub
                ${CMAKE_SOURCE_DIR}
                ${CMAKE_BINARY_DIR}
                ${CMAKE_CURRENT_SOURCE_DIR}/${TEST}.conf
            )
endforeach()
