# @@@LICENSE
#
#      Copyright (c) 2014 LG Electronics, Inc.
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

webos_add_compiler_flags(ALL -Wall "-std=gnu++0x")

webos_use_gtest()

set(UNIT_TEST_SOURCES
    test_error
    )

foreach(TEST ${UNIT_TEST_SOURCES})
    add_executable(${TEST} ${TEST}.cpp)
    target_link_libraries(${TEST} ${LIBRARIES} ${TESTLIBNAME} ${WEBOS_GTEST_LIBRARIES})
    add_test(${TEST} ${TEST})
endforeach()

set(INTEGRATION_TEST_SOURCES
    test_client
    )

foreach(TEST ${INTEGRATION_TEST_SOURCES})
    add_executable(${TEST} ${TEST}.cpp)
    target_link_libraries(${TEST} ${LIBRARIES} ${TESTLIBNAME} ${WEBOS_GTEST_LIBRARIES})
    add_test(
        NAME integration.${TEST}
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/../run_with_hub
                ${CMAKE_BINARY_DIR}
                ${CMAKE_CURRENT_BINARY_DIR}/${TEST}
             )
endforeach()
