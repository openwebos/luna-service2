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
    test_pattern
    test_security
    test_directories_scan
    )

add_definitions(-DTEST_STEADY_ROLES_DIRECTORY="${CMAKE_CURRENT_SOURCE_DIR}/steady/roles")
add_definitions(-DTEST_VOLATILE_ROLES_DIRECTORY="${CMAKE_CURRENT_SOURCE_DIR}/volatile/roles")
add_definitions(-DTEST_STEADY_SERVICES_DIRECTORY="${CMAKE_CURRENT_SOURCE_DIR}/steady/services")
add_definitions(-DTEST_VOLATILE_SERVICES_DIRECTORY="${CMAKE_CURRENT_SOURCE_DIR}/volatile/services")
add_definitions(-DUNIT_TESTS)

foreach (TEST ${UNIT_TEST_SOURCES})
    add_executable(${TEST} ${TEST}.c ../hub.c ../security.c)
    target_link_libraries(${TEST} ls-hublib ${CMAKE_PROJECT_NAME} ${TESTLIBNAME} ${PMLOGLIB_LDFLAGS})
    add_test(${TEST} ${TEST})
endforeach ()
