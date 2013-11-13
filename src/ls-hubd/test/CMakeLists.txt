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
    )

add_definitions(-DTEST_ROLES_DIRECTORY="${CMAKE_CURRENT_SOURCE_DIR}/roles")
add_definitions(-DUNIT_TESTS)

foreach (TEST ${UNIT_TEST_SOURCES})
    add_executable(${TEST} ${TEST}.c)
    target_link_libraries(${TEST} ls-hublib ${CMAKE_PROJECT_NAME} ${TESTLIBNAME})
    add_test(${TEST} ${TEST})
endforeach ()
