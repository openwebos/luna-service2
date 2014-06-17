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

webos_use_gtest()

# check for pbnjson cxx library
pkg_check_modules(PBNJSON_CXX REQUIRED pbnjson_cpp>=2.5.0)
include_directories(${PBNJSON_CXX_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${PBNJSON_CXX_CFLAGS_OTHER})

set(UNIT_TEST_SOURCES
    test_error
    test_jsonpayload
    )

foreach(TEST ${UNIT_TEST_SOURCES})
    add_executable(${TEST} ${TEST}.cpp)
    target_link_libraries(${TEST} ${PROJECT_NAME} ${TESTLIBNAME} ${WEBOS_GTEST_LIBRARIES} ${PBNJSON_CXX_LIBRARIES})
    add_test(${TEST} ${TEST})
endforeach()

set(INTEGRATION_TEST_SOURCES
    "bhv-3965-crash\;bhv-3965-crash-svc"
    test_client
    test_service
    test_category
    "test_call\;test_call_service"
    test_subscription_cxx
    test_disconnection
    category_notification
    "test_example++"
    metainfo_example
    )

add_library(util STATIC util.cpp)

foreach(SOURCES ${INTEGRATION_TEST_SOURCES})
    foreach(SOURCE ${SOURCES})
        add_executable(${SOURCE} ${SOURCE}.cpp)
        target_link_libraries(${SOURCE} ${PROJECT_NAME} util ${TESTLIBNAME} ${WEBOS_GTEST_LIBRARIES} ${PBNJSON_CXX_LIBRARIES})
    endforeach()
    list(GET SOURCES 0 TEST)
    add_test(
        NAME integration.c++.${TEST}
        COMMAND ${CMAKE_SOURCE_DIR}/src/libluna-service2/test/run_with_hub
                ${CMAKE_SOURCE_DIR}
                ${CMAKE_BINARY_DIR}
                ${CMAKE_CURRENT_SOURCE_DIR}/${TEST}.conf
             )
endforeach()
