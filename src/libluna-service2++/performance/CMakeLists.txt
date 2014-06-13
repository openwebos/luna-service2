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

webos_add_compiler_flags(ALL -Wall "-std=c++11")
add_executable(ls-performance ls-performance.cpp)
target_link_libraries(ls-performance ${PROJECT_NAME})
webos_build_program(NAME ls-performance)
add_custom_target(performance)
add_custom_command(TARGET performance
                    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/../../libluna-service2/test/run_with_hub
                            ${CMAKE_SOURCE_DIR}
                            ${CMAKE_BINARY_DIR}
                            ${CMAKE_CURRENT_SOURCE_DIR}/ls_performance.conf)
