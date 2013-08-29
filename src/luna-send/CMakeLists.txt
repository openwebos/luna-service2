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
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# LICENSE@@@

add_executable(luna-send luna-send.c)
target_link_libraries(luna-send ${CMAKE_PROJECT_NAME})
webos_build_program(NAME luna-send ${LS2_RESTRICTED})

add_executable(luna-send-pub luna-send.c)
target_link_libraries(luna-send-pub ${CMAKE_PROJECT_NAME})
set_target_properties(luna-send-pub PROPERTIES COMPILE_DEFINITIONS "PUBLIC_HUB_ONLY")
webos_build_program(NAME luna-send-pub)
