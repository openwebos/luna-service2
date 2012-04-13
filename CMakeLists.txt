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
# luna-service2/CMakeLists.txt
#

cmake_minimum_required(VERSION 2.6)

project(luna-service2)

set(LS2_API_VERSION_MAJOR 3)
set(LS2_API_VERSION_MINOR 0)
set(LS2_API_VERSION_PATCH 0)
set(LS2_LIBRARY_VERSION "${LS2_API_VERSION_MAJOR}.${LS2_API_VERSION_MINOR}.${LS2_API_VERSION_PATCH}")
set(LS2_LIBRARY_NAME "luna-service2")

# Make sure the build system's version of this component matches what we're building.
# The intent is for it to pass in LS2_COMPONENT_VERSION via the command line.
if (DEFINED LS2_COMPONENT_VERSION)
    if (NOT (LS2_LIBRARY_VERSION STREQUAL LS2_COMPONENT_VERSION))
        message(FATAL_ERROR "Component version from build system (${LS2_COMPONENT_VERSION}) != configured version (${LS2_LIBRARY_VERSION})")
    endif ()
endif ()

# XXX Why is CMAKE_BUILD_TYPE empty under Ubuntu?
if (NOT CMAKE_BUILD_TYPE)
    set (CMAKE_BUILD_TYPE "Release")
endif ()

if (NOT DEFINED ENV{PKG_CONFIG_PATH})
    set(ENV{PKG_CONFIG_PATH} "${CMAKE_INSTALL_PREFIX}/lib/pkgconfig")
endif ()

message ("")

message (STATUS "CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")
message (STATUS "CMAKE_FIND_ROOT_PATH: ${CMAKE_FIND_ROOT_PATH}")
message (STATUS "ENV{PKG_CONFIG_PATH}: $ENV{PKG_CONFIG_PATH}")
message (STATUS "CMAKE_INSTALL_PREFIX: ${CMAKE_INSTALL_PREFIX}")

set(DEFAULT_TARGET_CORE_OS "ubuntu" CACHE INTERNAL "The default core OS for which to build")

# Should specify a core OS (ubuntu, rockhopper, etc.)
if (NOT TARGET_CORE_OS)
    set(TARGET_CORE_OS "${DEFAULT_TARGET_CORE_OS}")
    message(STATUS "No TARGET_CORE_OS variable specified - defaulting to ${TARGET_CORE_OS}")
endif()
set(TARGET_CORE_OS ${TARGET_CORE_OS} CACHE STRING "The core OS for which to build")

# XXX ASSERT(TARGET_CORE_OS == rockhopper && CMAKE_SYSTEM_PROCESSOR != arm => TARGET_EMULATOR)
#     Should determine at runtime (using Nyx)
if (TARGET_CORE_OS STREQUAL "ubuntu")
    message(STATUS "Building for desktop")
    set(TARGET_DESKTOP 1)
elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "arm")
    message(STATUS "Building for device")
    set(TARGET_DEVICE 1)
else ()
    message(STATUS "Building for emulator")
    set(TARGET_EMULATOR 1)
endif ()

message ("")


macro(add_flags flags)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${flags}")
endmacro()

macro(add_linker_flags flags)
    # Appending to CMAKE_EXE_LINKER_FLAGS fails to add them to the link command line -- why?
    # Note that using add_definitions() also fails to add to the link command line.
    add_flags("${flags}")
endmacro()


# Search local directories for headers before external ones
# 
# PROJECT_SOURCE_DIR is a cmake provided variable.
# See http://www.cmake.org/cmake/help/cmake2.6docs.html#variable:PROJECT_SOURCE_DIR
# for more info
include_directories("${PROJECT_SOURCE_DIR}/src")
include_directories("${PROJECT_SOURCE_DIR}/include")
include_directories("${PROJECT_SOURCE_DIR}/include/private")


include(FindPkgConfig)

# check if we have glib-2.0
pkg_check_modules(GLIB2 REQUIRED glib-2.0)
pkg_check_modules(GTHREAD2 REQUIRED gthread-2.0)
add_definitions(${GLIB2_CFLAGS})
add_definitions(${GTHREAD2_CFLAGS})

# check if we have cjson
pkg_check_modules(CJSON REQUIRED cjson)
add_definitions(${CJSON_CFLAGS})

# check if we have PmLogLib
pkg_check_modules(PMLOGLIB REQUIRED PmLogLib)
add_definitions(${PMLOGLIB_CFLAGS})

if (TARGET_DEVICE OR TARGET_EMULATOR)
    if (TARGET_DEVICE)
        # Device
        add_definitions(-DTARGET_DEVICE)

        # Only root (owner) will be permitted access to certain binaries on device
        set(RESTRICTED_PERMS PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)
   
        # Custom (faster) memcpy library 
        find_library(MEMCPY_LIBRARIES memcpy)
    else ()
        # Emulator
        add_definitions(-DTARGET_EMULATOR)
    endif ()

    # Install conf files using full path
    set(CONF_INSTALL_PATH "/etc/ls2")

    # Install upstart jobs using full path
    set(UPSTART_INSTALL_PATH "/etc/event.d")

else ()
    # Desktop
    add_definitions(-DTARGET_DESKTOP)

    # Install relative to CMAKE_INSTALL_PREFIX 
    set(CONF_INSTALL_PATH "etc/ls2")
    set(UPSTART_INSTALL_PATH "etc/event.d")
endif ()

# These variables are meant to be used by CMakeLists.txt in subdirectories and
# used to automatically populate fields in test code and scripts
set(LS_PRV_CONF_FILE "${CONF_INSTALL_PATH}/ls-private.conf")
set(LS_PUB_CONF_FILE "${CONF_INSTALL_PATH}/ls-public.conf")


# TODO: Is there a better way than setting all the flags (i.e., built in support)?
if (USE_GCOV)
    message("Building with gcov support")
    
    add_flags("-fprofile-arcs -ftest-coverage")
    add_linker_flags("-lgcov -fprofile-arcs")
endif ()


# Debug definitions
add_definitions(-DMEMCHECK)
add_definitions(-DLSHANDLE_CHECK)


# Specifying this causes "inline function '<function>' declared but never defined" errors.
# add_definitions("-std=c99")

# Turn on all warnings except deprecated declarations and make them into errors
add_definitions("-Wall -Wno-deprecated-declarations -Werror")

# Specify which symbols are to be exported
# TODO: Create this
#add_linker_flags("-Wl,--version-script=${PROJECT_SOURCE_DIR}/src/${LS2_LIBRARY_NAME}Exports.map")

# Require that all undefined symbols are satisfied by the libraries from target_link_libraries()
add_linker_flags("-Wl,--no-undefined")
# XXX_ The libraries that come with gcc fail when --no-allow-shlib-undefined is specified
#add_linker_flags("-Wl,--no-allow-shlib-undefined")


add_subdirectory(src) 
add_subdirectory(src/hub) 
add_subdirectory(src/monitor) 
add_subdirectory(utils)
add_subdirectory(upstart)
add_subdirectory(conf)


# This adds a target called "docs" (i.e., make docs). doxygen and dot
# (from graphviz) are expected to be available.
# ${PROJECT_BINARY_DIR} is the build directory and ${PROJECT_SOURCE_DIR}
# is the source directory.
configure_file(${PROJECT_SOURCE_DIR}/doc/Doxyfile.in
                ${PROJECT_BINARY_DIR}/doc/Doxyfile)

add_custom_target(docs 
                        doxygen ${PROJECT_BINARY_DIR}/doc/Doxyfile
                        SOURCES ${PROJECT_SOURCE_DIR}/doc/Doxyfile.in
                        WORKING_DIRECTORY ${PROJECT_BINARY_DIR}/doc)
