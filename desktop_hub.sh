#!/bin/sh
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

BUILD_DIR="./build-x86"
BUILD_BIN_DIR="${BUILD_DIR}/usr/bin"
BUILD_SBIN_DIR="${BUILD_DIR}/usr/sbin"
BUILD_LIB_DIR="${BUILD_DIR}/usr/lib"

DESKTOP_BINARIES=/opt/Palm/luna/desktop-binaries/
export LD_LIBRARY_PATH=${BUILD_LIB_DIR}:${DESKTOP_BINARIES}/lib:${LD_LIBRARY_PATH}
#export PATH=./bin:${PATH}

HUB="${BUILD_SBIN_DIR}/ls-hubd"

PUB_CONF=${BUILD_DIR}/etc/ls2/ls-public.conf
PRV_CONF=${BUILD_DIR}/etc/ls2/ls-private.conf

# Start a desktop version of the hub
start_private() {
    ARGS="-i /var/palm/run -c ${PRV_CONF}"
    if [ "x${1}" = "xdebug" ]; then
        CMD="gdb --args ${HUB} ${ARGS}"
    else
        CMD="${HUB} ${ARGS} &"
    fi

    ${CMD}
}

start_public() {
    ARGS="-i /var/palm/run -c ${PUB_CONF} -p"
    if [ "x${1}" = "xdebug" ]; then
        CMD="gdb --args ${HUB} ${ARGS}"
    else
        CMD="${HUB} ${ARGS} &"
    fi

    ${CMD}
}

stop_all() {
#    killall ls-hubd
    for i in $LS_PID
    do
        echo "Killing process $i"
        kill $i
    done
}

usage() {
    echo "Start or stop a local hub"
    echo "Options:"
    echo "  help            Show this help message"
    echo ""
    echo "Commands:"
    echo "  start_public          Start public hub"
    echo "  start_public_debug    Start public hub under gdb"
    echo "  start_private         Start private hub"
    echo "  start_private_debug   Start private hub under gdb"
    echo "  start                 Start both public and private"
    echo "  stop                  Stop all running instances of hub"
}

LS_PID=`ps auwx | grep ${HUB} | grep -v grep | tr -s [:space:] | cut -f2 -d' '`

case "$1" in
start_public*)
    if [ "x${1}" = "xstart_public_debug" ]
    then
        start_public debug
    else
        start_public
    fi
    ;;
start_private*)
    if [ "x${1}" = "xstart_private_debug" ]
    then
        start_private debug
    else
        start_private
    fi
    ;;
start)
    start_public
    start_private
    ;;
stop)
    stop_all
    ;;
*)
    usage
    ;;
esac
