#!/bin/bash -ex
#
# Copyright 2017, Intel Corporation
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#
#     * Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#
# build-capstone.sh - builds capstone
#

cd
git clone https://github.com/aquynh/capstone.git capstone_4_0_aplha5
cd capstone_4_0_aplha5
git checkout 4.0-alpha5
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release \
	-DCAPSTONE_X86_SUPPORT=ON \
	-DCAPSTONE_ARM_SUPPORT=OFF \
	-DCAPSTONE_ARM64_SUPPORT=OFF \
	-DCAPSTONE_M68K_SUPPORT=OFF \
	-DCAPSTONE_MIPS_SUPPORT=OFF \
	-DCAPSTONE_PPC_SUPPORT=OFF \
	-DCAPSTONE_SPARC_SUPPORT=OFF \
	-DCAPSTONE_SYSZ_SUPPORT=OFF \
	-DCAPSTONE_XCORE_SUPPORT=OFF \
	-DCAPSTONE_TMS320C64X_SUPPORT=OFF \
	-DCAPSTONE_BUILD_STATIC=OFF \
	-DCAPSTONE_BUILD_STATIC_RUNTIME=OFF \
	-DCAPSTONE_BUILD_TESTS=OFF \
	-DCAPSTONE_BUILD_DIET=ON \
	..
make

# This branch in capstone does not install a package config file, but it is easy
# to mock one that works for a specific version of capstone.
echo Name: capstone > capstone.pc
echo Description: Capstone disassembly engine >> capstone.pc
echo Version: 4.0-alpha5 >> capstone.pc
echo libdir=$PWD >> capstone.pc
echo includedir=$PWD/../include/capstone >> capstone.pc
echo archive=\${libdir}/libcapstone.a >> capstone.pc
echo Libs: -L\${libdir} -lcapstone >> capstone.pc
echo Cflags: -I\${includedir} >> capstone.pc

cd
