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
# build-pmemfile.sh - builds libpmemfile
#

# libpmemfile needs syscall_intercept to build, so create a mock library
# that looks like libsyscall_intercept (as long as it is used for linking
# with, not for executing).
mkdir -p ~/mock_syscall_intercept
cp libsyscall_intercept_hook_point.h ~/mock_syscall_intercept/.

cd
cd mock_syscall_intercept

echo int intercept_hook_point\; > mock_syscall_intercept.c
echo int intercept_hook_point_clone_child\; >> mock_syscall_intercept.c
echo int syscall_no_intercept\(void\) \{return 0\;\} >> mock_syscall_intercept.c
echo int syscall_hook_in_process_allowed\(void\) \{return 0\;\} >> mock_syscall_intercept.c

gcc -xc -nostdlib -shared mock_syscall_intercept.c -o libsyscall_intercept.so

echo Name: libsyscall_intercept > libsyscall_intercept.pc
echo Version: mock >> libsyscall_intercept.pc
echo Description: Mock libsyscall_intercept >> libsyscall_intercept.pc
echo includedir=$PWD >> libsyscall_intercept.pc
echo Libs: -L$PWD -lsyscall_intercept >> libsyscall_intercept.pc
echo Cflags: -I$PWD >> libsyscall_intercept.pc

# Set some environment variables, allowing cmake to find the mock library
export LD_LIBRARY_PATH=$PWD
export PKG_CONFIG_PATH=$PWD

cd

# Build pmemfile.
# The tests from pmemfile repo are going to be used, so there is no point
# in calling `make install`.
# Trying to make a minimal build here, not needing libpmemfile-posix tests,
# antool tests.
git clone https://github.com/pmem/pmemfile.git
cd pmemfile
git checkout 6d1e91ecdf86263b9ddf0224963b37715f33874d
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo \
	-DBUILD_LIBPMEMFILE=ON \
	-DAUTO_GENERATE_SOURCES=OFF \
	-DTESTS_USE_FORCED_PMEM=ON \
	-DDEVELOPER_MODE=OFF \
	-DFAULT_INJECTION=OFF \
	-DLONG_TESTS=OFF \
	-DTRACE_TESTS=ON \
	-DUSE_ASAN=OFF \
	-DUSE_UBSAN=OFF \
	-DANTOOL_TESTS=SKIP \
	-DBUILD_LIBPMEMFILE_POSIX_TESTS=OFF \
	-DBUILD_LIBPMEMFILE_TESTS=ON \
	..
make
cd
rm -rf mock_syscall_intercept
