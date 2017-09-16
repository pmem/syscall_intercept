#!/bin/bash -ex
#
# Copyright 2016-2017, Intel Corporation
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
# run-build.sh - is called inside a Docker container;
#		starts a build of the project
#

# Which capstone to use?
# One can verify this by looking at ldd output in build logs
if [ -n "$CAPSTONE_EXPERIMENTAL" ]; then
	export PKG_CONFIG_LIBDIR=~/capstone_4_0_aplha5/build
fi

# Build all and run tests
cd $WORKDIR
if [ -n "$C_COMPILER" ]; then
	export CC=$C_COMPILER
fi
if [ -n "$CPP_COMPILER" ]; then
	export CXX=$CPP_COMPILER
fi


mkdir build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/tmp/${PROJECT} \
		-DCMAKE_BUILD_TYPE=Debug \

make -j2
ldd ./libsyscall_intercept.so
ctest --output-on-failure -j2
make install
cd ..
rm -r build

mkdir build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/tmp/${PROJECT} \
		-DCMAKE_BUILD_TYPE=Release \

make -j2
ldd ./libsyscall_intercept.so
ctest --output-on-failure -j2
make install
cd ..
rm -r build
