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
# Dockerfile - a 'recipe' for Docker to build an image of ubuntu-based
#              environment for building syscall_intercept
#

# Pull base image
FROM ubuntu:16.04
MAINTAINER gabor.buella@intel.com

# Update the Apt cache and install basic tools
RUN apt-get update
RUN apt-get install -y \
	autoconf \
	automake \
	clang \
	curl \
	cmake \
	debhelper \
	devscripts \
	doxygen \
	git \
	libcap-dev \
	libcapstone-dev \
	libunwind-dev \
	pandoc \
	libtext-diff-perl \
	pkg-config \
	debhelper \
	devscripts \
	ruby \
	sudo \
	sqlite3 \
	tcl-dev \
	wget \
	whois

# Add user
ENV USER user
ENV USERPASS pass
RUN useradd -m $USER -g sudo -p `mkpasswd $USERPASS`

# Install nvml
COPY install-nvml.sh install-nvml.sh
RUN ./install-nvml.sh dpkg

USER $USER

# Build pmemfile
COPY libsyscall_intercept_hook_point.h libsyscall_intercept_hook_point.h
COPY build-pmemfile.sh build-pmemfile.sh
RUN ./build-pmemfile.sh

# Build capstone - experimental version
COPY build-capstone.sh build-capstone.sh
RUN ./build-capstone.sh

# Set required environment variables
ENV OS ubuntu
ENV OS_VER 16.04
ENV PACKAGE_MANAGER deb
ENV NOTTY 1
