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

# See: https://cmake.org/Wiki/CMake/Testing_With_CTest

add_executable(logging_test logging_test.c)
add_executable(asm_pattern asm_pattern.c)

target_link_libraries(asm_pattern
	${CMAKE_DL_LIBS} capstone syscall_intercept_base)
set_property(TARGET asm_pattern
	APPEND PROPERTY INCLUDE_DIRECTORIES ${PROJECT_SOURCE_DIR}/src)

set(CMAKE_ASM_CREATE_SHARED_LIBRARY ${CMAKE_C_CREATE_SHARED_LIBRARY})

add_library(pattern0.in SHARED pattern0.in.s)
add_library(pattern0.out SHARED pattern0.out.s)
add_library(pattern1.in SHARED pattern1.in.s)
add_library(pattern1.out SHARED pattern1.out.s)

set(CHECK_LOG_COMMON_ARGS
	-DLIB_FILE=$<TARGET_FILE:syscall_intercept_shared>
	-DMATCH_SCRIPT=${PROJECT_SOURCE_DIR}/utils/match.pl
	-P ${CMAKE_CURRENT_SOURCE_DIR}/check_log.cmake)

add_test(NAME "logging_test"
	COMMAND ${CMAKE_COMMAND}
	-DTEST_PROG=$<TARGET_FILE:logging_test>
	-DTEST_PROG_ARG=${CMAKE_CURRENT_SOURCE_DIR}/logging_test.c
	-DMATCH_FILE=${CMAKE_CURRENT_SOURCE_DIR}/libcintercept0.log.match
	${CHECK_LOG_COMMON_ARGS})

add_test(NAME "asm_pattern0"
	COMMAND $<TARGET_FILE:asm_pattern>
	$<TARGET_FILE:pattern0.in>
	$<TARGET_FILE:pattern0.out>)

add_test(NAME "asm_pattern1"
	COMMAND $<TARGET_FILE:asm_pattern>
	$<TARGET_FILE:pattern1.in>
	$<TARGET_FILE:pattern1.out>)
