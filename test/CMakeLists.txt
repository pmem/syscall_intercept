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

include_directories(${PROJECT_SOURCE_DIR}/src ${PROJECT_SOURCE_DIR}/test)

set(CMAKE_ASM_CREATE_SHARED_LIBRARY ${CMAKE_C_CREATE_SHARED_LIBRARY})

set(CHECK_LOG_COMMON_ARGS
	-DMATCH_SCRIPT=${PROJECT_SOURCE_DIR}/utils/match.pl
	-P ${CMAKE_CURRENT_SOURCE_DIR}/check_log.cmake)


add_executable(logging_test logging_test.c)
add_test(NAME "logging"
	COMMAND ${CMAKE_COMMAND}
	-DLIB_FILE=$<TARGET_FILE:syscall_intercept_shared>
	-DTEST_PROG=$<TARGET_FILE:logging_test>
	-DTEST_PROG_ARG=${CMAKE_CURRENT_SOURCE_DIR}/logging_test.c
	-DMATCH_FILE=${CMAKE_CURRENT_SOURCE_DIR}/libcintercept0.log.match
	${CHECK_LOG_COMMON_ARGS})

add_executable(hook_test hook_test.c)
add_library(hook_test_preload SHARED hook_test_preload.c)
target_link_libraries(hook_test_preload syscall_intercept_shared)
add_test(NAME "hook"
	COMMAND ${CMAKE_COMMAND}
	-DLIB_FILE=$<TARGET_FILE:hook_test_preload>
	-DTEST_PROG=$<TARGET_FILE:hook_test>
	-DTEST_PROG_ARG=None
	-DMATCH_FILE=${CMAKE_CURRENT_SOURCE_DIR}/libcintercept1.log.match
	${CHECK_LOG_COMMON_ARGS})


add_executable(asm_pattern asm_pattern.c)
target_link_libraries(asm_pattern
	${CMAKE_DL_LIBS} ${capstone_LDFLAGS} syscall_intercept_base)

set(asm_patterns
	nosyscall
	pattern1
	pattern2
	pattern_loop
	pattern_loop2
	pattern_symbol_boundary0
	pattern_symbol_boundary1
	pattern_symbol_boundary2
	pattern_nop_padding0
	pattern_nop_padding1
	pattern_nop_padding2)

foreach(name ${asm_patterns})
	add_library(${name}.in SHARED ${name}.in.s)
	add_library(${name}.out SHARED ${name}.out.s)
	if(HAS_NOSTDLIB)
		set_target_properties(${name}.in
			PROPERTIES LINK_FLAGS "-nostdlib")
		set_target_properties(${name}.out
			PROPERTIES LINK_FLAGS "-nostdlib")
	endif()
	add_test(NAME "asm_pattern_${name}"
		COMMAND $<TARGET_FILE:asm_pattern>
		$<TARGET_FILE:${name}.in>
		$<TARGET_FILE:${name}.out>)
endforeach()
