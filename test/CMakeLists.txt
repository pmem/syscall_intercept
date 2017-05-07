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

find_package(Threads)

include_directories(${PROJECT_SOURCE_DIR}/src ${PROJECT_SOURCE_DIR}/test)

set(CMAKE_ASM_CREATE_SHARED_LIBRARY ${CMAKE_C_CREATE_SHARED_LIBRARY})

add_executable(asm_pattern asm_pattern.c)
target_link_libraries(asm_pattern
	${CMAKE_DL_LIBS} ${capstone_LDFLAGS}
	syscall_intercept_base_c syscall_intercept_base_asm)

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
	pattern_nop_padding2
	pattern_nop_padding3
	pattern_nop_padding4
	pattern_nop_padding5
	pattern_nop_padding6
	pattern_nop_padding7
	pattern_nop_padding8
	pattern_nop_padding9)

set(asm_patterns_failing
	pattern_double_syscall
	pattern_rets
	pattern_jmps)

macro(add_asm_test test_name failing)
	add_library(${test_name}.in SHARED ${test_name}.in.s)
	add_library(${test_name}.out SHARED ${test_name}.out.s)
	if(LINKER_HAS_NOSTDLIB)
		set_target_properties(${test_name}.in
			PROPERTIES LINK_FLAGS "-nostdlib")
		set_target_properties(${test_name}.out
			PROPERTIES LINK_FLAGS "-nostdlib")
	endif()
	if(HAS_NOUNUSEDARG)
		target_compile_options(${test_name}.in BEFORE
			PRIVATE "-Wno-unused-command-line-argument")
		target_compile_options(${test_name}.out BEFORE
			PRIVATE "-Wno-unused-command-line-argument")

	endif()
	add_test(NAME "asm_pattern_${test_name}"
		COMMAND $<TARGET_FILE:asm_pattern>
		$<TARGET_FILE:${test_name}.in>
		$<TARGET_FILE:${test_name}.out>)
	if(${failing})
		set_tests_properties("asm_pattern_${test_name}"
			PROPERTIES WILL_FAIL ON
			PASS_REGULAR_EXPRESSION "Invalid patch")
	endif()
endmacro()

foreach(name ${asm_patterns})
	add_asm_test(${name} FALSE)
endforeach()

foreach(name ${asm_patterns_failing})
	add_asm_test(${name} TRUE)
endforeach()

set(CHECK_LOG_COMMON_ARGS
	-DMATCH_SCRIPT=${PROJECT_SOURCE_DIR}/utils/match.pl
	-P ${CMAKE_CURRENT_SOURCE_DIR}/check_log.cmake)


add_executable(logging_test logging_test.c)
add_test(NAME "logging"
	COMMAND ${CMAKE_COMMAND}
	-DTEST_NAME=logging
	-DLIB_FILE=$<TARGET_FILE:syscall_intercept_shared>
	-DTEST_PROG=$<TARGET_FILE:logging_test>
	-DTEST_PROG_ARG=${CMAKE_CURRENT_SOURCE_DIR}/logging_test.c
	-DHAS_SECOND_LOG=1
	-DMATCH_FILE=${CMAKE_CURRENT_SOURCE_DIR}/libcintercept0.log.match
	-DSECOND_MATCH_FILE=${CMAKE_CURRENT_SOURCE_DIR}/libcintercept0_child.log.match
	${CHECK_LOG_COMMON_ARGS})

add_executable(hook_test hook_test.c)
add_library(hook_test_preload SHARED hook_test_preload.c)
target_link_libraries(hook_test_preload syscall_intercept_shared)
add_test(NAME "hook"
	COMMAND ${CMAKE_COMMAND}
	-DTEST_NAME=hook
	-DLIB_FILE=$<TARGET_FILE:hook_test_preload>
	-DTEST_PROG=$<TARGET_FILE:hook_test>
	-DTEST_PROG_ARG=None
	-DMATCH_FILE=${CMAKE_CURRENT_SOURCE_DIR}/libcintercept1.log.match
	${CHECK_LOG_COMMON_ARGS})

add_library(hook_test_clone_preload SHARED hook_test_clone_preload.c)
target_link_libraries(hook_test_clone_preload syscall_intercept_shared)
add_test(NAME "hook_clone"
	COMMAND ${CMAKE_COMMAND}
	-DTEST_NAME=hook_clone
	-DLIB_FILE=$<TARGET_FILE:hook_test_clone_preload>
	-DTEST_PROG=$<TARGET_FILE:logging_test>
	-DTEST_PROG_ARG=${CMAKE_CURRENT_SOURCE_DIR}/logging_test.c
	-DMATCH_FILE=${CMAKE_CURRENT_SOURCE_DIR}/libcintercept0.log.match
	-DHAS_SECOND_LOG=1
	-DSECOND_MATCH_FILE=${CMAKE_CURRENT_SOURCE_DIR}/libcintercept0_child.log.match
	${CHECK_LOG_COMMON_ARGS})

add_executable(filter_test filter_test.c)
target_link_libraries(filter_test syscall_intercept_shared)

add_test(NAME "filter_none"
	COMMAND ${CMAKE_COMMAND}
	-DTEST_PROG=$<TARGET_FILE:filter_test>
	-P ${CMAKE_CURRENT_SOURCE_DIR}/check_filter.cmake)
set_tests_properties("filter_none"
	PROPERTIES PASS_REGULAR_EXPRESSION "hooked - allowed")

get_filename_component(filter_test_filename $<TARGET_FILE:filter_test> NAME)

add_test(NAME "filter_positive"
	COMMAND ${CMAKE_COMMAND}
	-DFILTER=${filter_test_filename}
	-DTEST_PROG=$<TARGET_FILE:filter_test>
	-P ${CMAKE_CURRENT_SOURCE_DIR}/check_filter.cmake)
set_tests_properties("filter_positive"
	PROPERTIES PASS_REGULAR_EXPRESSION "hooked - allowed")

add_test(NAME "filter_negative"
	COMMAND ${CMAKE_COMMAND}
	-DFILTER=non_matching_filter
	-DTEST_PROG=$<TARGET_FILE:filter_test>
	-P ${CMAKE_CURRENT_SOURCE_DIR}/check_filter.cmake)
set_tests_properties("filter_negative"
	PROPERTIES PASS_REGULAR_EXPRESSION "disallowed")

add_executable(test_clone_thread test_clone_thread.c)
target_link_libraries(test_clone_thread PRIVATE ${CMAKE_THREAD_LIBS_INIT})
add_library(test_clone_thread_preload SHARED test_clone_thread_preload.c)
target_link_libraries(test_clone_thread_preload PRIVATE syscall_intercept_shared)
add_test(NAME "clone_thread"
	COMMAND ${CMAKE_COMMAND}
	-DFILTER=${test_clone_thread_filename}
	-DTEST_PROG=$<TARGET_FILE:test_clone_thread>
	-DLIB_FILE=$<TARGET_FILE:test_clone_thread_preload>
	-P ${CMAKE_CURRENT_SOURCE_DIR}/check_filter.cmake)
set_tests_properties("clone_thread"
	PROPERTIES PASS_REGULAR_EXPRESSION "clone_hook_child called")
