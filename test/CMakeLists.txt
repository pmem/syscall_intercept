#
# Copyright 2017-2020, Intel Corporation
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

if(EXPECT_SPURIOUS_SYSCALLS)
	add_definitions(-DEXPECT_SPURIOUS_SYSCALLS)
endif()

find_package(Threads)

include_directories(${PROJECT_SOURCE_DIR}/src ${PROJECT_SOURCE_DIR}/test)

set(CMAKE_ASM_CREATE_SHARED_LIBRARY ${CMAKE_C_CREATE_SHARED_LIBRARY})

add_executable(asm_pattern asm_pattern.c
		$<TARGET_OBJECTS:syscall_intercept_base_c>
		$<TARGET_OBJECTS:syscall_intercept_base_asm>)

target_link_libraries(asm_pattern
	PRIVATE ${CMAKE_DL_LIBS} ${capstone_LDFLAGS})

set(asm_patterns
	nosyscall
	pattern1
	pattern2
	pattern3
	pattern4
	pattern_loop
	pattern_loop2
	pattern_symbol_boundary0
	pattern_symbol_boundary1
	pattern_symbol_boundary2
	pattern_symbol_boundary3
	pattern_nop_padding0
	pattern_nop_padding1
	pattern_nop_padding2
	pattern_nop_padding3
	pattern_nop_padding4
	pattern_nop_padding5
	pattern_nop_padding6
	pattern_nop_padding7
	pattern_nop_padding8
	pattern_nop_padding9
	pattern_lea_rip_rdi
	pattern_lea_rip_r12)

try_compile(ASSEMBLER_SUPPORTS_ENDBR64 ${CMAKE_BINARY_DIR}
		${CMAKE_CURRENT_SOURCE_DIR}/pattern_endbr64.in.S
		CMAKE_FLAGS "-DCMAKE_ASM_LINK_EXECUTABLE='echo skip linking'")
if(ASSEMBLER_SUPPORTS_ENDBR64)
	list(APPEND asm_patterns pattern_endbr64)
endif()

set(asm_patterns_failing
	pattern_double_syscall
	pattern_rets
	pattern_jmps)

macro(add_asm_test test_name failing)
	add_library(${test_name}.in SHARED ${test_name}.in.S)
	add_library(${test_name}.out SHARED ${test_name}.out.S)
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
	-DEXPECT_SPURIOUS_SYSCALLS=${EXPECT_SPURIOUS_SYSCALLS}
	-P ${CMAKE_CURRENT_SOURCE_DIR}/check_log.cmake)

add_executable(fork_logging fork_logging.c)
add_test(NAME "fork_logging"
	COMMAND ${CMAKE_COMMAND}
	-DTEST_EXTRA_PRELOAD=${TEST_EXTRA_PRELOAD}
	-DTEST_NAME=logging
	-DLIB_FILE=$<TARGET_FILE:syscall_intercept_shared>
	-DTEST_PROG=$<TARGET_FILE:fork_logging>
	-DTEST_PROG_ARG=${CMAKE_CURRENT_SOURCE_DIR}/fork_logging.c
	-DHAS_SECOND_LOG=1
	-DMATCH_FILE=${CMAKE_CURRENT_SOURCE_DIR}/libcintercept0.log.match
	-DSECOND_MATCH_FILE=${CMAKE_CURRENT_SOURCE_DIR}/libcintercept0_child.log.match
	${CHECK_LOG_COMMON_ARGS})

add_library(hook_test_preload_o OBJECT hook_test_preload.c)

add_executable(hook_test hook_test.c)

add_library(hook_test_preload_with_shared SHARED
	$<TARGET_OBJECTS:hook_test_preload_o>)
target_link_libraries(hook_test_preload_with_shared PRIVATE syscall_intercept_shared)
add_test(NAME "hook_with_shared"
	COMMAND ${CMAKE_COMMAND}
	-DTEST_EXTRA_PRELOAD=${TEST_EXTRA_PRELOAD}
	-DTEST_NAME=hook
	-DLIB_FILE=$<TARGET_FILE:hook_test_preload_with_shared>
	-DTEST_PROG=$<TARGET_FILE:hook_test>
	-DTEST_PROG_ARG=None
	-DMATCH_FILE=${CMAKE_CURRENT_SOURCE_DIR}/libcintercept1.log.match
	${CHECK_LOG_COMMON_ARGS})

add_library(hook_test_preload_with_static SHARED
	$<TARGET_OBJECTS:hook_test_preload_o>)
target_link_libraries(hook_test_preload_with_static PRIVATE syscall_intercept_static)
add_test(NAME "hook_with_static"
	COMMAND ${CMAKE_COMMAND}
	-DTEST_EXTRA_PRELOAD=${TEST_EXTRA_PRELOAD}
	-DTEST_NAME=hook
	-DLIB_FILE=$<TARGET_FILE:hook_test_preload_with_static>
	-DTEST_PROG=$<TARGET_FILE:hook_test>
	-DTEST_PROG_ARG=None
	-DMATCH_FILE=${CMAKE_CURRENT_SOURCE_DIR}/libcintercept1.log.match
	${CHECK_LOG_COMMON_ARGS})


add_library(hook_test_clone_preload SHARED hook_test_clone_preload.c)
target_link_libraries(hook_test_clone_preload PRIVATE syscall_intercept_shared)
add_test(NAME "hook_clone"
	COMMAND ${CMAKE_COMMAND}
	-DTEST_EXTRA_PRELOAD=${TEST_EXTRA_PRELOAD}
	-DTEST_NAME=hook_clone
	-DLIB_FILE=$<TARGET_FILE:hook_test_clone_preload>
	-DTEST_PROG=$<TARGET_FILE:fork_logging>
	-DTEST_PROG_ARG=${CMAKE_CURRENT_SOURCE_DIR}/fork_logging.c
	-DMATCH_FILE=${CMAKE_CURRENT_SOURCE_DIR}/libcintercept0.log.match
	-DHAS_SECOND_LOG=1
	-DSECOND_MATCH_FILE=${CMAKE_CURRENT_SOURCE_DIR}/libcintercept0_child.log.match
	${CHECK_LOG_COMMON_ARGS})

add_executable(filter_test filter_test.c)
target_link_libraries(filter_test PRIVATE syscall_intercept_shared)

add_test(NAME "filter_none"
	COMMAND ${CMAKE_COMMAND}
	-DTEST_EXTRA_PRELOAD=${TEST_EXTRA_PRELOAD}
	-DTEST_PROG=$<TARGET_FILE:filter_test>
	-P ${CMAKE_CURRENT_SOURCE_DIR}/check.cmake)
set_tests_properties("filter_none"
	PROPERTIES PASS_REGULAR_EXPRESSION "hooked - allowed")

add_test(NAME "filter_positive"
	COMMAND ${CMAKE_COMMAND}
	-DTEST_EXTRA_PRELOAD=${TEST_EXTRA_PRELOAD}
	-DFILTER=$<TARGET_FILE_NAME:filter_test>
	-DTEST_PROG=$<TARGET_FILE:filter_test>
	-P ${CMAKE_CURRENT_SOURCE_DIR}/check.cmake)
set_tests_properties("filter_positive"
	PROPERTIES PASS_REGULAR_EXPRESSION "hooked - allowed")

add_test(NAME "filter_negative"
	COMMAND ${CMAKE_COMMAND}
	-DTEST_EXTRA_PRELOAD=${TEST_EXTRA_PRELOAD}
	-DFILTER=non_matching_filter
	-DTEST_PROG=$<TARGET_FILE:filter_test>
	-P ${CMAKE_CURRENT_SOURCE_DIR}/check.cmake)
set_tests_properties("filter_negative"
	PROPERTIES PASS_REGULAR_EXPRESSION "disallowed")

# the filter is a substring of the executable name
add_test(NAME "filter_negative_substring0"
	COMMAND ${CMAKE_COMMAND}
	-DTEST_EXTRA_PRELOAD=${TEST_EXTRA_PRELOAD}
	-DFILTER_PLUS_ONECHAR=$<TARGET_FILE_NAME:filter_test>
	-DTEST_PROG=$<TARGET_FILE:filter_test>
	-P ${CMAKE_CURRENT_SOURCE_DIR}/check.cmake)
set_tests_properties("filter_negative_substring0"
	PROPERTIES PASS_REGULAR_EXPRESSION "disallowed")

# the executable name is a substring of the filter
add_test(NAME "filter_negative_substring1"
	COMMAND ${CMAKE_COMMAND}
	-DTEST_EXTRA_PRELOAD=${TEST_EXTRA_PRELOAD}
	-DFILTER=A$<TARGET_FILE_NAME:filter_test>
	-DTEST_PROG=$<TARGET_FILE:filter_test>
	-P ${CMAKE_CURRENT_SOURCE_DIR}/check.cmake)
set_tests_properties("filter_negative_substring1"
	PROPERTIES PASS_REGULAR_EXPRESSION "disallowed")

add_executable(test_clone_thread test_clone_thread.c)
target_link_libraries(test_clone_thread PRIVATE ${CMAKE_THREAD_LIBS_INIT})
add_library(test_clone_thread_preload SHARED test_clone_thread_preload.c)
target_link_libraries(test_clone_thread_preload PRIVATE syscall_intercept_shared)
add_test(NAME "clone_thread"
	COMMAND ${CMAKE_COMMAND}
	-DTEST_EXTRA_PRELOAD=${TEST_EXTRA_PRELOAD}
	-DFILTER=${test_clone_thread_filename}
	-DTEST_PROG=$<TARGET_FILE:test_clone_thread>
	-DLIB_FILE=$<TARGET_FILE:test_clone_thread_preload>
	-P ${CMAKE_CURRENT_SOURCE_DIR}/check.cmake)
set_tests_properties("clone_thread"
	PROPERTIES PASS_REGULAR_EXPRESSION "clone_hook_child called")

add_library(intercept_sys_write SHARED intercept_sys_write.c)
target_link_libraries(intercept_sys_write PRIVATE syscall_intercept_shared)

add_executable(executable_with_syscall_pie executable_with_syscall.S)
if(HAS_NOUNUSEDARG)
	target_compile_options(executable_with_syscall_pie BEFORE
		PRIVATE "-Wno-unused-command-line-argument")
endif()
set_target_properties(executable_with_syscall_pie
			PROPERTIES POSITION_INDEPENDENT_CODE True)
if(HAS_ARG_PIE)
	target_compile_options(executable_with_syscall_pie PRIVATE "-pie")
	target_link_libraries(executable_with_syscall_pie PRIVATE "-pie")
endif()

add_executable(executable_with_syscall_no_pie executable_with_syscall.S)
if(HAS_NOUNUSEDARG)
	target_compile_options(executable_with_syscall_no_pie BEFORE
		PRIVATE "-Wno-unused-command-line-argument")
endif()
set_target_properties(executable_with_syscall_no_pie
			PROPERTIES POSITION_INDEPENDENT_CODE False)
if(HAS_ARG_NOPIE)
	target_compile_options(executable_with_syscall_no_pie PRIVATE "-nopie")
	target_link_libraries(executable_with_syscall_no_pie PRIVATE "-nopie")
elseif(HAS_ARG_NO_PIE)
	target_compile_options(executable_with_syscall_no_pie PRIVATE "-no-pie")
	target_link_libraries(executable_with_syscall_no_pie PRIVATE "-no-pie")
endif()

add_test(NAME "prog_pie_intercept_libc_only"
	COMMAND ${CMAKE_COMMAND}
	-DTEST_EXTRA_PRELOAD=${TEST_EXTRA_PRELOAD}
	-DTEST_PROG=$<TARGET_FILE:executable_with_syscall_pie>
	-DLIB_FILE=$<TARGET_FILE:intercept_sys_write>
	-DTEST_PROG_ARGS=original_syscall
	-P ${CMAKE_CURRENT_SOURCE_DIR}/check.cmake)
set_tests_properties("prog_pie_intercept_libc_only"
	PROPERTIES PASS_REGULAR_EXPRESSION "original_syscall")

add_test(NAME "prog_no_pie_intercept_libc_only"
	COMMAND ${CMAKE_COMMAND}
	-DTEST_EXTRA_PRELOAD=${TEST_EXTRA_PRELOAD}
	-DTEST_PROG=$<TARGET_FILE:executable_with_syscall_no_pie>
	-DLIB_FILE=$<TARGET_FILE:intercept_sys_write>
	-DTEST_PROG_ARGS=original_syscall
	-P ${CMAKE_CURRENT_SOURCE_DIR}/check.cmake)
set_tests_properties("prog_no_pie_intercept_libc_only"
	PROPERTIES PASS_REGULAR_EXPRESSION "original_syscall")

add_test(NAME "prog_pie_intercept_all"
	COMMAND ${CMAKE_COMMAND}
	-DTEST_EXTRA_PRELOAD=${TEST_EXTRA_PRELOAD}
	-DINTERCEPT_ALL=1
	-DTEST_PROG=$<TARGET_FILE:executable_with_syscall_pie>
	-DLIB_FILE=$<TARGET_FILE:intercept_sys_write>
	-DTEST_PROG_ARGS=original_syscall
	-P ${CMAKE_CURRENT_SOURCE_DIR}/check.cmake)
set_tests_properties("prog_pie_intercept_all"
	PROPERTIES PASS_REGULAR_EXPRESSION "intercepted_call")

add_test(NAME "prog_no_pie_intercept_all"
	COMMAND ${CMAKE_COMMAND}
	-DTEST_EXTRA_PRELOAD=${TEST_EXTRA_PRELOAD}
	-DINTERCEPT_ALL=1
	-DTEST_PROG=$<TARGET_FILE:executable_with_syscall_no_pie>
	-DLIB_FILE=$<TARGET_FILE:intercept_sys_write>
	-DTEST_PROG_ARGS=original_syscall
	-P ${CMAKE_CURRENT_SOURCE_DIR}/check.cmake)
set_tests_properties("prog_no_pie_intercept_all"
	PROPERTIES PASS_REGULAR_EXPRESSION "intercepted_call")

add_executable(vfork_logging vfork_logging.c)
add_test(NAME "vfork_logging"
	COMMAND ${CMAKE_COMMAND}
	-DTEST_EXTRA_PRELOAD=${TEST_EXTRA_PRELOAD}
	-DTEST_PROG=$<TARGET_FILE:vfork_logging>
	-DLIB_FILE=$<TARGET_FILE:syscall_intercept_shared>
	-DMATCH_FILE=${CMAKE_CURRENT_SOURCE_DIR}/libcintercept2.log.match
	-DTEST_NAME=vfork_logging
	${CHECK_LOG_COMMON_ARGS})
set_tests_properties("vfork_logging"
	PROPERTIES PASS_REGULAR_EXPRESSION "in_child_created_using_vfork")


add_executable(syscall_format syscall_format.c)
target_link_libraries(syscall_format PRIVATE syscall_intercept_shared)
add_test(NAME "syscall_format_logging"
	COMMAND ${CMAKE_COMMAND}
	-DTEST_EXTRA_PRELOAD=${TEST_EXTRA_PRELOAD}
	-DTEST_PROG=$<TARGET_FILE:syscall_format>
	-DLIB_FILE=
	-DMATCH_FILE=${CMAKE_CURRENT_SOURCE_DIR}/syscall_format.log.match
	-DTEST_NAME=syscall_format_logging
	${CHECK_LOG_COMMON_ARGS})
