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

cmake_minimum_required(VERSION 2.8.7)
project(syscall_intercept C CXX ASM)

include(FindPerl)

set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)
# Setting CMAKE_DISABLE_IN_SOURCE_BUILD to ON should
# disallow in source builds, but in practice it doesn't seem
# to disallow it. Check the paths as well:
if(",${CMAKE_SOURCE_DIR}," STREQUAL ",${CMAKE_BINARY_DIR},")
	message(FATAL_ERROR "In-source builds are not supported.")
endif()

option(DEVELOPER_MODE "enable developer checks" OFF)

set(SYSCALL_INTERCEPT_VERSION_MAJOR 0)
set(SYSCALL_INTERCEPT_VERSION_MINOR 1)
set(SYSCALL_INTERCEPT_VERSION_PATCH 0)
set(SYSCALL_INTERCEPT_VERSION
	${SYSCALL_INTERCEPT_VERSION_MAJOR}.${SYSCALL_INTERCEPT_VERSION_MINOR}.${SYSCALL_INTERCEPT_VERSION_PATCH})

include(GNUInstallDirs)
include(cmake/toolchain_features.cmake)
include(cmake/find_capstone.cmake)

# main source files - intentionally excluding src/entry.c
set(SOURCES_C
	src/disasm_wrapper.c
	src/intercept.c
	src/intercept_desc.c
	src/intercept_util.c
	src/patcher.c
	src/magic_syscalls.c)

set(SOURCES_ASM
	src/intercept_template.s
	src/util.s)


include_directories(include)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Main object files of the library, the entry point in entry.c
# is only built into the final libraries. This way, testing code
# can use the internal interface of the libraries (linking
# with syscall_intercept_base instead of the actual lib ), without
# the library trying to hotpatch libc every time.
add_library(syscall_intercept_base_c STATIC ${SOURCES_C})
add_library(syscall_intercept_base_asm STATIC ${SOURCES_ASM})

if(HAS_NOUNUSEDARG)
	target_compile_options(syscall_intercept_base_asm BEFORE
		PRIVATE "-Wno-unused-command-line-argument")
endif()

set_property(TARGET syscall_intercept_base_c
	APPEND PROPERTY COMPILE_FLAGS ${capstone_CFLAGS})

target_link_libraries(syscall_intercept_base_c
	${CMAKE_DL_LIBS} ${capstone_LIBRARIES})

add_library(syscall_intercept_shared SHARED src/entry.c)
target_link_libraries(syscall_intercept_shared
	syscall_intercept_base_c syscall_intercept_base_asm)
add_library(syscall_intercept_static STATIC src/entry.c)
target_link_libraries(syscall_intercept_static
	syscall_intercept_base_c syscall_intercept_base_asm)

set_target_properties(syscall_intercept_shared
	PROPERTIES VERSION ${SYSCALL_INTERCEPT_VERSION}
		   SOVERSION ${SYSCALL_INTERCEPT_VERSION_MAJOR})

add_executable(cpp_test src/cpp_compile_test.cc src/cpp_compile_mock.c)

if(CMAKE_OBJCOPY)
foreach(target syscall_intercept_shared syscall_intercept_static)
	add_custom_command(TARGET ${target}
	POST_BUILD COMMAND ${CMAKE_OBJCOPY}
	--localize-hidden
	-G intercept_hook_point
	-G syscall_no_intercept
	-G libc_hook_in_process_allowed
	$<TARGET_FILE:${target}>)
endforeach()
endif()

set_target_properties(syscall_intercept_shared syscall_intercept_static
	PROPERTIES
	PUBLIC_HEADER "include/libsyscall_intercept_hook_point.h"
	OUTPUT_NAME syscall_intercept)

add_dependencies(syscall_intercept_base_c cpp_test)

if(${PERL_FOUND} AND DEVELOPER_MODE)
	add_custom_target(cstyle
		COMMAND ${PERL_EXECUTABLE} ${PROJECT_SOURCE_DIR}/utils/cstyle.pl
		-pP ${PROJECT_SOURCE_DIR}/src/*.[ch]
		${PROJECT_SOURCE_DIR}/include/*.h
		${PROJECT_SOURCE_DIR}/test/*.c
		${PROJECT_SOURCE_DIR}/examples/*.c)

	add_custom_target(check_whitespace
		COMMAND ${PERL_EXECUTABLE} ${PROJECT_SOURCE_DIR}/utils/check_whitespace.pl
		-r ${PROJECT_SOURCE_DIR}/src)

	add_dependencies(syscall_intercept_base_c cstyle check_whitespace)
endif()

add_executable(check_license_executable utils/check_license/check-license.c)

add_custom_target(check-license
	COMMAND
	${PROJECT_SOURCE_DIR}/utils/check_license/check-headers.sh
	${PROJECT_SOURCE_DIR}
	$<TARGET_FILE:check_license_executable>
	${PROJECT_SOURCE_DIR}/LICENSE -a)

add_dependencies(check-license check_license_executable)
configure_file(libsyscall_intercept.pc.in libsyscall_intercept.pc)

install(TARGETS syscall_intercept_shared syscall_intercept_static
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(FILES ${CMAKE_BINARY_DIR}/libsyscall_intercept.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
	"${CMAKE_CURRENT_BINARY_DIR}/cmake/cmake_uninstall.cmake"
	IMMEDIATE @ONLY)
add_custom_target(uninstall
	"${CMAKE_COMMAND}" -P "${CMAKE_CURRENT_BINARY_DIR}/cmake/cmake_uninstall.cmake") 

enable_testing()

add_subdirectory(examples)
add_subdirectory(test)
add_subdirectory(doc)
