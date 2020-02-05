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

cmake_minimum_required(VERSION 3.3)
project(syscall_intercept C ASM)

set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)
# Setting CMAKE_DISABLE_IN_SOURCE_BUILD to ON should
# disallow in source builds, but in practice it doesn't seem
# to disallow it. Check the paths as well:
if(",${CMAKE_SOURCE_DIR}," STREQUAL ",${CMAKE_BINARY_DIR},")
	message(FATAL_ERROR "In-source builds are not supported.")
endif()

option(PERFORM_STYLE_CHECKS
	"check coding style, license headers (requires perl)" ON)
option(BUILD_TESTS "build and enable tests" ON)
option(BUILD_EXAMPLES "build examples" ON)
option(TREAT_WARNINGS_AS_ERRORS
	"make the build fail on any warnings during compilation, or linking" ON)
option(EXPECT_SPURIOUS_SYSCALLS
	"account for some unexpected syscalls in tests - enable while using sanitizers, gcov" OFF)
find_program(CTAGS ctags)
if(CTAGS)
	option(AUTO_RUN_CTAGS "create tags file every on every rebuild" ON)
endif()
set(TEST_EXTRA_PRELOAD "" CACHE STRING "path to preloadable lib used while running tests e.g.: /usr/lib/gcc/x86_64-linux-gnu/6/libasan.so")

set(SYSCALL_INTERCEPT_VERSION_MAJOR 0)
set(SYSCALL_INTERCEPT_VERSION_MINOR 1)
set(SYSCALL_INTERCEPT_VERSION_PATCH 0)
set(SYSCALL_INTERCEPT_VERSION
	${SYSCALL_INTERCEPT_VERSION_MAJOR}.${SYSCALL_INTERCEPT_VERSION_MINOR}.${SYSCALL_INTERCEPT_VERSION_PATCH})

include(cmake/find_capstone.cmake)
include(GNUInstallDirs)
include(cmake/toolchain_features.cmake)
include(CheckLanguage)

# main source files - intentionally excluding src/cmdline_filter.c
set(SOURCES_C
	src/disasm_wrapper.c
	src/intercept.c
	src/intercept_desc.c
	src/intercept_log.c
	src/intercept_util.c
	src/patcher.c
	src/magic_syscalls.c
	src/syscall_formats.c)

set(SOURCES_ASM
	src/intercept_template.S
	src/util.S
	src/intercept_wrapper.S)


include_directories(include)
link_directories(${capstone_LIBRARY_DIRS})

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Main object files of the library, the entry point in entry.c
# is only built into the final libraries. This way, testing code
# can use the internal interface of the libraries (linking
# with syscall_intercept_base instead of the actual lib ), without
# the library trying to hotpatch libc every time.
add_library(syscall_intercept_base_c OBJECT ${SOURCES_C})
add_library(syscall_intercept_base_asm OBJECT ${SOURCES_ASM})
add_library(syscall_intercept_base_clf OBJECT src/cmdline_filter.c)

if(HAS_NOUNUSEDARG)
	target_compile_options(syscall_intercept_base_asm BEFORE
		PRIVATE "-Wno-unused-command-line-argument")
endif()

set_property(TARGET syscall_intercept_base_c
	APPEND PROPERTY COMPILE_FLAGS ${capstone_CFLAGS})

add_library(syscall_intercept_unscoped STATIC
		$<TARGET_OBJECTS:syscall_intercept_base_c>
		$<TARGET_OBJECTS:syscall_intercept_base_asm>
		$<TARGET_OBJECTS:syscall_intercept_base_clf>)

set(syscall_intercept_unscoped_a $<TARGET_FILE:syscall_intercept_unscoped>)

add_custom_command(
	OUTPUT syscall_intercept_unscoped.o
	COMMAND ${CMAKE_LINKER}
		-r --whole-archive ${syscall_intercept_unscoped_a}
		-o syscall_intercept_unscoped.o
	DEPENDS syscall_intercept_unscoped)

add_custom_command(
	OUTPUT syscall_intercept_scoped.o
	COMMAND ${CMAKE_OBJCOPY}
		--localize-hidden
		syscall_intercept_unscoped.o
		syscall_intercept_scoped.o
	DEPENDS syscall_intercept_unscoped.o)

add_custom_target(generate_syscall_intercept_scoped
		DEPENDS syscall_intercept_scoped.o)

add_library(syscall_intercept_shared SHARED syscall_intercept_scoped.o)
add_library(syscall_intercept_static STATIC syscall_intercept_scoped.o)

add_dependencies(syscall_intercept_shared generate_syscall_intercept_scoped)
add_dependencies(syscall_intercept_static generate_syscall_intercept_scoped)

set_target_properties(syscall_intercept_base_c
		PROPERTIES C_VISIBILITY_PRESET hidden)

target_link_libraries(syscall_intercept_shared
	PRIVATE ${CMAKE_DL_LIBS} ${capstone_LIBRARIES})

target_link_libraries(syscall_intercept_static
	INTERFACE ${CMAKE_DL_LIBS} ${capstone_LIBRARIES})

set_target_properties(syscall_intercept_shared
	PROPERTIES VERSION ${SYSCALL_INTERCEPT_VERSION}
		   SOVERSION ${SYSCALL_INTERCEPT_VERSION_MAJOR})

set_target_properties(syscall_intercept_shared syscall_intercept_static
	PROPERTIES
	LINKER_LANGUAGE C
	PUBLIC_HEADER "include/libsyscall_intercept_hook_point.h"
	OUTPUT_NAME syscall_intercept)

check_language(CXX)
if(CMAKE_CXX_COMPILER)
	enable_language(CXX)
	add_executable(cpp_test src/cpp_compile_test.cc src/cpp_compile_mock.c)
	add_dependencies(syscall_intercept_base_c cpp_test)
endif()

if(PERFORM_STYLE_CHECKS)
	include(FindPerl)
	if(${PERL_FOUND})
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
	else()
		message(FATAL_ERROR
			"Perl not found. Perl is required for checking coding style. "
			"To disable such checks, build with PERFORM_STYLE_CHECKS=OFF.")
	endif()

	add_executable(check_license_executable utils/check_license/check-license.c)

	add_custom_target(check-license
		COMMAND
		${PROJECT_SOURCE_DIR}/utils/check_license/check-headers.sh
		${PROJECT_SOURCE_DIR}
		$<TARGET_FILE:check_license_executable>
		${PROJECT_SOURCE_DIR}/LICENSE -a)

	add_dependencies(check-license check_license_executable)
endif()

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

add_subdirectory(doc)


if(AUTO_RUN_CTAGS)
	add_custom_target(gen_ctags ALL
		${CTAGS} -R ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/test)
endif()

if(BUILD_EXAMPLES)
	add_subdirectory(examples)
endif()

if(BUILD_TESTS)
	enable_testing()
	add_subdirectory(test)
endif()
