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
project(syscall_intercept C ASM)
include(CheckCCompilerFlag)

set(VERSION_MAJOR 0)
set(VERSION_MINOR 1)
set(VERSION_PATCH 0)
set(VERSION ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH})

if (NOT CMAKE_VERSION VERSION_LESS 3.1.0)
	set(CMAKE_C_STANDARD 99)
else()
	check_c_compiler_flag(-std=c99 HAS_STDC99)
	if(HAS_STDC99)
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")
	else()
		check_c_compiler_flag(-std=gnu99 HAS_STDGNU99)
		if(HAS_STDGNU99)
			set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99")
		endif()
	endif()
endif()

# main source files - intentionally excluding src/entry.c
set(SOURCES
	src/disasm_wrapper.c
	src/intercept.c
	src/intercept_desc.c
	src/intercept_util.c
	src/patcher.c
	src/intercept_template.s
	src/util.s)

include_directories(include)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Main object files of the library, the entry point in entry.c
# is only built into the final libraries. This way, testing code
# can use the internal interface of the libraries (linking
# with syscall_intercept_base instead of the actual lib ), without
# the library trying to hotpatch libc every time.
add_library(syscall_intercept_base STATIC ${SOURCES})

add_library(syscall_intercept_shared SHARED src/entry.c)
add_library(syscall_intercept_static STATIC src/entry.c)
target_link_libraries(syscall_intercept_static
	${CMAKE_DL_LIBS} capstone syscall_intercept_base)
target_link_libraries(syscall_intercept_shared
	${CMAKE_DL_LIBS} capstone syscall_intercept_base)

set_target_properties(syscall_intercept_shared syscall_intercept_static
	PROPERTIES
	PUBLIC_HEADER "include/libsyscall_intercept_hook_point.h"
	OUTPUT_NAME syscall_intercept)

check_c_compiler_flag(-Werror HAS_WERROR)
check_c_compiler_flag(-Wall HAS_WALL)
check_c_compiler_flag(-Wextra HAS_WEXTRA)
check_c_compiler_flag(-pedantic HAS_PEDANTIC)
check_c_compiler_flag(-Wno-missing-field-initializers HAS_NOMFI)
check_c_compiler_flag(-Wno-c90-c99-compat HAS_NO9099)

# Hack, adding _GNU_SOURCE macro is just hardwired here for now.
# Todo: only do it when building with glibc.
# The only possible target in the foreseeable future is GNU/Linux x86_64
# so it doesn't matter.
# The only library extension used is dlinfo.
add_definitions(-D_GNU_SOURCE)

if(HAS_WERROR)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")
endif()
if(HAS_WALL)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
endif()
if(HAS_WEXTRA)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wextra")
endif()
if(HAS_PEDANTIC)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pedantic")
endif()
if(HAS_NO9099)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-c90-c99-compat")
endif()

if("${CMAKE_C_COMPILER_ID}" MATCHES "Clang" AND HAS_NOMFI)
	# See: https://llvm.org/bugs/show_bug.cgi?id=21689
	set(CMAKE_C_FLAGS
		"${CMAKE_C_FLAGS} -Wno-missing-field-initializers")
endif()

add_custom_target(cstyle
	COMMAND perl ${PROJECT_SOURCE_DIR}/utils/cstyle.pl
	-pP ${PROJECT_SOURCE_DIR}/src/*.{h,c}
	${PROJECT_SOURCE_DIR}/include/*.h
	${PROJECT_SOURCE_DIR}/test/*.c
	${PROJECT_SOURCE_DIR}/examples/*.c)

add_custom_target(check_whitespace
	COMMAND perl ${PROJECT_SOURCE_DIR}/utils/check_whitespace.pl
	-r ${PROJECT_SOURCE_DIR}/src)

add_dependencies(syscall_intercept_base cstyle check_whitespace)

add_executable(check_license_executable utils/check_license/check-license.c)
set_property(TARGET check_license_executable PROPERTY C_STANDARD 99)

add_custom_target(check-license
	COMMAND
	${PROJECT_SOURCE_DIR}/utils/check_license/check-headers.sh
	${PROJECT_SOURCE_DIR}
	$<TARGET_FILE:check_license_executable>
	${PROJECT_SOURCE_DIR}/LICENSE -a)

add_dependencies(check-license check_license_executable)
configure_file(libsyscall_intercept.pc.in libsyscall_intercept.pc)

install(TARGETS syscall_intercept_shared syscall_intercept_static
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib
	PUBLIC_HEADER DESTINATION include)

install(FILES ${CMAKE_BINARY_DIR}/libsyscall_intercept.pc DESTINATION lib/pkgconfig)

enable_testing()

add_subdirectory(examples)
add_subdirectory(test)
