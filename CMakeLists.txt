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

cmake_minimum_required(VERSION 3.2)
project(syscall_intercept C ASM)

include(CheckCCompilerFlag)

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
add_library(syscall_intercept_o OBJECT ${SOURCES})

add_library(syscall_intercept_shared
	SHARED $<TARGET_OBJECTS:syscall_intercept_o>)
add_library(syscall_intercept_static
	STATIC $<TARGET_OBJECTS:syscall_intercept_o>)

set_target_properties(syscall_intercept_shared PROPERTIES
  PUBLIC_HEADER "include/libsyscall_intercept_hook_point.h")
set_target_properties(syscall_intercept_static PROPERTIES
  PUBLIC_HEADER "include/libsyscall_intercept_hook_point.h")

set_property(TARGET syscall_intercept_o PROPERTY C_STANDARD 99)

check_c_compiler_flag(-Werror HAS_WERROR)
check_c_compiler_flag(-Wall HAS_WALL)
check_c_compiler_flag(-Wextra HAS_WEXTRA)
check_c_compiler_flag(-pedantic HAS_PEDANTIC)
check_c_compiler_flag(-Wno-missing-field-initializers HAS_NOMFI)

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

if("${CMAKE_C_COMPILER_ID}" MATCHES "Clang" AND HAS_NOMFI)
	# See: https://llvm.org/bugs/show_bug.cgi?id=21689
	set(CMAKE_C_FLAGS
		"${CMAKE_C_FLAGS} -Wno-missing-field-initializers")
endif()

TARGET_LINK_LIBRARIES(syscall_intercept_shared capstone)

add_custom_target(cstyle
	COMMAND perl ${PROJECT_SOURCE_DIR}/utils/cstyle
	-pP ${PROJECT_SOURCE_DIR}/src/*.{h,c}
	${PROJECT_SOURCE_DIR}/include/*.h
	${PROJECT_SOURCE_DIR}/examples/*.c)

add_custom_target(check_whitespace
	COMMAND perl ${PROJECT_SOURCE_DIR}/utils/check_whitespace
	-r ${PROJECT_SOURCE_DIR}/src)

add_dependencies(syscall_intercept_o cstyle check_whitespace)

add_executable(check_license_executable utils/check_license/check-license.c)
set_property(TARGET check_license_executable PROPERTY C_STANDARD 99)

add_custom_target(check-license
	COMMAND
	${PROJECT_SOURCE_DIR}/utils/check_license/check-headers.sh
	${PROJECT_SOURCE_DIR}
	$<TARGET_FILE:check_license_executable>
	${PROJECT_SOURCE_DIR}/LICENSE -a)

add_dependencies(check-license check_license_executable)

install(TARGETS syscall_intercept_shared syscall_intercept_static
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib
	PUBLIC_HEADER DESTINATION include)

add_subdirectory(examples)
add_subdirectory(test)
