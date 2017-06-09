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

include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)
include(CheckCSourceCompiles)
include(CheckIncludeFiles)
include(CheckFunctionExists)

if (NOT CMAKE_VERSION VERSION_LESS 3.1.0)
	set(CMAKE_C_STANDARD 99)
	set(CMAKE_C_STANDARD_REQUIRED ON)
	set(CMAKE_C_EXTENSIONS OFF)
	set(CMAKE_CXX_STANDARD 11)
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
	check_cxx_compiler_flag(-std=c++11 HAS_STDCPP11)
	if(HAS_STDCPP11)
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
	endif()
endif()

check_c_compiler_flag(-Werror HAS_WERROR)
check_c_compiler_flag(-Wall HAS_WALL)
check_c_compiler_flag(-Wextra HAS_WEXTRA)
check_c_compiler_flag(-pedantic HAS_PEDANTIC)
check_c_compiler_flag(-Wno-missing-field-initializers HAS_NOMFI)
check_c_compiler_flag(-Wno-c90-c99-compat HAS_NO9099)
check_c_compiler_flag(-Wl,-nostdlib LINKER_HAS_NOSTDLIB)
check_c_compiler_flag(-Wl,--fatal-warnings HAS_WLFATAL)
check_c_compiler_flag(-Wno-unused-command-line-argument HAS_NOUNUSEDARG)
check_c_compiler_flag(-pie HAS_ARG_PIE)
check_c_compiler_flag(-nopie HAS_ARG_NOPIE)
check_c_compiler_flag(-no-pie HAS_ARG_NO_PIE)

if(HAS_WERROR AND TREAT_WARNINGS_AS_ERRORS)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")
endif()
if(HAS_WLFATAL AND TREAT_WARNINGS_AS_ERRORS)
	set(CMAKE_LD_FLAGS ${CMAKE_LD_FLAGS} -Wl,--fatal-warnings)
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


# Hack, adding _GNU_SOURCE macro is just hardwired here for now.
# XXX: only do it when building with glibc.
# The only possible target in the foreseeable future is GNU/Linux x86_64
# so it doesn't matter.
# The only library extension used is dlinfo.
add_definitions(-D_GNU_SOURCE)


# GNUC extension
check_c_source_compiles("
static __attribute__((constructor)) void
entry_point(void) {}

int main(void) { return 0; }
"
 HAS_GCC_ATTR_CONSTR)

if(NOT HAS_GCC_ATTR_CONSTR)
	message(FATAL_ERROR "constructor attribute support required")
endif()


# GNUC extension -- system header pragma
set(orig_req_incs ${CMAKE_REQUIRED_INCLUDES})
set(CMAKE_REQUIRED_INCLUDES
	"${CMAKE_REQUIRED_INCLUDES} ${PROJECT_SOURCE_DIR}/cmake")

check_c_source_compiles("
#include \"test_header.h\"

int main(void) { return 0; }
"
 HAS_GCC_PRAGMA_SYSH)

set(CMAKE_REQUIRED_INCLUDES ${orig_req_incs})

if(HAS_GCC_PRAGMA_SYSH)
	add_definitions(-DHAS_GCC_PRAGMA_SYSH)
endif()


# elf.h -- syscall_intercept can only decode ELFs
check_include_files(elf.h HAS_ELF_H)

if(NOT HAS_ELF_H)
	message(FATAL_ERROR "elf.h not found")
endif()



# dladdr -- GNU libc extension
set(orig_req_libs ${CMAKE_REQUIRED_LIBRARIES})
set(CMAKE_REQUIRED_LIBRARIES ${CMAKE_DL_LIBS})

check_function_exists(dladdr HAS_DLADDR)

set(CMAKE_REQUIRED_LIBRARIES ${orig_req_libs})

if(NOT HAS_DLADDR)
	message(FATAL_ERROR "dladdr not found")
endif()
