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


if(FILTER_PLUS_ONECHAR)
	string(SUBSTRING "${FILTER_PLUS_ONECHAR}" 1 -1 FILTER)
endif()

if(FILTER)
	set(ENV{INTERCEPT_HOOK_CMDLINE_FILTER} ${FILTER})
	message("FILTER: ${FILTER}")
endif()

if(LIB_FILE)
if(TEST_EXTRA_PRELOAD)
	set(ENV{LD_PRELOAD} ${TEST_EXTRA_PRELOAD}:${LIB_FILE})
else()
	set(ENV{LD_PRELOAD} ${LIB_FILE})
endif()
endif()

endif()

if(INTERCEPT_ALL)
	set(ENV{INTERCEPT_ALL_OBJS} 1)
else()
	unset(ENV{INTERCEPT_ALL_OBJS})
endif()

execute_process(COMMAND ${TEST_PROG} ${TEST_PROG_ARGS} RESULT_VARIABLE HAD_ERROR)

unset(ENV{LD_PRELOAD})

if(HAD_ERROR)
	message(FATAL_ERROR "Error: ${HAD_ERROR}")
endif()
