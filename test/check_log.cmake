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


# XXX ask for a unique tempfile from cmake for LOG_OUTPUT
set(LOG_OUTPUT .log.${TEST_NAME})

execute_process(COMMAND ${CMAKE_COMMAND} -E remove -f ${LOG_OUTPUT})

set(ENV{INTERCEPT_ALL_OBJS} 1)

if(HAS_SECOND_LOG)
	set(SECOND_LOG_OUTPUT .log.2.${TEST_NAME})
	execute_process(COMMAND ${CMAKE_COMMAND} -E remove -f ${SECOND_LOG_OUTPUT})
endif()

if(HAS_SECOND_LOG)
	message("Executing: LD_PRELOAD=${LIB_FILE}
		INTERCEPT_ALL_OBJS=1
		${TEST_PROG} ${TEST_PROG_ARG} ${LOG_OUTPUT} ${SECOND_LOG_OUTPUT}")
	if(TEST_EXTRA_PRELOAD)
		set(ENV{LD_PRELOAD} ${TEST_EXTRA_PRELOAD}:${LIB_FILE})
	else()
		set(ENV{LD_PRELOAD} ${LIB_FILE})
	endif()
	execute_process(COMMAND ${TEST_PROG}
		${TEST_PROG_ARG} ${LOG_OUTPUT} ${SECOND_LOG_OUTPUT}
		RESULT_VARIABLE HAD_ERROR)
	unset(ENV{LD_PRELOAD})
else()
	message("Executing: LD_PRELOAD=${LIB_FILE}
		INTERCEPT_ALL_OBJS=1
		${TEST_PROG} ${TEST_PROG_ARG} ${LOG_OUTPUT}")
	if(TEST_EXTRA_PRELOAD)
		set(ENV{LD_PRELOAD} ${TEST_EXTRA_PRELOAD}:${LIB_FILE})
	else()
		set(ENV{LD_PRELOAD} ${LIB_FILE})
	endif()
	execute_process(COMMAND ${TEST_PROG} ${TEST_PROG_ARG} ${LOG_OUTPUT}
		RESULT_VARIABLE HAD_ERROR)
	unset(ENV{LD_PRELOAD})
endif()

if(HAD_ERROR)
	message(FATAL_ERROR "Test failed: ${HAD_ERROR}")
endif()

if(NOT EXPECT_SPURIOUS_SYSCALLS)
	execute_process(COMMAND
		${MATCH_SCRIPT} -o ${LOG_OUTPUT} ${MATCH_FILE}
		RESULT_VARIABLE MATCH_ERROR)

	if(MATCH_ERROR)
		message(FATAL_ERROR "Log does not match! ${MATCH_ERROR}")
	endif()

	if(HAS_SECOND_LOG)
		execute_process(COMMAND
			${MATCH_SCRIPT} -o ${SECOND_LOG_OUTPUT} ${SECOND_MATCH_FILE}
			RESULT_VARIABLE MATCH_ERROR)
		if(MATCH_ERROR)
			message(FATAL_ERROR "Second log does not match! ${MATCH_ERROR}")
		endif()
	endif()
endif()
