/*
 * Copyright 2017, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *
 *     * Neither the name of the copyright holder nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#ifdef NDEBUG
#undef NDEBUG
#endif

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syscall.h>

#include <stdio.h>

#include "libsyscall_intercept_hook_point.h"

#include "hook_test_data.h"

static int hook_counter;
static bool in_hook;
static bool deinit_called;

static int
hook(long syscall_number, long arg0, long arg1, long arg2, long *result)
{
	switch (hook_counter++) {
		case 0:
			/* fallthrough */
		case 2:
			assert(syscall_number == SYS_write);
			assert(arg0 == hook_test_fd);
			assert(strcmp((void *)(intptr_t)arg1, dummy_data) == 0);
			assert(arg2 == (long)sizeof(dummy_data));
			*result = hook_test_dummy_return_value;
			return 0;

		case 1:
			assert(syscall_number == SYS_write);
			assert(arg0 == hook_test_fd);
			return 1;

		default:
			assert(0);
	}
}

static int
hook_wrapper(long syscall_number,
	long arg0, long arg1,
	long arg2, long arg3,
	long arg4, long arg5,
	long *result)
{
	(void) arg3;
	(void) arg4;
	(void) arg5;

	if (in_hook || deinit_called)
		return 1;

	if (is_spurious_syscall(syscall_number, arg0))
		return 1;

	in_hook = true;

	int ret = hook(syscall_number, arg0, arg1, arg2, result);

	in_hook = false;

	return ret;
}

static __attribute__((constructor)) void
init(void)
{
	intercept_hook_point = hook_wrapper;
}

static __attribute__((destructor)) void
deinit(void)
{
	deinit_called = true;
	assert(hook_counter == 3);
}
