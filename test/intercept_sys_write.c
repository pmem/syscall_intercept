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

#include "libsyscall_intercept_hook_point.h"

#include <stddef.h>
#include <syscall.h>
#include <string.h>

static int
hook(long syscall_number,
	long arg0, long arg1,
	long arg2, long arg3,
	long arg4, long arg5,
	long *result)
{
	(void) arg0;
	(void) arg2;
	(void) arg3;
	(void) arg4;
	(void) arg5;
	(void) result;

	if (syscall_number == SYS_write) {
		const char interc[] = "intercepted_";
		const char *src = interc;

		/* write(fd, buf, len) */
		size_t len = (size_t)arg2;
		char *buf = (char *)arg1;

#ifdef EXPECT_SPURIOUS_SYSCALLS
		if (strcmp(buf, "original_syscall") != 0)
			return 1;
#endif

		if (len > sizeof(interc)) {
			while (*src != '\0')
				*buf++ = *src++;
		}
	}

	return 1;
}

static __attribute__((constructor)) void
init(void)
{
	intercept_hook_point = hook;
}
