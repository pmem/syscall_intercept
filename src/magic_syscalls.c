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

#ifndef SYSCALL_INTERCEPT_WITHOUT_MAGIC_SYSCALLS

#include <stdint.h>
#include <string.h>

#include "magic_syscalls.h"
#include "intercept_util.h"

int
handle_magic_syscalls(long nr, long arg0, long arg1,
			long arg2, long arg3,
			long arg4, long arg5)
{
	(void) arg5;

	if (nr != SYS_write)
		return -1;

	if (arg0 != SYSCALL_INT_MAGIC_WRITE_FD)
		return -1;

	const char *message = (void *)(uintptr_t)arg1;
	size_t len = (size_t)arg2;

	if (strncmp(message, start_log_message, len) == 0) {
		const char *path = (const void *)(uintptr_t)arg3;
		const char *trunc = (const void *)(uintptr_t)arg4;
		intercept_setup_log(path, trunc);
		return 0;
	}

	if (strncmp(message, stop_log_message, len) == 0) {
		intercept_log_close();
		return 0;
	}

	return -1;
}

#endif /* SYSCALL_INTERCEPT_WITHOUT_MAGIC_SYSCALLS */
