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

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <fcntl.h>
#include <unistd.h>

#include "libsyscall_intercept_hook_point.h"

/*
 * match_with_file_end
 * Compare a string with the end of a file's contents.
 * Reads only char by char, but it is expected to be used only for a dozen or so
 * chars at a time. See syscall_hook_in_process_allowed below.
 */
static bool
match_with_file_end(const char *expected, int fd)
{
	char file_c; /* next character from file */
	const char *c; /* next character from the expected string */

	if (expected[0] == '\0')
		return false;

	c = expected;

	while (syscall_no_intercept(SYS_read, fd, &file_c, (size_t)1)
			== (ssize_t)1) {
		if (file_c == '\0') /* this probably never happens */
			break;

		if (file_c != *c)
			c = expected; /* start from the beginning */
		else
			++c; /* match next char */
	}

	return *c == '\0';
}

/*
 * syscall_hook_in_process_allowed - checks if a filter should be applied
 * for processes. If the users requests it (via an environment variable) the
 * syscall interception should not be performed in the current process.
 * This is part of syscall_intercept's public API.
 */
int
syscall_hook_in_process_allowed(void)
{
	int fd;
	bool result;
	const char *filter;

	filter = getenv("INTERCEPT_HOOK_CMDLINE_FILTER");
	if (filter == NULL)
		return 1;

	fd = (int)syscall_no_intercept(SYS_open,
			"/proc/self/cmdline", O_RDONLY, (mode_t)0);

	if (fd < 0)
		return 0;

	result = match_with_file_end(filter, fd);

	(void) syscall_no_intercept(SYS_close, fd);

	return result;
}
