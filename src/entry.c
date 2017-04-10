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

/*
 * entry.c -- the entry point for libsyscall_intercept
 *  expected to be executed by the loader while using LD_PRELOAD
 */

#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <fcntl.h>
#include <unistd.h>

#include "libsyscall_intercept_hook_point.h"
#include "intercept.h"

/*
 * entry_point - the main entry point for syscall_intercept
 *
 * The loader calls this routine once the library is loaded, except in certain
 * cases when testing -- see asm_wrapper.c for more details.
 * The actual work of hotpatching libraries is done the routine
 * called intercept.
 */
static __attribute__((constructor)) void
entry_point(void)
{
	if (libc_hook_in_process_allowed())
		intercept();
}

/*
 * libc_hook_in_process_allowed - checks if a filter should be applied
 * for processes. If the users requests it (via an environment variable) the
 * syscall interception should not be performed in the current process.
 * This is part of syscall_intercept's public API.
 */
int
libc_hook_in_process_allowed(void)
{
	long fd;
	long r;

	char *c = getenv("INTERCEPT_HOOK_CMDLINE_FILTER");
	if (c == NULL)
		return 1;

	size_t len = strlen(c) + 1;

	fd = syscall_no_intercept(SYS_open, "/proc/self/cmdline",
	    O_RDONLY, 0);
	if (fd < 0)
		return 0;

	char buf[len];
	r = syscall_no_intercept(SYS_lseek, fd, -len, SEEK_END);

	/*
	 * If SEEK_END failed, assume it happened because there are fewer than
	 * len characters in the contents of "/proc/self/cmdline".
	 */
	if (r < 0)
		return 1;

	r = syscall_no_intercept(SYS_read, fd, buf, len);

	syscall_no_intercept(SYS_close, fd);

	if (r <= 1 || buf[0] == '\0')
		return 0;

	buf[len - 1] = '\0';

	/*
	 * Find the last component of the path in "/proc/self/cmdline"
	 * The user might provide something like:
	 *
	 * INTERCEPT_HOOK_CMDLINE_FILTER=mkdir
	 *
	 * in which case we should compare the string "mkdir" with the
	 * last component of a path, e.g.:
	 * "usr/bin/mkdir"
	 */

	char *name = buf + len;

	/* find the last slash - search backwards from the end of the string */

	while (*name != '/' && name != buf)
		--name;

	if (*name == '/') {
		/*
		 * Found a slash, don't include the slash
		 * itself in the comparison
		 */
		++name;
	} else {
		/* No slash found, use the whole string */
	}

	return strcmp(name, c) == 0;
}
