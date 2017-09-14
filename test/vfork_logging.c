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
#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>

#include "magic_syscalls.h"

int
main(int argc, char *argv[])
{
	static char msg[] = "in_child_created_using_vfork";

	if (strcmp(argv[0], msg) == 0) {
		puts(msg);
		return EXIT_SUCCESS;
	}

	if (argc < 2)
		return EXIT_FAILURE;

	char *log_path = argv[1];

	magic_syscall_start_log(log_path, "1");

	pid_t r = vfork();
	if (r < 0)
		err(EXIT_FAILURE, "vfork");

	if (r == 0) {
		/* In vfork child process */
		_exit(EXIT_SUCCESS);
	}

	const char *line =
	    "In original process, after first vfork\n";

	assert(write(1, line, strlen(line)) == (ssize_t)strlen(line));

	r = vfork();
	if (r < 0)
		err(EXIT_FAILURE, "vfork");

	if (r == 0) {
		/* In vfork child process again */
		execve(argv[0], (char *[]) {msg, NULL}, (char *[]) {NULL});
		err(EXIT_FAILURE, "execve returned");
	}

	line = "In original process, after second vfork\n";

	assert(write(1, line, strlen(line)) == (ssize_t)strlen(line));

	magic_syscall_stop_log();

	return EXIT_SUCCESS;
}
