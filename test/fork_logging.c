/*
 * Copyright 2016-2017, Intel Corporation
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
 * fork_logging.c -- dummy program, to issue fork via libc
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <sys/wait.h>

#include <pthread.h>

#include "magic_syscalls.h"

static const char *log_parent;
static const char *log_child;

static void *
busy(void *arg)
{
	FILE *f;
	const char *path = (const char *)arg;
	char buffer[0x100];
	size_t s;

	if ((f = fopen(path, "r")) == NULL)
		exit(EXIT_FAILURE);

	s = fread(buffer, 1, sizeof(buffer), f);
	if (s < 4)
		exit(EXIT_FAILURE);
	fwrite(buffer, 1, 1, stdout);
	fflush(stdout);
	fwrite(buffer, 2, 1, stdout);
	fflush(stdout);
	fwrite(buffer, 3, 1, stdout);
	fflush(stdout);
	putchar('\n');
	fflush(stdout);
	puts("Done being busy here");
	fflush(stdout);
	fclose(f);

	magic_syscall_stop_log();

	return NULL;
}

int
main(int argc, char *argv[])
{
	if (argc < 4)
		return EXIT_FAILURE;

	log_parent = argv[2];
	log_child = argv[3];

	magic_syscall_start_log(log_parent, "1");

	int r = fork();
	if (r < 0)
		err(EXIT_FAILURE, "fork");

	if (r == 0) {
		magic_syscall_start_log(log_child, "1");
		busy(argv[1]);
	} else {
		wait(NULL);
		busy(argv[1]);
	}

	magic_syscall_stop_log();

	return EXIT_SUCCESS;
}
