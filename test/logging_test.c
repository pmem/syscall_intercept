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
 * logging_test.c -- dummy program, to issue some syscalls via libc
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <sys/wait.h>

#include <pthread.h>

#include "magic_syscalls.h"

static void *
busy(void *arg)
{
	FILE *f;
	const char *path = (const char *)arg;
	char buffer[0x100];
	size_t s;

	if ((f = fopen(path, "r")) == NULL)
		exit(EXIT_FAILURE);

	usleep(10000);
	s = fread(buffer, 1, sizeof(buffer), f);
	if (s < 4)
		exit(EXIT_FAILURE);
	usleep(10000);
	fwrite(buffer, 1, 1, stdout);
	fflush(stdout);
	fwrite(buffer, 2, 1, stdout);
	fflush(stdout);
	fwrite(buffer, 3, 1, stdout);
	fflush(stdout);
	putchar('\n');
	usleep(10000);
	fflush(stdout);
	puts("Done being busy here");
	fflush(stdout);
	usleep(10000);
	fclose(f);

	return NULL;
}

int
main(int argc, char *argv[])
{
	if (argc < 3)
		return EXIT_FAILURE;

	magic_syscall_start_log(argv[2], "1");

	if (fork() == 0) {
		busy(argv[1]);
	} else {
		wait(NULL);
		busy(argv[1]);
	}

	magic_syscall_stop_log();

	return EXIT_SUCCESS;
}
