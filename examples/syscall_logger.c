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
#include "syscall_desc.h"

#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>

long log_fd;

static char buffer[0x20000];
static char *nextc;

static size_t
buffer_avaliable(void)
{
	return (size_t)(sizeof(buffer) - (size_t)(nextc - buffer));
}

static const char xdigit[16] = "0123456789abcdef";

static void
print_fd(long n)
{
	if (n == AT_FDCWD)
		nextc += sprintf(nextc, "AT_FDCWD");
	else
		nextc += sprintf(nextc, "%ld", n);
}

static void
print_hex(long n)
{
	nextc += sprintf(nextc, "0x%lx", n);
}

#define CSTR_MAX_LEN 0x100

static void
print_cstr_escaped(const char *path)
{
	size_t len = 0;
	*nextc++ = '"';
	while (*path != '\0' && len < CSTR_MAX_LEN) {
		if (*path == '\n') {
			*nextc++ = '\\';
			*nextc++ = 'n';
		} else if (*path == '\\') {
			*nextc++ = '\\';
			*nextc++ = '\\';
		} else if (*path == '\t') {
			*nextc++ = '\\';
			*nextc++ = 't';
		} else if (*path == '\"') {
			*nextc++ = '\\';
			*nextc++ = '"';
		} else if (isprint((unsigned char)*path)) {
			*nextc++ = *path;
		} else {
			*nextc++ = '\\';
			*nextc++ = 'x';
			*nextc++ = xdigit[((unsigned char)*path) / 0x10];
			*nextc++ = xdigit[((unsigned char)*path) % 0x10];
		}

		++len;
		++path;
	}

	if (*path != '\0') {
		*nextc++ = '.';
		*nextc++ = '.';
		*nextc++ = '.';
	}

	*nextc++ = '"';
}

static void
dump_log(void)
{
	if (nextc == buffer)
		return;

	syscall_no_intercept(SYS_write, log_fd, buffer, nextc - buffer);

	nextc = buffer;
}

static void
print_cstr(const char *name)
{
	while (*name != '\0')
		*nextc++ = *name++;
}

static void
print_rdec(long n)
{
	nextc += sprintf(nextc, "%ld", n);

	if (n < 0 && n >= -((long)INT_MAX)) {
		print_cstr(" (");

		/* See the glibc related man page for strerror_r */
#if (_POSIX_C_SOURCE >= 200112L) && !defined(_GNU_SOURCE)
		if (strerror_r((int)(0 - n), nextc, 0x100) == 0)
			nextc += strlen(nextc);
		else
			print_cstr("unknown error code");
#else
		char *strerr_result = strerror_r((int)(0 - n), nextc, 0x100);
		if (strerr_result != nextc)
			print_cstr(strerr_result);
		else
			nextc += strlen(nextc);
#endif

		print_cstr(")");
	}
}

static void
print_runsigned(long n)
{
	nextc += sprintf(nextc, "%lu", (unsigned long)n);
}

static void
print_roct(long n)
{
	nextc += sprintf(nextc, "%lo", n);
}

#define MIN_AVAILABLE_REQUIRED (0x100 + 8 * CSTR_MAX_LEN)

static void
print_unknown_syscall(long syscall_number, long args[static 6], long result)
{
	nextc += sprintf(nextc, "syscall(%ld", syscall_number);
	for (unsigned i = 0; i < 6; ++i)
		nextc += sprintf(nextc, ", 0x%lx", args[i]);
	nextc += sprintf(nextc, ") = 0x%lx\n", result);
}

static void
print_known_syscall(const struct syscall_desc *desc,
			const long args[static 6], long result)
{
	print_cstr(desc->name);
	*nextc++ = '(';

	for (unsigned i = 0; desc->args[i] != arg_none; ++i) {
		if (i > 0)
			print_cstr(", ");

		switch (desc->args[i]) {
		case arg_fd:
			print_fd(args[i]);
			break;
		case arg_cstr:
			print_hex(args[i]);
			print_cstr_escaped((const char *)(args[i]));
			break;
		default:
			print_hex(args[i]);
			break;
		}
	}

	print_cstr(") = ");
	switch (desc->return_type) {
	case rhex:
		print_hex(result);
		break;
	case rdec:
		print_rdec(result);
		break;
	case runsigned:
		print_runsigned(result);
		break;
	case roct:
		print_roct(result);
		break;
	}
	*nextc++ = '\n';
}

static int
hook(long syscall_number,
		long arg0, long arg1,
		long arg2, long arg3,
		long arg4, long arg5,
		long *result)
{
	*result = syscall_no_intercept(syscall_number,
					arg0, arg1, arg2, arg3, arg4, arg5);

	long args[6] = {arg0, arg1, arg2, arg3, arg4, arg5};

	const struct syscall_desc *desc = get_syscall_desc(syscall_number);

	if (desc != NULL)
		print_known_syscall(desc, args, *result);
	else
		print_unknown_syscall(syscall_number, args, *result);

	if (buffer_avaliable() < MIN_AVAILABLE_REQUIRED)
		dump_log();

	return 0;
}

static __attribute__((constructor)) void
start(void)
{
	const char *path = getenv("SYSCALL_LOG_PATH");

	nextc = buffer;

	if (path == NULL)
		syscall_no_intercept(SYS_exit_group, 3);

	log_fd = syscall_no_intercept(SYS_open, path, O_CREAT | O_RDWR, 0700);

	if (log_fd < 0)
		syscall_no_intercept(SYS_exit_group, 4);

	intercept_hook_point = &hook;
}

static __attribute__((destructor)) void
end(void)
{
	dump_log();
}
