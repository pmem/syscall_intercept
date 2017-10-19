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

#ifndef INTERCEPT_SYSCALL_FORMATS_H
#define INTERCEPT_SYSCALL_FORMATS_H

#include "intercept.h"

/*
 * The formats of syscall arguments, as they should appear in logs.
 * Note: the code is specific to the x86_64 ABI used on Linux, thus
 * assumes the following integer sizes:
 * int - 32bit
 * long - 64bit
 * intptr_t - 64bit
 * These assumptions would only be wrong when the assembly code in the
 * library would also be ported to some different ABI.
 */
enum arg_format {
	arg_none = 0, /* no argument, used as a null terminator */
	arg_, /* general argument, not interpreted, print as hexadecimal */
	arg_dec, /* decimal number */
	arg_dec32, /* 32 bit decimal number */
	arg_oct_mode, /* mode_t, octal number ( open, chmod, etc.. ) */
	arg_hex, /* hexadecimal number, with zero padding e.g. pointers */
	arg_cstr, /* zero terminated string */
	arg_buf_in, /* input buffer, with a size in the next argument */
	arg_buf_out, /* output buffer, with a size in the result */
	arg_open_flags, /* only used for oflags in open, openat */
	arg_fd, /* fd argument - not the first argument of *at syscalls */
	arg_atfd, /* fd argument - the first argument of *at syscalls */
	arg_pointer, /* general pointer argument */
	arg_fcntl_cmd, /* 2nd argument of fcntl */
	arg_clone_flags, /* 1st argument of clone */
	arg_seek_whence, /* 3rd argument of lseek */
	arg_2fds, /* array of 2 int fd numbers */
	arg_pipe2_flags, /* second argument of pipe2 */
	arg_access_mode, /* second argument of access */
	arg_flock /* pointer to struct flock */
};

/*
 * The formats of syscall return values.
 * Negative values greater than -4096 are always treated as error codes.
 */
enum return_type {
	rpointer,
	rhex,
	rdec,
	rmode,
	rnoreturn /* syscall does not return, e.g. exit */
};

struct syscall_format {
	const char *name;
	enum return_type return_type;
	const enum arg_format args[7];
};

const struct syscall_format *
get_syscall_format(const struct syscall_desc *desc);

#endif
