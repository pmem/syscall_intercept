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

#include "intercept_log.h"
#include "intercept.h"
#include "intercept_util.h"
#include "syscall_formats.h"

#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>

/*
 * print_cstr - similar to strcpy, but returns a pointer to the terminating
 * null character in the destination string, instead of a count. This is done
 * without calling into libc, which is part of an effort to eliminate as many
 * libc calls in syscall_intercept as is possible in practice.
 *
 * Note: sprintf can result in a format string warning when given a variable
 * as second argument. This is sort of an fputs for strings, an sputs.
 */
static char *
print_cstr(char *dst, const char *src)
{
	while (*src != '\0')
		*dst++ = *src++;

	*dst = '\0';

	return dst;
}

/*
 * print_number - prints a number in the given base
 * A minimum number of digits can requested in the width argument.
 * Returns a pointer to end of the destination string.
 */
static char *
print_number(char *dst, unsigned long n, int base, unsigned width)
{
	static const char digit_chars[] = "0123456789abcdef";
	char digits[0x20];

	assert(base > 0 && (size_t)base < sizeof(digit_chars));

	digits[sizeof(digits) - 1] = '\0';
	char *c = digits + sizeof(digits) - 1;
	if (width >= sizeof(digits) - 1)
		width = sizeof(digits) - 2;

	do {
		c--;
		*c = digit_chars[n % base];
		n /= base;
		if (width > 0)
			width--;
	} while (n > 0 || width > 0);

	while (*c != '\0')
		*dst++ = *c++;

	return dst;
}

/*
 * print_hex - prints a 64 but value as a hexadecimal number
 */
static char *
print_hex(char *c, long n)
{
	*c++ = '0';
	*c++ = 'x';
	return print_number(c, (unsigned long)n, 16, 1);
}

/*
 * print_hex - prints a 64 but value as a 16 digit hexadecimal number
 * If the number is zero, prints "(null)".
 */
static char *
print_pointer(char *c, long pointer)
{
	if (pointer == 0)
		return print_cstr(c, "(null)");

	*c++ = '0';
	*c++ = 'x';
	return print_number(c, (unsigned long)pointer, 16, 16);
}

/*
 * print_signed_dec - prints a 64 but value as a signed decimal
 */
static char *
print_signed_dec(char *dst, long n)
{
	unsigned long abs_n;

	if (n >= 0) {
		abs_n = (unsigned long)n;
	} else {
		*dst++ = '-';
		abs_n = -((unsigned long)n);
	}

	return print_number(dst, abs_n, 10, 1);
}

/*
 * print_signed_dec - prints a 32 but value as a signed decimal
 *
 * Every syscall argument is captured from the value of the corresponding
 * 64 bit register, which might or might not be zero extended. Since the
 * print_signed_dec function is only implemented for 64 bit values, a 32 bit
 * value must be sign extended before printing.
 * Without the explicit sign extenstion (the casts to the second argument in
 * the function), such erroneous results can appear in logs, when for example
 * calling fstat and lseek with fd number -100:
 *
 * +--------------------------------------------------------------------+
 * | /lib/libc.so.6 0xf8260 -- fstat(-100, 0x00007ffec24b78f0) = ?      |
 * | /lib/libc.so.6 0xf8260 -- fstat(-100, 0x00007ffec24b78f0) = 77     |
 * | /lib/libc.so.6 0x108da5 -- lseek(4294967196, 99999, SEEK_SET) = ?  |
 * | /lib/libc.so.6 0x108da5 -- lseek(4294967196, 99999, SEEK_SET) = 77 |
 * +--------------------------------------------------------------------+
 *
 * Which is the result of libc sign extending in the fstat implementation, but
 * not in the lseek implementation.
 */
static char *
print_signed_dec32(char *dst, long n)
{
	return print_signed_dec(dst, (long)(int32_t)n);
}

/*
 * print_octal - prints as an octal number
 */
static char *
print_octal(char *dst, long n)
{
	*dst++ = '0';
	return print_number(dst, (unsigned long)n, 8, 1);
}

/*
 * print_flag - appends a vertical bar separated list of strings with a
 * new one, returns a pointer to end of the resulting string.
 * The buffer_start argument is expected to point to the beginning of
 * the list (where no separator is needed), and the c argument is treated
 * as current iterator in the list.
 */
static char *
print_flag(char *buffer_start, char *c, const char *flag_name)
{
	if (c != buffer_start)
		c = print_cstr(c, " | ");

	return c = print_cstr(c, flag_name);
}

struct flag_desc {
	long flag;
	const char *printable_name;
};

#define FLAG_ENTRY(flag_macro) \
	{ .flag = flag_macro, .printable_name = #flag_macro }

/*
 * print_flag_set
 * Prints a set of flags which are set in an integer. The names and values of
 * the possible flags are taken from an array passed as the fourth argument.
 * All flags in the array are expected to be distinct, and non-zero.
 */
static char *
print_flag_set(char *buffer_start, char *c, long flags,
		const struct flag_desc *desc)
{
	bool is_zero = flags == 0;
	while (flags != 0 && desc->printable_name != NULL) {
		if (is_zero && desc->flag == 0)
			return print_flag(buffer_start, c,
						desc->printable_name);
		if ((flags & desc->flag) != 0) {
			c = print_flag(buffer_start, c, desc->printable_name);
			flags &= ~desc->flag;
		}
		desc++;
	}

	if (flags != 0) {
		if (c != buffer_start)
			c = print_cstr(c, " | ");
		c = print_hex(c, flags);
	}

	if (c == buffer_start)
		c = print_cstr(c, "0");

	return c;
}

static const struct flag_desc clone_flags[] = {
	FLAG_ENTRY(CLONE_CHILD_CLEARTID),
	FLAG_ENTRY(CLONE_CHILD_SETTID),
	FLAG_ENTRY(CLONE_FILES),
	FLAG_ENTRY(CLONE_FS),
	FLAG_ENTRY(CLONE_IO),
#ifdef CLONE_NEWCGROUP
	FLAG_ENTRY(CLONE_NEWCGROUP),
#endif
#ifdef CLONE_NEWIPC
	FLAG_ENTRY(CLONE_NEWIPC),
#endif
#ifdef CLONE_NEWNET
	FLAG_ENTRY(CLONE_NEWNET),
#endif
#ifdef CLONE_NEWNS
	FLAG_ENTRY(CLONE_NEWNS),
#endif
#ifdef CLONE_NEWPID
	FLAG_ENTRY(CLONE_NEWPID),
#endif
	FLAG_ENTRY(CLONE_NEWUSER),
#ifdef CLONE_NEWUTS
	FLAG_ENTRY(CLONE_NEWUTS),
#endif
	FLAG_ENTRY(CLONE_PARENT),
	FLAG_ENTRY(CLONE_PARENT_SETTID),
	FLAG_ENTRY(CLONE_PTRACE),
	FLAG_ENTRY(CLONE_SETTLS),
	FLAG_ENTRY(CLONE_SIGHAND),
	FLAG_ENTRY(CLONE_SYSVSEM),
	FLAG_ENTRY(CLONE_THREAD),
	FLAG_ENTRY(CLONE_UNTRACED),
	FLAG_ENTRY(CLONE_VFORK),
	FLAG_ENTRY(CLONE_VM),
	{ .flag = 0, }
};

/*
 * xprint_escape
 * Prints a user provided buffer (in src) as printable characters (to dst).
 * The zero_term argument specifies if it is a zero terminated buffer, e.g.
 * used with SYS_open, SYS_stat, or a buffer with a specified length, e.g.
 * used with SYS_write.
 * No more than dst_size characters are written.
 *
 * Returns the pointer advanced while printing.
 */
static char *
xprint_escape(char *restrict dst, const char *restrict src,
			size_t dst_size, bool zero_term, size_t src_size)
{
	char *dst_end = dst + dst_size - 5;

	if (src == NULL)
		return print_cstr(dst, "(null)");

	*dst++ = '"';
	while (dst < dst_end && (zero_term || src_size > 0)) {
		if (zero_term && *src == 0)
			break;

		if (*src == '\"') {
			*dst++ = '\\';
			*dst++ = '"';
		} else if (*src == '\\') {
			*dst++ = '\\';
			*dst++ = '\\';
		} else if (isprint(*src)) {
			*dst++ = *src;
		} else {
			*dst++ = '\\';
			if (*src == '\n') {
				*dst++ = 'n';
			} else if (*src == '\t') {
				*dst++ = 't';
			} else if (*src == '\r') {
				*dst++ = 'r';
			} else if (*src == '\a') {
				*dst++ = 'a';
			} else if (*src == '\b') {
				*dst++ = 'b';
			} else if (*src == '\f') {
				*dst++ = 'f';
			} else if (*src == '\v') {
				*dst++ = 'v';
			} else if (*src == '\0') {
				*dst++ = '0';
			} else {
				*dst++ = 'x';
				dst = print_number(dst,
				    (unsigned char)*src, 16, 2);
			}

		}

		++src;

		if (!zero_term)
			--src_size;
	}

	if ((src_size > 0 && !zero_term) || (zero_term && *src != 0))
		dst = print_cstr(dst, "...");

	*dst++ = '"';
	*dst = 0;

	return dst;
}

typedef char *(*arg_printer_func)(char *buffer, const struct syscall_desc *,
				int arument_index, enum intercept_log_result,
				long result);

typedef char *(*return_value_printer_func)(char *buffer, long value);

static char *
arg_print_signed_dec(char *buffer, const struct syscall_desc *desc, int i,
				enum intercept_log_result result_status,
				long result)
{
	(void) result_status;
	(void) result;

	return print_signed_dec(buffer, desc->args[i]);
}

static char *
arg_print_signed_dec32(char *buffer, const struct syscall_desc *desc, int i,
				enum intercept_log_result result_status,
				long result)
{
	(void) result_status;
	(void) result;

	return print_signed_dec32(buffer, desc->args[i]);
}

static char *
arg_print_octal_mode(char *buffer, const struct syscall_desc *desc, int i,
				enum intercept_log_result result_status,
				long result)
{
	(void) result_status;
	(void) result;

	return print_octal(buffer, desc->args[i]);
}

static char *
arg_print_pointer(char *buffer, const struct syscall_desc *desc, int i,
				enum intercept_log_result result_status,
				long result)
{
	(void) result_status;
	(void) result;

	return print_pointer(buffer, desc->args[i]);
}

static char *
arg_print_general(char *buffer, const struct syscall_desc *desc, int i,
				enum intercept_log_result result_status,
				long result)
{
	(void) result_status;
	(void) result;

	return print_hex(buffer, desc->args[i]);
}

static char *
arg_print_atfd(char *buffer, const struct syscall_desc *desc, int i,
				enum intercept_log_result result_status,
				long result)
{
	(void) result_status;
	(void) result;

	int fd = (int32_t)desc->args[i];
	if (fd == AT_FDCWD)
		return print_cstr(buffer, "AT_FDCWD");

	return print_signed_dec32(buffer, fd);
}

static const struct flag_desc open_flags[] = {
#ifdef O_EXEC
	FLAG_ENTRY(O_EXEC),
#endif
#ifdef O_SEARCH
	FLAG_ENTRY(O_SEARCH),
#endif
	FLAG_ENTRY(O_APPEND),
	FLAG_ENTRY(O_CLOEXEC),
	FLAG_ENTRY(O_CREAT),
	FLAG_ENTRY(O_DIRECTORY),
	FLAG_ENTRY(O_DSYNC),
	FLAG_ENTRY(O_EXCL),
	FLAG_ENTRY(O_NOCTTY),
	FLAG_ENTRY(O_NOFOLLOW),
	FLAG_ENTRY(O_NONBLOCK),
	FLAG_ENTRY(O_RSYNC),
	FLAG_ENTRY(O_SYNC),
	FLAG_ENTRY(O_TRUNC),
#ifdef O_TTY_INIT
	FLAG_ENTRY(O_TTY_INIT),
#endif
	{ 0, }
};

static char *
arg_print_open_flags(char *buffer, const struct syscall_desc *desc, int i,
				enum intercept_log_result result_status,
				long result)
{
	(void) result_status;
	(void) result;

	char *c = buffer;
	int flags = (int)desc->args[i];

	if (flags == 0)
		return print_cstr(c, "O_RDONLY");

	switch (flags & O_ACCMODE) {
	case O_RDWR:
		c = print_flag(buffer, c, "O_RDWR");
		break;
	case O_WRONLY:
		c = print_flag(buffer, c, "O_WRONLY");
		break;
	case O_RDONLY:
		c = print_flag(buffer, c, "O_RDONLY");
		break;
	}

	flags &= ~(O_RDONLY | O_WRONLY | O_RDWR);

#ifdef O_TMPFILE
	if ((flags & O_TMPFILE) == O_TMPFILE) {
		/*
		 * Listing it with the other flags can result in
		 * printing O_DIRECTORY, when it should not be listed.
		 *
		 * See O_TMPFILE' definition in fcntl-linux.h :
		 * #define __O_TMPFILE   (020000000 | __O_DIRECTORY)
		 */
		c = print_flag(buffer, c, "O_TMPFILE");
		flags &= ~O_TMPFILE;
	}
#endif

	buffer = print_flag_set(buffer, c, flags, open_flags);

	return buffer;
}

static char *
arg_print_cstr(char *buffer, const struct syscall_desc *desc, int i,
				enum intercept_log_result result_status,
				long result)
{
	(void) result_status;
	(void) result;

	if (desc->args[i] == 0)
		return print_pointer(buffer, desc->args[i]);

	const char *str = (const char *)(uintptr_t)(desc->args[i]);
	return xprint_escape(buffer, str, 0x80, true, 0);
}

static char *
arg_print_input_buf(char *buffer, const struct syscall_desc *desc, int i,
				enum intercept_log_result result_status,
				long result)
{
	(void) result_status;
	(void) result;

	if (desc->args[i] == 0)
		return print_pointer(buffer, desc->args[i]);

	const char *output = (const char *)(uintptr_t)(desc->args[i]);
	size_t size = (size_t)desc->args[i + 1];
	return xprint_escape(buffer, output, 0x80, false, size);
}

static char *
arg_print_output_buf(char *buffer, const struct syscall_desc *desc, int i,
				enum intercept_log_result result_status,
				long result)
{
	if (desc->args[i] == 0 || result_status == UNKNOWN || result < 0)
		return print_pointer(buffer, desc->args[i]);

	const char *input = (const char *)(uintptr_t)(desc->args[i]);
	size_t size = (size_t)result;
	return xprint_escape(buffer, input, 0x80, false, size);
}

static const struct flag_desc pipe2_flags[] = {
	FLAG_ENTRY(O_CLOEXEC),
#ifdef O_DIRECT
	FLAG_ENTRY(O_DIRECT),
#endif
	FLAG_ENTRY(O_NONBLOCK),
	{ .flag = 0, }
};

static const struct flag_desc access_modes[] = {
	FLAG_ENTRY(R_OK),
	FLAG_ENTRY(W_OK),
	FLAG_ENTRY(X_OK),
	{ .flag = 0, }
};

static const struct flag_desc flock_type[] = {
	FLAG_ENTRY(F_RDLCK),
	FLAG_ENTRY(F_WRLCK),
	FLAG_ENTRY(F_UNLCK),
	{ 0, }
};

static char *
print_seek_whence(char *buffer, int whence)
{
	switch (whence) {
	case SEEK_SET:
		return print_cstr(buffer, "SEEK_SET");
	case SEEK_CUR:
		return print_cstr(buffer, "SEEK_CUR");
	case SEEK_END:
		return print_cstr(buffer, "SEEK_END");
	case SEEK_DATA:
		return print_cstr(buffer, "SEEK_DATA");
	case SEEK_HOLE:
		return print_cstr(buffer, "SEEK_HOLE");
	default:
		return print_hex(buffer, whence);
	}
}

static const struct flag_desc fcntl_cmds[] = {
	FLAG_ENTRY(F_DUPFD),
	FLAG_ENTRY(F_DUPFD_CLOEXEC),
	FLAG_ENTRY(F_GETFD),
	FLAG_ENTRY(F_SETFD),
	FLAG_ENTRY(F_GETFL),
	FLAG_ENTRY(F_SETFL),
	FLAG_ENTRY(F_SETLK),
	FLAG_ENTRY(F_SETLKW),
	FLAG_ENTRY(F_GETLK),
#ifdef F_OFD_SETLK
	FLAG_ENTRY(F_OFD_SETLK),
	FLAG_ENTRY(F_OFD_SETLKW),
	FLAG_ENTRY(F_OFD_GETLK),
#endif
	FLAG_ENTRY(F_GETOWN),
	FLAG_ENTRY(F_SETOWN),
	FLAG_ENTRY(F_GETOWN_EX),
	FLAG_ENTRY(F_SETOWN_EX),
	FLAG_ENTRY(F_GETSIG),
	FLAG_ENTRY(F_SETSIG),
	FLAG_ENTRY(F_SETLEASE),
	FLAG_ENTRY(F_GETLEASE),
	FLAG_ENTRY(F_NOTIFY),
	FLAG_ENTRY(F_SETPIPE_SZ),
	FLAG_ENTRY(F_GETPIPE_SZ),
#ifdef F_ADD_SEALS
	FLAG_ENTRY(F_ADD_SEALS),
	FLAG_ENTRY(F_GET_SEALS),
	FLAG_ENTRY(F_SEAL_SEAL),
	FLAG_ENTRY(F_SEAL_SHRINK),
	FLAG_ENTRY(F_SEAL_GROW),
	FLAG_ENTRY(F_SEAL_WRITE),
#endif
	{ 0, }
};

static char *
print_fcntl_cmd(char *buffer, int cmd)
{
	for (const struct flag_desc *d = fcntl_cmds;
		d->printable_name != NULL;
		++d) {
		if (d->flag == cmd)
			return print_cstr(buffer, d->printable_name);
	}

	return print_cstr(buffer, "unknown");
}

static char *
print_fcntl_flock(char *buffer, long arg)
{
	if (arg == 0)
		return buffer;

	struct flock *fl = (struct flock *)arg;

	/*
	 * Printing in following format:
	 * " ({.l_type = %d (%s),"
	 * " .l_whence = %d (%s),"
	 * " .l_start = %ld,
	 * " .l_len = %ld,
	 * " .l_pid = %d})"
	 */
	buffer = print_cstr(buffer, " ({.l_type = ");
	buffer = print_signed_dec(buffer, fl->l_type);
	buffer = print_cstr(buffer, " (");
	buffer = print_flag_set(buffer, buffer, fl->l_type, flock_type);
	buffer = print_cstr(buffer, "), .l_whence = ");
	buffer = print_signed_dec(buffer, fl->l_whence);
	buffer = print_cstr(buffer, " (");
	buffer = print_seek_whence(buffer, fl->l_whence);
	buffer = print_cstr(buffer, "), .l_start = ");
	buffer = print_signed_dec(buffer, fl->l_start);
	buffer = print_cstr(buffer, ", .l_len = ");
	buffer = print_signed_dec(buffer, fl->l_len);
	buffer = print_cstr(buffer, ", .l_pid = ");
	buffer = print_signed_dec(buffer, fl->l_pid);
	buffer = print_cstr(buffer, "})");

	return buffer;
}


static char *
arg_print_fcntl_cmd(char *buffer, const struct syscall_desc *desc, int i,
				enum intercept_log_result result_status,
				long result)
{
	(void) result_status;
	(void) result;

	int cmd = (int)desc->args[i];

	buffer = print_signed_dec(buffer, cmd);
	buffer = print_cstr(buffer, " (");
	buffer = print_fcntl_cmd(buffer, cmd);
	buffer = print_cstr(buffer, ")");

	return buffer;
}

static char *
arg_print_flock(char *buffer, const struct syscall_desc *desc, int i,
				enum intercept_log_result result_status,
				long result)
{
	(void) result_status;
	(void) result;

	buffer = print_pointer(buffer, desc->args[i]);
	return print_fcntl_flock(buffer, desc->args[i]);
}

static char *
arg_print_clone_flags(char *buffer, const struct syscall_desc *desc, int i,
				enum intercept_log_result result_status,
				long result)
{
	(void) result_status;
	(void) result;
	long flags = desc->args[i];
	return print_flag_set(buffer, buffer, flags, clone_flags);
}

static char *
arg_print_seek_whence(char *buffer, const struct syscall_desc *desc, int i,
				enum intercept_log_result result_status,
				long result)
{
	(void) result_status;
	(void) result;

	return print_seek_whence(buffer, (int)desc->args[i]);
}

static char *
arg_print_2fds(char *buffer, const struct syscall_desc *desc, int i,
				enum intercept_log_result result_status,
				long result)
{
	(void) result;

	if (desc->args[i] == 0 || result_status == UNKNOWN || result < 0)
		return print_pointer(buffer, desc->args[i]);

	int *fds = (int *)desc->args[i];
	buffer = print_cstr(buffer, "[");
	buffer = print_signed_dec(buffer, fds[0]);
	buffer = print_cstr(buffer, ", ");
	buffer = print_signed_dec(buffer, fds[1]);
	buffer = print_cstr(buffer, "]");

	return buffer;
}

static char *
arg_print_pipe2_flags(char *buffer, const struct syscall_desc *desc, int i,
				enum intercept_log_result result_status,
				long result)
{
	(void) result_status;
	(void) result;
	return print_flag_set(buffer, buffer, desc->args[i], pipe2_flags);
}

static char *
arg_print_access_mode(char *buffer, const struct syscall_desc *desc, int i,
				enum intercept_log_result result_status,
				long result)
{
	(void) result_status;
	(void) result;
	int mode = desc->args[i];
	if (mode == F_OK)
		return print_cstr(buffer, "F_OK");

	return print_flag_set(buffer, buffer, mode, access_modes);
}

static const arg_printer_func arg_printer_func_table[] = {
	[arg_] = arg_print_general,
	[arg_dec] = arg_print_signed_dec,
	[arg_dec32] = arg_print_signed_dec32,
	[arg_oct_mode] = arg_print_octal_mode,
	[arg_pointer] = arg_print_pointer,
	[arg_open_flags] = arg_print_open_flags,
	[arg_fd] = arg_print_signed_dec32,
	[arg_atfd] = arg_print_atfd,
	[arg_cstr] = arg_print_cstr,
	[arg_buf_in] = arg_print_input_buf,
	[arg_buf_out] = arg_print_output_buf,
	[arg_fcntl_cmd] = arg_print_fcntl_cmd,
	[arg_clone_flags] = arg_print_clone_flags,
	[arg_seek_whence] = arg_print_seek_whence,
	[arg_2fds] = arg_print_2fds,
	[arg_pipe2_flags] = arg_print_pipe2_flags,
	[arg_access_mode] = arg_print_access_mode,
	[arg_flock] = arg_print_flock
};

static const return_value_printer_func return_value_printer_table[] = {
	[rpointer] = print_pointer,
	[rhex] = print_hex,
	[rdec] = print_signed_dec,
	[rmode] = print_octal
};

static int log_fd = -1;

/*
 * intercept_setup_log
 * Open (create) a log file. If requested, the current processes pid
 * number is attached to the path.
 */
void
intercept_setup_log(const char *path, const char *trunc)
{
	char full_path[PATH_MAX];

	if (path == NULL || path[0] == '\0')
		return;

	char *c = full_path;
	while ((*c = *path) != '\0') {
		c++;
		path++;
	}

	/* c points to the terminating null */
	if (c[-1] == '-') {
		/* if the last char was '-', append the pid to the path */
		long pid = syscall_no_intercept(SYS_getpid);
		if (pid < 0)
			return;

		print_number(c, pid, 10, 0);
	}

	int flags = O_CREAT | O_RDWR | O_APPEND | O_TRUNC;
	if (trunc && trunc[0] == '0')
		flags &= ~O_TRUNC;

	intercept_log_close(); /* in case a log was already open */

	log_fd = (int)syscall_no_intercept(SYS_open, full_path, flags, 0700);

	xabort_on_syserror(log_fd, "opening log");
}

static char *
print_return_value(char *c, enum return_type type, long value)
{
	if (value > -4096 && value < 0) {
		c = print_signed_dec(c, value);
		*c++ = ' ';
		return print_cstr(c, strerror_no_intercept(-value));
	}

	return return_value_printer_table[type](c, value);
}

static char *
print_syscall(char *c, const struct syscall_desc *desc,
			enum intercept_log_result result_known, long result)
{
	const struct syscall_format *format = get_syscall_format(desc);

	if (format->name != NULL) {
		/* known syscall, e.g.: "open(" */
		c = print_cstr(c, format->name);
		c = print_cstr(c, "(");
	} else {
		/* unknown syscall, e.g.: "syscall(456, " */
		c = print_cstr(c, "syscall(");
		c = print_signed_dec(c, desc->nr);
		c = print_cstr(c, ", ");
	}

	for (int i = 0; format->args[i] != arg_none; ++i) {
		if (i != 0)
			c = print_cstr(c, ", ");

		arg_printer_func func = arg_printer_func_table[format->args[i]];
		c = func(c, desc, i, result_known, result);
	}
	c = print_cstr(c, ")");

	if (format->return_type != rnoreturn) {
		c = print_cstr(c, " = ");
		if (result_known == KNOWN)
			c = print_return_value(c, format->return_type, result);
		else
			*c++ = '?';
	}

	return c;
}

/*
 * Log syscalls after intercepting, in a human readable ( as much as possible )
 * format. The format is either:
 *
 * offset -- name(arguments...) = result
 *
 * where the name is known, or
 *
 * offset -- syscall(syscall_number, arguments...) = result
 *
 * where the name is not known.
 *
 * Each line starts with the offset of the syscall instruction in libc's ELF.
 * This should be easy to pass to addr2line, to see in what symbol in libc
 * the syscall was initiated.
 *
 * E.g.:
 * 0xdaea2 -- fstat(1, 0x7ffd115206f0) = 0
 *
 * Each syscall should be logged after being executed, so the result can be
 * logged as well.
 */
void
intercept_log_syscall(const struct patch_desc *patch,
			const struct syscall_desc *desc,
			enum intercept_log_result result_known, long result)
{
	if (log_fd < 0)
		return;

	char buffer[0x1000];
	char *c = buffer;

	/* prefix: "/lib/libc.so 0x1234 -- " */
	c = print_cstr(c, patch->containing_lib_path);
	c = print_cstr(c, " ");
	c = print_hex(c, patch->syscall_offset);
	c = print_cstr(c, " -- ");

	c = print_syscall(c, desc, result_known, result);

	*c++ = '\n';

	syscall_no_intercept(SYS_write, log_fd, buffer, c - buffer);
}

/*
 * intercept_log
 * Write a buffer to the log, with a specified length.
 * No conversion is done to make it human readable.
 */
void
intercept_log(const char *buffer, size_t len)
{
	if (log_fd >= 0)
		syscall_no_intercept(SYS_write, log_fd, buffer, len);
}

/*
 * intercept_log_close
 * Closes the log, if one was open.
 */
void
intercept_log_close(void)
{
	if (log_fd >= 0) {
		syscall_no_intercept(SYS_close, log_fd);
		log_fd = -1;
	}
}
