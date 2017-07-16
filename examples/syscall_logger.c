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

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

long log_fd;

static char buffer[0x20000];
static size_t buffer_offset;

static bool
exchange_buffer_offset(size_t *expected, size_t new)
{
	return __atomic_compare_exchange_n(&buffer_offset, expected, new, false,
			__ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}

#define DUMP_TRESHOLD (sizeof(buffer) - 0x1000)

static void
append_buffer(const char *data, ssize_t len)
{
	static long writers;
	size_t offset = buffer_offset;

	while (true) {
		while (offset >= DUMP_TRESHOLD) {
			syscall_no_intercept(SYS_sched_yield);
			offset = buffer_offset;
		}

		__atomic_fetch_add(&writers, 1, __ATOMIC_SEQ_CST);

		if (exchange_buffer_offset(&offset, offset + len)) {
			memcpy(buffer + offset, data, len);
			break;
		}

		__atomic_fetch_sub(&writers, 1, __ATOMIC_SEQ_CST);
	}

	if (offset + len > DUMP_TRESHOLD) {
		while (__atomic_load_n(&writers, __ATOMIC_SEQ_CST) != 0)
			syscall_no_intercept(SYS_sched_yield);

		syscall_no_intercept(SYS_write, log_fd, buffer, buffer_offset);
		__atomic_store_n(&buffer_offset, 0, __ATOMIC_SEQ_CST);
	}
}

static char *
print_cstr(char *dst, const char *str)
{
	while (*str != '\0')
		*dst++ = *str++;

	return dst;
}

static const char xdigit[16] = "0123456789abcdef";

static char *
print_hex(char *dst, long n)
{
	*dst++ = '0';
	*dst++ = 'x';

	int shift = 64;
	do {
		shift -= 4;
		*dst++ = xdigit[(n >> shift) % 0x10];
	} while (shift > 0);

	return dst;
}

static char *
print_number(char *dst, unsigned long n, long base)
{
	char digits[0x40];

	digits[sizeof(digits) - 1] = '\0';
	char *c = digits + sizeof(digits) - 1;

	do {
		*--c = xdigit[n % base];
		n /= base;
	} while (n > 0);

	while (*c != '\0')
		*dst++ = *c++;

	return dst;
}

static char *
print_signed_dec(char *dst, long n)
{
	unsigned long nu;
	if (n >= 0) {
		nu = (unsigned long)n;
	} else {
		*dst++ = '-';
		nu = ((unsigned long)((0l - 1l) - n)) + 1lu;
	}

	return print_number(dst, nu, 10);
}

static char *
print_fd(char *dst, long n)
{
	return print_signed_dec(dst, n);
}

static char *
print_atfd(char *dst, long n)
{
	if (n == AT_FDCWD)
		return print_cstr(dst, "AT_FDCWD");
	else
		return print_signed_dec(dst, n);
}

#define CSTR_MAX_LEN 0x100

static char *
print_cstr_escaped(char *dst, const char *str)
{
	size_t len = 0;
	*dst++ = '"';
	while (*str != '\0' && len < CSTR_MAX_LEN) {
		if (*str == '\n') {
			*dst++ = '\\';
			*dst++ = 'n';
		} else if (*str == '\\') {
			*dst++ = '\\';
			*dst++ = '\\';
		} else if (*str == '\t') {
			*dst++ = '\\';
			*dst++ = 't';
		} else if (*str == '\"') {
			*dst++ = '\\';
			*dst++ = '"';
		} else if (isprint((unsigned char)*str)) {
			*dst++ = *str;
		} else {
			*dst++ = '\\';
			*dst++ = 'x';
			*dst++ = xdigit[((unsigned char)*str) / 0x10];
			*dst++ = xdigit[((unsigned char)*str) % 0x10];
		}

		++len;
		++str;
	}

	if (*str != '\0')
		dst = print_cstr(dst, "...");

	*dst++ = '"';

	return dst;
}

static const char *const error_codes[] = {
#ifdef EPERM
	[EPERM] = "Operation not permitted",
#endif
#ifdef ENOENT
	[ENOENT] = "No such file or directory",
#endif
#ifdef ESRCH
	[ESRCH] = "No such process",
#endif
#ifdef EINTR
	[EINTR] = "Interrupted system call",
#endif
#ifdef EIO
	[EIO] = "I/O error",
#endif
#ifdef ENXIO
	[ENXIO] = "No such device or address",
#endif
#ifdef E2BIG
	[E2BIG] = "Argument list too long",
#endif
#ifdef ENOEXEC
	[ENOEXEC] = "Exec format error",
#endif
#ifdef EBADF
	[EBADF] = "Bad file number",
#endif
#ifdef ECHILD
	[ECHILD] = "No child processes",
#endif
#ifdef EAGAIN
	[EAGAIN] = "Try again",
#endif
#ifdef ENOMEM
	[ENOMEM] = "Out of memory",
#endif
#ifdef EACCES
	[EACCES] = "Permission denied",
#endif
#ifdef EFAULT
	[EFAULT] = "Bad address",
#endif
#ifdef ENOTBLK
	[ENOTBLK] = "Block device required",
#endif
#ifdef EBUSY
	[EBUSY] = "Device or resource busy",
#endif
#ifdef EEXIST
	[EEXIST] = "File exists",
#endif
#ifdef EXDEV
	[EXDEV] = "Cross-device link",
#endif
#ifdef ENODEV
	[ENODEV] = "No such device",
#endif
#ifdef ENOTDIR
	[ENOTDIR] = "Not a directory",
#endif
#ifdef EISDIR
	[EISDIR] = "Is a directory",
#endif
#ifdef EINVAL
	[EINVAL] = "Invalid argument",
#endif
#ifdef ENFILE
	[ENFILE] = "File table overflow",
#endif
#ifdef EMFILE
	[EMFILE] = "Too many open files",
#endif
#ifdef ENOTTY
	[ENOTTY] = "Not a typewriter",
#endif
#ifdef ETXTBSY
	[ETXTBSY] = "Text file busy",
#endif
#ifdef EFBIG
	[EFBIG] = "File too large",
#endif
#ifdef ENOSPC
	[ENOSPC] = "No space left on device",
#endif
#ifdef ESPIPE
	[ESPIPE] = "Illegal seek",
#endif
#ifdef EROFS
	[EROFS] = "Read-only file system",
#endif
#ifdef EMLINK
	[EMLINK] = "Too many links",
#endif
#ifdef EPIPE
	[EPIPE] = "Broken pipe",
#endif
#ifdef EDOM
	[EDOM] = "Math argument out of domain of func",
#endif
#ifdef ERANGE
	[ERANGE] = "Math result not representable",
#endif
#ifdef EDEADLK
	[EDEADLK] = "Resource deadlock would occur",
#endif
#ifdef ENAMETOOLONG
	[ENAMETOOLONG] = "File name too long",
#endif
#ifdef ENOLCK
	[ENOLCK] = "No record locks available",
#endif
#ifdef ENOSYS
	[ENOSYS] = "Invalid system call number",
#endif
#ifdef ENOTEMPTY
	[ENOTEMPTY] = "Directory not empty",
#endif
#ifdef ELOOP
	[ELOOP] = "Too many symbolic links encountered",
#endif
#ifdef ENOMSG
	[ENOMSG] = "No message of desired type",
#endif
#ifdef EIDRM
	[EIDRM] = "Identifier removed",
#endif
#ifdef ECHRNG
	[ECHRNG] = "Channel number out of range",
#endif
#ifdef EL2NSYNC
	[EL2NSYNC] = "Level 2 not synchronized",
#endif
#ifdef EL3HLT
	[EL3HLT] = "Level 3 halted",
#endif
#ifdef EL3RST
	[EL3RST] = "Level 3 reset",
#endif
#ifdef ELNRNG
	[ELNRNG] = "Link number out of range",
#endif
#ifdef EUNATCH
	[EUNATCH] = "Protocol driver not attached",
#endif
#ifdef ENOCSI
	[ENOCSI] = "No CSI structure available",
#endif
#ifdef EL2HLT
	[EL2HLT] = "Level 2 halted",
#endif
#ifdef EBADE
	[EBADE] = "Invalid exchange",
#endif
#ifdef EBADR
	[EBADR] = "Invalid request descriptor",
#endif
#ifdef EXFULL
	[EXFULL] = "Exchange full",
#endif
#ifdef ENOANO
	[ENOANO] = "No anode",
#endif
#ifdef EBADRQC
	[EBADRQC] = "Invalid request code",
#endif
#ifdef EBADSLT
	[EBADSLT] = "Invalid slot",
#endif
#ifdef EBFONT
	[EBFONT] = "Bad font file format",
#endif
#ifdef ENOSTR
	[ENOSTR] = "Device not a stream",
#endif
#ifdef ENODATA
	[ENODATA] = "No data available",
#endif
#ifdef ETIME
	[ETIME] = "Timer expired",
#endif
#ifdef ENOSR
	[ENOSR] = "Out of streams resources",
#endif
#ifdef ENONET
	[ENONET] = "Machine is not on the network",
#endif
#ifdef ENOPKG
	[ENOPKG] = "Package not installed",
#endif
#ifdef EREMOTE
	[EREMOTE] = "Object is remote",
#endif
#ifdef ENOLINK
	[ENOLINK] = "Link has been severed",
#endif
#ifdef EADV
	[EADV] = "Advertise error",
#endif
#ifdef ESRMNT
	[ESRMNT] = "Srmount error",
#endif
#ifdef ECOMM
	[ECOMM] = "Communication error on send",
#endif
#ifdef EPROTO
	[EPROTO] = "Protocol error",
#endif
#ifdef EMULTIHOP
	[EMULTIHOP] = "Multihop attempted",
#endif
#ifdef EDOTDOT
	[EDOTDOT] = "RFS specific error",
#endif
#ifdef EBADMSG
	[EBADMSG] = "Not a data message",
#endif
#ifdef EOVERFLOW
	[EOVERFLOW] = "Value too large for defined data type",
#endif
#ifdef ENOTUNIQ
	[ENOTUNIQ] = "Name not unique on network",
#endif
#ifdef EBADFD
	[EBADFD] = "File descriptor in bad state",
#endif
#ifdef EREMCHG
	[EREMCHG] = "Remote address changed",
#endif
#ifdef ELIBACC
	[ELIBACC] = "Can not access a needed shared library",
#endif
#ifdef ELIBBAD
	[ELIBBAD] = "Accessing a corrupted shared library",
#endif
#ifdef ELIBSCN
	[ELIBSCN] = ".lib section in a.out corrupted",
#endif
#ifdef ELIBMAX
	[ELIBMAX] = "Attempting to link in too many shared libraries",
#endif
#ifdef ELIBEXEC
	[ELIBEXEC] = "Cannot exec a shared library directly",
#endif
#ifdef EILSEQ
	[EILSEQ] = "Illegal byte sequence",
#endif
#ifdef ERESTART
	[ERESTART] = "Interrupted system call should be restarted",
#endif
#ifdef ESTRPIPE
	[ESTRPIPE] = "Streams pipe error",
#endif
#ifdef EUSERS
	[EUSERS] = "Too many users",
#endif
#ifdef ENOTSOCK
	[ENOTSOCK] = "Socket operation on non-socket",
#endif
#ifdef EDESTADDRREQ
	[EDESTADDRREQ] = "Destination address required",
#endif
#ifdef EMSGSIZE
	[EMSGSIZE] = "Message too long",
#endif
#ifdef EPROTOTYPE
	[EPROTOTYPE] = "Protocol wrong type for socket",
#endif
#ifdef ENOPROTOOPT
	[ENOPROTOOPT] = "Protocol not available",
#endif
#ifdef EPROTONOSUPPORT
	[EPROTONOSUPPORT] = "Protocol not supported",
#endif
#ifdef ESOCKTNOSUPPORT
	[ESOCKTNOSUPPORT] = "Socket type not supported",
#endif
#ifdef EOPNOTSUPP
	[EOPNOTSUPP] = "Operation not supported on transport endpoint",
#endif
#ifdef EPFNOSUPPORT
	[EPFNOSUPPORT] = "Protocol family not supported",
#endif
#ifdef EAFNOSUPPORT
	[EAFNOSUPPORT] = "Address family not supported by protocol",
#endif
#ifdef EADDRINUSE
	[EADDRINUSE] = "Address already in use",
#endif
#ifdef EADDRNOTAVAIL
	[EADDRNOTAVAIL] = "Cannot assign requested address",
#endif
#ifdef ENETDOWN
	[ENETDOWN] = "Network is down",
#endif
#ifdef ENETUNREACH
	[ENETUNREACH] = "Network is unreachable",
#endif
#ifdef ENETRESET
	[ENETRESET] = "Network dropped connection because of reset",
#endif
#ifdef ECONNABORTED
	[ECONNABORTED] = "Software caused connection abort",
#endif
#ifdef ECONNRESET
	[ECONNRESET] = "Connection reset by peer",
#endif
#ifdef ENOBUFS
	[ENOBUFS] = "No buffer space available",
#endif
#ifdef EISCONN
	[EISCONN] = "Transport endpoint is already connected",
#endif
#ifdef ENOTCONN
	[ENOTCONN] = "Transport endpoint is not connected",
#endif
#ifdef ESHUTDOWN
	[ESHUTDOWN] = "Cannot send after transport endpoint shutdown",
#endif
#ifdef ETOOMANYREFS
	[ETOOMANYREFS] = "Too many references: cannot splice",
#endif
#ifdef ETIMEDOUT
	[ETIMEDOUT] = "Connection timed out",
#endif
#ifdef ECONNREFUSED
	[ECONNREFUSED] = "Connection refused",
#endif
#ifdef EHOSTDOWN
	[EHOSTDOWN] = "Host is down",
#endif
#ifdef EHOSTUNREACH
	[EHOSTUNREACH] = "No route to host",
#endif
#ifdef EALREADY
	[EALREADY] = "Operation already in progress",
#endif
#ifdef EINPROGRESS
	[EINPROGRESS] = "Operation now in progress",
#endif
#ifdef ESTALE
	[ESTALE] = "Stale file handle",
#endif
#ifdef EUCLEAN
	[EUCLEAN] = "Structure needs cleaning",
#endif
#ifdef ENOTNAM
	[ENOTNAM] = "Not a XENIX named type file",
#endif
#ifdef ENAVAIL
	[ENAVAIL] = "No XENIX semaphores available",
#endif
#ifdef EISNAM
	[EISNAM] = "Is a named type file",
#endif
#ifdef EREMOTEIO
	[EREMOTEIO] = "Remote I/O error",
#endif
#ifdef EDQUOT
	[EDQUOT] = "Quota exceeded",
#endif
#ifdef ENOMEDIUM
	[ENOMEDIUM] = "No medium found",
#endif
#ifdef EMEDIUMTYPE
	[EMEDIUMTYPE] = "Wrong medium type",
#endif
#ifdef ECANCELED
	[ECANCELED] = "Operation Canceled",
#endif
#ifdef ENOKEY
	[ENOKEY] = "Required key not available",
#endif
#ifdef EKEYEXPIRED
	[EKEYEXPIRED] = "Key has expired",
#endif
#ifdef EKEYREVOKED
	[EKEYREVOKED] = "Key has been revoked",
#endif
#ifdef EKEYREJECTED
	[EKEYREJECTED] = "Key was rejected by service",
#endif
#ifdef EOWNERDEAD
	[EOWNERDEAD] = "Owner died",
#endif
#ifdef ENOTRECOVERABLE
	[ENOTRECOVERABLE] = "State not recoverable",
#endif
#ifdef ERFKILL
	[ERFKILL] = "Operation not possible due to RF-kill",
#endif
#ifdef EHWPOISON
	[EHWPOISON] = "Memory page has hardware error",
#endif
};

static char *
print_rdec(char *dst, long n)
{
	dst = print_signed_dec(dst, n);

	if (n < 0 && n >= -((long)ARRAY_SIZE(error_codes))) {
		if (error_codes[-n] != NULL) {
			dst = print_cstr(dst, " (");
			dst = print_cstr(dst, error_codes[-n]);
			dst = print_cstr(dst, ")");
		}
	}

	return dst;
}

static char *
print_runsigned(char *dst, long n)
{
	return print_number(dst, (unsigned long)n, 10);
}

static char *
print_roct(char *dst, long n)
{
	*dst++ = '0';
	return print_number(dst, (unsigned long)n, 8);
}

#define MIN_AVAILABLE_REQUIRED (0x100 + 8 * CSTR_MAX_LEN)

static char *
print_unknown_syscall(char *dst, long syscall_number,
			const long args[static 6], long result)
{
	dst = print_cstr(dst, "syscall(");
	dst = print_number(dst, syscall_number, 10);
	for (unsigned i = 0; i < 6; ++i) {
		dst = print_cstr(dst, ", ");
		dst = print_hex(dst, args[i]);
	}
	dst = print_cstr(dst, ") = ");
	dst = print_hex(dst, result);
	return dst;
}

static char *
print_known_syscall(char *dst, const struct syscall_desc *desc,
			const long args[static 6], long result)
{
	dst = print_cstr(dst, desc->name);
	*dst++ = '(';

	for (unsigned i = 0; desc->args[i] != arg_none; ++i) {
		if (i > 0)
			dst = print_cstr(dst, ", ");

		switch (desc->args[i]) {
		case arg_fd:
			dst = print_fd(dst, args[i]);
			break;
		case arg_atfd:
			dst = print_atfd(dst, args[i]);
			break;
		case arg_cstr:
			dst = print_hex(dst, args[i]);
			dst = print_cstr_escaped(dst, (const char *)(args[i]));
			break;
		default:
			dst = print_hex(dst, args[i]);
			break;
		}
	}

	dst = print_cstr(dst, ") = ");
	switch (desc->return_type) {
	case rhex:
		dst = print_hex(dst, result);
		break;
	case rdec:
		dst = print_rdec(dst, result);
		break;
	case runsigned:
		dst = print_runsigned(dst, result);
		break;
	case roct:
		dst = print_roct(dst, result);
		break;
	}

	return dst;
}

static ssize_t
print_syscall(char *dst, long syscall_number, const long args[6], long result)
{
	const struct syscall_desc *desc = get_syscall_desc(syscall_number);
	char *c;

	if (desc != NULL)
		c = print_known_syscall(dst, desc, args, result);
	else
		c = print_unknown_syscall(dst, syscall_number, args, result);

	*c++ = '\n';
	return c - dst;
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

	char local_buffer[0x300];
	ssize_t len;

	len = print_syscall(local_buffer, syscall_number, args, *result);

	append_buffer(local_buffer, len);

	return 0;
}

static __attribute__((constructor)) void
start(void)
{
	const char *path = getenv("SYSCALL_LOG_PATH");

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
	if (buffer_offset > 0)
		syscall_no_intercept(SYS_write, log_fd, buffer, buffer_offset);
}
