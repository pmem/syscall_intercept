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
static char *nextc;

static size_t
buffer_avaliable(void)
{
	return (size_t)(sizeof(buffer) - (size_t)(nextc - buffer));
}

static void
print_cstr(const char *name)
{
	while (*name != '\0')
		*nextc++ = *name++;
}

static const char xdigit[16] = "0123456789abcdef";

static void
print_hex(long n)
{
	*nextc++ = '0';
	*nextc++ = 'x';

	int shift = 64;
	do {
		shift -= 4;
		*nextc++ = xdigit[(n >> shift) % 0x10];
	} while (shift > 0);
}

static void
print_number(unsigned long n, long base)
{
	char digits[0x40];

	digits[sizeof(digits) - 1] = '\0';
	char *c = digits + sizeof(digits) - 2;

	do {
		*--c = xdigit[n % base];
		n /= base;
	} while (n > 0);

	while (*c != '\0')
		*nextc++ = *c++;
}

static void
print_signed_dec(long n)
{
	unsigned long nu;
	if (n >= 0) {
		nu = (unsigned long)n;
	} else {
		*nextc++ = '-';
		nu = ((unsigned long)((0l - 1L) - n)) + 1LU;
	}

	print_number(nu, 10);
}

static void
print_fd(long n)
{
	print_signed_dec(n);
}

static void
print_atfd(long n)
{
	if (n == AT_FDCWD)
		print_cstr("AT_FDCWD");
	else
		print_signed_dec(n);
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

static void
print_rdec(long n)
{
	print_signed_dec(n);

	if (n < 0 && n >= -((long)ARRAY_SIZE(error_codes))) {
		if (error_codes[-n] != NULL) {
			print_cstr(" (");
			print_cstr(error_codes[-n]);
			print_cstr(")");
		}
	}
}

static void
print_runsigned(long n)
{
	print_number((unsigned long)n, 10);
}

static void
print_roct(long n)
{
	nextc += '0';
	print_number((unsigned long)n, 8);
}

#define MIN_AVAILABLE_REQUIRED (0x100 + 8 * CSTR_MAX_LEN)

static void
print_unknown_syscall(long syscall_number, long args[static 6], long result)
{
	print_cstr("syscall(");
	print_number(syscall_number, 10);
	for (unsigned i = 0; i < 6; ++i) {
		print_cstr(", ");
		print_hex(args[i]);
	}
	print_cstr(") = ");
	print_hex(result);
	print_cstr("\n");
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
		case arg_atfd:
			print_atfd(args[i]);
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
