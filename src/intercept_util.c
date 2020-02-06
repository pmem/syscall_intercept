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

#include "intercept_util.h"
#include "intercept.h"
#include "libsyscall_intercept_hook_point.h"

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <ctype.h>
#include <stddef.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syscall.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <sched.h>
#include <linux/limits.h>

void
mprotect_no_intercept(void *addr, size_t len, int prot,
			const char *msg_on_error)
{
	long result = syscall_no_intercept(SYS_mprotect, addr, len, prot);

	xabort_on_syserror(result, msg_on_error);
}

void *
xmmap_anon(size_t size)
{
	long addr = syscall_no_intercept(SYS_mmap,
				NULL, size,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANON, -1, (off_t)0);

	xabort_on_syserror(addr, __func__);

	return (void *) addr;
}

void *
xmremap(void *addr, size_t old, size_t new)
{
	long new_addr = syscall_no_intercept(SYS_mremap, addr,
				old, new, MREMAP_MAYMOVE);

	xabort_on_syserror(new_addr, __func__);

	return (void *) new_addr;
}

void
xmunmap(void *addr, size_t len)
{
	long result = syscall_no_intercept(SYS_munmap, addr, len);

	xabort_on_syserror(result, __func__);
}

long
xlseek(long fd, unsigned long off, int whence)
{
	long result = syscall_no_intercept(SYS_lseek, fd, off, whence);

	xabort_on_syserror(result, __func__);

	return result;
}

void
xread(long fd, void *buffer, size_t size)
{
	long result = syscall_no_intercept(SYS_read, fd, buffer, size);

	if (result != (long)size)
		xabort_errno(syscall_error_code(result), __func__);
}

/* BEGIN CSTYLED */
static const char *const error_strings[] = {
#ifdef EPERM
	[EPERM] = "EPERM (Operation not permitted)",
#endif
#ifdef ENOENT
	[ENOENT] = "ENOENT (No such file or directory)",
#endif
#ifdef ESRCH
	[ESRCH] = "ESRCH (No such process)",
#endif
#ifdef EINTR
	[EINTR] = "EINTR (Interrupted system call)",
#endif
#ifdef EIO
	[EIO] = "EIO (I/O error)",
#endif
#ifdef ENXIO
	[ENXIO] = "ENXIO (No such device or address)",
#endif
#ifdef E2BIG
	[E2BIG] = "E2BIG (Argument list too long)",
#endif
#ifdef ENOEXEC
	[ENOEXEC] = "ENOEXEC (Exec format error)",
#endif
#ifdef EBADF
	[EBADF] = "EBADF (Bad file number)",
#endif
#ifdef ECHILD
	[ECHILD] = "ECHILD (No child processes)",
#endif
#ifdef EAGAIN
	[EAGAIN] = "EAGAIN (Try again)",
#endif
#ifdef ENOMEM
	[ENOMEM] = "ENOMEM (Out of memory)",
#endif
#ifdef EACCES
	[EACCES] = "EACCES (Permission denied)",
#endif
#ifdef EFAULT
	[EFAULT] = "EFAULT (Bad address)",
#endif
#ifdef ENOTBLK
	[ENOTBLK] = "ENOTBLK (Block device required)",
#endif
#ifdef EBUSY
	[EBUSY] = "EBUSY (Device or resource busy)",
#endif
#ifdef EEXIST
	[EEXIST] = "EEXIST (File exists)",
#endif
#ifdef EXDEV
	[EXDEV] = "EXDEV (Cross-device link)",
#endif
#ifdef ENODEV
	[ENODEV] = "ENODEV (No such device)",
#endif
#ifdef ENOTDIR
	[ENOTDIR] = "ENOTDIR (Not a directory)",
#endif
#ifdef EISDIR
	[EISDIR] = "EISDIR (Is a directory)",
#endif
#ifdef EINVAL
	[EINVAL] = "EINVAL (Invalid argument)",
#endif
#ifdef ENFILE
	[ENFILE] = "ENFILE (File table overflow)",
#endif
#ifdef EMFILE
	[EMFILE] = "EMFILE (Too many open files)",
#endif
#ifdef ENOTTY
	[ENOTTY] = "ENOTTY (Not a typewriter)",
#endif
#ifdef ETXTBSY
	[ETXTBSY] = "ETXTBSY (Text file busy)",
#endif
#ifdef EFBIG
	[EFBIG] = "EFBIG (File too large)",
#endif
#ifdef ENOSPC
	[ENOSPC] = "ENOSPC (No space left on device)",
#endif
#ifdef ESPIPE
	[ESPIPE] = "ESPIPE (Illegal seek)",
#endif
#ifdef EROFS
	[EROFS] = "EROFS (Read-only file system)",
#endif
#ifdef EMLINK
	[EMLINK] = "EMLINK (Too many links)",
#endif
#ifdef EPIPE
	[EPIPE] = "EPIPE (Broken pipe)",
#endif
#ifdef EDOM
	[EDOM] = "EDOM (Math argument out of domain of func)",
#endif
#ifdef ERANGE
	[ERANGE] = "ERANGE (Math result not representable)",
#endif
#ifdef EDEADLK
	[EDEADLK] = "EDEADLK (Resource deadlock would occur)",
#endif
#ifdef ENAMETOOLONG
	[ENAMETOOLONG] = "ENAMETOOLONG (File name too long)",
#endif
#ifdef ENOLCK
	[ENOLCK] = "ENOLCK (No record locks available)",
#endif
#ifdef ENOSYS
	[ENOSYS] = "ENOSYS (Invalid system call number)",
#endif
#ifdef ENOTEMPTY
	[ENOTEMPTY] = "ENOTEMPTY (Directory not empty)",
#endif
#ifdef ELOOP
	[ELOOP] = "ELOOP (Too many symbolic links encountered)",
#endif
#ifdef ENOMSG
	[ENOMSG] = "ENOMSG (No message of desired type)",
#endif
#ifdef EIDRM
	[EIDRM] = "EIDRM (Identifier removed)",
#endif
#ifdef ECHRNG
	[ECHRNG] = "ECHRNG (Channel number out of range)",
#endif
#ifdef EL2NSYNC
	[EL2NSYNC] = "EL2NSYNC (Level 2 not synchronized)",
#endif
#ifdef EL3HLT
	[EL3HLT] = "EL3HLT (Level 3 halted)",
#endif
#ifdef EL3RST
	[EL3RST] = "EL3RST (Level 3 reset)",
#endif
#ifdef ELNRNG
	[ELNRNG] = "ELNRNG (Link number out of range)",
#endif
#ifdef EUNATCH
	[EUNATCH] = "EUNATCH (Protocol driver not attached)",
#endif
#ifdef ENOCSI
	[ENOCSI] = "ENOCSI (No CSI structure available)",
#endif
#ifdef EL2HLT
	[EL2HLT] = "EL2HLT (Level 2 halted)",
#endif
#ifdef EBADE
	[EBADE] = "EBADE (Invalid exchange)",
#endif
#ifdef EBADR
	[EBADR] = "EBADR (Invalid request descriptor)",
#endif
#ifdef EXFULL
	[EXFULL] = "EXFULL (Exchange full)",
#endif
#ifdef ENOANO
	[ENOANO] = "ENOANO (No anode)",
#endif
#ifdef EBADRQC
	[EBADRQC] = "EBADRQC (Invalid request code)",
#endif
#ifdef EBADSLT
	[EBADSLT] = "EBADSLT (Invalid slot)",
#endif
#ifdef EBFONT
	[EBFONT] = "EBFONT (Bad font file format)",
#endif
#ifdef ENOSTR
	[ENOSTR] = "ENOSTR (Device not a stream)",
#endif
#ifdef ENODATA
	[ENODATA] = "ENODATA (No data available)",
#endif
#ifdef ETIME
	[ETIME] = "ETIME (Timer expired)",
#endif
#ifdef ENOSR
	[ENOSR] = "ENOSR (Out of streams resources)",
#endif
#ifdef ENONET
	[ENONET] = "ENONET (Machine is not on the network)",
#endif
#ifdef ENOPKG
	[ENOPKG] = "ENOPKG (Package not installed)",
#endif
#ifdef EREMOTE
	[EREMOTE] = "EREMOTE (Object is remote)",
#endif
#ifdef ENOLINK
	[ENOLINK] = "ENOLINK (Link has been severed)",
#endif
#ifdef EADV
	[EADV] = "EADV (Advertise error)",
#endif
#ifdef ESRMNT
	[ESRMNT] = "ESRMNT (Srmount error)",
#endif
#ifdef ECOMM
	[ECOMM] = "ECOMM (Communication error on send)",
#endif
#ifdef EPROTO
	[EPROTO] = "EPROTO (Protocol error)",
#endif
#ifdef EMULTIHOP
	[EMULTIHOP] = "EMULTIHOP (Multihop attempted)",
#endif
#ifdef EDOTDOT
	[EDOTDOT] = "EDOTDOT (RFS specific error)",
#endif
#ifdef EBADMSG
	[EBADMSG] = "EBADMSG (Not a data message)",
#endif
#ifdef EOVERFLOW
	[EOVERFLOW] = "EOVERFLOW (Value too large for defined data type)",
#endif
#ifdef ENOTUNIQ
	[ENOTUNIQ] = "ENOTUNIQ (Name not unique on network)",
#endif
#ifdef EBADFD
	[EBADFD] = "EBADFD (File descriptor in bad state)",
#endif
#ifdef EREMCHG
	[EREMCHG] = "EREMCHG (Remote address changed)",
#endif
#ifdef ELIBACC
	[ELIBACC] = "ELIBACC (Can not access a needed shared library)",
#endif
#ifdef ELIBBAD
	[ELIBBAD] = "ELIBBAD (Accessing a corrupted shared library)",
#endif
#ifdef ELIBSCN
	[ELIBSCN] = "ELIBSCN (.lib section in a.out corrupted)",
#endif
#ifdef ELIBMAX
	[ELIBMAX] = "ELIBMAX (Attempting to link in too many shared libraries)",
#endif
#ifdef ELIBEXEC
	[ELIBEXEC] = "ELIBEXEC (Cannot exec a shared library directly)",
#endif
#ifdef EILSEQ
	[EILSEQ] = "EILSEQ (Illegal byte sequence)",
#endif
#ifdef ERESTART
	[ERESTART] = "ERESTART (Interrupted system call should be restarted)",
#endif
#ifdef ESTRPIPE
	[ESTRPIPE] = "ESTRPIPE (Streams pipe error)",
#endif
#ifdef EUSERS
	[EUSERS] = "EUSERS (Too many users)",
#endif
#ifdef ENOTSOCK
	[ENOTSOCK] = "ENOTSOCK (Socket operation on non-socket)",
#endif
#ifdef EDESTADDRREQ
	[EDESTADDRREQ] = "EDESTADDRREQ (Destination address required)",
#endif
#ifdef EMSGSIZE
	[EMSGSIZE] = "EMSGSIZE (Message too long)",
#endif
#ifdef EPROTOTYPE
	[EPROTOTYPE] = "EPROTOTYPE (Protocol wrong type for socket)",
#endif
#ifdef ENOPROTOOPT
	[ENOPROTOOPT] = "ENOPROTOOPT (Protocol not available)",
#endif
#ifdef EPROTONOSUPPORT
	[EPROTONOSUPPORT] = "EPROTONOSUPPORT (Protocol not supported)",
#endif
#ifdef ESOCKTNOSUPPORT
	[ESOCKTNOSUPPORT] = "ESOCKTNOSUPPORT (Socket type not supported)",
#endif
#ifdef EOPNOTSUPP
	[EOPNOTSUPP] = "EOPNOTSUPP (Operation not supported on transport endpoint)",
#endif
#ifdef EPFNOSUPPORT
	[EPFNOSUPPORT] = "EPFNOSUPPORT (Protocol family not supported)",
#endif
#ifdef EAFNOSUPPORT
	[EAFNOSUPPORT] = "EAFNOSUPPORT (Address family not supported by protocol)",
#endif
#ifdef EADDRINUSE
	[EADDRINUSE] = "EADDRINUSE (Address already in use)",
#endif
#ifdef EADDRNOTAVAIL
	[EADDRNOTAVAIL] = "EADDRNOTAVAIL (Cannot assign requested address)",
#endif
#ifdef ENETDOWN
	[ENETDOWN] = "ENETDOWN (Network is down)",
#endif
#ifdef ENETUNREACH
	[ENETUNREACH] = "ENETUNREACH (Network is unreachable)",
#endif
#ifdef ENETRESET
	[ENETRESET] = "ENETRESET (Network dropped connection because of reset)",
#endif
#ifdef ECONNABORTED
	[ECONNABORTED] = "ECONNABORTED (Software caused connection abort)",
#endif
#ifdef ECONNRESET
	[ECONNRESET] = "ECONNRESET (Connection reset by peer)",
#endif
#ifdef ENOBUFS
	[ENOBUFS] = "ENOBUFS (No buffer space available)",
#endif
#ifdef EISCONN
	[EISCONN] = "EISCONN (Transport endpoint is already connected)",
#endif
#ifdef ENOTCONN
	[ENOTCONN] = "ENOTCONN (Transport endpoint is not connected)",
#endif
#ifdef ESHUTDOWN
	[ESHUTDOWN] = "ESHUTDOWN (Cannot send after transport endpoint shutdown)",
#endif
#ifdef ETOOMANYREFS
	[ETOOMANYREFS] = "ETOOMANYREFS (Too many references: cannot splice)",
#endif
#ifdef ETIMEDOUT
	[ETIMEDOUT] = "ETIMEDOUT (Connection timed out)",
#endif
#ifdef ECONNREFUSED
	[ECONNREFUSED] = "ECONNREFUSED (Connection refused)",
#endif
#ifdef EHOSTDOWN
	[EHOSTDOWN] = "EHOSTDOWN (Host is down)",
#endif
#ifdef EHOSTUNREACH
	[EHOSTUNREACH] = "EHOSTUNREACH (No route to host)",
#endif
#ifdef EALREADY
	[EALREADY] = "EALREADY (Operation already in progress)",
#endif
#ifdef EINPROGRESS
	[EINPROGRESS] = "EINPROGRESS (Operation now in progress)",
#endif
#ifdef ESTALE
	[ESTALE] = "ESTALE (Stale file handle)",
#endif
#ifdef EUCLEAN
	[EUCLEAN] = "EUCLEAN (Structure needs cleaning)",
#endif
#ifdef ENOTNAM
	[ENOTNAM] = "ENOTNAM (Not a XENIX named type file)",
#endif
#ifdef ENAVAIL
	[ENAVAIL] = "ENAVAIL (No XENIX semaphores available)",
#endif
#ifdef EISNAM
	[EISNAM] = "EISNAM (Is a named type file)",
#endif
#ifdef EREMOTEIO
	[EREMOTEIO] = "EREMOTEIO (Remote I/O error)",
#endif
#ifdef EDQUOT
	[EDQUOT] = "EDQUOT (Quota exceeded)",
#endif
#ifdef ENOMEDIUM
	[ENOMEDIUM] = "ENOMEDIUM (No medium found)",
#endif
#ifdef EMEDIUMTYPE
	[EMEDIUMTYPE] = "EMEDIUMTYPE (Wrong medium type)",
#endif
#ifdef ECANCELED
	[ECANCELED] = "ECANCELED (Operation Canceled)",
#endif
#ifdef ENOKEY
	[ENOKEY] = "ENOKEY (Required key not available)",
#endif
#ifdef EKEYEXPIRED
	[EKEYEXPIRED] = "EKEYEXPIRED (Key has expired)",
#endif
#ifdef EKEYREVOKED
	[EKEYREVOKED] = "EKEYREVOKED (Key has been revoked)",
#endif
#ifdef EKEYREJECTED
	[EKEYREJECTED] = "EKEYREJECTED (Key was rejected by service)",
#endif
#ifdef EOWNERDEAD
	[EOWNERDEAD] = "EOWNERDEAD (Owner died)",
#endif
#ifdef ENOTRECOVERABLE
	[ENOTRECOVERABLE] = "ENOTRECOVERABLE (State not recoverable)",
#endif
#ifdef ERFKILL
	[ERFKILL] = "ERFKILL (Operation not possible due to RF-kill)",
#endif
#ifdef EHWPOISON
	[EHWPOISON] = "EHWPOISON (Memory page has hardware error)",
#endif
};
/* END CSTYLED */

const char *
strerror_no_intercept(long errnum)
{
	static const char unkown[] = "Unknown error";

	if (errnum < 0 || (size_t)errnum >= ARRAY_SIZE(error_strings))
		return unkown;

	if (error_strings[errnum] == NULL)
		return unkown;

	return error_strings[errnum];
}
