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

#include <assert.h>
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

static long log_fd = -1;

void *
xmmap_anon(size_t size)
{
	void *addr = (void *) syscall_no_intercept(SYS_mmap,
				NULL, size,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANON, -1, 0);

	if (addr == MAP_FAILED)
		xabort();

	return addr;
}

void *
xmremap(void *addr, size_t old, size_t new)
{
	addr = (void *) syscall_no_intercept(SYS_mremap, addr,
				old, new, MREMAP_MAYMOVE);

	if (addr == MAP_FAILED)
		xabort();

	return addr;
}

void
xmunmap(void *addr, size_t len)
{
	if (syscall_no_intercept(SYS_munmap, addr, len) != 0)
		xabort();
}

long
xlseek(long fd, unsigned long off, int whence)
{
	long result = syscall_no_intercept(SYS_lseek, fd, off, whence);

	if (result < 0)
		xabort();

	return result;
}

void
xread(long fd, void *buffer, size_t size)
{
	if (syscall_no_intercept(SYS_read, fd,
	    (long)buffer, (long)size) != (long)size)
		xabort();
}

/*
 * intercept_setup_log
 * Open (create) a log file. If requested, the current processes pid
 * number is attached to the path.
 */
void
intercept_setup_log(const char *path_base, const char *trunc)
{
	char full_path[PATH_MAX];
	const char *path = path_base;

	if (path_base == NULL)
		return;

	if (path_base[strlen(path_base) - 1] == '-') {
		snprintf(full_path, sizeof(full_path), "%s%ld",
			path_base,
			syscall_no_intercept(SYS_getpid));

		path = full_path;
	}

	int flags = O_CREAT | O_RDWR | O_APPEND | O_TRUNC;
	if (trunc && trunc[0] == '0')
		flags &= ~O_TRUNC;

	intercept_log_close();

	log_fd = syscall_no_intercept(SYS_open, path, flags, 0700);

	if (log_fd < 0)
		xabort();
}

/*
 * print_open_flags
 * Parses and prints open syscall specific flags to the buffer passed as the
 * first argument.
 * Returns a pointer pointing to the first char right after the just
 * printed strings.
 */
static char *
print_open_flags(char *buffer, int flags)
{
	char *c = buffer;

	*c = 0;

	if (flags == 0)
		return c + sprintf(c, "O_RDONLY");

#ifdef O_EXEC
	if ((flags & O_EXEC) == O_EXEC)
		c += sprintf(c, "O_EXEC | ");
#endif
	if ((flags & O_RDWR) == O_RDWR)
		c += sprintf(c, "O_RDWR | ");
	if ((flags & O_WRONLY) == O_WRONLY)
		c += sprintf(c, "O_WRONLY | ");
	if ((flags & (O_WRONLY|O_RDWR)) == 0)
		c += sprintf(c, "O_RDONLY | ");
#ifdef O_SEARCH
	if ((flags & O_SEARCH) = O_SEARCH)
		c += sprintf(c, "O_SEARCH | ");
#endif
	if ((flags & O_APPEND) == O_APPEND)
		c += sprintf(c, "O_APPEND | ");
	if ((flags & O_CLOEXEC) == O_CLOEXEC)
		c += sprintf(c, "O_CLOEXEC | ");
	if ((flags & O_CREAT) == O_CREAT)
		c += sprintf(c, "O_CREAT | ");
	if ((flags & O_DIRECTORY) == O_DIRECTORY)
		c += sprintf(c, "O_DIRECTORY | ");
	if ((flags & O_DSYNC) == O_DSYNC)
		c += sprintf(c, "O_DSYNC | ");
	if ((flags & O_EXCL) == O_EXCL)
		c += sprintf(c, "O_EXCL | ");
	if ((flags & O_NOCTTY) == O_NOCTTY)
		c += sprintf(c, "O_NOCTTY | ");
	if ((flags & O_NOFOLLOW) == O_NOFOLLOW)
		c += sprintf(c, "O_NOFOLLOW | ");
	if ((flags & O_NONBLOCK) == O_NONBLOCK)
		c += sprintf(c, "O_NONBLOCK | ");
	if ((flags & O_RSYNC) == O_RSYNC)
		c += sprintf(c, "O_RSYNC | ");
	if ((flags & O_SYNC) == O_SYNC)
		c += sprintf(c, "O_SYNC | ");
	if ((flags & O_TRUNC) == O_TRUNC)
		c += sprintf(c, "O_TRUNC | ");
#ifdef O_TTY_INIT
	if ((flags & O_TTY_INIT) == O_TTY_INIT)
		c += sprintf(c, "O_TTY_INIT | ");
#endif

#ifdef O_EXEC
	flags &= ~O_EXEC;
#endif
#ifdef O_TTY_INIT
	flags &= ~O_TTY_INIT;
#endif
#ifdef O_SEARCH
	flags &= ~O_SEARCH;
#endif

	flags &= ~(O_RDONLY | O_RDWR | O_WRONLY | O_APPEND |
	    O_CLOEXEC | O_CREAT | O_DIRECTORY | O_DSYNC | O_EXCL |
	    O_NOCTTY | O_NOFOLLOW | O_NONBLOCK | O_RSYNC | O_SYNC |
	    O_TRUNC);

	if (flags != 0) {
		/*
		 * Some values in the flag were not recognized, just print the
		 * raw number.
		 * e.g.: "O_RDONLY | O_NONBLOCK | 0x9876"
		 */
		c += sprintf(c, "0x%dx", flags);
	} else if (c != buffer) {
		/*
		 * All bits in flag were parsed, and the pointer c does not
		 * point to the start of the buffer, therefore some text was
		 * written already, with a separator on the end. Remove the
		 * trailing three characters: " | "
		 *
		 * e.g.: "O_RDONLY | O_NONBLOCK | " -> "O_RDONLY | O_NONBLOCK"
		 */
		c -= 3;
		*c = 0;
	}

	return c;
}

/*
 * fcntl_name
 * Returns a pointer to string literal describing an fcntl command.
 */
static const char *
fcntl_name(long cmd)
{
#define F(x) case x: return #x;
	switch (cmd) {
		F(F_DUPFD);
		F(F_DUPFD_CLOEXEC);
		F(F_GETFD);
		F(F_SETFD);
		F(F_GETFL);
		F(F_SETFL);
		F(F_SETLK);
		F(F_SETLKW);
		F(F_GETLK);
#ifdef F_OFD_SETLK
		F(F_OFD_SETLK);
		F(F_OFD_SETLKW);
		F(F_OFD_GETLK);
#endif
		F(F_GETOWN);
		F(F_SETOWN);
		F(F_GETOWN_EX);
		F(F_SETOWN_EX);
		F(F_GETSIG);
		F(F_SETSIG);
		F(F_SETLEASE);
		F(F_GETLEASE);
		F(F_NOTIFY);
		F(F_SETPIPE_SZ);
		F(F_GETPIPE_SZ);
#ifdef F_ADD_SEALS
		F(F_ADD_SEALS);
		F(F_GET_SEALS);
		F(F_SEAL_SEAL);
		F(F_SEAL_SHRINK);
		F(F_SEAL_GROW);
		F(F_SEAL_WRITE);
#endif
	}
	return "unknown";
#undef F
}

/*
 * print_fcntl_cmd
 * Prints an fcntl command in a human readable format to a buffer,
 * advances to char pointer, and returns the pointer pointing right
 * after the just printed text.
 */
static char *
print_fcntl_cmd(char *buffer, long cmd)
{
	return buffer + sprintf(buffer, "%ld (%s)", cmd, fcntl_name(cmd));
}

/*
 * print_clone_flags
 * Prints SYS_clone specific flags into the buffer provided. Does not return
 * the to pointer advanced while printing.
 */
static char *
print_clone_flags(char buffer[static 0x100], long flags)
{
	char *c = buffer;

	*c = '\0';

	if ((flags & CLONE_CHILD_CLEARTID) == CLONE_CHILD_CLEARTID)
		c += sprintf(c, "CLONE_CHILD_CLEARTID | ");
	if ((flags & CLONE_CHILD_SETTID) == CLONE_CHILD_SETTID)
		c += sprintf(c, "CLONE_CHILD_SETTID | ");
	if ((flags & CLONE_FILES) == CLONE_FILES)
		c += sprintf(c, "CLONE_FILES | ");
	if ((flags & CLONE_FS) == CLONE_FS)
		c += sprintf(c, "CLONE_FS | ");
	if ((flags & CLONE_IO) == CLONE_IO)
		c += sprintf(c, "CLONE_IO | ");
#ifdef CLONE_NEWCGROUP
	if ((flags & CLONE_NEWCGROUP) == CLONE_NEWCGROUP)
		c += sprintf(c, "CLONE_NEWCGROUP | ");
#endif
#ifdef CLONE_NEWIPC
	if ((flags & CLONE_NEWIPC) == CLONE_NEWIPC)
		c += sprintf(c, "CLONE_NEWIPC | ");
#endif
#ifdef CLONE_NEWNET
	if ((flags & CLONE_NEWNET) == CLONE_NEWNET)
		c += sprintf(c, "CLONE_NEWNET | ");
#endif
#ifdef CLONE_NEWNS
	if ((flags & CLONE_NEWNS) == CLONE_NEWNS)
		c += sprintf(c, "CLONE_NEWNS | ");
#endif
#ifdef CLONE_NEWPID
	if ((flags & CLONE_NEWPID) == CLONE_NEWPID)
		c += sprintf(c, "CLONE_NEWPID | ");
#endif
	if ((flags & CLONE_NEWUSER) == CLONE_NEWUSER)
		c += sprintf(c, "CLONE_NEWUSER | ");
#ifdef CLONE_NEWUTS
	if ((flags & CLONE_NEWUTS) == CLONE_NEWUTS)
		c += sprintf(c, "CLONE_NEWUTS | ");
#endif
	if ((flags & CLONE_PARENT) == CLONE_PARENT)
		c += sprintf(c, "CLONE_PARENT | ");
	if ((flags & CLONE_PARENT_SETTID) == CLONE_PARENT_SETTID)
		c += sprintf(c, "CLONE_PARENT_SETTID | ");
	if ((flags & CLONE_PTRACE) == CLONE_PTRACE)
		c += sprintf(c, "CLONE_PTRACE | ");
	if ((flags & CLONE_SETTLS) == CLONE_SETTLS)
		c += sprintf(c, "CLONE_SETTLS | ");
	if ((flags & CLONE_SIGHAND) == CLONE_SIGHAND)
		c += sprintf(c, "CLONE_SIGHAND | ");
	if ((flags & CLONE_SYSVSEM) == CLONE_SYSVSEM)
		c += sprintf(c, "CLONE_SYSVSEM | ");
	if ((flags & CLONE_THREAD) == CLONE_THREAD)
		c += sprintf(c, "CLONE_THREAD | ");
	if ((flags & CLONE_UNTRACED) == CLONE_UNTRACED)
		c += sprintf(c, "CLONE_UNTRACED | ");
	if ((flags & CLONE_VFORK) == CLONE_VFORK)
		c += sprintf(c, "CLONE_VFORK | ");
	if ((flags & CLONE_VM) == CLONE_VM)
		c += sprintf(c, "CLONE_VM | ");

	if (c != buffer) {
		c -= 3;
		*c = '\0';
	} else {
		c += sprintf(buffer, "%ld", flags);
	}

	return c;
}

/*
 * The formats of syscall arguments, as they should appear in logs.
 */

/* decimal number */
#define F_DEC 1

/* mode_t, octal number ( open, chmod, etc.. ) */
#define F_OCT_MODE 2

/* hexadecimal number, with zero padding e.g. pointers */
#define F_HEX 3

/* zero terminated string */
#define F_STR 4

/* buffer, with a given size */
#define F_BUF 5

/* only used for oflags in open, openat */
#define F_OPEN_FLAGS 6

/* 2nd argument of fcntl */
#define F_FCNTL_CMD 7

/* 1st argument of clone */
#define F_CLONE_FLAGS 8

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
	static const char xdigit[16] = "0123456789abcdef";

	char *dst_end = dst + dst_size - 5;

	if (src == NULL)
		return dst + sprintf(dst, "(null)");

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
				*dst++ = xdigit[(unsigned char)(*src) / 16];
				*dst++ = xdigit[(unsigned char)(*src) % 16];
			}

		}

		++src;

		if (!zero_term)
			--src_size;
	}

	if ((src_size > 0 && !zero_term) || (zero_term && *src != 0))
		dst += sprintf(dst, "...");

	*dst++ = '"';
	*dst = 0;

	return dst;
}

/*
 * print_syscall
 * A more general way of printing syscalls into a buffer. The args argument
 * specifies the number of syscall arguments to be printed, the rest of the
 * arguments specifiy their format.
 *
 * Returns a pointer pointing to right after the just printed text.
 */
static char *
print_syscall(char *b, const char *name, unsigned args, ...)
{
	bool first = true;
	va_list ap;

	b += sprintf(b, "%s(", name);

	va_start(ap, args);

	while (args > 0) {
		int format = va_arg(ap, int);

		if (!first) {
			*b++ = ',';
			*b++ = ' ';
		}

		if (format == F_DEC) {
			b += sprintf(b, "%ld", va_arg(ap, long));
		} else if (format == F_OCT_MODE) {
			b += sprintf(b, "0%lo", va_arg(ap, unsigned long));
		} else if (format == F_HEX) {
			b += sprintf(b, "0x%lx", va_arg(ap, unsigned long));
		} else if (format == F_STR) {
			b = xprint_escape(b, va_arg(ap, char *), 0x80, true, 0);
		} else if (format == F_BUF) {
			size_t size = va_arg(ap, size_t);
			const char *data = va_arg(ap, char *);
			b = xprint_escape(b, data, 0x80, false, size);
		} else if (format == F_OPEN_FLAGS) {
			b = print_open_flags(b, va_arg(ap, int));
		} else if (format == F_FCNTL_CMD) {
			b = print_fcntl_cmd(b, va_arg(ap, long));
		} else if (format == F_CLONE_FLAGS) {
			b = print_clone_flags(b, va_arg(ap, long));
		}

		--args;
		first = false;
	}

	if (va_arg(ap, enum intercept_log_result) == KNOWN)
		b += sprintf(b, ") = %ld", va_arg(ap, long));
	else
		b += sprintf(b, ") = ?");

	va_end(ap);

	return b;
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
intercept_log_syscall(const char *libpath, long nr, long arg0, long arg1,
			long arg2, long arg3,
			long arg4, long arg5, unsigned long syscall_offset,
			enum intercept_log_result result_known, long result)
{
	if (log_fd < 0)
		return;

	char buffer[0x1000];
	char *buf = buffer;

	buf += sprintf(buf, "%s 0x%lx -- ", libpath, syscall_offset);

	if (nr == SYS_read) {
		ssize_t print_size = (ssize_t)result;

		if (result_known == UNKNOWN || result < 0) {
			/*
			 * Avoid printing the buffer before the syscall.
			 * It is useless, and can trigger a message from
			 * valgrind.
			 */
			print_size = 0;
		}

		buf = print_syscall(buf, "read", 3,
				F_DEC, arg0,
				F_BUF, print_size, arg1,
				F_DEC, arg2,
				result_known, result);
	} else if (nr == SYS_write) {
		buf = print_syscall(buf, "write", 3,
				F_DEC, arg0,
				F_BUF, arg2, arg1,
				F_DEC, arg2,
				result_known, result);
	} else if (nr == SYS_open) {
		buf = print_syscall(buf, "open", 3,
				F_STR, arg0,
				F_OPEN_FLAGS, arg1,
				F_OCT_MODE, arg2,
				result_known, result);
	} else if (nr == SYS_close) {
		buf = print_syscall(buf, "close", 1,
				F_DEC, arg0,
				result_known, result);
	} else if (nr == SYS_stat) {
		buf = print_syscall(buf, "stat", 2,
				F_STR, arg0,
				F_HEX, arg1,
				result_known, result);
	} else if (nr == SYS_fstat) {
		buf = print_syscall(buf, "fstat", 2,
				F_DEC, arg0,
				F_HEX, arg1,
				result_known, result);
	} else if (nr == SYS_lstat) {
		buf = print_syscall(buf, "lstat", 2,
				F_STR, arg0,
				F_HEX, arg1,
				result_known, result);
	} else if (nr == SYS_lseek) {
		buf = print_syscall(buf, "lseek", 3,
				F_DEC, arg0,
				F_DEC, arg1,
				F_DEC, arg2,
				result_known, result);
	} else if (nr == SYS_mmap) {
		buf = print_syscall(buf, "mmap", 6,
				F_HEX, arg0,
				F_DEC, arg1,
				F_DEC, arg2,
				F_DEC, arg3,
				F_DEC, arg4,
				F_HEX, arg5,
				result_known, result);
	} else if (nr == SYS_mprotect) {
		buf = print_syscall(buf, "mprotect", 3,
				F_HEX, arg0,
				F_DEC, arg1,
				F_DEC, arg2,
				result_known, result);
	} else if (nr == SYS_munmap) {
		buf = print_syscall(buf, "munmap", 2,
				F_HEX, arg0,
				F_DEC, arg1,
				result_known, result);
	} else if (nr == SYS_brk) {
		buf = print_syscall(buf, "brk", 1,
				F_DEC, arg0,
				result_known, result);
	} else if (nr == SYS_ioctl) {
		buf = print_syscall(buf, "ioctl", 3,
				F_DEC, arg0,
				F_DEC, arg1,
				F_DEC, arg2,
				result_known, result);
	} else if (nr == SYS_pread64) {
		buf = print_syscall(buf, "pread64", 4,
				F_DEC, arg0,
				F_BUF, arg2, arg1,
				F_DEC, arg2,
				F_DEC, arg3,
				result_known, result);
	} else if (nr == SYS_pwrite64) {
		buf = print_syscall(buf, "pwrite64", 4,
				F_DEC, arg0,
				F_BUF, arg2, arg1,
				F_DEC, arg2,
				F_DEC, arg3,
				result_known, result);
	} else if (nr == SYS_readv) {
		buf = print_syscall(buf, "readv", 3,
				F_DEC, arg0,
				F_HEX, arg1,
				F_DEC, arg2,
				result_known, result);
	} else if (nr == SYS_writev) {
		buf = print_syscall(buf, "writev", 3,
				F_DEC, arg0,
				F_HEX, arg1,
				F_DEC, arg2,
				result_known, result);
	} else if (nr == SYS_access) {
		buf = print_syscall(buf, "access", 2,
				F_STR, arg0,
				F_DEC, arg1,
				result_known, result);
	} else if (nr == SYS_mremap) {
		buf = print_syscall(buf, "mremap", 5,
				F_HEX, arg0,
				F_DEC, arg1,
				F_DEC, arg2,
				F_DEC, arg3,
				F_HEX, arg4,
				result_known, result);
	} else if (nr == SYS_msync) {
		buf = print_syscall(buf, "msync", 3,
				F_HEX, arg0,
				F_DEC, arg1,
				F_DEC, arg2,
				result_known, result);
	} else if (nr == SYS_dup) {
		buf = print_syscall(buf, "dup", 1,
				F_DEC, arg0,
				result_known, result);
	} else if (nr == SYS_dup2) {
		buf = print_syscall(buf, "dup2", 2,
				F_DEC, arg0,
				F_DEC, arg1,
				result_known, result);
	} else if (nr == SYS_fcntl) {
		buf = print_syscall(buf, "fcntl", 3,
				F_DEC, arg0,
				F_FCNTL_CMD, arg1,
				F_DEC, arg1,
				result_known, result);
	} else if (nr == SYS_flock) {
		buf = print_syscall(buf, "flock", 2,
				F_DEC, arg0,
				F_DEC, arg1,
				result_known, result);
	} else if (nr == SYS_fsync) {
		buf = print_syscall(buf, "fsync", 1,
				F_DEC, arg0,
				result_known, result);
	} else if (nr == SYS_fdatasync) {
		buf = print_syscall(buf, "fdatasync", 1,
				F_DEC, arg0,
				result_known, result);
	} else if (nr == SYS_truncate) {
		buf = print_syscall(buf, "truncate", 2,
				F_STR, arg0,
				F_DEC, arg1,
				result_known, result);
	} else if (nr == SYS_ftruncate) {
		buf = print_syscall(buf, "ftruncate", 2,
				F_DEC, arg0,
				F_DEC, arg1,
				result_known, result);
	} else if (nr == SYS_getdents) {
		buf = print_syscall(buf, "getdents", 3,
				F_DEC, arg0,
				F_HEX, arg1,
				F_DEC, arg2,
				result_known, result);
	} else if (nr == SYS_getcwd) {
		buf = print_syscall(buf, "getcwd", 2,
				F_STR, arg0,
				F_DEC, arg1,
				result_known, result);
	} else if (nr == SYS_chdir) {
		buf = print_syscall(buf, "chdir", 1,
				F_STR, arg0,
				result_known, result);
	} else if (nr == SYS_fchdir) {
		buf = print_syscall(buf, "fchdir", 1,
				F_DEC, arg0,
				result_known, result);
	} else if (nr == SYS_rename) {
		buf = print_syscall(buf, "rename", 2,
				F_STR, arg0,
				F_STR, arg1,
				result_known, result);
	} else if (nr == SYS_mkdir) {
		buf = print_syscall(buf, "mkdir", 2,
				F_STR, arg0,
				F_OCT_MODE, arg1,
				result_known, result);
	} else if (nr == SYS_rmdir) {
		buf = print_syscall(buf, "rmdir", 1,
				F_STR, arg0,
				result_known, result);
	} else if (nr == SYS_creat) {
		buf = print_syscall(buf, "creat", 2,
				F_STR, arg0,
				F_OCT_MODE, arg1,
				result_known, result);
	} else if (nr == SYS_link) {
		buf = print_syscall(buf, "link", 2,
				F_STR, arg0,
				F_STR, arg1,
				result_known, result);
	} else if (nr == SYS_unlink) {
		buf = print_syscall(buf, "unlink", 1,
				F_STR, arg0,
				result_known, result);
	} else if (nr == SYS_symlink) {
		buf = print_syscall(buf, "symlink", 2,
				F_STR, arg0,
				F_STR, arg1,
				result_known, result);
	} else if (nr == SYS_readlink) {
		ssize_t print_size = (ssize_t)result;

		if (result_known == UNKNOWN || result < 0)
			print_size = 0;

		buf = print_syscall(buf, "readlink", 3,
				F_STR, arg0,
				F_BUF, print_size, arg1,
				F_DEC, arg2,
				result_known, result);
	} else if (nr == SYS_chmod) {
		buf = print_syscall(buf, "chmod", 2,
				F_STR, arg0,
				F_OCT_MODE, arg2,
				result_known, result);
	} else if (nr == SYS_fchmod) {
		buf = print_syscall(buf, "fchmod", 2,
				F_DEC, arg0,
				F_OCT_MODE, arg2,
				result_known, result);
	} else if (nr == SYS_chown) {
		buf = print_syscall(buf, "chown", 3,
				F_STR, arg0,
				F_DEC, arg1,
				F_DEC, arg2,
				result_known, result);
	} else if (nr == SYS_fchown) {
		buf = print_syscall(buf, "fchown", 3,
				F_DEC, arg0,
				F_DEC, arg1,
				F_DEC, arg2,
				result_known, result);
	} else if (nr == SYS_lchown) {
		buf = print_syscall(buf, "lchown", 3,
				F_STR, arg0,
				F_DEC, arg1,
				F_DEC, arg2,
				result_known, result);
	} else if (nr == SYS_umask) {
		buf = print_syscall(buf, "umask", 1,
				F_OCT_MODE, arg0,
				result_known, result);
	} else if (nr == SYS_mknod) {
		buf = print_syscall(buf, "mknod", 3,
				F_STR, arg0,
				F_OCT_MODE, arg1,
				F_DEC, arg2,
				result_known, result);
	} else if (nr == SYS_statfs) {
		buf = print_syscall(buf, "statfs", 2,
				F_STR, arg0,
				F_HEX, arg1,
				result_known, result);
	} else if (nr == SYS_fstatfs) {
		buf = print_syscall(buf, "fstatfs", 2,
				F_DEC, arg0,
				F_HEX, arg1,
				result_known, result);
	} else if (nr == SYS_chroot) {
		buf = print_syscall(buf, "chroot", 1,
				F_STR, arg0,
				result_known, result);
	} else if (nr == SYS_readahead) {
		buf = print_syscall(buf, "readahead", 3,
				F_DEC, arg0,
				F_DEC, arg1,
				F_DEC, arg2,
				result_known, result);
	} else if (nr == SYS_getdents64) {
		buf = print_syscall(buf, "getdents64", 3,
				F_DEC, arg0,
				F_HEX, arg1,
				F_DEC, arg2,
				result_known, result);
	} else if (nr == SYS_fadvise64) {
		buf = print_syscall(buf, "fadvise64", 4,
				F_DEC, arg0,
				F_DEC, arg1,
				F_DEC, arg2,
				F_DEC, arg3,
				result_known, result);
	} else if (nr == SYS_openat) {
		buf = print_syscall(buf, "openat", 4,
				F_DEC, arg0,
				F_STR, arg1,
				F_OPEN_FLAGS, arg2,
				F_OCT_MODE, arg3,
				result_known, result);
	} else if (nr == SYS_mkdirat) {
		buf = print_syscall(buf, "mkdirat", 4,
				F_DEC, arg0,
				F_STR, arg1,
				F_OPEN_FLAGS, arg2,
				result_known, result);
	} else if (nr == SYS_mknodat) {
		buf = print_syscall(buf, "mknodat", 4,
				F_DEC, arg0,
				F_STR, arg1,
				F_OCT_MODE, arg2,
				F_DEC, arg3,
				result_known, result);
	} else if (nr == SYS_fchownat) {
		buf = print_syscall(buf, "fchownat", 5,
				F_DEC, arg0,
				F_STR, arg1,
				F_DEC, arg2,
				F_DEC, arg3,
				F_DEC, arg4,
				result_known, result);
	} else if (nr == SYS_futimesat) {
		buf = print_syscall(buf, "futimesat", 3,
				F_DEC, arg0,
				F_STR, arg1,
				F_HEX, arg2,
				result_known, result);
	} else if (nr == SYS_newfstatat) {
		buf = print_syscall(buf, "newfstatat", 4,
				F_DEC, arg0,
				F_STR, arg1,
				F_HEX, arg2,
				F_DEC, arg3,
				result_known, result);
	} else if (nr == SYS_unlinkat) {
		buf = print_syscall(buf, "unlinkat", 3,
				F_DEC, arg0,
				F_STR, arg1,
				F_DEC, arg2,
				result_known, result);
	} else if (nr == SYS_renameat) {
		buf = print_syscall(buf, "renameat", 4,
				F_DEC, arg0,
				F_STR, arg1,
				F_DEC, arg2,
				F_STR, arg3,
				result_known, result);
	} else if (nr == SYS_linkat) {
		buf = print_syscall(buf, "linkat", 5,
				F_DEC, arg0,
				F_STR, arg1,
				F_DEC, arg2,
				F_STR, arg3,
				F_DEC, arg4,
				result_known, result);
	} else if (nr == SYS_symlinkat) {
		buf = print_syscall(buf, "symlinkat", 3,
				F_STR, arg0,
				F_DEC, arg1,
				F_STR, arg2,
				result_known, result);
	} else if (nr == SYS_readlinkat) {
		buf = print_syscall(buf, "readlinkat", 4,
				F_DEC, arg0,
				F_STR, arg1,
				F_STR, arg2,
				F_DEC, arg3,
				result_known, result);
	} else if (nr == SYS_fchmodat) {
		buf = print_syscall(buf, "fchmodat", 3,
				F_DEC, arg0,
				F_STR, arg1,
				F_OCT_MODE, arg2,
				result_known, result);
	} else if (nr == SYS_faccessat) {
		buf = print_syscall(buf, "faccessat", 4,
				F_DEC, arg0,
				F_STR, arg1,
				F_OCT_MODE, arg2,
				F_DEC, arg3,
				result_known, result);
	} else if (nr == SYS_splice) {
		buf = print_syscall(buf, "splice", 6,
				F_DEC, arg0,
				F_HEX, arg1,
				F_DEC, arg2,
				F_HEX, arg3,
				F_DEC, arg4,
				F_DEC, arg5,
				result_known, result);
	} else if (nr == SYS_tee) {
		buf = print_syscall(buf, "tee", 4,
				F_DEC, arg0,
				F_DEC, arg1,
				F_DEC, arg2,
				F_DEC, arg3,
				result_known, result);
	} else if (nr == SYS_sync_file_range) {
		buf = print_syscall(buf, "sync_file_range", 4,
				F_DEC, arg0,
				F_DEC, arg1,
				F_DEC, arg2,
				F_DEC, arg3,
				result_known, result);
	} else if (nr == SYS_utimensat) {
		buf = print_syscall(buf, "utimensat", 4,
				F_DEC, arg0,
				F_STR, arg1,
				F_HEX, arg2,
				F_DEC, arg3,
				result_known, result);
	} else if (nr == SYS_fallocate) {
		buf = print_syscall(buf, "fallocate", 4,
				F_DEC, arg0,
				F_DEC, arg1,
				F_DEC, arg2,
				F_DEC, arg3,
				result_known, result);
	} else if (nr == SYS_dup3) {
		buf = print_syscall(buf, "dup3", 3,
				F_DEC, arg0,
				F_DEC, arg1,
				F_DEC, arg2,
				result_known, result);
	} else if (nr == SYS_preadv) {
		buf = print_syscall(buf, "preadv", 4,
				F_DEC, arg0,
				F_HEX, arg1,
				F_DEC, arg2,
				F_DEC, arg3,
				result_known, result);
	} else if (nr == SYS_pwritev) {
		buf = print_syscall(buf, "pwritev", 3,
				F_DEC, arg0,
				F_HEX, arg1,
				F_DEC, arg2,
				result_known, result);
	} else if (nr == SYS_name_to_handle_at) {
		buf = print_syscall(buf, "name_to_handle_at", 5,
				F_DEC, arg0,
				F_STR, arg1,
				F_HEX, arg2,
				F_HEX, arg3,
				F_DEC, arg4,
				result_known, result);
	} else if (nr == SYS_open_by_handle_at) {
		buf = print_syscall(buf, "open_by_handle_at", 3,
				F_DEC, arg0,
				F_HEX, arg1,
				F_DEC, arg2,
				result_known, result);
	} else if (nr == SYS_syncfs) {
		buf = print_syscall(buf, "syncfs", 1,
				F_DEC, arg0,
				result_known, result);
#ifdef SYS_renameat2
	} else if (nr == SYS_renameat2) {
		buf = print_syscall(buf, "renameat2", 5,
				F_DEC, arg0,
				F_STR, arg1,
				F_DEC, arg2,
				F_STR, arg3,
				F_DEC, arg4,
				result_known, result);
#endif
	} else if (nr == SYS_execve) {
		buf = print_syscall(buf, "execve", 3,
				F_STR, arg0,
				F_HEX, arg1,
				F_HEX, arg2,
				result_known, result);
#ifdef SYS_execveat
	} else if (nr == SYS_execveat) {
		buf = print_syscall(buf, "execveat", 4,
				F_DEC, arg0,
				F_STR, arg1,
				F_HEX, arg2,
				F_HEX, arg3,
				result_known, result);
#endif
	} else if (nr == SYS_exit_group) {
		buf += sprintf(buf, "exit_group(%d)", (int)arg0);
	} else if (nr == SYS_exit) {
		buf += sprintf(buf, "exit(%d)", (int)arg0);
	} else if (nr == SYS_clone) {
		buf = print_syscall(buf, "clone", 5,
				F_CLONE_FLAGS, arg0,
				F_HEX, arg1,
				F_HEX, arg2,
				F_HEX, arg3,
				F_HEX, arg4,
				result_known, result);
	} else if (nr == SYS_fork) {
		buf = print_syscall(buf, "fork", 0, result_known, result);
	} else if (nr == SYS_vfork) {
		buf += sprintf(buf, "vfork()");
	} else if (nr == SYS_wait4) {
		buf = print_syscall(buf, "wait4", 4,
				F_DEC, arg0,
				F_HEX, arg1,
				F_HEX, arg2,
				F_HEX, arg3,
				result_known, result);
	} else if (nr == SYS_select) {
		buf = print_syscall(buf, "select", 5,
				F_DEC, arg0,
				F_HEX, arg1,
				F_HEX, arg2,
				F_HEX, arg3,
				F_HEX, arg4,
				result_known, result);
	} else if (nr == SYS_pselect6) {
		buf = print_syscall(buf, "pselect6", 6,
				F_DEC, arg0,
				F_HEX, arg1,
				F_HEX, arg2,
				F_HEX, arg3,
				F_HEX, arg4,
				F_HEX, arg5,
				result_known, result);
	} else if (nr == SYS_rt_sigaction) {
		buf = print_syscall(buf, "rt_sigaction", 3,
				F_DEC, arg0,
				F_HEX, arg1,
				F_HEX, arg2,
				result_known, result);
	} else if (nr == SYS_rt_sigprocmask) {
		buf = print_syscall(buf, "rt_sigprocmask", 3,
				F_DEC, arg0,
				F_HEX, arg1,
				F_HEX, arg2,
				result_known, result);
	} else if (nr == SYS_rt_sigreturn) {
		buf = print_syscall(buf, "rt_sigreturn", 1,
				F_HEX, arg0,
				result_known, result);
	} else if (nr == SYS_getuid) {
		buf = print_syscall(buf, "getuid", 0, result_known, result);
	} else if (nr == SYS_geteuid) {
		buf = print_syscall(buf, "geteuid", 0, result_known, result);
	} else if (nr == SYS_getgid) {
		buf = print_syscall(buf, "getgid", 0, result_known, result);
	} else if (nr == SYS_getegid) {
		buf = print_syscall(buf, "getegid", 0, result_known, result);
	} else if (nr == SYS_setsid) {
		buf = print_syscall(buf, "setsid", 0, result_known, result);
	} else if (nr == SYS_getsid) {
		buf = print_syscall(buf, "getsid", 1,
				F_DEC, arg0,
				result_known, result);
	} else if (nr == SYS_uname) {
		buf = print_syscall(buf, "uname", 1,
				F_HEX, arg0,
				result_known, result);
	} else if (nr == SYS_futex) {
		buf = print_syscall(buf, "futex", 6,
				F_HEX, arg0,
				F_DEC, arg1,
				F_DEC, arg2,
				F_HEX, arg3,
				F_HEX, arg4,
				F_DEC, arg5,
				result_known, result);
	} else if (nr == SYS_get_robust_list) {
		buf = print_syscall(buf, "get_robust_list", 3,
				F_DEC, arg0,
				F_HEX, arg1,
				F_HEX, arg2,
				result_known, result);
	} else if (nr == SYS_set_robust_list) {
		buf = print_syscall(buf, "set_robust_list", 2,
				F_HEX, arg0,
				F_DEC, arg1,
				result_known, result);
	} else if (nr == SYS_pipe) {
		buf = print_syscall(buf, "pipe", 1,
				F_HEX, arg0,
				result_known, result);
	} else if (nr == SYS_pipe2) {
		buf = print_syscall(buf, "pipe2", 2,
				F_HEX, arg0,
				F_HEX, arg1,
				result_known, result);
	} else if (nr == SYS_socket) {
		buf = print_syscall(buf, "socket", 3,
				F_DEC, arg0,
				F_DEC, arg1,
				F_DEC, arg2,
				result_known, result);
	} else if (nr == SYS_connect) {
		buf = print_syscall(buf, "connect", 3,
				F_DEC, arg0,
				F_HEX, arg1,
				F_DEC, arg2,
				result_known, result);
	} else if (nr == SYS_kill) {
		buf = print_syscall(buf, "kill", 2,
				F_DEC, arg0,
				F_DEC, arg1,
				result_known, result);
	} else if (nr == SYS_sysinfo) {
		buf = print_syscall(buf, "sysinfo", 1,
				F_HEX, arg0,
				result_known, result);
	} else if (nr == SYS_getxattr) {
		buf = print_syscall(buf, "getxattr", 4,
				F_STR, arg0,
				F_STR, arg1,
				F_BUF, arg3, arg2,
				F_DEC, arg3,
				result_known, result);
	} else if (nr == SYS_lgetxattr) {
		buf = print_syscall(buf, "lgetxattr", 4,
				F_STR, arg0,
				F_STR, arg1,
				F_BUF, arg3, arg2,
				F_DEC, arg3,
				result_known, result);
	} else if (nr == SYS_fgetxattr) {
		buf = print_syscall(buf, "fgetxattr", 4,
				F_DEC, arg0,
				F_STR, arg1,
				F_BUF, arg3, arg2,
				F_DEC, arg3,
				result_known, result);
	} else if (nr == SYS_setrlimit) {
		buf = print_syscall(buf, "setrlimit", 2,
				F_DEC, arg0,
				F_HEX, arg1,
				result_known, result);
	} else if (nr == SYS_getrlimit) {
		buf = print_syscall(buf, "getrlimit", 2,
				F_DEC, arg0,
				F_HEX, arg1,
				result_known, result);
	} else if (nr == SYS_getrusage) {
		buf = print_syscall(buf, "getrusage", 2,
				F_DEC, arg0,
				F_HEX, arg1,
				result_known, result);
	} else {
		buf = print_syscall(buf, "syscall", 7,
				F_DEC, nr,
				F_HEX, arg0,
				F_HEX, arg1,
				F_HEX, arg2,
				F_HEX, arg3,
				F_HEX, arg4,
				F_HEX, arg5,
				result_known, result);
	}

	*buf++ = '\n';

	intercept_log(buffer, (size_t)(buf - buffer));
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
		syscall_no_intercept(SYS_write, log_fd,
		    (long)buffer, (long)len);
}

/*
 * intercept_logs - intercept_log string
 * Similar to the above routine, except for null terminated strings.
 */
void
intercept_logs(const char *str)
{
	if (log_fd < 0)
		return;

	size_t len = strlen(str) + 1;
	char buffer[len];

	strncpy(buffer, str, len);
	buffer[len - 1] = '\n';

	syscall_no_intercept(SYS_write, log_fd,
	    (long)buffer, (long)len);
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
