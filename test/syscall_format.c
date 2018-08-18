/*
 * Copyright 2017-2018, Intel Corporation
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
 * syscall_format.c
 * A simple test program that makes a lot of basic syscalls.
 * Basic in the sense of there being no special case for handling
 * them in syscall_intercept. The main goal is to test logging
 * of these syscalls.
 *
 */

#ifdef __clang__

#pragma clang optimize off
#pragma clang diagnostic ignored "-Wnonnull"
#pragma clang diagnostic ignored "-Wunused-result"
#pragma clang diagnostic ignored "-Wall"

#elif defined(__GNUC_MINOR__)

#pragma GCC optimize "-O0"
#pragma GCC diagnostic ignored "-Wnonnull"
#pragma GCC diagnostic ignored "-Wunused-result"
#pragma GCC diagnostic ignored "-Wall"

#endif

/* Avoid "warning _FORTIFY_SOURCE requires compiling with optimization (-O)" */
#ifdef _FORTIFY_SOURCE
#undef _FORTIFY_SOURCE
#endif

#include <asm/prctl.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/futex.h>
#include <linux/kexec.h>
#include <linux/mempolicy.h>
#include <mqueue.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/fanotify.h>
#include <sys/file.h>
#include <sys/fsuid.h>
#include <sys/inotify.h>
#include <sys/io.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/msg.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/sem.h>
#include <sys/sendfile.h>
#include <sys/shm.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/swap.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/timerfd.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <sys/quota.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>

#include "libsyscall_intercept_hook_point.h"
#include "magic_syscalls.h"

static bool test_in_progress;

static long mock_result = 22;

static char buffer[2][0x200];

/*
 * input data for buffers - expected to appear in the logs when
 * some syscall has a string, or binary data buffer argument.
 */
static const char input[2][sizeof(buffer[0])] = {
	"input_data\x01\x02\x03\n\r\t",
	"other_input_data\x01\x02\x03\n\r\t"};

/*
 * output data for buffers - expected to appear in the logs when
 * a hooked syscall's result is logged.
 * Of course it only really makes sense with those syscalls, which
 * would really write to some buffer. Even though the hook function
 * here would be able to mock buffer modifications for a write(2) syscall,
 * this test does not require syscall_intercept to handle that correctly.
 */
static const char expected_output[2][sizeof(buffer[0])] = {
	"expected_output_data\x06\xff\xe0\t"
	"other_expected_output_data\x06\xff\xe0\t"};

/*
 * setup_buffers - Should be called before every test using a buffer.
 */
static void
setup_buffers(void)
{
	memcpy(buffer, input, sizeof(buffer));
}

/*
 * mock_output
 * This function overwrites buffers pointed to by syscall arguments
 * with their expected output. This helps test the output logging syscall
 * results. These values are expected in the logs, and syscall_intercept
 * should definitely not print what was their contents before the hooking,
 * when a syscall is expected to write to some buffer.
 */
static void
mock_output(long arg)
{
	if ((uintptr_t)arg == (uintptr_t)(buffer[0]))
		memcpy(buffer[0], expected_output[0], sizeof(buffer[0]));

	if ((uintptr_t)arg == (uintptr_t)(buffer[1]))
		memcpy(buffer[1], expected_output[1], sizeof(buffer[1]));
}

/*
 * hook
 * The hook function used for all logged syscalls in this test. This test would
 * be impractical, if all these syscalls would be forwarded to the kernel.
 * Mocking all the syscalls guarantees the reproducibility of syscall results.
 */
static int
hook(long syscall_number,
	long arg0, long arg1,
	long arg2, long arg3,
	long arg4, long arg5,
	long *result)
{
	(void) syscall_number;

	if (!test_in_progress)
		return 1;

	mock_output(arg0);
	mock_output(arg1);
	mock_output(arg2);
	mock_output(arg3);
	mock_output(arg4);
	mock_output(arg5);

	*result = mock_result;

	return 0;
}

static const int all_o_flags =
	O_RDWR | O_APPEND | O_APPEND | O_CLOEXEC | O_CREAT | O_DIRECTORY |
	O_DSYNC | O_EXCL | O_NOCTTY | O_NOFOLLOW | O_NONBLOCK | O_RSYNC |
	O_SYNC | O_TRUNC;

int
main(int argc, char **argv)
{
	if (argc < 2)
		return EXIT_FAILURE;

	intercept_hook_point = hook;

	/*
	 * The two input buffers contain null terminated strings, with
	 * extra null characters following the string. For testing the logging
	 * of syscall arguments pointing to binary data, one can pass
	 * e.g. len0 - 3 to test printing a buffer without a null terminator,
	 * or len0 + 3 for printing null characters.
	 */
	size_t len0 = strlen(input[0]);
	size_t len1 = strlen(input[1]);

	(void) len1;
	test_in_progress = true;

	struct stat statbuf;
	int fd2[2] = {123, 234};
	struct pollfd pfds[3] = {
		{.fd = 1, .events = 0},
		{.fd = 7, .events = POLLIN | POLLPRI | POLLOUT | POLLRDHUP},
		{.fd = 99, .events = POLLERR | POLLHUP | POLLNVAL }
	};

	void *p0 = (void *)0x123000;
	void *p1 = (void *)0x234000;
	void *p2 = (void *)0x456000;
	void *p3 = (void *)0x567000;

	socklen_t sl[2] = {1, 1};

	struct utsname uname_buf;

	struct flock fl = {
		.l_type = F_WRLCK,
		.l_whence = SEEK_END,
		.l_start = 123,
		.l_len = 456,
		.l_pid = 768
	};

	magic_syscall_start_log(argv[1], "1");


	/* file read, write */
	read(9, NULL, 44);
	setup_buffers();
	read(7, buffer[0], len0 + 3);
	write(7, input[0], len0 + 4);
	setup_buffers();
	pread64(7, buffer[0], len0 + 3, ((size_t)UINT32_MAX) + 16);
	setup_buffers();
	pread64(-99, buffer[0], len0 + 2, 0);
	pread64(8, NULL, len0 + 2, 0);
	pwrite64(7, input[0], len0 + 3, ((size_t)UINT32_MAX) + 16);
	pwrite64(-99, input[0], len0 + 2, 0);
	pwrite64(-100, NULL, len0 + 2, -1);
	readv(1, p0, 4);
	readv(1, NULL, 4);
	writev(1, p0, 4);
	writev(1, NULL, 4);
	preadv(1, p0, 4, 0x1000);
	preadv(1, NULL, 4, 0x1000);
	pwritev(1, p0, 4, 0x1000);
	pwritev(1, NULL, 4, 0x1000);

	/* open, close */
	syscall(SYS_open, input[0], O_CREAT | O_RDWR | O_SYNC, 0321);
	syscall(SYS_open, input[0], 0, 0321);
	syscall(SYS_open, NULL, all_o_flags, 0777);
	syscall(SYS_open, input[0], all_o_flags, 0777);
	syscall(SYS_open, input[1], O_RDWR | O_NONBLOCK, 0111);
	syscall(SYS_open, input[1], 0);
	syscall(SYS_open, NULL, 0);
	openat(AT_FDCWD, input[0], O_CREAT | O_RDWR | O_SYNC, 0321);
	openat(AT_FDCWD, input[0], 0, 0321);
	openat(AT_FDCWD, NULL, all_o_flags, 0777);
	openat(AT_FDCWD, input[0], all_o_flags, 0777);
	openat(AT_FDCWD, input[1], O_RDWR | O_NONBLOCK, 0111);
	openat(AT_FDCWD, input[1], 0);
	openat(AT_FDCWD, NULL, 0);
	openat(99, input[0], O_CREAT, 0777);
#ifdef O_TMPFILE
	openat(AT_FDCWD, input[1], O_RDWR | O_TMPFILE, 0333);
#endif

	close(9);

	/* stat */
	stat(NULL, NULL);
	stat("/", NULL);
	stat(NULL, &statbuf);
	stat("/", &statbuf);
	fstat(0, NULL);
	fstat(-1, NULL);
	fstat(AT_FDCWD, &statbuf);
	fstat(2, &statbuf);
	lstat(NULL, NULL);
	lstat("/", NULL);
	lstat(NULL, &statbuf);
	lstat("/", &statbuf);
	fstatat(AT_FDCWD, input[0], NULL, 0);
	fstatat(AT_FDCWD, NULL, NULL, 0);
	fstatat(-1000, "", &statbuf, 0);
	fstatat(AT_FDCWD, input[1], &statbuf, AT_SYMLINK_NOFOLLOW);

	poll(NULL, 0, 7);
	poll(pfds, 3, 7);
	syscall(SYS_ppoll, pfds, 2, p0, p1, 2);

	/* seek in file, dir */
	lseek(0, 0, SEEK_SET);
	lseek(0, 0, SEEK_CUR);
	lseek(0, 0, SEEK_END);
	lseek(0, 0, SEEK_HOLE);
	lseek(0, 0, SEEK_DATA);
	lseek(2, -1, SEEK_SET);
	lseek(2, -1, SEEK_CUR);
	lseek(2, -1, SEEK_END);
	lseek(2, -1, SEEK_HOLE);
	lseek(2, -1, SEEK_DATA);
	lseek(AT_FDCWD, 99999, SEEK_SET);
	lseek(AT_FDCWD, 99999, SEEK_CUR);
	lseek(AT_FDCWD, 99999, SEEK_END);
	lseek(AT_FDCWD, 99999, SEEK_HOLE);
	lseek(AT_FDCWD, 99999, SEEK_DATA);

	/* VM management */
	mock_result = -EINVAL;
	mmap(NULL, 0, 0, 0, 0, 0);
	mock_result = 22;
	mmap(p0, 0x8000, PROT_EXEC, MAP_SHARED, 99, 0x1000);
	mprotect(p0, 0x4000, PROT_READ);
	mprotect(NULL, 0x4000, PROT_WRITE);
	munmap(p0, 0x4000);
	munmap(NULL, 0x4000);
	brk(p0);
	brk(NULL);
	mremap(p0, ((size_t)UINT32_MAX) + 7, ((size_t)UINT32_MAX) + 77,
			MREMAP_MAYMOVE);
	msync(p0, 0, MS_ASYNC);
	msync(NULL, 888, MS_INVALIDATE);
	mincore(p0, 99, p1);
	mincore(p1, 1234, NULL);
	mincore(NULL, 0, p0);
	madvise(p0, 99, MADV_NORMAL);
	madvise(p1, 1234, MADV_DONTNEED);
	madvise(NULL, 0, MADV_SEQUENTIAL);
	mlock(p0, 0x3000);
#ifdef SYS_mlock2
	syscall(SYS_mlock2, p0, 0x3000, 0);
#endif
	munlock(p0, 0x3000);
	mlockall(MCL_CURRENT);
	mlockall(MCL_FUTURE);
	munlockall();

	/* calling sigaction() with invalid pointers can result in segfault */
	syscall(SYS_rt_sigaction, SIGINT, p0, p1, 10);
	syscall(SYS_rt_sigprocmask, SIG_SETMASK, p0, p1, 10);

	ioctl(1, 77, p1);

	access(NULL, F_OK);
	access(input[0], X_OK);
	access("", R_OK | W_OK);
	access(input[0], X_OK | R_OK | W_OK);
	faccessat(AT_FDCWD, NULL, F_OK, 0);
	faccessat(AT_FDCWD, input[0], X_OK, 0);
	faccessat(AT_FDCWD, "", R_OK | W_OK, 0);
	faccessat(9, input[0], X_OK | R_OK | W_OK, 0);

	pipe(fd2);
	pipe2(fd2, 0);

	select(2, p0, p1, p2, p3);
	syscall(SYS_pselect6, 2, p0, p1, p0, p1, p0);

	sched_yield();

	/* shared memory */
	shmget(3, 4, 5);
	shmat(3, p0, 5);
	shmctl(3, 5, p0);
	shmdt(p0);

	dup(4);
	dup2(4, 5);
	dup3(4, 5, 0);
	dup3(4, 5, O_CLOEXEC);

	pause();

	nanosleep(p0, p1);

	getitimer(3, p0);

	alarm(4);

	setitimer(6, p0, p1);

	getpid();

	sendfile(6, 7, p0, 99);

	/* sockets */
	socket(AF_INET, SOCK_NONBLOCK, 0);
	connect(8, p0, 12);
	accept(4, p0, p1);
	accept4(4, p0, p1, 0);
	accept4(4, p0, p1, SOCK_NONBLOCK | SOCK_CLOEXEC);
	sendto(5, p0, 12, MSG_DONTROUTE, p1, 12);
	recvfrom(5, p0, 12, MSG_DONTROUTE, p1, p1);
	recvmsg(2, p0, MSG_PEEK);
	recvmmsg(2, p0, 12, MSG_WAITFORONE, p1);
	sendmsg(2, p0, MSG_NOSIGNAL);
	sendmmsg(2, p0, 12, MSG_NOSIGNAL);
	shutdown(3, SHUT_RD);
	bind(6, p0, 9);
	listen(5, 3);
	getsockname(4, p0, p1);
	getpeername(4, p0, p1);
	socketpair(4, 5, 6, p0);
	setsockopt(4, 5, 6, p0, 7);
	getsockopt(4, 5, 6, p0, sl);

	wait4(7, p0, 0, p1);

	kill(4, SIGINT);

	uname(&uname_buf);

	/* semaphores */
	semget(4, 1, IPC_CREAT);
	semop(4, p0, 1);
	semtimedop(4, p0, 1, p1);
	semctl(1, 2, 3);

	msgget(1, IPC_CREAT);
	msgsnd(1, p0, 3, 3);
	msgrcv(1, p0, 1, 1, 1);
	msgctl(1, IPC_STAT, p0);

	fcntl(1, F_DUPFD_CLOEXEC, 3, 4);
	fcntl(10, F_SETFL, O_NOATIME);
	fcntl(11, F_SETLK, &fl);
	flock(1, LOCK_EX);
	fsync(2);
	fdatasync(2);

	truncate(input[0], 4);
	ftruncate(3, 3);

	syscall(SYS_getdents, 4, p0, 1);
	syscall(SYS_getdents64, 4, p0, 1);

	setup_buffers();
	syscall(SYS_getcwd, buffer[0], 9);

	chdir(input[0]);
	fchdir(6);

	rename(input[0], input[1]);
	renameat(1, input[0], 2, input[1]);
	renameat(AT_FDCWD, input[0], 7, input[1]);
	renameat(9, input[0], AT_FDCWD, input[1]);

	syscall(SYS_mkdir, input[0], 0644);
	syscall(SYS_mkdirat, AT_FDCWD, input[0], 0644);
	mkdirat(33, input[0], 0644);
	mkdirat(33, NULL, 0555);
	syscall(SYS_rmdir, input[0]);
	syscall(SYS_rmdir, NULL);

	/* libc implementations might translate creat to open with O_CREAT */
	syscall(SYS_creat, input[0], 0644);

	link(input[0], input[1]);
	linkat(1, input[0], 2, input[1], 0);
	linkat(1, input[0], 2, input[1], AT_SYMLINK_FOLLOW);
	linkat(AT_FDCWD, input[0], 2, input[1], AT_SYMLINK_FOLLOW);
	linkat(7, input[0], AT_FDCWD, input[1], 0);
	unlink(input[0]);
	unlinkat(0, input[0], 0);
	unlinkat(AT_FDCWD, input[0], AT_REMOVEDIR);
	unlinkat(9, input[1], AT_REMOVEDIR);

	symlink(input[0], input[1]);
	symlinkat(input[0], 7, input[1]);
	symlinkat(input[0], AT_FDCWD, input[1]);
	symlinkat(input[0], AT_FDCWD, NULL);
	setup_buffers();
	readlink(input[0], buffer[0], len0);
	setup_buffers();
	readlinkat(2, input[0], buffer[0], len0);
	readlinkat(AT_FDCWD, input[0], buffer[0], len0);

	chmod(input[0], 0644);
	fchmod(4, 0644);
	fchmodat(0, input[0], 0644, 0);
	fchmodat(AT_FDCWD, input[0], 0111, 0);

	chown(input[0], 2, 3);
	fchown(4, 2, 3);
	fchownat(AT_FDCWD, input[0], 2, 3, 0);
	fchownat(AT_FDCWD, input[0], 2, 3, AT_SYMLINK_NOFOLLOW);
	fchownat(99, input[0], 2, 3, AT_EMPTY_PATH);
	lchown(input[0], 2, 3);

	umask(0222);

	syscall(SYS_gettimeofday, p0, p1);
	syscall(SYS_gettimeofday, NULL, NULL);
	syscall(SYS_settimeofday, p0, p1);

	syscall(SYS_getrlimit, RLIMIT_CORE, p1);
	syscall(SYS_getrlimit, RLIMIT_FSIZE, p1);
	prlimit(9, RLIMIT_CORE, p0, p1);
	prlimit(8, RLIMIT_FSIZE, p0, p1);
	syscall(SYS_setrlimit, RLIMIT_CPU, p0);

	getrusage(RUSAGE_SELF, p0);

	sysinfo(p0);

	times(NULL);
	times(p0);

	getuid();
	getgid();
	setuid(123);
	setgid(123);
	geteuid();
	getegid();
	setpgid(1, 2);
	getppid();
	getpgrp();
	setsid();
	setreuid(3, 4);
	setregid(6, 7);
	getgroups(9, p0);
	setgroups(9, p0);
	setresuid(1, 2, 3);
	getresuid(p0, p1, p1);
	setresgid(1, 2, 3);
	getresgid(p0, p1, p1);
	getpgid(99);
	setfsuid(88);
	setfsgid(77);
	getsid(66);

	syscall(SYS_syslog, LOG_FTP | LOG_WARNING, "msg", 3);

	syscall(SYS_capget, p0, p1);
	syscall(SYS_capset, p0, p1);

	syscall(SYS_rt_sigpending, p0, 9);
	syscall(SYS_rt_sigtimedwait, p0, p1, p1, 2);
	syscall(SYS_rt_sigqueueinfo, 77, SIGILL, p0);
	syscall(SYS_rt_tgsigqueueinfo, 77, 88, SIGUSR2, p0);
	syscall(SYS_rt_sigsuspend, p0, 3);
	syscall(SYS_sigaltstack, p0, p1);

	utime(input[0], p0);
	utimes(input[0], p0);
	futimesat(4, input[0], p0);

	mknod(input[0], 1, 2);
	mknodat(1, input[0], 1, 2);
	mknodat(AT_FDCWD, input[0], 1, 2);

	syscall(SYS_ustat, 2, p0);

	statfs(input[0], p0);
	fstatfs(4, p0);

	getpriority(1, 2);
	setpriority(1, 2, 3);
	sched_setparam(1, p0);
	sched_getparam(1, p0);
	sched_setscheduler(1, SCHED_BATCH, p0);
	sched_getscheduler(1);
	sched_get_priority_max(SCHED_RR);
	sched_get_priority_min(SCHED_RR);
	sched_rr_get_interval(1, p0);
	syscall(SYS_sched_setaffinity, 77, 4, p0);
	syscall(SYS_sched_getaffinity, 77, 4, p0);

	vhangup();

	syscall(SYS_modify_ldt, 1, p0, 1);

	setup_buffers();
	syscall(SYS_pivot_root, input[0], buffer[0]);

	syscall(SYS__sysctl, p0);

	prctl(PR_CAPBSET_DROP, 1, 2, 3, 4);
	syscall(SYS_arch_prctl, ARCH_SET_FS, p0);

	adjtimex(p0);

	chroot(input[0]);

	sync();
	syncfs(3);

	acct(input[0]);

	mount(input[0], input[1], p0, MS_DIRSYNC, p1);
	umount(input[0]);
	umount2(input[0], MNT_DETACH);
	swapon(input[0], SWAP_FLAG_PREFER);
	swapoff(input[0]);

	sethostname(input[0], len0);
	setdomainname(input[0], len0);

	iopl(1);
	ioperm(3, 4, 1);

	syscall(SYS_init_module, p0, 16, p1);
	syscall(SYS_finit_module, 3, p0, 0);
	syscall(SYS_delete_module, input[0], O_NONBLOCK | O_TRUNC);

	quotactl(1, p0, 2, p1);

	syscall(SYS_gettid);

	readahead(4, 0x4321, 123);

	setxattr(input[0], input[1], input[1], 3, XATTR_CREATE);
	setxattr(input[0], input[1], input[1], 3, XATTR_REPLACE);
	lsetxattr(input[0], input[1], input[1], 3, XATTR_CREATE);
	lsetxattr(input[0], input[1], input[1], 3, XATTR_REPLACE);
	fsetxattr(4, input[1], input[1], 3, XATTR_REPLACE);
	getxattr(input[0], input[1], p0, 3);
	getxattr(input[0], input[1], p0, 3);
	lgetxattr(input[0], input[1], p0, 3);
	lgetxattr(input[0], input[1], p0, 3);
	fgetxattr(4, input[1], p0, 3);
	listxattr(input[0], p0, 4);
	llistxattr(input[0], p0, 4);
	flistxattr(5, p0, 4);
	flistxattr(AT_FDCWD, p0, 4);
	removexattr(input[0], input[1]);
	lremovexattr(input[0], input[1]);
	fremovexattr(7, input[1]);

	syscall(SYS_tkill, 44, SIGSTOP);
	syscall(SYS_tgkill, 44, 55, SIGSTOP);

	syscall(SYS_time, p0);

	syscall(SYS_futex, p0, FUTEX_WAKE, 7L, p0, p1, 1L);

	syscall(SYS_set_thread_area, p0);
	syscall(SYS_get_thread_area, p0);

	syscall(SYS_io_setup, 1, p0);
	syscall(SYS_io_destroy, 77);
	syscall(SYS_io_getevents, 1L, 2L, 3L, p0, p1);
	syscall(SYS_io_submit, 1L, 2L, p0);
	syscall(SYS_io_cancel, 1L, p0, p1);

	syscall(SYS_lookup_dcookie, 123, p0, 12);

	epoll_create(7);
	epoll_create1(0);
	epoll_create1(EPOLL_CLOEXEC);
	syscall(SYS_epoll_wait, 2L, p0, 4L, 5L);
	syscall(SYS_epoll_pwait, 2L, p0, 4L, 5L, p1, 6L);
	epoll_ctl(2L, 3L, 4L, p0);

	syscall(SYS_set_tid_address, p0);

	syscall(SYS_fadvise64, 3L, 100L, 99L, POSIX_FADV_SEQUENTIAL);

	syscall(SYS_timer_create, 3, p0, p1);
	syscall(SYS_timer_settime, 4, 0, p0, p1);
	syscall(SYS_timer_settime, 4, TIMER_ABSTIME, p0, p1);
	syscall(SYS_timer_gettime, 3, p0);
	syscall(SYS_timer_getoverrun, 3);
	syscall(SYS_timer_delete, 3);

	syscall(SYS_clock_settime, CLOCK_BOOTTIME, p0);
	syscall(SYS_clock_gettime, CLOCK_BOOTTIME, p0);
	syscall(SYS_clock_getres, CLOCK_THREAD_CPUTIME_ID, p0);
	syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, TIMER_ABSTIME, p0, p1);

	syscall(SYS_mbind, p0, 0, MPOL_F_STATIC_NODES | MPOL_BIND, p1, 4, 0);
	syscall(SYS_set_mempolicy, MPOL_F_STATIC_NODES, p0, 5);
	syscall(SYS_get_mempolicy, p0, p1, 6, p0, 0);

	syscall(SYS_mq_open, input[0], O_RDWR | O_CREAT, 0777, p0);
	syscall(SYS_mq_unlink, input[0]);
	syscall(SYS_mq_timedsend, 1, input[0], len0, 3, p0);
	syscall(SYS_mq_timedreceive, 1, input[0], len0, 3, p0);
	syscall(SYS_mq_notify, 1, p0);
	syscall(SYS_mq_getsetattr, 1, p0, p1);

	syscall(SYS_kexec_load, 1, 2, p0, KEXEC_PRESERVE_CONTEXT);
#ifdef SYS_kexec_file_load
	syscall(SYS_kexec_file_load, 1, 2, 3, input[0], KEXEC_PRESERVE_CONTEXT);
#endif

	syscall(SYS_waitid, 1, 2, p0, 4, p1);

	syscall(SYS_add_key, p0, p1, p0, p1, 1);
	syscall(SYS_request_key, p0, p1, p0, 1);
	syscall(SYS_keyctl, 0, 1, 2, 3, 4);

	syscall(SYS_ioprio_set, 1, 3, 123);
	syscall(SYS_ioprio_get, 1, 3);

	inotify_init();
	inotify_init1(IN_NONBLOCK);
	inotify_init1(IN_CLOEXEC);
	inotify_add_watch(7, input[0], 123);
	inotify_rm_watch(7, 8);

	syscall(SYS_migrate_pages, 1, 2, p0, p1);

	unshare(CLONE_FILES | CLONE_NEWNS);

	syscall(SYS_set_robust_list, p0, 33);
	syscall(SYS_get_robust_list, 44, p0, p1);

	splice(2, p0, 3, p1, 123, SPLICE_F_MOVE);
	splice(2, p0, 3, p1, 0, SPLICE_F_MORE);
	vmsplice(1, p0, 2L, 3L);

	tee(1, 2, 3, 0);
	tee(1, 2, 3, SPLICE_F_MOVE);
	tee(1, 2, 3, SPLICE_F_NONBLOCK);

	sync_file_range(2, 3, 4, 0);
	sync_file_range(2, 3, 4, SYNC_FILE_RANGE_WAIT_BEFORE);

	syscall(SYS_signalfd, 1, p0, 12);
	syscall(SYS_signalfd4, 1, p0, 13, SFD_NONBLOCK);

	timerfd_create(CLOCK_REALTIME, TFD_CLOEXEC);
	timerfd_settime(1, TFD_TIMER_ABSTIME, p0, p1);
	timerfd_gettime(2, p0);

	syscall(SYS_eventfd, 45);
	syscall(SYS_eventfd2, 47, EFD_SEMAPHORE);

	fallocate(1, FALLOC_FL_PUNCH_HOLE, 3, 4);

	syscall(SYS_perf_event_open, p0, 1L, 2L, 3L, 4L, 5L);

	fanotify_init(FAN_CLASS_PRE_CONTENT | FAN_CLOEXEC, O_RDWR);
	fanotify_mark(2, FAN_MARK_REMOVE, FAN_Q_OVERFLOW, 3, input[0]);

	syscall(SYS_name_to_handle_at, AT_FDCWD, input[0], p0, p1, 0L);
	syscall(SYS_open_by_handle_at, 3, p0, 0L);

	setns(2, 0);

	syscall(SYS_getcpu, p0, p0, p1);

	syscall(SYS_process_vm_readv, 1L, 2L, 3L, 4L, 5L, 6L);
	syscall(SYS_process_vm_writev, 1L, 2L, 3L, 4L, 5L, 6L);

	syscall(SYS_kcmp, 1L, 2L, 3L, 4L, 5L);

	test_in_progress = false;
	magic_syscall_stop_log();

	return EXIT_SUCCESS;
}
