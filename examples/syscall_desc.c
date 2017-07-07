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

#include "syscall_desc.h"

#include <stddef.h>
#include <syscall.h>

#define SARGS(name, r, ...) \
	[SYS_##name] = {#name, r, {__VA_ARGS__, }}

static const struct syscall_desc table[] = {
	SARGS(read, rdec, arg_fd, arg_, arg_),
	SARGS(write, rdec, arg_fd, arg_, arg_),
	SARGS(open, rdec, arg_cstr, arg_, arg_),
	SARGS(close, rdec, arg_fd),
	SARGS(stat, rdec, arg_cstr, arg_),
	SARGS(fstat, rdec, arg_fd, arg_),
	SARGS(lstat, rdec, arg_cstr, arg_),
	SARGS(poll, rdec, arg_, arg_, arg_),
	SARGS(lseek, rdec, arg_fd, arg_, arg_),
	SARGS(mmap, rhex, arg_, arg_, arg_, arg_, arg_fd, arg_),
	SARGS(mprotect, rdec, arg_, arg_, arg_),
	SARGS(munmap, rdec, arg_, arg_, arg_, arg_, arg_fd, arg_),
	SARGS(brk, rdec, arg_),
	SARGS(rt_sigaction, rdec, arg_, arg_, arg_),
	SARGS(rt_sigprocmask, rdec, arg_, arg_, arg_, arg_),
	SARGS(rt_sigreturn, rdec, arg_none),
	SARGS(ioctl, rdec, arg_fd, arg_, arg_),
	SARGS(pread64, rdec, arg_fd, arg_, arg_, arg_),
	SARGS(pwrite64, rdec, arg_fd, arg_, arg_, arg_),
	SARGS(readv, rdec, arg_fd, arg_, arg_),
	SARGS(writev, rdec, arg_fd, arg_, arg_),
	SARGS(access, rdec, arg_cstr, arg_),
	SARGS(pipe, rdec, arg_),
	SARGS(select, rdec, arg_, arg_, arg_, arg_, arg_),
	SARGS(sched_yield, rdec, arg_none),
	SARGS(mremap, rhex, arg_, arg_, arg_, arg_, arg_),
	SARGS(msync, rdec, arg_, arg_, arg_),
	SARGS(mincore, rdec, arg_, arg_, arg_),
	SARGS(madvise, rdec, arg_, arg_, arg_),
	SARGS(shmget, rdec, arg_, arg_, arg_),
	SARGS(shmat, rhex, arg_, arg_, arg_),
	SARGS(shmctl, rdec, arg_, arg_, arg_),
	SARGS(dup, rdec, arg_fd),
	SARGS(dup2, rdec, arg_fd, arg_fd),
	SARGS(pause, rdec, arg_none),
	SARGS(nanosleep, rdec, arg_, arg_),
	SARGS(getitimer, rdec, arg_, arg_),
	SARGS(alarm, runsigned, arg_),
	SARGS(setitimer, rdec, arg_, arg_, arg_),
	SARGS(getpid, rdec, arg_none),
	SARGS(sendfile, rdec, arg_fd, arg_fd, arg_, arg_),
	SARGS(socket, rdec, arg_, arg_, arg_),
	SARGS(connect, rdec, arg_fd, arg_, arg_),
	SARGS(accept, rdec, arg_fd, arg_, arg_),
	SARGS(sendto, rdec, arg_fd, arg_, arg_, arg_),
	SARGS(recvfrom, rdec, arg_fd, arg_, arg_, arg_, arg_, arg_),
	SARGS(sendmsg, rdec, arg_fd, arg_, arg_),
	SARGS(recvmsg, rdec, arg_fd, arg_, arg_),
	SARGS(shutdown, rdec, arg_fd, arg_),
	SARGS(bind, rdec, arg_fd, arg_, arg_),
	SARGS(listen, rdec, arg_fd, arg_),
	SARGS(getsockname, rdec, arg_fd, arg_, arg_),
	SARGS(getpeername, rdec, arg_fd, arg_, arg_),
	SARGS(socketpair, rdec, arg_, arg_, arg_, arg_),
	SARGS(setsockopt, rdec, arg_fd, arg_, arg_, arg_, arg_),
	SARGS(getsockopt, rdec, arg_fd, arg_, arg_, arg_, arg_),
	SARGS(clone, rdec, arg_, arg_, arg_, arg_, arg_, arg_),
	SARGS(fork, rdec, arg_none),
	SARGS(vfork, rdec, arg_none),
	SARGS(execve, rdec, arg_, arg_, arg_),
	SARGS(exit, rdec, arg_),
	SARGS(wait4, rdec, arg_, arg_, arg_, arg_),
	SARGS(kill, rdec, arg_, arg_),
	SARGS(uname, rdec, arg_),
	SARGS(semget, rdec, arg_, arg_, arg_),
	SARGS(semop, rdec, arg_, arg_, arg_),
	SARGS(semctl, rdec, arg_, arg_, arg_, arg_, arg_, arg_),
	SARGS(shmdt, rdec, arg_),
	SARGS(msgget, rdec, arg_, arg_),
	SARGS(msgsnd, rdec, arg_, arg_, arg_, arg_),
	SARGS(msgrcv, rdec, arg_, arg_, arg_, arg_, arg_),
	SARGS(msgctl, rdec, arg_, arg_, arg_),
	SARGS(fcntl, rdec, arg_fd, arg_, arg_),
	SARGS(flock, rdec, arg_fd, arg_),
	SARGS(fsync, rdec, arg_fd),
	SARGS(fdatasync, rdec, arg_fd),
	SARGS(truncate, rdec, arg_cstr, arg_),
	SARGS(ftruncate, rdec, arg_fd, arg_),
	SARGS(getdents, rdec, arg_fd, arg_, arg_),
	SARGS(getcwd, rdec, arg_, arg_),
	SARGS(chdir, rdec, arg_cstr),
	SARGS(fchdir, rdec, arg_fd),
	SARGS(rename, rdec, arg_cstr, arg_cstr),
	SARGS(mkdir, rdec, arg_cstr, arg_),
	SARGS(rmdir, rdec, arg_cstr),
	SARGS(creat, rdec, arg_cstr, arg_),
	SARGS(link, rdec, arg_cstr, arg_cstr),
	SARGS(unlink, rdec, arg_cstr),
	SARGS(symlink, rdec, arg_cstr, arg_cstr),
	SARGS(readlink, rdec, arg_cstr, arg_, arg_),
	SARGS(chmod, rdec, arg_cstr, arg_),
	SARGS(fchmod, rdec, arg_fd, arg_),
	SARGS(chown, rdec, arg_cstr, arg_, arg_),
	SARGS(fchown, rdec, arg_fd, arg_, arg_),
	SARGS(lchown, rdec, arg_cstr, arg_, arg_),
	SARGS(umask, roct, arg_),
	SARGS(gettimeofday, rdec, arg_, arg_),
	SARGS(getrlimit, rdec, arg_, arg_),
	SARGS(getrusage, rdec, arg_, arg_),
	SARGS(sysinfo, rdec, arg_, arg_),
	SARGS(times, rdec, arg_),
	SARGS(ptrace, rhex, arg_, arg_, arg_, arg_),
	SARGS(getuid, rdec, arg_none),
	SARGS(syslog, rdec, arg_, arg_, arg_),
	SARGS(getgid, rdec, arg_none),
	SARGS(setuid, rdec, arg_),
	SARGS(setgid, rdec, arg_),
	SARGS(geteuid, rdec, arg_none),
	SARGS(getegid, rdec, arg_none),
	SARGS(setpgid, rdec, arg_none),
	SARGS(getpgrp, rdec, arg_none),
	SARGS(setsid, rdec, arg_none),
	SARGS(setreuid, rdec, arg_, arg_),
	SARGS(setregid, rdec, arg_, arg_),
	SARGS(getgroups, rdec, arg_, arg_),
	SARGS(setgroups, rdec, arg_, arg_),
	SARGS(setresuid, rdec, arg_, arg_, arg_),
	SARGS(getresuid, rdec, arg_, arg_, arg_),
	SARGS(setresgid, rdec, arg_, arg_, arg_),
	SARGS(getresgid, rdec, arg_, arg_, arg_),
	SARGS(getpgid, rdec, arg_),
	SARGS(setfsuid, rdec, arg_),
	SARGS(setfsgid, rdec, arg_),
	SARGS(getsid, rdec, arg_),
	SARGS(capget, rdec, arg_, arg_),
	SARGS(capset, rdec, arg_, arg_),
	SARGS(rt_sigpending, rdec, arg_),
	SARGS(rt_sigtimedwait, rdec, arg_, arg_, arg_, arg_),
	SARGS(rt_sigqueueinfo, rdec, arg_, arg_, arg_),
	SARGS(rt_sigsuspend, rdec, arg_, arg_),
	SARGS(sigaltstack, rdec, arg_, arg_),
	SARGS(utime, rdec, arg_cstr, arg_),
	SARGS(mknod, rdec, arg_cstr, arg_, arg_),
	SARGS(uselib, rdec, arg_cstr),
	SARGS(personality, rdec, arg_),
	SARGS(ustat, rdec, arg_, arg_),
	SARGS(statfs, rdec, arg_cstr, arg_),
	SARGS(fstatfs, rdec, arg_fd, arg_),
	SARGS(sysfs, rdec, arg_, arg_, arg_),
	SARGS(getpriority, rdec, arg_, arg_),
	SARGS(setpriority, rdec, arg_, arg_, arg_),
	SARGS(sched_setparam, rdec, arg_, arg_),
	SARGS(sched_getparam, rdec, arg_, arg_),
	SARGS(sched_setscheduler, rdec, arg_, arg_, arg_),
	SARGS(sched_getscheduler, rdec, arg_),
	SARGS(sched_get_priority_max, rdec, arg_),
	SARGS(sched_get_priority_min, rdec, arg_),
	SARGS(sched_rr_get_interval, rdec, arg_, arg_),
	SARGS(mlock, rdec, arg_, arg_),
	SARGS(munlock, rdec, arg_, arg_),
	SARGS(mlockall, rdec, arg_),
	SARGS(munlockall, rdec, arg_none),
	SARGS(vhangup, rdec, arg_none),
	SARGS(modify_ldt, rdec, arg_, arg_, arg_),
	SARGS(pivot_root, rdec, arg_cstr, arg_),
	SARGS(_sysctl, rdec, arg_),
	SARGS(prctl, rdec, arg_, arg_, arg_, arg_, arg_),
	SARGS(arch_prctl, rdec, arg_, arg_, arg_),
	SARGS(adjtimex, rdec, arg_),
	SARGS(setrlimit, rdec, arg_, arg_),
	SARGS(chroot, rdec, arg_cstr),
	SARGS(sync, rdec, arg_none),
	SARGS(acct, rdec, arg_cstr),
	SARGS(settimeofday, rdec, arg_, arg_),
	SARGS(mount, rdec, arg_cstr, arg_cstr, arg_, arg_, arg_),
	SARGS(umount2, rdec, arg_cstr, arg_),
	SARGS(swapon, rdec, arg_cstr, arg_),
	SARGS(swapoff, rdec, arg_cstr),
	SARGS(reboot, rdec, arg_, arg_, arg_, arg_),
	SARGS(sethostname, rdec, arg_, arg_),
	SARGS(setdomainname, rdec, arg_, arg_),
	SARGS(iopl, rdec, arg_),
	SARGS(ioperm, rdec, arg_, arg_, arg_),
	SARGS(gettid, rdec, arg_none),
	SARGS(readahead, rdec, arg_fd, arg_, arg_),
	SARGS(setxattr, rdec, arg_cstr, arg_cstr, arg_, arg_, arg_),
	SARGS(lsetxattr, rdec, arg_cstr, arg_cstr, arg_, arg_, arg_),
	SARGS(fsetxattr, rdec, arg_fd, arg_cstr, arg_, arg_, arg_),
	SARGS(getxattr, rdec, arg_cstr, arg_cstr, arg_, arg_),
	SARGS(lgetxattr, rdec, arg_cstr, arg_cstr, arg_, arg_),
	SARGS(fgetxattr, rdec, arg_fd, arg_cstr, arg_, arg_),
	SARGS(listxattr, rdec, arg_cstr, arg_, arg_),
	SARGS(llistxattr, rdec, arg_cstr, arg_, arg_),
	SARGS(flistxattr, rdec, arg_cstr, arg_, arg_),
	SARGS(removexattr, rdec, arg_cstr, arg_cstr),
	SARGS(lremovexattr, rdec, arg_cstr, arg_cstr),
	SARGS(fremovexattr, rdec, arg_fd, arg_cstr),
	SARGS(tkill, rdec, arg_, arg_),
	SARGS(time, rdec, arg_),
	SARGS(futex, rdec, arg_, arg_, arg_, arg_, arg_, arg_),
	SARGS(sched_setaffinity, rdec, arg_, arg_, arg_),
	SARGS(sched_getaffinity, rdec, arg_, arg_, arg_),
	SARGS(set_thread_area, rdec, arg_),
	SARGS(io_setup, rdec, arg_, arg_),
	SARGS(io_destroy, rdec, arg_),
	SARGS(io_getevents, rdec, arg_, arg_, arg_, arg_, arg_),
	SARGS(io_submit, rdec, arg_, arg_, arg_),
	SARGS(io_cancel, rdec, arg_, arg_, arg_),
	SARGS(get_thread_area, rdec, arg_),
	SARGS(lookup_dcookie, rdec, arg_, arg_, arg_),
	SARGS(epoll_create, rdec, arg_),
	SARGS(getdents64, rdec, arg_fd, arg_, arg_),
	SARGS(set_tid_address, rdec, arg_),
	SARGS(semtimedop, rdec, arg_, arg_, arg_, arg_),
	SARGS(fadvise64, rdec, arg_fd, arg_, arg_, arg_),
	SARGS(timer_create, rdec, arg_, arg_, arg_),
	SARGS(timer_settime, rdec, arg_, arg_, arg_, arg_),
	SARGS(timer_gettime, rdec, arg_, arg_),
	SARGS(timer_getoverrun, rdec, arg_),
	SARGS(timer_delete, rdec, arg_)
	/* to be continued... at this point I got tired */
};

#undef SARGS

const struct syscall_desc *
get_syscall_desc(long syscall_number)
{
	if (syscall_number < 0)
		return NULL;

	if ((size_t)syscall_number >= (sizeof(table) / sizeof(table[0])))
		return NULL;

	return table + syscall_number;
}
