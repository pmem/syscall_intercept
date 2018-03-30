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

#include "syscall_formats.h"
#include "intercept_util.h"

#include <fcntl.h>
#include <sys/syscall.h>

#define SARGS(name, r, ...) [SYS_##name] = {#name, r, {__VA_ARGS__}}

/* Linux syscalls on X86_64 */
/* BEGIN CSTYLED */
static const struct syscall_format formats[] = {
	SARGS(read, rdec, arg_fd, arg_buf_out, arg_dec),
	SARGS(write, rdec, arg_fd, arg_buf_in, arg_dec),
	SARGS(open, rdec, arg_cstr, arg_open_flags),
	SARGS(close, rdec, arg_fd),
	SARGS(stat, rdec, arg_cstr, arg_pointer),
	SARGS(fstat, rdec, arg_fd, arg_pointer),
	SARGS(lstat, rdec, arg_cstr, arg_pointer),
	SARGS(poll, rdec, arg_pointer, arg_, arg_),
	SARGS(lseek, rdec, arg_fd, arg_dec, arg_seek_whence),
	SARGS(mmap, rpointer, arg_pointer, arg_, arg_, arg_, arg_fd, arg_),
	SARGS(mprotect, rdec, arg_pointer, arg_, arg_),
	SARGS(munmap, rdec, arg_pointer, arg_),
	SARGS(brk, rdec, arg_dec),
	SARGS(rt_sigaction, rdec, arg_dec32, arg_pointer, arg_pointer, arg_dec),
	SARGS(rt_sigprocmask, rdec, arg_, arg_pointer, arg_pointer, arg_dec),
	SARGS(rt_sigreturn, rnoreturn, arg_none),
	SARGS(ioctl, rdec, arg_fd, arg_, arg_pointer),
	SARGS(pread64, rdec, arg_fd, arg_buf_out, arg_dec, arg_dec),
	SARGS(pwrite64, rdec, arg_fd, arg_buf_in, arg_dec, arg_dec),
	SARGS(readv, rdec, arg_fd, arg_pointer, arg_dec),
	SARGS(writev, rdec, arg_fd, arg_pointer, arg_dec),
	SARGS(access, rdec, arg_cstr, arg_access_mode),
	SARGS(pipe, rdec, arg_2fds),
	SARGS(select, rdec, arg_dec32, arg_pointer, arg_pointer, arg_pointer, arg_pointer),
	SARGS(sched_yield, rdec, arg_none),
	SARGS(mremap, rpointer, arg_pointer, arg_dec, arg_dec, arg_dec32, arg_),
	SARGS(msync, rdec, arg_pointer, arg_dec, arg_dec32),
	SARGS(mincore, rdec, arg_pointer, arg_dec, arg_pointer),
	SARGS(madvise, rdec, arg_pointer, arg_dec, arg_dec32),
	SARGS(shmget, rdec, arg_, arg_, arg_),
	SARGS(shmat, rhex, arg_, arg_, arg_),
	SARGS(shmctl, rdec, arg_, arg_, arg_),
	SARGS(dup, rdec, arg_fd),
	SARGS(dup2, rdec, arg_fd, arg_fd),
	SARGS(pause, rdec, arg_none),
	SARGS(nanosleep, rdec, arg_, arg_),
	SARGS(getitimer, rdec, arg_, arg_),
	SARGS(alarm, rdec, arg_),
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
	SARGS(clone, rdec, arg_clone_flags, arg_pointer, arg_pointer, arg_pointer, arg_),
	SARGS(fork, rdec, arg_none),
	SARGS(vfork, rdec, arg_none),
	SARGS(execve, rdec, arg_, arg_, arg_),
	SARGS(exit, rnoreturn, arg_),
	SARGS(wait4, rdec, arg_dec, arg_, arg_, arg_),
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
	SARGS(fcntl, rdec, arg_fd, arg_fcntl_cmd, arg_),
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
	SARGS(mkdir, rdec, arg_cstr, arg_oct_mode),
	SARGS(rmdir, rdec, arg_cstr),
	SARGS(creat, rdec, arg_cstr, arg_oct_mode),
	SARGS(link, rdec, arg_cstr, arg_cstr),
	SARGS(unlink, rdec, arg_cstr),
	SARGS(symlink, rdec, arg_cstr, arg_cstr),
	SARGS(readlink, rdec, arg_cstr, arg_buf_out, arg_dec),
	SARGS(chmod, rdec, arg_cstr, arg_oct_mode),
	SARGS(fchmod, rdec, arg_fd, arg_oct_mode),
	SARGS(chown, rdec, arg_cstr, arg_, arg_),
	SARGS(fchown, rdec, arg_fd, arg_, arg_),
	SARGS(lchown, rdec, arg_cstr, arg_, arg_),
	SARGS(umask, rmode, arg_oct_mode),
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
	SARGS(readahead, rdec, arg_fd, arg_dec, arg_dec),
	SARGS(setxattr, rdec, arg_cstr, arg_cstr, arg_buf_in, arg_dec, arg_),
	SARGS(lsetxattr, rdec, arg_cstr, arg_cstr, arg_buf_in, arg_dec, arg_),
	SARGS(fsetxattr, rdec, arg_fd, arg_cstr, arg_buf_in, arg_dec, arg_),
	SARGS(getxattr, rdec, arg_cstr, arg_cstr, arg_dec, arg_),
	SARGS(lgetxattr, rdec, arg_cstr, arg_cstr, arg_dec, arg_),
	SARGS(fgetxattr, rdec, arg_fd, arg_cstr, arg_dec, arg_),
	SARGS(listxattr, rdec, arg_cstr, arg_pointer, arg_dec),
	SARGS(llistxattr, rdec, arg_cstr, arg_pointer, arg_dec),
	SARGS(flistxattr, rdec, arg_fd, arg_pointer, arg_dec),
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
	SARGS(timer_delete, rdec, arg_),
	SARGS(clock_settime, rdec, arg_, arg_),
	SARGS(clock_gettime, rdec, arg_, arg_),
	SARGS(clock_getres, rdec, arg_, arg_),
	SARGS(clock_nanosleep, rdec, arg_, arg_, arg_, arg_),
	SARGS(exit_group, rnoreturn, arg_),
	SARGS(epoll_wait, rdec, arg_fd, arg_, arg_, arg_),
	SARGS(epoll_ctl, rdec, arg_fd, arg_, arg_fd, arg_),
	SARGS(tgkill, rdec, arg_, arg_, arg_),
	SARGS(utimes, rdec, arg_cstr, arg_),
	SARGS(mbind, rdec, arg_, arg_, arg_, arg_, arg_),
	SARGS(set_mempolicy, rdec, arg_, arg_, arg_),
	SARGS(get_mempolicy, rdec, arg_, arg_, arg_, arg_, arg_),
	SARGS(mq_open, rdec, arg_cstr, arg_, arg_, arg_, arg_),
	SARGS(mq_unlink, rdec, arg_cstr),
	SARGS(mq_timedsend, rdec, arg_, arg_, arg_, arg_, arg_),
	SARGS(mq_timedreceive, rdec, arg_, arg_, arg_, arg_, arg_),
	SARGS(mq_notify, rdec, arg_, arg_),
	SARGS(mq_getsetattr, rdec, arg_, arg_, arg_),
	SARGS(kexec_load, rdec, arg_, arg_, arg_, arg_),
	SARGS(waitid, rdec, arg_, arg_, arg_, arg_),
	SARGS(add_key, rdec, arg_, arg_, arg_, arg_, arg_),
	SARGS(request_key, rdec, arg_, arg_, arg_, arg_),
	SARGS(keyctl, rdec, arg_, arg_, arg_, arg_, arg_),
	SARGS(ioprio_set, rdec, arg_, arg_, arg_),
	SARGS(ioprio_get, rdec, arg_, arg_),
	SARGS(inotify_init, rdec, arg_none),
	SARGS(inotify_add_watch, rdec, arg_fd, arg_cstr, arg_),
	SARGS(inotify_rm_watch, rdec, arg_fd, arg_),
	SARGS(migrate_pages, rdec, arg_, arg_, arg_, arg_),
	SARGS(openat, rdec, arg_atfd, arg_cstr, arg_open_flags),
	SARGS(mkdirat, rdec, arg_atfd, arg_cstr, arg_oct_mode),
	SARGS(mknodat, rdec, arg_atfd, arg_cstr, arg_oct_mode, arg_),
	SARGS(fchownat, rdec, arg_atfd, arg_cstr, arg_, arg_, arg_),
	SARGS(futimesat, rdec, arg_atfd, arg_cstr, arg_),
	SARGS(newfstatat, rdec, arg_atfd, arg_cstr, arg_, arg_),
	SARGS(unlinkat, rdec, arg_atfd, arg_cstr, arg_),
	SARGS(renameat, rdec, arg_atfd, arg_cstr, arg_atfd, arg_cstr),
	SARGS(linkat, rdec, arg_atfd, arg_cstr, arg_atfd, arg_cstr, arg_),
	SARGS(symlinkat, rdec, arg_cstr, arg_atfd, arg_cstr),
	SARGS(readlinkat, rdec, arg_atfd, arg_cstr, arg_buf_out, arg_dec),
	SARGS(fchmodat, rdec, arg_atfd, arg_cstr, arg_oct_mode),
	SARGS(faccessat, rdec, arg_atfd, arg_cstr, arg_oct_mode),
	SARGS(pselect6, rdec, arg_, arg_, arg_, arg_, arg_, arg_),
	SARGS(ppoll, rdec, arg_, arg_, arg_, arg_, arg_),
	SARGS(unshare, rdec, arg_),
	SARGS(set_robust_list, rdec, arg_, arg_),
	SARGS(get_robust_list, rdec, arg_, arg_, arg_),
	SARGS(splice, rdec, arg_fd, arg_, arg_fd, arg_, arg_, arg_),
	SARGS(tee, rdec, arg_fd, arg_fd, arg_, arg_),
	SARGS(sync_file_range, rdec, arg_fd, arg_, arg_, arg_),
	SARGS(vmsplice, rdec, arg_fd, arg_, arg_, arg_),
	SARGS(move_pages, rdec, arg_, arg_, arg_, arg_, arg_, arg_),
	SARGS(utimensat, rdec, arg_atfd, arg_cstr, arg_, arg_),
	SARGS(epoll_pwait, rdec, arg_fd, arg_, arg_, arg_, arg_, arg_),
	SARGS(signalfd, rdec, arg_fd, arg_, arg_),
	SARGS(timerfd_create, rdec, arg_, arg_),
	SARGS(eventfd, rdec, arg_),
	SARGS(fallocate, rdec, arg_fd, arg_, arg_, arg_),
	SARGS(timerfd_settime, rdec, arg_fd, arg_, arg_, arg_),
	SARGS(timerfd_gettime, rdec, arg_fd, arg_),
	SARGS(accept4, rdec, arg_fd, arg_, arg_, arg_, arg_),
	SARGS(signalfd4, rdec, arg_fd, arg_, arg_, arg_, arg_),
	SARGS(eventfd2, rdec, arg_, arg_),
	SARGS(epoll_create1, rdec, arg_),
	SARGS(dup3, rdec, arg_fd, arg_fd, arg_),
	SARGS(pipe2, rdec, arg_2fds, arg_pipe2_flags),
	SARGS(inotify_init1, rdec, arg_),
	SARGS(preadv, rdec, arg_fd, arg_, arg_, arg_),
	SARGS(pwritev, rdec, arg_fd, arg_, arg_, arg_),
	SARGS(rt_tgsigqueueinfo, rdec, arg_, arg_, arg_, arg_),
	SARGS(perf_event_open, rdec, arg_, arg_, arg_, arg_, arg_),
	SARGS(recvmmsg, rdec, arg_fd, arg_, arg_, arg_, arg_),
	SARGS(fanotify_init, rdec, arg_, arg_),
	SARGS(fanotify_mark, rdec, arg_, arg_, arg_, arg_, arg_),
	SARGS(prlimit64, rdec, arg_, arg_, arg_, arg_),
	SARGS(name_to_handle_at, rdec, arg_atfd, arg_cstr, arg_, arg_, arg_),
	SARGS(open_by_handle_at, rdec, arg_fd, arg_pointer, arg_dec32),
	SARGS(clock_adjtime, rdec, arg_, arg_),
	SARGS(syncfs, rdec, arg_fd),
	SARGS(sendmmsg, rdec, arg_fd, arg_, arg_, arg_),
	SARGS(setns, rdec, arg_fd, arg_),
	SARGS(getcpu, rdec, arg_, arg_, arg_),
	SARGS(process_vm_readv, rdec, arg_, arg_, arg_, arg_, arg_, arg_),
	SARGS(process_vm_writev, rdec, arg_, arg_, arg_, arg_, arg_, arg_),
	SARGS(kcmp, rdec, arg_, arg_, arg_, arg_, arg_),
	SARGS(finit_module, rdec, arg_fd, arg_, arg_),
#ifdef SYS_sched_setattr
	SARGS(sched_setattr, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_sched_getattr
	SARGS(sched_getattr, rdec, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_renameat2
	SARGS(renameat2, rdec, arg_atfd, arg_cstr, arg_atfd, arg_cstr, arg_),
#endif
#ifdef SYS_seccomp
	SARGS(seccomp, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_getrandom
	SARGS(getrandom, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_memfd_create
	SARGS(memfd_create, rdec, arg_cstr, arg_),
#endif
#ifdef SYS_kexec_file_load
	SARGS(kexec_file_load, rdec, arg_, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_bpf
	SARGS(bpf, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_execveat
	SARGS(execveat, rdec, arg_atfd, arg_cstr, arg_, arg_, arg_),
#endif
#ifdef SYS_userfaultfd
	SARGS(userfaultfd, rdec, arg_),
#endif
#ifdef SYS_membarrier
	SARGS(membarrier, rdec, arg_, arg_),
#endif
#ifdef SYS_mlock2
	SARGS(mlock2, rdec, arg_, arg_, arg_),
#endif
#ifdef SYS_copy_file_range
	SARGS(copy_file_range, rdec, arg_fd, arg_, arg_fd, arg_, arg_, arg_),
#endif
#ifdef SYS_preadv2
	SARGS(preadv2, rdec, arg_fd, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_pwritev2
	SARGS(pwritev2, rdec, arg_fd, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_pkey_mprotect
	SARGS(pkey_mprotect, rdec, arg_, arg_, arg_, arg_),
#endif
#ifdef SYS_pkey_alloc
	SARGS(pkey_alloc, rdec, arg_, arg_),
#endif
#ifdef SYS_pkey_free
	SARGS(pkey_free, rdec, arg_),
#endif
};
/* END CSTYLED */

#undef SARGS

static struct syscall_format open_with_o_creat = {.name = "open", rdec,
	{arg_cstr, arg_open_flags, arg_oct_mode}};

static struct syscall_format openat_with_o_creat = {.name = "openat", rdec,
	{arg_atfd, arg_cstr, arg_open_flags, arg_oct_mode}};

static struct syscall_format fcntl_with_flock = {.name = "fcntl", rdec,
	{arg_fd, arg_fcntl_cmd, arg_flock}};

static struct syscall_format unkown = {.name = NULL, rdec,
	{arg_, arg_, arg_, arg_, arg_, arg_}};

static bool
is_fcntl_with_flock(const struct syscall_desc *desc)
{
	if (desc->nr != SYS_fcntl)
		return false;

	switch ((int)desc->args[1]) {
		case F_GETLK:
		case F_SETLK:
		case F_SETLKW:
#ifdef F_OFD_GETLK
		case F_OFD_GETLK:
		case F_OFD_SETLK:
		case F_OFD_SETLKW:
#endif
			return true;
		default:
			return false;
	}
}

static bool
oflags_refer_mode_arg(int flags)
{
	if ((flags & O_CREAT) == O_CREAT)
		return true;
#ifdef O_TMPFILE
	if ((flags & O_TMPFILE) == O_TMPFILE)
		return true;
#endif
	return false;
}

const struct syscall_format *
get_syscall_format(const struct syscall_desc *desc)
{
	if (desc->nr < 0 || (size_t)desc->nr >= ARRAY_SIZE(formats))
		return &unkown;

	if (formats[desc->nr].name == NULL)
		return &unkown;

	if (desc->nr == SYS_open && oflags_refer_mode_arg((int)desc->args[1]))
		return &open_with_o_creat;

	if (desc->nr == SYS_openat && oflags_refer_mode_arg((int)desc->args[2]))
		return &openat_with_o_creat;

	if (is_fcntl_with_flock(desc))
		return &fcntl_with_flock;

	return formats + desc->nr;
}
