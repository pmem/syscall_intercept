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

/*
 * fork_ban.c - Block forking new processes after a maximum number of
 * forks.
 * This library demonstrates a way to handle fork syscalls. In contrast
 * to thread creation (for an example see test/test_clone_thread_preload.c)
 * the fork can be done right inside of a hook routine.
 */

#include "libsyscall_intercept_hook_point.h"

#include <errno.h>
#include <stdbool.h>
#include <sched.h>
#include <syscall.h>
#include <stdlib.h>

#define FORK_MAX_COUNT 16

/*
 * specifies_new_stack - does the syscall ask for a new stack?
 *
 * The second argument of a clone syscall specifies the
 * top of a stack area for the new child thread/process.
 * Zero is a special value, which means not using a new stack
 * pointer. A fork() is expected to not change the stack
 * pointer, but it is checked here anyways.
 */
static bool
specifies_new_stack(long syscall_number, long arg0, long arg1)
{
	(void) arg0;

	return syscall_number == SYS_clone && (arg1 != 0);
}

/*
 * is_syscall_fork
 * Is it a syscall creating a new process, that does not share virtual
 * memory with the parent process?
 */
static bool
is_syscall_fork(long syscall_number, long arg0)
{
	if (syscall_number == SYS_fork || syscall_number == SYS_vfork)
		return true;

	if (syscall_number == SYS_clone && (arg0 & CLONE_THREAD) == 0)
		return true;

	return false;
}

static int fork_counter; /* how many forks intercepted so far? */

/* how many are allowed to pass through, before blocking? */
static int fork_counter_max = FORK_MAX_COUNT;

static long
example_fork_hook(long syscall_number,
		long arg0, long arg1,
		long arg2, long arg3,
		long arg4, long arg5)
{
	long result;

	/* pass it on to the kernel */
	result = syscall_no_intercept(syscall_number,
	    arg0, arg1, arg2, arg3, arg4, arg5);

	if (fork_counter > 4 && result > 0) {
		/*
		 * Messing with parent process: return wrong
		 * pid, just for fun.
		 */
		result += 16;
	}

	return result;
}

static int
hook(long syscall_number,
		long arg0, long arg1,
		long arg2, long arg3,
		long arg4, long arg5,
		long *result)
{
	(void) arg2;
	(void) arg3;
	(void) arg4;
	(void) arg5;

	if (!is_syscall_fork(syscall_number, arg0))
		return 1; /* ignore other syscalls */

	if (fork_counter >= fork_counter_max) {
		static const char msg[] = "fork count has exceeded maximum.\n";
		syscall_no_intercept(SYS_write, 2, msg, sizeof(msg));
		*result = -EAGAIN;
		return 0;
	}

	++fork_counter;

	if (specifies_new_stack(syscall_number, arg0, arg1)) {
		/* Not messing with changing stack address */
		return 1;
	} else {
		*result = example_fork_hook(syscall_number,
		    arg0, arg1, arg2, arg3, arg4, arg5);
		return 0;
	}
}

static __attribute__((constructor)) void
start(void)
{
	const char *e = getenv("ALLOW_FORK_MAX");

	if (e != NULL)
		fork_counter_max = atoi(e);

	intercept_hook_point = &hook;
}
