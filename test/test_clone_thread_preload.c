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
 * This library's purpose is to hook the syscalls of the program
 * built from test_clone_thread.c, and to check the
 * intercept_hook_point_clone_child and intercept_hook_point_clone_parent
 * hook point while doing so.
 *
 * See also: examples/fork_ban.c about forking a new process.
 */

#ifdef NDEBUG
#undef NDEBUG
#endif

#include "libsyscall_intercept_hook_point.h"

#include <assert.h>
#include <syscall.h>
#include <stdio.h>

typedef struct {
	unsigned long clone_flags;
	unsigned long newsp;
	void *parent_tid;
	void *child_tid;
	unsigned tid;
} clone_args_t;

static clone_args_t clone_args;

static int
hook(long syscall_number,
	long arg0, long arg1,
	long arg2, long arg3,
	long arg4, long arg5,
	long *result)
{
	(void) arg5;
	(void) result;

	/*
	 * One can not just simply issue a clone syscall that alters
	 * the stack pointer, as C compiler generates code that assumes
	 * the values pushed to the stack remain there. The only options
	 * are, to handle the situation in place (with some rather elaborate
	 * inline assembly tricks), or let libsyscall_intercept handle
	 * the details. This example returns 1, thus asks libsyscall_intercept
	 * to issue the actual syscall.
	 *
	 * So, such a clone syscall can be observed with a hook function
	 * before the syscall, and in the child process, after the syscall.
	 *
	 * At the moment, libsyscall_intercept does not provide a way to
	 * execute a hook function after the syscall in the parent process,
	 * therefore the return value (the child's pid) can not be observed,
	 * or modified.
	 */
	if (syscall_number == SYS_clone && (arg1 != 0)) {
		clone_args.clone_flags = arg0;
		clone_args.newsp = arg1;
		clone_args.parent_tid = (void *) arg2;
		clone_args.child_tid = (void *) arg3;
		clone_args.tid = arg4;
	}

	return 1;
}

/*
 * This function is executed in the child process right after the the
 * actual syscall returned zero. The return value of clone can not
 * be overridden, syscall_intercept returns zero to the syscall's caller.
 *
 * This function is executed on the stack associated with the new thread,
 * the top of which was passed to the kernel as the second argument (arg1 above)
 * of the clone syscall.
 */
static void
hook_child(unsigned long clone_flags,
	unsigned long newsp,
	void *parent_tid,
	void *child_tid,
	unsigned tid)
{

	static const char msg[] = "clone_hook_child called\n";

	assert(clone_flags == clone_args.clone_flags);
	assert(newsp == clone_args.newsp);
	assert(parent_tid == clone_args.parent_tid);
	assert(child_tid == clone_args.child_tid);
	assert(tid == clone_args.tid);
	syscall_no_intercept(SYS_write, 1, msg, sizeof(msg));
}

static void
hook_parent(long *ret,
	unsigned long clone_flags,
	unsigned long newsp,
	void *parent_tid,
	void *child_tid,
	unsigned tid) {
	static const char msg[] = "clone_hook_parent called\n";

	(void) ret;
	assert(clone_flags == clone_args.clone_flags);
	assert(newsp == clone_args.newsp);
	assert(parent_tid == clone_args.parent_tid);
	assert(child_tid == clone_args.child_tid);
	assert(tid == clone_args.tid);
	syscall_no_intercept(SYS_write, 1, msg, sizeof(msg));
}

static __attribute__((constructor)) void
init(void)
{
	intercept_hook_point = hook;
	intercept_hook_point_clone_child = hook_child;
	intercept_hook_point_clone_parent = hook_parent;
}
