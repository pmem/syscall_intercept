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

#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

volatile bool should_be_busy;

static __thread bool reentrance_guard_flag;

typedef void sig_handler_func(int, siginfo_t *, void *);

struct sig_snapshot {
	sig_handler_func *handler;
	int sig;
	siginfo_t *info;
	void *arg;
};

static __thread struct sig_snapshot deferred_queue[0x1000];

static __thread size_t deferred_queue_usage;

static void
deferr_signal_handler(sig_handler_func *handler_addr,
		int sig, siginfo_t *info, void *arg)
{
	if (deferred_queue_usage == ARRAY_SIZE(deferred_queue))
		return; /* signal ignored */

	static const char busy_msg[] = "Sorry, I'm busy!\n";
	syscall_no_intercept(SYS_write, 2, busy_msg, strlen(busy_msg));

	/* XXX Another signal can arrive here, and that makes me a sad panda. */
	deferred_queue[deferred_queue_usage].handler = handler_addr;
	deferred_queue[deferred_queue_usage].sig = sig;
	deferred_queue[deferred_queue_usage].info = info;
	deferred_queue[deferred_queue_usage].arg = arg;
	deferred_queue_usage++;
}

/* Assume 32 is a hard limit on signal number in the Linux kernel. */
static sig_handler_func *requested_signal_handlers[32 + 1];

static void
signal_hook(int sig, siginfo_t *info, void *arg)
{
	if (sig < 0 || (size_t)sig >= ARRAY_SIZE(requested_signal_handlers))
		return; /* Shoud never happen, in theory */

	sig_handler_func *handler = requested_signal_handlers[sig];
	if (reentrance_guard_flag)
		deferr_signal_handler(handler, sig, info, arg);
	else
		handler(sig, info, arg);
}

static int
hook_rt_sigaction(int sig, const struct sigaction *action,
			struct sigaction *original_action,
			size_t sigsetsize, long *result)
{
	if (sig < 0 || (size_t)sig >= ARRAY_SIZE(requested_signal_handlers))
		return 1;

	if (action->sa_handler == SIG_IGN || action->sa_handler == SIG_DFL)
		return 1;

	struct sigaction hooked_sigaction = *action;
	hooked_sigaction.sa_sigaction = signal_hook;
	*result = syscall_no_intercept(SYS_rt_sigaction,
				sig, &hooked_sigaction, original_action,
				sigsetsize);
	if (*result == 0) {
		original_action->sa_sigaction = requested_signal_handlers[sig];
		requested_signal_handlers[sig] = action->sa_sigaction;
	}
	return 0;
}

static int
hook_write(int fd, const char *buf, size_t count)
{
	static const char msg[] = "BLOCKING_SYSCALL\n";
	if (fd != 1)
		return 1;
	if (count != strlen(msg))
		return 1;
	if (memcmp(buf, msg, strlen(msg)) != 0)
		return 1;

	should_be_busy = true;

	while (should_be_busy) {
		should_be_busy = should_be_busy || !should_be_busy;
		/* set it to false in a debugger to finish this write syscall */
	}

	return 1;
}

static int
syscall_hook(long syscall_number,
	long arg0, long arg1, long arg2, long arg3, long arg4, long arg5,
	long *result)
{
	(void) arg4;
	(void) arg5;

	switch (syscall_number) {
	case SYS_rt_sigaction:
		return hook_rt_sigaction((int)arg0,
					(const void *)(uintptr_t)arg1,
					(void *)(uintptr_t)arg2,
					(size_t)arg3,
					result);
	case SYS_write:
		return hook_write((int)arg0, (const char *)arg1, (size_t)arg2);
	}

	return 1;
}

static void
run_deferred_signals(void)
{
	while (deferred_queue_usage > 0) {
		struct sig_snapshot *sig =
			deferred_queue + (--deferred_queue_usage);
		sig->handler(sig->sig, sig->info, sig->arg);
	}
}

static int
guarded_syscall_hook(long syscall_number,
	long arg0, long arg1, long arg2, long arg3, long arg4, long arg5,
	long *result)
{
	bool is_first_level_entrance = !reentrance_guard_flag;

	if (is_first_level_entrance)
		reentrance_guard_flag = true;

	int r = syscall_hook(syscall_number,
				arg0, arg1, arg2, arg3, arg4, arg5, result);

	if (is_first_level_entrance) {
		reentrance_guard_flag = false;
		run_deferred_signals();
	}

	return r;
}

static __attribute__((constructor)) void
start(void)
{
	intercept_hook_point = guarded_syscall_hook;
}
