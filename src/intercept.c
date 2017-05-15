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

/*
 * intercept.c - The entry point of libsyscall_intercept, and some of
 * the main logic.
 *
 * intercept() - the library entry point
 * intercept_routine() - the entry point for each hooked syscall
 */

#include <assert.h>
#include <stdbool.h>
#include <elf.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/mman.h>
#include <stdarg.h>

#include "intercept.h"
#include "intercept_util.h"
#include "libsyscall_intercept_hook_point.h"
#include "disasm_wrapper.h"
#include "magic_syscalls.h"

int (*intercept_hook_point)(long syscall_number,
			long arg0, long arg1,
			long arg2, long arg3,
			long arg4, long arg5,
			long *result);

void (*intercept_hook_point_clone_child)(void);

bool debug_dumps_on;

void
debug_dump(const char *fmt, ...)
{
	int len;
	va_list ap;

	if (!debug_dumps_on)
		return;

	va_start(ap, fmt);
	len = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);

	if (len <= 0)
		return;

	char buf[len + 1];

	va_start(ap, fmt);
	len = vsprintf(buf, fmt, ap);
	va_end(ap);

	syscall_no_intercept(SYS_write, 2, buf, len);
}

static Dl_info libc_dlinfo;
static Dl_info pthreads_dlinfo;

static int find_glibc_dl(void);
static int find_libpthread_dl(void);

static struct intercept_desc glibc_patches;
static struct intercept_desc pthreads_patches;

static void log_header(void);

void __attribute__((noreturn)) xlongjmp(long rip, long rsp, long rax);

static void
intercept_routine(long nr, long arg0, long arg1,
			long arg2, long arg3,
			long arg4, long arg5,
			uint32_t syscall_offset,
			const char *libpath,
			long return_to_asm_wrapper_syscall,
			long return_to_asm_wrapper,
			long (*clone_wrapper)(long, long, long, long, long),
			long rsp_in_asm_wrapper);

static void clone_child_intercept_routine(void);

/*
 * intercept - This is where the highest level logic of hotpatching
 * is described. Upon startup, this routine looks for libc, and libpthread.
 * If these libraries are found in the process's address space, they are
 * patched.
 * The reason to look for these two libraries, is that these two are essential
 * parts of the glibc implementation, containing a lot of syscall instructions
 * most users would care to override. Some other parts of glibc (e.g.: libm)
 * don't contain syscalls - at least not ones that many would care about.
 * Other libraries are expected to never issue any syscalls directly, and are
 * not patched here.
 */
void
intercept(void)
{
	bool pthreads_available;

	debug_dumps_on = getenv("INTERCEPT_DEBUG_DUMP") != NULL;

	glibc_patches.c_destination =
	    (void *)((uintptr_t)&intercept_routine);
	glibc_patches.c_destination_clone_child =
	    (void *)((uintptr_t)&clone_child_intercept_routine);
	pthreads_patches.c_destination =
	    (void *)((uintptr_t)&intercept_routine);
	pthreads_patches.c_destination_clone_child =
	    (void *)((uintptr_t)&clone_child_intercept_routine);
	intercept_setup_log(getenv("INTERCEPT_LOG"),
			getenv("INTERCEPT_LOG_TRUNC"));

	if (find_glibc_dl() != 0) {
		intercept_logs("libc not found");
		intercept_log_close();
		return;
	}

	init_patcher();

	log_header();

	glibc_patches.dlinfo = libc_dlinfo;
	find_syscalls(&glibc_patches);
	allocate_trampoline_table(&glibc_patches);
	create_patch_wrappers(&glibc_patches);

	pthreads_available = (find_libpthread_dl() == 0);

	if (pthreads_available) {
		pthreads_patches.dlinfo = pthreads_dlinfo;
		find_syscalls(&pthreads_patches);
		allocate_trampoline_table(&pthreads_patches);
		create_patch_wrappers(&pthreads_patches);
		activate_patches(&pthreads_patches);
	} else {
		intercept_logs("libpthread not found");
	}

	mprotect_asm_wrappers();
	activate_patches(&glibc_patches);
	if (pthreads_available)
		activate_patches(&pthreads_patches);
}

/*
 * log_header - part of logging
 * This routine outputs some potentially useful information into the log
 * file, which can be very useful during development.
 */
static void
log_header(void)
{
	static const char self_decoder[] =
		"tempfile=$(mktemp) ; tempfile2=$(mktemp) ; "
		"grep \"^/\" $0 | cut -d \" \" -f 1,2 | "
		"sed \"s/^/addr2line -p -f -e /\" > $tempfile ; "
		"{ echo ; . $tempfile ; echo ; } > $tempfile2 ; "
		"paste $tempfile2 $0 ; exit 0\n";

	intercept_log(self_decoder, sizeof(self_decoder) - 1);
}

/*
 * find_glibc_dl - look for libc
 */
static int
find_glibc_dl(void)
{
	/* Assume the library that provides fopen is glibc */

	if (!dladdr((void *)((uintptr_t)&fopen), &libc_dlinfo))
		return -1;

	if (libc_dlinfo.dli_fbase == NULL)
		return -1;

	if (libc_dlinfo.dli_fname == NULL)
		return -1;

	return 0;
}

/*
 * find_libpthread_dl - look for libpthread
 * Returns zero if pthreads is found. It is required to have libpthread
 * loaded in order to intercept syscalls.
 */
static int
find_libpthread_dl(void)
{
	/*
	 * Assume the library that provides pthread_create is libpthread.
	 * Use dlsym instead of &pthread_create, as that would abort the
	 * program if libpthread is not actually loaded.
	 */

	void *pcreate_addr = dlsym(RTLD_DEFAULT, "pthread_create");

	if (pcreate_addr == NULL)
		return -1;

	if (!dladdr(pcreate_addr, &pthreads_dlinfo))
		return -1;

	if (pthreads_dlinfo.dli_fbase == NULL)
		return -1;

	if (pthreads_dlinfo.dli_fname == NULL)
		return -1;

	return 0;
}

/*
 * xabort - speaks for itself
 * Calling abort() in libc might result other syscalls being called
 * by libc.
 */
void
xabort(void)
{
	static const char msg[] = "libsyscall_intercept error\n";

	syscall_no_intercept(SYS_write, 2, msg, sizeof(msg));
	syscall_no_intercept(SYS_exit_group, 1);

	__builtin_trap();
}

/*
 * intercept_routine(...)
 * This is the function called from the asm wrappers,
 * forwarding the syscall parameters to a hook function
 * if one is present.
 *
 * Arguments:
 * nr, arg0 - arg 5 -- syscall number
 *
 * For logging ( debugging, validating ):
 *
 * syscall_offset -- the offset of the original syscall
 *  instruction in the shared object
 * libpath -- the path of the .so being intercepted,
 *  e.g.: "/usr/lib/libc.so.6"
 *
 * For returning to libc:
 * return_to_asm_wrapper_syscall, return_to_asm_wrapper -- the
 *  address to jump to, when this function is done. The function
 *  is called with a faked return address on the stack ( to aid
 *  stack unwinding ). So, instead of just returning from this
 *  function, one must jump to one of these addresses. The first
 *  one triggers the execution of the syscall after restoring all
 *  registers, and before actually jumping back to the subject library.
 *
 * clone_wrapper -- the address to call in the special case of thread
 *  creation using clone.
 *
 * rsp_in_asm_wrapper -- the stack pointer to restore after returning
 *  from this function.
 */
static void
intercept_routine(long nr, long arg0, long arg1,
			long arg2, long arg3,
			long arg4, long arg5,
			uint32_t syscall_offset,
			const char *libpath,
			long return_to_asm_wrapper_syscall,
			long return_to_asm_wrapper,
			long (*clone_wrapper)(long, long, long, long, long),
			long rsp_in_asm_wrapper)
{
	long result;
	int forward_to_kernel = true;

	if (handle_magic_syscalls(nr, arg0, arg1, arg2, arg3, arg4, arg5) == 0)
		xlongjmp(return_to_asm_wrapper_syscall, rsp_in_asm_wrapper, 0);

	intercept_log_syscall(libpath, nr, arg0, arg1, arg2, arg3, arg4, arg5,
	    syscall_offset, UNKNOWN, 0);

	if (intercept_hook_point != NULL)
		forward_to_kernel = intercept_hook_point(nr,
		    arg0, arg1, arg2, arg3, arg4, arg5, &result);

	if (nr == SYS_vfork || nr == SYS_rt_sigreturn) {
		/* can't handle these syscall the normal way */
		xlongjmp(return_to_asm_wrapper_syscall, rsp_in_asm_wrapper, nr);
	}

	if (forward_to_kernel) {
		/*
		 * The clone syscall's arg1 is a pointer to a memory region
		 * that serves as the stack space of a new child thread.
		 * If this is zero, the child thread uses the same address
		 * as stack pointer as the parent does (e.g.: a copy of
		 * of the memory area after fork).
		 *
		 * The code at clone_wrapper only returns to this routine
		 * in the parent thread. In the child thread, it calls
		 * the clone_child_intercept_routine instead, executing
		 * it on the new child threads stack, then returns to libc.
		 */
		if (nr == SYS_clone && arg1 != 0)
			result = clone_wrapper(arg0, arg1, arg2, arg3, arg4);
		else
			result = syscall_no_intercept(nr,
			    arg0, arg1, arg2, arg3, arg4, arg5);
	}

	intercept_log_syscall(libpath, nr, arg0, arg1, arg2, arg3, arg4, arg5,
	    syscall_offset, KNOWN, result);

	xlongjmp(return_to_asm_wrapper, rsp_in_asm_wrapper, result);
}

/*
 * clone_child_intercept_routine
 * The routine called by an assembly wrapper when a clone syscall returns zero,
 * and a new stack pointer is used in the child thread.
 */
static void
clone_child_intercept_routine(void)
{
	if (intercept_hook_point_clone_child != NULL)
		intercept_hook_point_clone_child();
}
