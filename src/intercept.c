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
#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <sys/auxv.h>

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

/* Should all objects be patched, or only libc and libpthread? */
static bool patch_all_objs;

/*
 * Information collected during disassemble phase, and anything else
 * needed for hotpatching are stored in this dynamically allocated
 * array of structs.
 * The number currently allocated is in the objs_count variable.
 */
static struct intercept_desc *objs;
static unsigned objs_count;

/* was libc found while looking for loaded objects? */
static bool libc_found;

/* address of [vdso] */
static void *vdso_addr;

/*
 * allocate_next_obj_desc
 * Handles the dynamic allocation of the struct intercept_desc array.
 * Returns a pointer to a newly allocated item.
 */
static struct intercept_desc *
allocate_next_obj_desc(void)
{
	if (objs_count == 0)
		objs = xmmap_anon(sizeof(objs[0]));
	else
		objs = xmremap(objs, objs_count * sizeof(objs[0]),
			(objs_count + 1) * sizeof(objs[0]));

	++objs_count;
	return objs + objs_count - 1;
}

/*
 * get_lib_short_name - find filename in path containing directories.
 */
static const char *
get_lib_short_name(const char *name)
{
	const char *slash = strrchr(name, '/');
	if (slash != NULL)
		name = slash + 1;

	return name;
}

/*
 * str_match - matching library names.
 * The first string (name) is not null terminated, while
 * the second string (expected) is null terminated.
 * This allows matching e.g.: "libc-2.25.so\0" with "libc\0".
 * If name_len is 4, the comparison is between: "libc" and "libc".
 */
static bool
str_match(const char *name, size_t name_len,
		const char *expected)
{
	return name_len == strlen(expected) &&
		strncmp(name, expected, name_len) == 0;
}

/*
 * get_name_from_proc_maps
 * Tries to find the path of an object file loaded at a specific
 * address.
 *
 * The paths found are stored in BSS, in the paths variable. The
 * returned pointer points into this variable. The next_path
 * pointer keeps track of the already "allocated" space inside
 * the paths array.
 */
static const char *
get_name_from_proc_maps(uintptr_t addr)
{
	static char paths[0x10000];
	static char *next_path = paths;
	const char *path = NULL;

	char line[0x2000];
	FILE *maps;

	if ((next_path >= paths + sizeof(paths) - sizeof(line)))
		return NULL; /* No more space left */

	if ((maps = fopen("/proc/self/maps", "r")) == NULL)
		return NULL;

	while ((fgets(line, sizeof(line), maps)) != NULL) {
		unsigned char *start;
		unsigned char *end;

		/* Read the path into next_path */
		if (sscanf(line, "%p-%p %*s %*x %*x:%*x %*u %s",
		    (void **)&start, (void **)&end, next_path) != 3)
			continue;

		if (addr < (uintptr_t)start)
			break;

		if ((uintptr_t)start <= addr && addr < (uintptr_t)end) {
			/*
			 * Object found, setting the return value.
			 * Adjusting the next_path pointer to point past the
			 * string found just now, to the unused space behind it.
			 * The next string found (if this routine is called
			 * again) will be stored there.
			 */
			path = next_path;
			next_path += strlen(next_path) + 1;
			break;
		}
	}

	fclose(maps);

	return path;
}

/*
 * get_any_used_vaddr - find a virtual address that is expected to
 * be a used for the object file mapped into memory.
 *
 * An Elf64_Phdr struct contains information about a segment in an on object
 * file. This routine looks for a segment with type LOAD, that has a non-zero
 * size in memory. The p_vaddr field contains the virtual address where this
 * segment should be loaded to. This of course is relative to the base address.
 *
 * typedef struct
 * {
 *   Elf64_Word p_type;			Segment type
 *   Elf64_Word p_flags;		Segment flags
 *   Elf64_Off p_offset;		Segment file offset
 *   Elf64_Addr p_vaddr;		Segment virtual address
 *   Elf64_Addr p_paddr;		Segment physical address
 *   Elf64_Xword p_filesz;		Segment size in file
 *   Elf64_Xword p_memsz;		Segment size in memory
 *   Elf64_Xword p_align;		Segment alignment
 * } Elf64_Phdr;
 *
 *
 */
static uintptr_t
get_any_used_vaddr(const struct dl_phdr_info *info)
{
	const Elf64_Phdr *pheaders = info->dlpi_phdr;

	for (Elf64_Word i = 0; i < info->dlpi_phnum; ++i) {
		if (pheaders[i].p_type == PT_LOAD && pheaders[i].p_memsz != 0)
			return info->dlpi_addr + pheaders[i].p_vaddr;
	}

	return 0; /* not found */
}

/*
 * get_object_path - attempt to find the path of the object in the
 * filesystem.
 *
 * This is usually supplied by dl_iterate_phdr in the dl_phdr_info struct,
 * but sometimes that does not contain it.
 */
static const char *
get_object_path(const struct dl_phdr_info *info)
{
	if (info->dlpi_name != NULL && info->dlpi_name[0] != '\0') {
		return info->dlpi_name;
	} else {
		uintptr_t addr = get_any_used_vaddr(info);
		if (addr == 0)
			return NULL;
		return get_name_from_proc_maps(addr);
	}
}

static bool
is_vdso(uintptr_t addr, const char *path)
{
	return addr == (uintptr_t)vdso_addr || strstr(path, "vdso") != NULL;
}

/*
 * should_patch_object
 * Decides whether a particular loaded object should should be targeted for
 * hotpatching.
 * Always skipped: [vdso], and the syscall_intercept library itself.
 * Besides these two, if patch_all_objs is true, everything object is
 * a target. When patch_all_objs is false, only libraries that are parts of
 * the glibc implementation are targeted, i.e.: libc and libpthread.
 */
static bool
should_patch_object(uintptr_t addr, const char *path)
{
	static const char self[] = "libsyscall_intercept";
	static const char libc[] = "libc";
	static const char pthr[] = "libpthread";
	static const char caps[] = "libcapstone";

	if (is_vdso(addr, path)) {
		debug_dump(" - skipping: is_vdso\n");
		return false;
	}

	const char *name = get_lib_short_name(path);
	size_t len = strcspn(name, "-.");

	if (len == 0)
		return false;

	if (str_match(name, len, self)) {
		debug_dump(" - skipping: matches self\n");
		return false;
	}

	if (str_match(name, len, caps)) {
		debug_dump(" - skipping: matches capstone\n");
		return false;
	}

	if (str_match(name, len, libc)) {
		debug_dump(" - libc found\n");
		libc_found = true;
		return true;
	}

	if (patch_all_objs)
		return true;

	if (str_match(name, len, pthr)) {
		debug_dump(" - libpthread found\n");
		return true;
	}

	debug_dump(" - skipping, patch_all_objs == false\n");
	return false;
}

/*
 * analyze_object
 * Look at a library loaded into the current process, and determine as much as
 * possible about it. The disassembling, allocations are initiated here.
 *
 * This is a callback function, passed to dl_iterate_phdr(3).
 * data and size are just unused callback arguments.
 *
 *
 * From dl_iterate_phdr(3) man page:
 *
 * struct dl_phdr_info
 * {
 *     ElfW(Addr) dlpi_addr;             Base address of object
 *     const char *dlpi_name;            (Null-terminated) name of object
 *     const ElfW(Phdr) *dlpi_phdr;      Pointer to array of ELF program headers
 *     ElfW(Half) dlpi_phnum;            # of items in dlpi_phdr
 *     ...
 * }
 *
 */
static int
analyze_object(struct dl_phdr_info *info, size_t size, void *data)
{
	(void) data;
	(void) size;
	const char *path;

	debug_dump("analyze_object called on \"%s\" at 0x%016" PRIxPTR "\n",
	    info->dlpi_name, info->dlpi_addr);

	if ((path = get_object_path(info)) == NULL)
		return 0;

	debug_dump("analyze %s\n", path);

	if (!should_patch_object(info->dlpi_addr, path))
		return 0;

	struct intercept_desc *patches = allocate_next_obj_desc();

	patches->base_addr = (unsigned char *)info->dlpi_addr;
	patches->path = path;
	patches->c_destination = (void *)((uintptr_t)&intercept_routine);
	patches->c_destination_clone_child =
	    (void *)((uintptr_t)&clone_child_intercept_routine);
	find_syscalls(patches);
	allocate_trampoline_table(patches);
	create_patch_wrappers(patches);

	return 0;
}

/*
 * intercept - This is where the highest level logic of hotpatching
 * is described. Upon startup, this routine looks for libc, and libpthread.
 * If these libraries are found in the process's address space, they are
 * patched.
 */
void
intercept(void)
{
	vdso_addr = (void *)(uintptr_t)getauxval(AT_SYSINFO_EHDR);
	debug_dumps_on = getenv("INTERCEPT_DEBUG_DUMP") != NULL;
	patch_all_objs = (getenv("INTERCEPT_ALL_OBJS") != NULL);
	intercept_setup_log(getenv("INTERCEPT_LOG"),
			getenv("INTERCEPT_LOG_TRUNC"));
	log_header();
	init_patcher();

	dl_iterate_phdr(analyze_object, NULL);
	if (!libc_found)
		xabort("libc not found");

	mprotect_asm_wrappers();
	for (unsigned i = 0; i < objs_count; ++i)
		activate_patches(objs + i);
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
 * xabort - speaks for itself
 * Calling abort() in libc might result other syscalls being called
 * by libc.
 */
void
xabort(const char *msg)
{
	static const char main_msg[] = " libsyscall_intercept error\n";

	if (msg != NULL)
		syscall_no_intercept(SYS_write, 2, msg, strlen(msg));
	syscall_no_intercept(SYS_write, 2, main_msg, sizeof(main_msg));
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
