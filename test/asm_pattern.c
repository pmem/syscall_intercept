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
 * This program can be used to test certain instruction level details
 * of disassembling/patching the text section of a library.
 * One needs an 'input' and an 'expected output' library as two
 * shared objects in order to perform a comparison between what
 * syscall_intercept's patching results in, and what the result should be.
 * The paths of these two libraries are expected to be supplied as command
 * line arguments.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <dlfcn.h>
#include <string.h>

#include "libsyscall_intercept_hook_point.h"

#include "intercept.h"

/*
 * All test libraries are expected to provide the following symbols:
 * trampoline_table - the mock trampoline table using while patching
 * trampoline_table_end - used to calculate the size
 *				of the mock trampoline table
 * text_start, text_end - symbols that help this program find the
 *				text section of the shared object
 *
 * The lib_data struct is used to describe a shared library loaded
 * for testing.
 */
struct lib_data {
	Dl_info info;
	unsigned char *mock_trampoline_table;
	size_t mock_trampoline_table_size;
	const unsigned char *text_start;
	const unsigned char *text_end;
	size_t text_size;
};

/*
 * xdlsym - no-fail wrapper around dlsym
 */
static void *
xdlsym(void *lib, const char *name, const char *path)
{
	void *symbol = dlsym(lib, name);
	if (symbol == NULL) {
		fprintf(stderr,
		    "\"%s\" not found in %s: %s\n",
		    name, path, dlerror());
		exit(EXIT_FAILURE);
	}

	return symbol;
}

/*
 * Load a shared object into this process's address space, and set up
 * a lib_data struct to be used later while testing.
 * This same routine is used to load an 'input' library, and
 * an 'expected output' library.
 */
static struct lib_data
load_test_lib(const char *path)
{
	struct lib_data data;

	void *lib = dlopen(path, RTLD_LAZY);
	if (lib == NULL) {
		fprintf(stderr, "error loading \"%s\": %s\n",
		    path, dlerror());
		exit(EXIT_FAILURE);
	}

	data.mock_trampoline_table = xdlsym(lib, "trampoline_table", path);

	if ((!dladdr(data.mock_trampoline_table, &data.info)) ||
	    (data.info.dli_fname == NULL) ||
	    (data.info.dli_fbase == NULL)) {
		fprintf(stderr,
		    "error querying dlinfo for %s: %s\n",
		    path, dlerror());
		exit(EXIT_FAILURE);
	}

	unsigned char *end = xdlsym(lib, "trampoline_table_end", path);

	if (end <= data.mock_trampoline_table) {
		fprintf(stderr,
		    "trampoline_table_end invalid in %s: \"%s\"\n",
		    path, dlerror());
		exit(EXIT_FAILURE);
	}

	data.mock_trampoline_table_size = end - data.mock_trampoline_table;

	data.text_start = xdlsym(lib, "text_start", path);
	data.text_end = xdlsym(lib, "text_end", path);

	if (data.text_start >= data.text_end) {
		fprintf(stderr, "text_start <= text_end in %s\n", path);
		exit(EXIT_FAILURE);
	}

	data.text_size = data.text_end - data.text_start;

	return data;
}

/*
 * check_patch - binary comparison of text sections
 * This routine compares each byte in the text section of the 'input'
 * library and the 'expected output library' -- after the input library
 * has been patched.
 *
 * If a difference is found, it prints both text sections, highlighting
 * the differences.
 */
static void
check_patch(const struct lib_data *in, const struct lib_data *out)
{
	if (memcmp(in->text_start, out->text_start, in->text_size) == 0)
		return;

	fputs("Invalid patch\n", stderr);

	const unsigned char *text = in->text_start;
	const unsigned char *expected = out->text_start;
	size_t count = in->text_size;

	fputs("patch vs. expected:\n", stderr);
	while (count > 0) {
		fprintf(stderr,
		    "0x%04zx: 0x%02hhx 0x%02hhx%s\n",
		    text - in->text_start,
		    *text, *expected, (*text == *expected) ? "" : " <-");
		++text;
		++expected;
		--count;
	}

	exit(EXIT_FAILURE);
}

int
main(int argc, char **argv)
{
	if (argc < 3)
		return EXIT_FAILURE;

	debug_dumps_on = getenv("INTERCEPT_DEBUG_DUMP") != NULL;

	/* first load both libraries */
	struct lib_data lib_in = load_test_lib(argv[1]);
	struct lib_data lib_out = load_test_lib(argv[2]);

	if (lib_in.text_size != lib_out.text_size) {
		fprintf(stderr,
		    "text_size mismatch for %s(%zu) and %s(%zu)\n",
		    argv[1], lib_in.text_size, argv[2], lib_out.text_size);
		exit(EXIT_FAILURE);
	}

	/*
	 * Initialize syscall_intercept -- this initialization is usually
	 * done in the routine called intercept in the intercept.c source
	 * file.
	 */
	struct intercept_desc patches;
	init_patcher();

	/*
	 * patches.c_destination - The routine that would be called from the
	 * assembly wrapper templates.
	 * This is never called while this testing, so the only thing
	 * that matters here, is that it is a 2GB range of the generated
	 * assembly wrappers.
	 */
	patches.c_destination = (void *)(uintptr_t)init_patcher;
	patches.c_destination_clone_child = (void *)(uintptr_t)init_patcher;

	/*
	 * Some more information about the library to be patched, normally
	 * these variables would refer to libc.
	 */
	patches.dlinfo = lib_in.info;
	patches.uses_trampoline_table = true;
	patches.trampoline_table = lib_in.mock_trampoline_table;
	patches.trampoline_table_size = lib_in.mock_trampoline_table_size;
	patches.next_trampoline = patches.trampoline_table;

	/* perform the actually patching */
	find_syscalls(&patches);
	create_patch_wrappers(&patches);
	mprotect_asm_wrappers();
	activate_patches(&patches);

	/* compare the result of patching with the expected result */
	check_patch(&lib_in, &lib_out);

	return EXIT_SUCCESS;
}
