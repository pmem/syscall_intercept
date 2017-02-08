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

#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>

#include "libsyscall_intercept_hook_point.h"

#include "intercept.h"

static Dl_info
load_test_lib(const char *path)
{
	static const char symbol_name[] = "test_marker_symbol";

	void *lib = dlopen(path, RTLD_LAZY);
	if (lib == NULL) {
		fprintf(stderr, "error loading \"%s\": %s\n",
		    path, dlerror());
		exit(EXIT_FAILURE);
	}

	Dl_info dlinfo;
	if ((!dladdr(symbol_name, &dlinfo)) ||
	    (dlinfo.dli_fname == NULL) ||
	    (strcmp(dlinfo.dli_fname, path) != 0) ||
	    (dlinfo.dli_fbase == NULL)) {
		fprintf(stderr, "error location marker symbol in %s: \"%s\"",
		    path, dlerror());
		exit(EXIT_FAILURE);
	}

	return dlinfo;
}

int
main(int argc, char **argv)
{
	if (argc < 2)
		return EXIT_FAILURE;

	Dl_info dlinfo = load_test_lib(argv[1]);

	struct intercept_desc patches;
	init_patcher();
	find_syscalls(&patches, &dlinfo);
	create_patch_wrappers(&patches);
	mprotect_asm_wrappers();
	activate_patches(&patches);

	return EXIT_SUCCESS;
}
