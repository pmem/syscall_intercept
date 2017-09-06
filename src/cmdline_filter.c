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

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <fcntl.h>
#include <unistd.h>

#include "libsyscall_intercept_hook_point.h"
#include "intercept.h"

/*
 * cmdline_match - match the last component of the path in cmdline
 */
static int
cmdline_match(const char *filter)
{
	if (filter == NULL)
		return 1;

	size_t flen = strlen(filter);
	size_t clen = strlen(cmdline);

	if (flen > clen)
		return 0; /* cmdline can't contain filter */

	/*
	 * If cmdline is longer, it must end with a slash + filter:
	 * "./somewhere/a.out" matches "a.out"
	 * "./a.out" matches "a.out"
	 * "./xa.out" does not match "a.out"
	 *
	 * Of course if cmdline is not longer, the slash is not needed:
	 * "a.out" matches "a.out"
	 */
	if (clen > flen && cmdline[clen - flen - 1] != '/')
		return 0;

	return strcmp(cmdline + clen - flen, filter) == 0;
}

/*
 * syscall_hook_in_process_allowed - checks if a filter should be applied
 * for processes. If the users requests it (via an environment variable) the
 * syscall interception should not be performed in the current process.
 * This is part of syscall_intercept's public API.
 */
int
syscall_hook_in_process_allowed(void)
{
	static bool is_decided;
	static int result;

	if (is_decided)
		return result;

	if (cmdline == NULL)
		return 0;

	result = cmdline_match(getenv("INTERCEPT_HOOK_CMDLINE_FILTER"));
	is_decided = true;

	return result;
}
