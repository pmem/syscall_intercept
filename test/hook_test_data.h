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
 * hook_test_data.h -- defines some symbols/values to be used in
 * hook_test.c (making syscalls) and in hook_test_preload.c (intercepting those
 * same syscalls). This file defines variables with internal linkage, and
 * compiler wanrs if they are not used in a TU. This is ugly usually, but
 * these are really meant to be used in the two other files source files
 * mentioned above.
 * This header is not meant to be used anywhere else.
 */

#ifndef INTERCEPT_HOOK_TEST_DATA_H
#define INTERCEPT_HOOK_TEST_DATA_H

#include <unistd.h>
#include <stdbool.h>

/* arbitrary fd, expected not to conflict with any valid fd */
static const int hook_test_fd = 8765;

static const char dummy_data[] = "dummy_data";

static const ssize_t hook_test_dummy_return_value = 5;

static inline bool
is_spurious_syscall(long syscall_number, long arg0)
{
#ifdef EXPECT_SPURIOUS_SYSCALLS

	/*
	 * A filter function which is aware of syscall originating
	 * from ASAN, gcov, etc...
	 *
	 * In regulard builds, such filtering should not be applied, and
	 * the hook test should look at every syscall.
	 * The goal of insturmented builds is not to retest the same logic as
	 * the test do otherwise, but rather to execute the code with the
	 * instrumentation in place. Therefore, it is not a problem if
	 * the test just allows through pretty much any syscall here.
	 */
	return syscall_number != SYS_write || arg0 != hook_test_fd;

#else

	/* regular testing, no syscalls ignored */
	(void) syscall_number;
	(void) arg0;
	return false;

#endif
}

#endif
