---
layout: manual
Content-Style: 'text/css'
title: libsyscall_intercept(3)
header: SYSCALL_INTERCEPT
date: syscall_intercept API version 0.1.0
...

[comment]: <> (Copyright 2017, Intel Corporation)

[comment]: <> (Redistribution and use in source and binary forms, with or without)
[comment]: <> (modification, are permitted provided that the following conditions)
[comment]: <> (are met:)
[comment]: <> (    * Redistributions of source code must retain the above copyright)
[comment]: <> (      notice, this list of conditions and the following disclaimer.)
[comment]: <> (    * Redistributions in binary form must reproduce the above copyright)
[comment]: <> (      notice, this list of conditions and the following disclaimer in)
[comment]: <> (      the documentation and/or other materials provided with the)
[comment]: <> (      distribution.)
[comment]: <> (    * Neither the name of the copyright holder nor the names of its)
[comment]: <> (      contributors may be used to endorse or promote products derived)
[comment]: <> (      from this software without specific prior written permission.)

[comment]: <> (THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS)
[comment]: <> ("AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT)
[comment]: <> (LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR)
[comment]: <> (A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT)
[comment]: <> (OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,)
[comment]: <> (SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT)
[comment]: <> (LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,)
[comment]: <> (DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY)
[comment]: <> (THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT)
[comment]: <> ((INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE)
[comment]: <> (OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.)

[comment]: <> (libsyscall_intercept.3 -- man page for libsyscall_intercept)

[NAME](#name)<br />
[SYNOPSIS](#synopsis)<br />
[DESCRIPTION](#description)<br />
[ENVIRONMENT VARIABLES](#environment-variables)<br />
[EXAMPLE](#example)<br />
[SEE ALSO](#see-also)


# NAME #
**libsyscall_intercept** -- User space syscall intercepting library

# SYNOPSIS #

```c
#include <libsyscall_intercept_hook_point.h>
```
```sh
cc -lsyscall_intercept -fpic -shared source.c -o preloadlib.so

LD_PRELOAD=preloadlib.so ./application
```

# DESCRIPTION #
The system call intercepting library provides a low-level interface
for hooking Linux system calls in user space. This is achieved
by hotpatching the machine code of the standard C library in the
memory of a process. The user of this library can provide the
functionality of almost any syscall in user space, using the very
simple API specified in the libsyscall_intercept\_hook\_point.h header file:
```c
int (*intercept_hook_point)(long syscall_number,
			long arg0, long arg1,
			long arg2, long arg3,
			long arg4, long arg5,
			long *result);
```

The user of the library shall assign to the variable called
intercept_hook_point a pointer to the address of a callback function.
A non-zero return value returned by the callback function is used
to signal to the intercepting library that the specific system
call was ignored by the user and the original syscall should be
executed. A zero return value signals that the user takes over the
system call. In this case, the result of the system call
(the value stored in the RAX register after the system call)
can be set via the \*result pointer. In order to use the library,
the intercepting code is expected to be loaded using the
LD_PRELOAD feature provided by the system loader.

All syscalls issued by libc are intercepted. Syscalls made
by code outside libc are not intercepted. In order to
be able to issue syscalls that are not intercepted, a
convenience function is provided by the library:
```c
long syscall_no_intercept(long syscall_number, ...);
```

In addition to hooking syscalls before they would be called, the API
has one special hook point that is executed after thread creation, right
after a clone syscall creating a thread returns in a child thread:
```c
void (*intercept_hook_point_clone_child)(void);
```
Using `intercept_hook_point_clone_child`, one can be notified of thread
creations.

To make it easy to detect syscall return values indicating errors, one
can use the syscall_error_code function:
```c
int syscall_error_code(long result);
```
When passed a return value from syscall_no_intercept, this function
can translate it to an error code equivalent to a libc error code:
```c
int fd = (int)syscall_no_intercept(SYS_open, "file", O_RDWR);
if (syscall_error_code(fd) != 0)
	fprintf(stderr, strerror(syscall_error_code(fd)));
```

# ENVIRONMENT VARIABLES #
Three environment variables control the operation of the library:

*INTERCEPT_LOG* -- when set, the library logs each syscall intercepted
to a file. If it ends with "-" the path of the file is formed by appending
a process id to the value provided in the environment variable.
E.g.: initializing the library in a process with pid 123 when the
INTERCEPT_LOG is set to "intercept.log-" will result in a log file named
intercept.log-123.

*INTERCEPT_LOG_TRUNC -- when set to 0, the log file from INTERCEPT_LOG
is not truncated.

*INTERCEPT_HOOK_CMDLINE_FILTER* -- when set, the library
checks the contents of the /proc/self/cmdline file.
Hotpatching, and syscall intercepting is only done, if the
last component of the first zero terminated string in
/proc/self/cmdline matches the string provided
in the environment variable. This can also be queried
by the user of the library:
```c
int syscall_hook_in_process_allowed(void);
```

# EXAMPLE #

```c
#include <libsyscall_intercept_hook_point.h>
#include <syscall.h>
#include <errno.h>

static int
hook(long syscall_number,
			long arg0, long arg1,
			long arg2, long arg3,
			long arg4, long arg5,
			long *result)
{
	if (syscall_number == SYS_getdents) {
		/*
		 * Prevent the application from
		 * using the getdents syscall. From
		 * the point of view of the calling
		 * process, it is as if the kernel
		 * would return the ENOTSUP error
		 * code from the syscall.
		 */
		*result = -ENOTSUP;
		return 0;
	} else {
		/*
		 * Ignore any other syscalls
		 * i.e.: pass them on to the kernel
		 * as would normally happen.
		 */
		return 1;
	}
}

static __attribute__((constructor)) void
init(void)
{
	// Set up the callback function
	intercept_hook_point = hook;
}
```

```sh
$ cc example.c -lsyscall_intercept -fpic -shared -o example.so
$ LD_LIBRARY_PATH=. LD_PRELOAD=example.so ls
ls: reading directory '.': Operation not supported
```

# SEE ALSO #
**syscall**(2)
