# syscall_intercept

[![Build Status](https://travis-ci.org/pmem/syscall_intercept.svg)](https://travis-ci.org/pmem/syscall_intercept)
[![Coverage Status](https://codecov.io/github/pmem/syscall_intercept/coverage.svg)](https://codecov.io/gh/pmem/syscall_intercept)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/12890/badge.svg)](https://scan.coverity.com/projects/syscall_intercept)

Userspace syscall intercepting library.

# Dependencies #

## Runtime dependencies ##

 * libcapstone -- the disassembly engine used under the hood

## Build dependencies ##

# Local build dependencies #

 * C99 toolchain -- tested with recent versions of GCC and clang
 * cmake
 * perl -- for checking coding style
 * pandoc -- for generating the man page

### Travis CI build dependencies ###

The travis builds use some scripts to generate a docker images, in which syscall_intercept is built/tested.
These docker images are pushed to Dockerhub, to be reused in later travis builds.
The scripts expect four environment variables to be set in the travis environment:
 * DOCKERHUB_REPO - where to store the docker images used for building
    e.g. in order to refer to a Dockerhub repository at https://hub.docker.com/r/pmem/syscall_intercept, this variable
    should contain the string "pmem/syscall_intercept"
 * DOCKERHUB_USER - used for logging into Dockerhub
 * DOCKERHUB_PASSWORD - used for logging into Dockerhub
 * GITHUB_REPO - where the repository is available on github (e.g. "pmem/syscall_intercept" )

### How to build ###

Building libsyscall_intercept requires cmake.
Example:
```sh
cmake path_to_syscall_intercept -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang
make
```
alternatively:
```sh
ccmake path_to_syscall_intercept
make
```

There is an install target. For now, all it does, is cp.
```sh
make install
```

Coming soon:
```sh
make test
```

# Synopsis #

```c
#include <libsyscall_intercept_hook_point.h>
```
```sh
cc -lsyscall_intercept -fpic -shared source.c -o preloadlib.so

LD_PRELOAD=preloadlib.so ./application
```

##### Description: #####

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
can be set via the *result pointer. In order to use the library,
the intercepting code is expected to be loaded using the
LD_PRELOAD feature provided by the system loader.

All syscalls issued by libc are intercepted. Syscalls made
by code outside libc are not intercepted. In order to
be able to issue syscalls that are not intercepted, a
convenience function is provided by the library:
```c
long syscall_no_intercept(long syscall_number, ...);
```

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
checks the command line used to start the program.
Hotpatching, and syscall intercepting is only done, if the
last component of the command used to start the program
is the same as the string provided in the environment variable.
This can also be queried by the user of the library:
```c
int syscall_hook_in_process_allowed(void);
```

##### Example: #####

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

# Under the hood: #

##### Assumptions: #####
In order to handle syscalls in user space, the library relies
on the following assumptions:

- Each syscall made by the applicaton is issued via libc
- No other facility attempts to hotpatch libc in the same process
- The libc implementation is already loaded in the processes
memory space when the intercepting library is being initialized
- The machine code in the libc implementation is suitable
for the methods listed in this section
- For some more basic assumptions, see the section on limitations.

##### Disassembly: #####
The library disassembles the text segment of the libc loaded
into the memory space of the process it is initialized in. It
locates all syscall instructions, and replaces each of them
with a jump to a unique address. Since the syscall instruction
of the x86_64 ISA occupies only two bytes, the method involves
locating other bytes close to the syscall suitable for overwriting.
The destination of the jump (unique for each syscall) is a
small routine, which accomplishes the following tasks:

1. Optionally executes any instruction that originally
preceded the syscall instruction, and was overwritten to
make space for the jump instruction
2. Saves the current state of all registers to the stack
3. Translates the arguments (in the registers) from
the Linux x86_64 syscall calling convention to the C ABI's
calling convention used on x86_64
4. Calls a function written in C (which in turn calls
the callback supplied by the library user)
5. Loads the values from the stack back into the registers
6. Jumps back to libc, to the instruction following the
overwritten part

##### In action: #####

*Simple hotpatching:*
Replace a mov and a syscall instruction with a jmp instruction
```
Before:                         After:

db2a0 <__open>:                 db2b0 <__open>:
db2aa: mov $2, %eax           /-db2aa: jmp e0000
db2af: syscall                |
db2b1: cmp $-4095, %rax       | db2b1: cmp $-4095, %rax ---\
db2b7: jae db2ea              | db2b7: jae db2ea           |
db2b9: retq                   | db2b9: retq                |
                              | ...                        |
                              | ...                        |
                              \_...                        |
                                e0000: mov $2, $eax        |
                                ...                        |
                                e0100: call implementation /
                                ...                       /
                                e0200: jmp db2aa ________/
```
*Hotpatching using a trampoline jump:*
Replace a syscall instruction with a short jmp instruction,
the destination of which is a regular jmp instruction.
The reason to use this, is that a short jmp instruction
consumes only two bytes, thus fits in the place of a syscall
instruction. Sometimes the instructions directly preceding
or following the syscall instruction can not be overwritten,
leaving only the two bytes of the syscall instruction
for patching.
The hotpatching library looks for place for the trampoline jump
in the padding found to the end of each routine. Since the start
of all routines is aligned to 16 bytes, often there is a padding
space between the end of a symbol, and the start of the next symbol.
In the example below, this padding is filled with 7 byte long
nop instruction (so the next symbol can start at the address 3f410).
```
Before:                         After:

3f3fe: mov %rdi, %rbx           3f3fe: mov %rdi, %rbx
3f401: syscall                /-3f401: jmp 3f430
3f403: jmp 3f415              | 3f403: jmp 3f415 ----------\
3f407: retq                   | 3f407: retq                |
                              \                            |
3f408: nopl 0x0(%rax,%rax,1)  /-3f408: jmp e1000           |
                              | ...                        |
                              | ...                        |
                              \_...                        |
                                e1000: nop                 |
                                ...                        |
                                e1100: call implementation /
                                ...                       /
                                e1200: jmp 3f403 ________/

```

# Limitations: #
* Only Linux is supported
* Only x86\_64 is supported
* Only tested with glibc, although perhaps it works
with some other libc implementations as well
* There are known issues with the following syscalls:
  * clone
  * rt_sigreturn

# Debugging: #
Besides logging, the most important factor during debugging is to make
sure the syscalls in the debugger are not intercepted. To achieve this, use
the INTERCEPT_HOOK_CMDLINE_FILTER variable described above.

```
INTERCEPT_HOOK_CMDLINE_FILTER=ls \
	LD_PRELOAD=libsyscall_intercept.so \
	gdb ls
```

With this filtering, the intercepting library is not activated in the gdb
process itself.
