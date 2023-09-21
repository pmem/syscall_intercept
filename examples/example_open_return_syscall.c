#include <libsyscall_intercept_hook_point.h>
#include <syscall.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h> // Include the standard library for setenv

static int
hook(long syscall_number,
			long arg0, long arg1,
			long arg2, long arg3,
			long arg4, long arg5,
			long *result)
{
	if (syscall_number == SYS_openat) {
		/*
		 * Prevent the application from
		 * using the getdents syscall. From
		 * the point of view of the calling
		 * process, it is as if the kernel
		 * would return the ENOTSUP error
		 * code from the syscall.
		 */
        *result = syscall_number;
        printf("Syscall number = %ld\n",syscall_number);
        printf("SYS_openat(%ld, %ld, %ld, %ld, %ld, %ld)\n",
               arg0, arg1, arg2, arg3, arg4, arg5);
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
    setenv("INTERCEPT_LOG", "intercept.log", 1);

	// Set up the callback function
	intercept_hook_point = hook;
}