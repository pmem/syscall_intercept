# Assembly code used during interception #

### Introduction

This text is only valid in the context of the x86-64 ABI, and only on Linux.

  One can not issue a jump from the place of a patched syscall instruction
to C function, due perky ABI details. This is simply not supported, and is
only possible with taking some ISA specific knowledge, and some handwritten
assembly is required for this transition.

### Generating instances from intercept_template.s ###

  The syscall instructions can't replaced with a call instruction (that could
ruin the stack by pushing a return value), and can't be returned to using a ret
instruction (the stack!). Thus the syscalls are replaced by jump instructions.
But the intercepting code must eventually jump back to the intercepted code,
and has no information about where that is. The solution is to jump to a
different destination from the place of each syscall, giving the intercepting
code the information about the origin of the jumps: its own address. Since all
jumps jump to different places, this can be used to infer the origin of those
jumps. The code in [intercept_template.s](intercept_template.s) serves
this purpuse. Different instances are generated from this template to
different locations in memory, all of which are able to jump back to the
right address in the intercepted code. These instance are also equipped with
an another information specific to a syscall: a pointer to the
[struct patch_desc](intercept.h#L92) instance associated with the
particular patched syscall.

An illustrain of this with two syscalls in a section of intercepted code:

```asm
0x0010       mov  $2, %eax
0x0019       jmp  $0x1100         # an overwritten syscall
0x0020       cmp  $-4095, %rax
0x0026       jle  $0x0100
0x0032       ret
0x0040       mov  $3, %eax
0x0049       jmp  $0x1200         # another overwritten syscall
0x0040       cmp  $-4095, %rax
0x0049       jle  $0x0100
0x0052       ret
```

This code has two jumps:
One jump to 0x1100, from where the intercepting code must jump back to 0x0020,
one jump to 0x1200, from where the intercepting code must jump back to 0x0040.

A simplifed version of the template in
[intercept_template.s](intercept_template.s#L65):

```asm
mov  %rsp, %r11   # remember the original value of $rsp
sub  $0x80, $rsp  # respect the red zone
and  $-32, %rsp   # align the stack
sub  $0x38, %rsp  # allocate space for some locals
mov  %r11, (%rsp) # save the original value of #rsp
mov  $0x000000000000, %r11 # the address of a function to call
call *r11         # call into code common to all syscalls
mov  (%rsp), %rsp # restore original %rsp, as it was in the intercepted code
```

Two copies of this template are generated, with some different additions, both
of which give eventually control to a function at address 0x3333330, and return
to the correct address:

```asm
0x1100       mov  %rsp, %r11
0x1105       sub  $0x80, $rsp
0x110a       and  $-32, %rsp
0x1110       sub  $0x38, %rsp
0x1116       mov  %r11, (%rsp)
0x111b       mov  $0x000003333330, %r11
0x113a       call *%r11
0x1140       mov  (%rsp), %rsp
0x1144       jmp  absolute address 0x0020 # instruction appended to the template
...
0x1200       mov  %rsp, %r11
0x1205       sub  $0x80, $rsp
0x120a       and  $-32, %rsp
0x1210       sub  $0x38, %rsp
0x1216       mov  %r11, (%rsp)
0x121b       mov  $0x000003333330, %r11
0x113a       call *%r11
0x1140       mov  (%rsp), %rsp
0x1144       jmp  absolute address 0x0040 # instruction appended to the template
```

Both copies of the template must be patched to contain the address of the
common function, and both are appended with a jump instruction.


### Life is difficult near a syscall instruction ###

  The code around the syscall instruction does not expect a C function
to be executed at that point. There are some differences between the
two scenario, which must be hidden from the calling code.

  One important difference is the set of registers being callee-saved,
and the set of caller-saved registers [[1]](#1-x86-64-abi). The code in
[intercept_wrapper.s](intercept_wrapper.s#L93) saves all registers
it can on the stack, and restores them before returning to the caller.
Recently both clang and GCC implemented a function attribute called
no_caller_saved_registers [[2]](#2-gcc-attributes) [[4]](#4-clang-attributes),
which could be used to solve this without handwritten assembly, but as of
September 2017 these new compiler versions are not widespread enough.

  The stack pointer is not necessarily correctly
aligned [[1]](#1-x86-64-abi) for a C function call. This is easily fixed
in [intercept_template.s](intercept_template.s#L70).
It is very easy to think that the force_align_arg_pointer [[2]](#2-gcc-attributes)
function attribute available in GNUC can be used to solve this issue without
handwritten assembly, but that is not the case [[3]](#3-about-force-align-arg-pointer-function).
Also, the code aligns the stack to a 32 byte boundary, rather than the 16 byte
boundary required for regular C functions. This is because the AVX registers
are saved on this stack (if they are available).

  If the syscall instruction is in a leaf function, the routine containing
it might be using the red zone [[1]](#1-x86-64-abi) for local variables.
This is also solved trivially in [intercept_template.s](intercept_template.s#L69)
by adjusting the stack pointer.

  In the case of most syscalls, this first level wrapper code doesn't do anything
other than calling the other [intercept_wrapper](intercept_wrapper.s#L75), and
jumping back to the intercepted code, once everything is done.

### Footnotes

###### [1] [x86-64 ABI](https://github.com/hjl-tools/x86-psABI/wiki/x86-64-psABI-r252.pdf)
  * Appendix A.2.1 "User-level applications use as integer registers for passing the sequence %rdi, %rsi, %rdx, %rcx, %r8 and %r9. The kernel interface uses %rdi, %rsi, %rdx, %r10, %r8 and %r9."
  * 3.2.2 "The end of the input argument area shall be aligned on a 16 byte boundary."
  * 3.2.2 "The 128-byte area beyond the location pointed to by %rsp is considered to be reserved and shall not be modified by signal or interrupt handlers...This area is known as the red zone"
###### [2] [GCC attributes](https://gcc.gnu.org/onlinedocs/gcc/x86-Function-Attributes.html)
  * "On x86 targets, the force_align_arg_pointer attribute may be applied to individual function definitions, generating an alternate prologue and epilogue that realigns the run-time stack if necessary."
###### [3] [about force-align-arg-pointer-function](http://clang-developers.42468.n3.nabble.com/Is-force-align-arg-pointer-function-attribute-supported-at-x86-td4057053.html)
###### [4] [clang attributes](https://clang.llvm.org/docs/AttributeReference.html)
