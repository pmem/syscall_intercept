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
 * intercept_template.s
 *
 * The syscall instructions in glibc are
 * overwritten with a call instruction, which
 * jumps here. This assembly wrapper has to achieve multiple things
 * that can not be achieved in C:
 *
 * libc expects the registers not clobbered by a syscall to have the
 * same value before and after a syscall instruction. C function calls
 * clobber a different set of registers. To make sure this doesn't cause
 * problems, all registers are saved on the stack before calling the
 * C function, and these register values are restored after the function
 * returns. This gives the following steps:
 *
 * - save registers
 * - call C function
 * - restore registers
 * - jump back to libc
 *
 * Besides this, many syscall instructions in libc are present in leaf
 * functions. These don't necessarily have to set up the stack pointer,
 * leaf functions can just use e.g. the address (RSP - 16) to store
 * local variables. But they definitely can not use the memory more than
 * 128 bytes below the stack pointer -- this area is usually referred to as
 * red zone, see: https://en.wikipedia.org/wiki/Red_zone_(computing) .
 * Signal handlers are examples of code that can use the stack of the current
 * thread between any two instructions, like this code does. This leaves us
 * with the following steps ( new steps are marked with an asterisk ) :
 *
 * - * decrement the stack pointer by 128
 * - save registers
 * - call C function
 * - restore registers
 * - * increment the stack pointer by 128
 * - jump back to libc
 *
 * When patching libc, sometimes some instructions surrounding the original
 * syscall instruction need to be relocated, to make space for a jump
 * instruction that would otherwise not fit in the two byte of the syscall
 * instruction. These instructions are moved into this assembly template.
 * Considering these additional steps:
 *
 * - * execute instructions relocated from before the original syscall
 * - decrement the stack pointer by 128
 * - save registers
 * - call C function
 * - restore registers
 * - increment the stack pointer by 128
 * - * execute instructions relocated from after the original syscall
 * - jump back to libc
 *
 * Note: the relocated instructions need to be executed while the
 * stack pointer is not altered. This way, they can still use RSP.
 * The only register these instructions can't rely on, is RIP. Therefore
 * instructions such as 'mov $5, 6(%rip)', 'jmp 4', etc... can not be
 * relocated.
 *
 * The arguments in the C function call ABI are passed in a way
 * that is different from the syscall ABI. E.g. when calling the libc
 * function called 'syscall', the first argument is the syscall number,
 * and it is passed in RDI. A syscall instruction expects the syscall number
 * in RAX. A conversion between the two calling conventions must be done
 * before calling the C function.
 *
 * - execute instructions relocated from before the original syscall
 * - decrement the stack pointer by 128
 * - save registers
 * - * rearrange arguments to use the appropriate calling convention
 * - call C function
 * - restore registers
 * - increment the stack pointer by 128
 * - execute instructions relocated from after the original syscall
 * - jump back to libc
 *
 * Sometimes the C function executes the actual syscall, sometimes
 * it calls a hook function to provide a user space implementation.
 * In case of creating a thread ( using SYS_clone ), none of these
 * two approaches can work. The new thread is starting execution on a
 * new stack - therefore the 'restore registers' step would fail.
 * So creating a new thread can not be hooked, and this assembly
 * template provides a way to execute such a syscall while avoiding
 * any stack related issues. This is achieved by actually executing the
 * syscall instruction *after* all the registers are already restored.
 *
 * - execute instructions relocated from before the original syscall
 * - decrement the stack pointer by 128
 * - save registers
 * - rearrange arguments to use the appropriate calling convention
 * - call C function
 * - restore registers
 * - increment the stack pointer by 128
 * - * if(special_syscall) execute syscall
 * - execute instructions relocated from after the original syscall
 * - jump back to libc
 *
 * Since there is a separate copy of this assembly template made in the
 * data segment for each patched syscall, a debugger is generally not able to
 * unwind the stack -- it needs debug information which can only be supplied
 * for code in the stack segment, not for code generated dynamically. This
 * lack of complete callstack information can make debugging very difficult.
 * To address this problem, a trick is introduced that supplies a 'fake'
 * return address when calling the C function. This fake return address points
 * to a function in the text segment, for which appropriate debug information
 * is available for debuggers. This is the magic routine seen in the code
 * below, and seen in the callstack. So instead calling the C function with
 * call instruction, and address inside a placeholder routine is pushed on the
 * stack, and a jump instruction jumps to the C function -- this makes a
 * debugger believe that the C function was called from the said placeholder
 * Appropriate debug information is provided using the cfi_def_cfa_offset
 * assembler directive as follows:
 *
 * backtrace_placeholder:
 *	.cfi_startproc
 *	.cfi_def_cfa_offset 0x580
 *	nop
 *	nop
 *	nop
 *	nop
 *	.cfi_endproc
 *
 * Whenever a debugger sees the instruction pointer pointing to an instruction
 * inside this routine, it assumes the routine uses 0x580 bytes of stack space.
 * This matches the stack space used by the assembly code generated from this
 * template, so a debugger can look for the stack of original libc routine
 * at the correct place. This brings up a new problem: The C function can't
 * just return once it has all it needs to do, as the return address it would
 * normally return to is a faked return address. To handle this problem, the C
 * function receives the real return address as an argument, and jumps to this
 * address instead of returning. The xlongjmp routine serves this purpose:
 * xlongjmp sets the RAX register ( the return value of the C function ), the
 * RSP register ( to restore the stack pointer after the C function ), and the
 * RIP register ( instead of using a ret instruction ).
 * This mechanism is also used for deciding if the original syscall instruction
 * should be executed in this assembly code or not ( remember SYS_clone ).
 * So the additional arguments passed to the C function are as follows:
 *
 * long return_to_asm_wrapper_syscall
 * long return_to_asm_wrapper
 * long rsp_in_asm_wrapper
 *
 * Where return_to_asm_wrapper_syscall is address to jump back to if
 * original syscall instruction must be executed once the original stack is
 * not used anymore.
 * The return_to_asm_wrapper argument is address to jump back to if that is
 * not needed.
 * The rsp_in_asm_wrapper is the value RSP held before calling the function,
 * and should be restored to after the function 'returns'. Normally this would
 * be achieved by the function prologue generated by the compiler.
 * The R11 register used as a flag to signal a special syscall.
 * The resulting steps are:
 *
 * - execute instructions relocated from before the original syscall
 * - decrement the stack pointer by 128
 * - save registers
 * - * pass additional argument to the C function
 * - rearrange syscall arguments to use the appropriate calling convention
 * - * call the C function using the faked return address
 * - * C function returns, and doesn't ask for the syscall, R11 := 1
 * - * C function returns, and does ask for the syscall, R11 := 0
 * - restore registers
 * - increment the stack pointer by 128
 * - if(R11 == 0) execute syscall
 * - execute instructions relocated from after the original syscall
 * - jump back to libc
 *
 * Alignment issues:
 * The ABI requires the stack pointer to aligned to a 16 byte boundary
 * upon entering a function. The leaf functions inside libc don't always
 * leave the stack pointer 16 byte aligned when issuing a syscall, as that
 * is not required for a syscall instruction. Thus, this code must take
 * care of stack alignment before calling anything created with a C
 * compiler. This has a nasty side effect: the magic routine explained above
 * presents a fixed stack size to debuggers. But aligning the stack can
 * makes it impossible to guarantee using a fixed stack size. Therefore,
 * two versions of the magic placeholder routine are supplied, with different
 * stack sizes. One of them is used if the stack used by this code is 16n bytes
 * ( when the stack pointer was already 16 aligned ), the other one is used when
 * 16n + 8 bytes of stack is used ( when the original RSP is just 8 bytes
 * aligned ). An address in the appropriate function is used as the faked
 * return address pushed on the stack before calling the C function.
 */

.global backtrace_placeholder;
.type   backtrace_placeholder, @function

.global backtrace_placeholder_2;
.type   backtrace_placeholder_2, @function

.global intercept_asm_wrapper_tmpl;
.global intercept_asm_wrapper_simd_save;
.global intercept_asm_wrapper_prefix;
.global intercept_asm_wrapper_push_origin_addr;
.global intercept_asm_wrapper_mov_return_addr_r11_no_syscall;
.global intercept_asm_wrapper_mov_return_addr_r11_syscall;
.global intercept_asm_wrapper_mov_libpath_r11;
.global intercept_asm_wrapper_mov_phaddr_r11;
.global intercept_asm_wrapper_mov_ph2addr_r11;
.global intercept_asm_wrapper_call;
.global intercept_asm_wrapper_simd_restore;
.global intercept_asm_wrapper_postfix;
.global intercept_asm_wrapper_return_jump;
.global intercept_asm_wrapper_end;
.global intercept_asm_wrapper_simd_save_YMM;
.global intercept_asm_wrapper_simd_save_YMM_end;
.global intercept_asm_wrapper_simd_restore_YMM;
.global intercept_asm_wrapper_simd_restore_YMM_end;
.global intercept_asm_wrapper_return_and_no_syscall;
.global intercept_asm_wrapper_return_and_syscall;
.global intercept_asm_wrapper_push_stack_first_return_addr;
.global intercept_asm_wrapper_mov_r11_stack_first_return_addr;
.global intercept_asm_wrapper_clone_wrapper;
.global intercept_asm_wrapper_call_clone_child_intercept;

.text

backtrace_placeholder:
	.cfi_startproc
	.cfi_def_cfa_offset 0x580
	nop
	nop
	nop
	nop
	.cfi_endproc

.size   backtrace_placeholder, .-backtrace_placeholder

backtrace_placeholder_2:
	.cfi_startproc
	.cfi_def_cfa_offset 0x578
	nop
	nop
	nop
	nop
	.cfi_endproc

.size   backtrace_placeholder_2, .-backtrace_placeholder_2

intercept_asm_wrapper_tmpl:
	nop

intercept_asm_wrapper_prefix:
	/*
	 * The placeholder nops for whatever instruction
	 * preceding the syscall instruction in glibc was overwritten
	 */
.fill 20, 1, 0x90

intercept_asm_wrapper_mov_r11_stack_first_return_addr:
.fill 20, 1, 0x90
intercept_asm_wrapper_push_stack_first_return_addr:
	subq        $0x8, %rsp
.fill 10, 1, 0x90

	subq        $0x78, %rsp  /* red zone */

	pushq       %rbp
	movq        %rsp, %rbp /* save the original rsp value */
	addq        $0x88, %rbp
	pushf
	pushq       %r15
	pushq       %r14
	pushq       %r13
	pushq       %r12
	pushq       %r10
	pushq       %r9
	pushq       %r8
	pushq       %rcx
	pushq       %rdx
	pushq       %rsi
	pushq       %rdi

	pushq       %rbx

	movq        %rsp, %rbx

	orq         $0x1f, %rsp
	subq        $0x3f, %rsp
	/*
	 * Reserve stack for SIMD registers.
	 * Largest space is used in the AVX512 case, 32 * 32 bytes.
	 */
	subq       $0x400, %rsp
intercept_asm_wrapper_simd_save:
	/*
	 * Save any SIMD registers that need to be saved,
	 * these nops are going to be replace with CPU
	 * dependent code.
	 */
	movaps      %xmm0, (%rsp)
	movaps      %xmm1, 0x10 (%rsp)
	movaps      %xmm2, 0x20 (%rsp)
	movaps      %xmm3, 0x30 (%rsp)
	movaps      %xmm4, 0x40 (%rsp)
	movaps      %xmm5, 0x50 (%rsp)
	movaps      %xmm6, 0x60 (%rsp)
	movaps      %xmm7, 0x70 (%rsp)
.fill 32, 1, 0x90

	pushq       %rbx
	movq        %rsp, %r11

	movq        %rbp, %rsp
	subq        $0x548, %rsp

	/*
	 * Fix the alignment if needed. The C functions called
	 * from here expect 16 byte aligned stack.
	 *
	 * Important! The alignment is fixed up before the function
	 * call arguments are pushed to the stack. Therefore, the branch
	 * below must be jz or jnz based on the number of arguments pushed.
	 * The stack must be aligned to a 16 byte boundary right after the
	 * push instructions, and before the call instruction.
	 */
	andq        $0x8, %rbp
	jz          L3
	subq        $0x8, %rsp
L3:

	/*
	 * The following values pushed on the stack are
	 * arguments of the C routine.
	 * First we push value of rsp that should be restored
	 * upon returning to this code.
	 *
	 * See: intercept_routine in intercept.c
	 */
	pushq       %r11 /* rsp_in_asm_wrapper */

	leaq        L7(%rip), %r11
	pushq       %r11 /* clone_wrapper */

intercept_asm_wrapper_mov_return_addr_r11_no_syscall:
.fill 10, 1, 0x90
	pushq       %r11 /* return_to_asm_wrapper */

intercept_asm_wrapper_mov_return_addr_r11_syscall:
.fill 10, 1, 0x90
	pushq       %r11 /* return_to_asm_wrapper_syscall */

intercept_asm_wrapper_mov_libpath_r11:
.fill 10, 1, 0x90
	pushq       %r11 /* libpath */

intercept_asm_wrapper_push_origin_addr:
.fill 5, 1, 0x90 /* syscall_offset */


	/*
	 * Convert the arguments list to one used in
	 * the linux x86_64 ABI. The reverse of what
	 * is done syscall_no_intercept.
	 *
	 * syscall arguments are expected in:
	 *   rax, rdi, rsi, rdx, r10, r8, r9
	 *
	 * C function expects arguments in:
	 *   rdi, rsi, rdx, rcx, r8, r9, [rsp + 8]
	 */
	pushq       %r9

	movq        %r8, %r9
	movq        %r10, %r8
	movq        %rdx, %rcx
	movq        %rsi, %rdx
	movq        %rdi, %rsi
	movq        %rax, %rdi

	/*
	 * Move the faked return address into r11, so that it can be
	 * pushed to the stack. The stack size to present to gdb depends
	 * on the stack alignment.
	 * If the stack pointer originally was not 16 byte aligned, this
	 * code will use 16n+8 bytes of stack -- this should fix the alignment.
	 * We ignore the case the RSP is not even 8 byte aligned, as that wasn't
	 * encountered before, and this is just a nicety for debugging.
	 * If the stack was originally 16 byte aligned, this code will use
	 * 16n bytes of stack, thus keeping the alignment correct.
	 *
	 * To explain all this to gdb, the return address should point into
	 * a function that uses the appropriate stack space, and the binary
	 * has debug information associated with it. For this purpuse addresses
	 * in backtrace_placeholder, or backtrace_placeholder_2 are used.
	 * The appropriate mov instructions should be filled in the template, e.g.:
	 * at intercept_asm_wrapper_mov_ph2addr_r11, where mov_ph2addr_r11
	 * stands for 'mov placeholder2 address into r11' a movabs instruction
	 * is expected, with an actual runtime address in
	 * backtrace_placeholder_2. It wouldn't be easy to fill this compile,
	 * especially since GAS is designed for compiler generated assembly, and
	 * I don't know how to describe such a thing in this syntax.
	 */
	andq        $0x8, %rbp
	jnz         L4
intercept_asm_wrapper_mov_phaddr_r11:
.fill 10, 1, 0x90
	jmp         L5
L4:
intercept_asm_wrapper_mov_ph2addr_r11:
.fill 10, 1, 0x90
L5:
	pushq       %r11  /* push the fake return address */

intercept_asm_wrapper_call:
	/*
	 * Calling into the code written in C.
	 * Use the return value in rax as the return value
	 * of the syscall.
	 */
.fill 5, 1, 0x90

	/* addq        $0x18, %rsp */

intercept_asm_wrapper_return_and_no_syscall:
	movq        $0x1, %r11
	jmp L1
intercept_asm_wrapper_return_and_syscall:
	movq        $0x0, %r11
L1:
	popq        %rbx

intercept_asm_wrapper_simd_restore:
	movaps      (%rsp), %xmm0
	movaps      0x10 (%rsp), %xmm1
	movaps      0x20 (%rsp), %xmm2
	movaps      0x30 (%rsp), %xmm3
	movaps      0x40 (%rsp), %xmm4
	movaps      0x50 (%rsp), %xmm5
	movaps      0x60 (%rsp), %xmm6
	movaps      0x70 (%rsp), %xmm7
.fill 32, 1, 0x90


	movq        %rbx, %rsp

	popq        %rbx    /* restoring the rest of the registers */

	popq        %rdi
	popq        %rsi
	popq        %rdx
	popq        %rcx
	popq        %r8
	popq        %r9
	popq        %r10
	popq        %r12
	popq        %r13
	popq        %r14
	popq        %r15
	popf
	popq        %rbp
	addq        $0x80, %rsp  /* return address + mock rbp + red zone */

	cmp         $0x1, %r11
	je          L2
	/* execute fork, clone, etc.. */
	/* assuming the syscall does not use a seventh argument */
	syscall
L2:
	nop
intercept_asm_wrapper_postfix:
	/*
	 * The placeholder nops for whatever instruction
	 * following the syscall instruction in glibc was overwritten.
	 */
.fill 20, 1, 0x90

intercept_asm_wrapper_return_jump:
.fill 20, 1, 0x90

L7:
intercept_asm_wrapper_clone_wrapper:
	/*
	 * Called from C, as clone_wrapper(arg0, arg1, arg2, arg3, arg4, arg5)
	 * The arguments passed from C vs. arguments of the clone syscall (in
	 * the case of creating a new thread):
	 *
	 *                   C (System V ABI)  vs.  Linux syscall
	 * syscall number       [implied]              rax
	 *          flags         rdi                  rdi
	 *      new stack         rsi                  rsi
	 *     parent TID         rdx                  rdx
	 *      child TID         rcx                  r10
	 * thread pointer         r8                   r8
	 *
	 * The only two differences in the above table: the syscall number is
	 * not in rax when this code is called from C, and arg3 must be passed
	 * in r10 instead of rcx.
	 *
	 * If the syscall return value is non-zero, this subroutine behaves
	 * as a regular function, called from C, returning to C. On the other
	 * hand, if the return value is zero, this subroutine jumps back to
	 * libc (without restoring any of the registers) instead of returning
	 * to the C caller.
	 */
	movq        $56, %rax       /* Linux SYS_clone */
	movq        %rcx, %r10      /* account for syscall calling convention */
	syscall
	testq       %rax, %rax      /* in a child thread? */
	jz          L6              /* yes, in a new child */
	retq                        /* no, return as normal */

L6:                                 /* in a new child */
intercept_asm_wrapper_call_clone_child_intercept:
.fill 20, 1, 0x90                   /* placeholder for call to C hook */
	movq        $0, %rax        /* clone - return value in child */
	jmp         L2              /* back to libc */

intercept_asm_wrapper_end:

intercept_asm_wrapper_simd_save_YMM:
	vmovaps     %ymm0, (%rsp)
	vmovaps     %ymm1, 0x20 (%rsp)
	vmovaps     %ymm2, 0x40 (%rsp)
	vmovaps     %ymm3, 0x60 (%rsp)
	vmovaps     %ymm4, 0x80 (%rsp)
	vmovaps     %ymm5, 0xa0 (%rsp)
	vmovaps     %ymm6, 0xc0 (%rsp)
	vmovaps     %ymm7, 0xe0 (%rsp)
intercept_asm_wrapper_simd_save_YMM_end:

intercept_asm_wrapper_simd_restore_YMM:
	vmovaps     (%rsp), %ymm0
	vmovaps     0x20 (%rsp), %ymm1
	vmovaps     0x40 (%rsp), %ymm2
	vmovaps     0x60 (%rsp), %ymm3
	vmovaps     0x80 (%rsp), %ymm4
	vmovaps     0xa0 (%rsp), %ymm5
	vmovaps     0xc0 (%rsp), %ymm6
	vmovaps     0xe0 (%rsp), %ymm7
intercept_asm_wrapper_simd_restore_YMM_end:
