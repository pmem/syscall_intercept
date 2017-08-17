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
 */

.global intercept_asm_wrapper_tmpl;
.hidden intercept_asm_wrapper_tmpl;
.global intercept_asm_wrapper_patch_desc_addr;
.hidden intercept_asm_wrapper_patch_desc_addr;
.global intercept_asm_wrapper_wrapper_level1_addr;
.hidden intercept_asm_wrapper_wrapper_level1_addr;
.global intercept_asm_wrapper_tmpl_end;
.hidden intercept_asm_wrapper_tmpl_end;

.text

intercept_asm_wrapper_tmpl:
	movq        $0x0, %rcx /* choose intercept_routine */

0:	movq        %rsp, %r11 /* remember original rsp */
	subq        $0x80, %rsp  /* red zone */
	andq        $-32, %rsp /* align the stack */
	subq        $0x38, %rsp
	movq        %r11, (%rsp) /* orignal rsp on stack */
intercept_asm_wrapper_patch_desc_addr:
	movabsq     $0x000000000000, %r11
	movq        %r11, 0x8 (%rsp) /* patch_desc pointer on stack */
intercept_asm_wrapper_wrapper_level1_addr:
	movabsq     $0x000000000000, %r11
	callq       *%r11 /* call intercept_wrapper */
	movq        (%rsp), %rsp /* restore original rsp */
	/*
	 * The intercept_wrapper function did restore all registers to their
	 * original state, except for rax, rsp, rip, and r11.
	 *
	 * If r11 is zero, rax contains a syscall number, and that syscall
	 *  is executed here.
	 * If r11 is 1, rax contains the return value of the hooked syscall.
	 * If r11 is 2, a clone syscall is executed here.
	 */
	cmp         $0x0, %r11
	je          2f
	cmp         $0x1, %r11
	je          3f
	cmp         $0x2, %r11
	je          1f

	hlt /* r11 value is invalid? */

1:
	/* execute the clone syscall in its original context */
	syscall
	movq        $0x1, %rcx /* choose intercept_routine_post_clone */
	/*
	 * Now goto 0, and call the C function named
	 * intercept_routine_post_clone both in the parent thread, adn the
	 * child thread.
	 */
	jmp         0b

2:
	syscall
3:
intercept_asm_wrapper_tmpl_end:
