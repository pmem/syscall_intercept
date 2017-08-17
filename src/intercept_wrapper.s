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

.global intercept_wrapper
.type intercept_wrapper, @function

.global intercept_routine
.type intercept_routine, @function

.global intercept_routine_post_clone
.type intercept_routine_post_clone, @function

.text

/*
 * Arguments:
 * 0x00(%rsp)  -- return address, to the generated asm wrapper
 * 0x08(%rsp)  -- original value of rsp
 * 0x10(%rsp)  -- pointer to patch_desc
 */
intercept_wrapper:
	.cfi_startproc
	.cfi_def_cfa_offset 0x440

	movq        %rax, -0x160 (%rsp)
	.cfi_offset 0, -0x160
	movq        %rdx, -0x158 (%rsp)
	.cfi_offset 1, -0x158
	/* rcx is already clobbered, no reason to save it */
	movq        %rbx, -0x150 (%rsp)
	.cfi_offset 3, -0x150
	movq        %rsi, -0x148 (%rsp)
	.cfi_offset 4, -0x148
	movq        %rdi, -0x140 (%rsp)
	.cfi_offset 5, -0x140
	movq        %rbp, -0x138 (%rsp)
	.cfi_offset 6, -0x138
	movq        0x8 (%rsp), %r11 /* fetch original value of rsp */
	movq        %r11, -0x130 (%rsp)
	.cfi_offset 7, -0x130
	movq        %r8, -0x128 (%rsp)
	.cfi_offset 8, -0x128
	movq        %r9, -0x120 (%rsp)
	.cfi_offset 9, -0x120
	movq        %r10, -0x118 (%rsp)
	.cfi_offset 10, -0x118
	/* r11 is already clobbered, no reason to save it */
	movq        %r12, -0x110 (%rsp)
	.cfi_offset 12, -0x110
	movq        %r13, -0x108 (%rsp)
	.cfi_offset 13, -0x108
	movq        %r14, -0x100 (%rsp)
	.cfi_offset 14, -0x100
	movq        %r15, -0xf8 (%rsp)
	.cfi_offset 15, -0xf8
	movq        0x10 (%rsp), %r11 /* fetch pointer to patch_desc */
	movq        %r11, -0xe8 (%rsp)
	movq        (%r11), %r11 /* fetch original value of rip */
	movq        %r11, -0xf0 (%rsp)
	.cfi_offset 16, -0xf0

	movaps      %xmm0, -0x3c0 (%rsp)
	movaps      %xmm1, -0x380 (%rsp)
	movaps      %xmm2, -0x340 (%rsp)
	movaps      %xmm3, -0x300 (%rsp)
	movaps      %xmm4, -0x2c0 (%rsp)
	movaps      %xmm5, -0x280 (%rsp)
	movaps      %xmm6, -0x240 (%rsp)
	movaps      %xmm7, -0x200 (%rsp)

	/* argument passed to intercept_routine */
	leaq        -0x160 (%rsp), %rdi

	subq        $0x440, %rsp
	cmp         $0x1, %rcx /* which function should be called? */
	je          0f
	call        intercept_routine@PLT
	jmp         1f
0:	call        intercept_routine_post_clone@PLT
1:
	/*
	 * At this point, the return value of the C
	 * function (a struct wrapper_ret instance) is in rax, rdx.
	 */

	movq        %rdx, %r11
	/*
	 * At this point, the return values of this asm function
	 * are in rax, r11.
	 */

	addq        $0x440, %rsp

	movaps      -0x3c0 (%rsp), %xmm0
	movaps      -0x380 (%rsp), %xmm1
	movaps      -0x340 (%rsp), %xmm2
	movaps      -0x300 (%rsp), %xmm3
	movaps      -0x2c0 (%rsp), %xmm4
	movaps      -0x280 (%rsp), %xmm5
	movaps      -0x240 (%rsp), %xmm6
	movaps      -0x200 (%rsp), %xmm7

	movq        -0x158 (%rsp), %rdx
	movq        -0x150 (%rsp), %rbx
	movq        -0x148 (%rsp), %rsi
	movq        -0x140 (%rsp), %rdi
	movq        -0x138 (%rsp), %rbp
	movq        -0x128 (%rsp), %r8
	movq        -0x120 (%rsp), %r9
	movq        -0x118 (%rsp), %r10
	movq        -0x110 (%rsp), %r12
	movq        -0x108 (%rsp), %r13
	movq        -0x100 (%rsp), %r14
	movq        -0xf8 (%rsp), %r15

	retq
	.cfi_endproc
