#
# Copyright 2017, Intel Corporation
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#
#     * Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# see pattern_nop_padding2.in.S
#
# The same test as in pattern_nop_padding3, except the nop is much further
# from the syscall. Still, it is close enough, to use the 5 bytes starting
# at the third byte of the nop as a mini trampoline.

.intel_syntax noprefix

.global text_start;
.global text_end;

.global dummy_symbol;
.type dummy_symbol, @function;

#include "mock_trampoline_table.S"

.text

text_start:
		xor     rax, rax
		.byte   0x66           # nop     WORD PTR cs:[rax+rax*1+0x0]
		.byte   0x2e
		.byte   0x0f
		.byte   0x1f
		.byte   0x84
		.byte   0x00
		.byte   0x00
		.byte   0x00
		.byte   0x00
		.byte   0x00
		inc     rax
		inc     rax
		dec     rax
		dec     rax
		dec     rax
		dec     rax
		dec     rax
		dec     rax
		dec     rax
		dec     rax
		dec     rax
		dec     rax
		dec     rax
		dec     rax
		dec     rax
		dec     rax
		dec     rax
		dec     rax
		dec     rax
		dec     rax
		dec     rax
		dec     rax
		dec     rax
		dec     rax
		dec     rax
		dec     rax
		dec     rax
		dec     rax
		dec     rax
		dec     rax
		dec     rax
		dec     rax
		dec     rax
		dec     rax
		dec     rax
		dec     rax
		inc     rax
		mov     rax, 1
		syscall
		cmp     rax, -1
		mov     rax, 2
		inc     rax
		mov     rax, 1
		syscall
		cmp     rax, -1
		mov     rax, 2
		inc     rax
text_end:
