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

#
# A single syscall instruction, with a suitable NOP close to it. The patching
# code is expected to recognize, that altering the instructions right next to
# the syscall is not necessary. The 2 byte syscall instruction can be
# overwritten with a jmp instruction of the same size, and a jump with a longer
# range can be inserted into the unused bytes in the nop instruction.

.intel_syntax noprefix

.global text_start;
.global text_end;

.global dummy_symbol;
.type dummy_symbol, @function;

#include "mock_trampoline_table.S"

.text

text_start:
		xor     rax, rax
		mov     rax, 1
		syscall        # should be replaced with a jmp having 8bit disp.
		cmp     rax, -1
		mov     rax, 2
		inc     rax
		.byte   0x0f           # nop     DWORD PTR [rax+rax*1+0x0]
		.byte   0x1f           # this nop should be overwritten
		.byte   0x84           # to provide the jump that actually
		.byte   0x00           # jumps out of the text segment
		.byte   0x00
		.byte   0x00
		.byte   0x00
		.byte   0x00
		inc     rax

text_end:
