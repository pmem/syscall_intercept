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

# A program with a syscall instruction.
# This only serves for testing syscall_intercept's ability to
# patch syscalls in the main executable object of a process.

.intel_syntax noprefix

.global main;

.text

main:
		cmp     rdi, 2         # cmp argc with 2
		jl      0f             # jump if argc < 2
		add     rsi, 8         # inc argv
		mov     rsi, [rsi]     # syscall argument: argv[1]
		mov     rdi, rsi       # copy argv[1] to rdi
		xor     rcx, rcx
		not     rcx
		shr     rcx, 1         # scan -- max iteration count: SSIZE_MAX
		sub     al, al         # scan -- byte to look for: '\0'
		cld                    # scan -- setup direction: forward
repne		scasb                  # scan memory to find null terminator
		sub     rdi, rsi       # compute strlen
		mov     rdx, rdi       # syscall argument: buffer len
		mov     rdi, 1         # syscall argument: stdout
		mov     rax, 1         # syscall number: SYS_write
		syscall
		mov     rdi, 1         # syscall argument: stdout
		lea     rsi, [rip + newline] # syscall argument: buffer
		mov     rdx, 1         # syscall argument: length
		mov     rax, 1         # syscall number: SYS_write
		syscall
		mov     rax, 0         # return 0
		ret
0:		mov     rax, 1         # return 1
		ret

.data
newline:	.byte 0xa
