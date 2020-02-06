/*
 * Copyright 2016-2020, Intel Corporation
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
 * Wrapper function to use with the disassembler.
 * This should allow us to use a different disassembler,
 * without changing the intercept.c source file.
 *
 * The result of disassembling deliberately lacks a lot
 * of information about the instruction seen, to make it
 * easy to interface a new disassembler.
 */

#ifndef INTERCEPT_DISASM_WRAPPER_H
#define INTERCEPT_DISASM_WRAPPER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct intercept_disasm_result {
	const unsigned char *address;

	bool is_set;

	bool is_syscall;

	/* Length in bytes, zero if disasm was not successful. */
	unsigned length;

	/*
	 * Flag marking instructions that have a RIP relative address
	 * as an operand.
	 */
	bool has_ip_relative_opr;

	/* as of now this only refers to endbr64 */
	bool is_endbr;

	/*
	 * Flag marking lea instructions setting a 64 bit register to a
	 * RIP relative address. They can be relocated -- but by simple memcpy.
	 */
	bool is_lea_rip;

	/*
	 * The X86 encoding of 64 bit register being set in an instruction
	 * marked above as is_lea_rip.
	 */
	unsigned char arg_register_bits;

	/* call instruction */
	bool is_call;

	bool is_jump;

	/*
	 * The flag is_rel_jump marks any instruction that jumps, to
	 * a relative address encoded in its operand.
	 * This includes call as well.
	 */
	bool is_rel_jump;

	bool is_indirect_jump;

	bool is_ret;

	bool is_nop;

	/*
	 * Optional fields:
	 * The rip_disp field contains the displacement used in
	 * instructions referring to RIP relative addresses.
	 * The rip_ref_addr field contains the absolute address of
	 * such a reference, computed based on the rip_disp.
	 * These are only valid, when has_ip_relative_opr is true.
	 */
	int32_t rip_disp;
	const unsigned char *rip_ref_addr;

#ifndef NDEBUG
	const char *mnemonic;
#endif
};

struct intercept_disasm_context;

struct intercept_disasm_context *
intercept_disasm_init(const unsigned char *begin, const unsigned char *end);

void intercept_disasm_destroy(struct intercept_disasm_context *context);

struct intercept_disasm_result
intercept_disasm_next_instruction(struct intercept_disasm_context *context,
					const unsigned char *code);

#endif
