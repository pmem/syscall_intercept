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
 * disasm_wrapper.c -- connecting the interceptor code
 * to the disassembler code from the capstone project.
 *
 * See:
 * http://www.capstone-engine.org/lang_c.html
 */

#include "intercept.h"
#include "intercept_util.h"
#include "disasm_wrapper.h"

#include <assert.h>
#include <string.h>
#include <syscall.h>
#include "capstone_wrapper.h"

struct intercept_disasm_context {
	csh handle;
	cs_insn *insn;
	const unsigned char *begin;
	const unsigned char *end;
};

/*
 * nop_vsnprintf - A dummy function, serving as a callback called by
 * the capstone implementation. The syscall_intercept library never makes
 * any use of string representation of instructions, but there seems to no
 * trivial way to use disassemble using capstone without it spending time
 * on printing syscalls. This seems to be the most that can be done in
 * this regard i.e. providing capstone with nop implementation of vsnprintf.
 */
static int
nop_vsnprintf()
{
	return 0;
}

/*
 * intercept_disasm_init -- should be called before disassembling a region of
 * code. The context created contains the context capstone needs ( or generally
 * the underlying disassembling library, if something other than capstone might
 * be used ).
 *
 * One must pass this context pointer to intercept_disasm_destroy following
 * a disassembling loop.
 */
struct intercept_disasm_context *
intercept_disasm_init(const unsigned char *begin, const unsigned char *end)
{
	struct intercept_disasm_context *context;

	context = xmmap_anon(sizeof(*context));
	context->begin = begin;
	context->end = end;

	/*
	 * Initialize the disassembler.
	 * The handle here must be passed to capstone each time it is used.
	 */
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &context->handle) != CS_ERR_OK)
		xabort("cs_open");

	/*
	 * Kindly ask capstone to return some details about the instruction.
	 * Without this, it only prints the instruction, and we would need
	 * to parse the resulting string.
	 */
	if (cs_option(context->handle, CS_OPT_DETAIL, CS_OPT_ON) != 0)
		xabort("cs_option - CS_OPT_DETAIL");

	/*
	 * Overriding the printing routine used by capstone,
	 * see comments above about nop_vsnprintf.
	 */
	cs_opt_mem x = {
		.malloc = malloc,
		.free = free,
		.calloc = calloc,
		.realloc = realloc,
		.vsnprintf = nop_vsnprintf};
	if (cs_option(context->handle, CS_OPT_MEM, (size_t)&x) != 0)
		xabort("cs_option - CS_OPT_MEM");

	if ((context->insn = cs_malloc(context->handle)) == NULL)
		xabort("cs_malloc");

	return context;
}

/*
 * intercept_disasm_destroy -- see comments for above routine
 */
void
intercept_disasm_destroy(struct intercept_disasm_context *context)
{
	cs_free(context->insn, 1);
	cs_close(&context->handle);
	xmunmap(context, sizeof(*context));
}

/*
 * check_op - checks a single operand of an instruction, looking
 * for RIP relative addressing.
 */
static void
check_op(struct intercept_disasm_result *result, cs_x86_op *op,
		const unsigned char *code)
{
	/*
	 * the address the RIP register is going to contain during the
	 * execution of this instruction
	 */
	const unsigned char *rip = code + result->length;

	if (op->type == X86_OP_REG) {
		if (op->reg == X86_REG_IP ||
				op->reg == X86_REG_RIP) {
			/*
			 * Example: mov %rip, %rax
			 */
			result->has_ip_relative_opr = true;
			result->rip_disp = 0;
			result->rip_ref_addr = rip;
		}
		if (result->is_jump) {
			/*
			 * Example: jmp *(%rax)
			 */
			/*
			 * An indirect jump can't have arguments other
			 * than a register - therefore the asserts.
			 * ( I'm 99.99% sure this is true )
			 */
			assert(!result->is_rel_jump);
			result->is_indirect_jump = true;
		}
	} else if (op->type == X86_OP_MEM) {
		if (op->mem.base == X86_REG_IP ||
				op->mem.base == X86_REG_RIP ||
				op->mem.index == X86_REG_IP ||
				op->mem.index == X86_REG_RIP ||
				result->is_jump) {
			result->has_ip_relative_opr = true;
			assert(!result->is_indirect_jump);

			if (result->is_jump)
				result->is_rel_jump = true;

			assert(op->mem.disp <= INT32_MAX);
			assert(op->mem.disp >= INT32_MIN);

			result->rip_disp = (int32_t)op->mem.disp;
			result->rip_ref_addr = rip + result->rip_disp;
		}
	} else if (op->type == X86_OP_IMM) {
		if (result->is_jump) {
			assert(!result->is_indirect_jump);
			result->has_ip_relative_opr = true;
			result->is_rel_jump = true;
			result->rip_ref_addr = (void *)op->imm;

			result->rip_disp =
			    (int32_t)((unsigned char *)op->imm - rip);
		}
	}
}

/*
 * intercept_disasm_next_instruction - Examines a single instruction
 * in a text section. This is only a wrapper around capstone specific code,
 * collecting data that can be used later to make decisions about patching.
 */
struct intercept_disasm_result
intercept_disasm_next_instruction(struct intercept_disasm_context *context,
					const unsigned char *code)
{
	static const unsigned char endbr64[] = {0xf3, 0x0f, 0x1e, 0xfa};

	struct intercept_disasm_result result = {.address = code, 0, };
	const unsigned char *start = code;
	size_t size = (size_t)(context->end - code + 1);
	uint64_t address = (uint64_t)code;

	if (size >= sizeof(endbr64) &&
	    memcmp(code, endbr64, sizeof(endbr64)) == 0) {
		result.is_set = true;
		result.is_endbr = true;
		result.length = 4;
#ifndef NDEBUG
		result.mnemonic = "endbr64";
#endif
		return result;
	}

	if (!cs_disasm_iter(context->handle, &start, &size,
	    &address, context->insn)) {
		return result;
	}

	result.length = context->insn->size;

	assert(result.length != 0);

	result.is_syscall = (context->insn->id == X86_INS_SYSCALL);
	result.is_call = (context->insn->id == X86_INS_CALL);
	result.is_ret = (context->insn->id == X86_INS_RET);
	result.is_rel_jump = false;
	result.is_indirect_jump = false;
#ifndef NDEBUG
	result.mnemonic = context->insn->mnemonic;
#endif

	switch (context->insn->id) {
		case X86_INS_JAE:
		case X86_INS_JA:
		case X86_INS_JBE:
		case X86_INS_JB:
		case X86_INS_JCXZ:
		case X86_INS_JECXZ:
		case X86_INS_JE:
		case X86_INS_JGE:
		case X86_INS_JG:
		case X86_INS_JLE:
		case X86_INS_JL:
		case X86_INS_JMP:
		case X86_INS_JNE:
		case X86_INS_JNO:
		case X86_INS_JNP:
		case X86_INS_JNS:
		case X86_INS_JO:
		case X86_INS_JP:
		case X86_INS_JRCXZ:
		case X86_INS_JS:
		case X86_INS_LOOP:
		case X86_INS_CALL:
			result.is_jump = true;
			assert(context->insn->detail->x86.op_count == 1);
			break;
		case X86_INS_NOP:
			result.is_nop = true;
			break;
		default:
			result.is_jump = false;
			break;
	}

	result.has_ip_relative_opr = false;

	/*
	 * Loop over all operands of the instruction currently being decoded.
	 * These operands are decoded by capstone, and described in the
	 * context->insn->detail->x86.operands array.
	 *
	 * This operand checking serves multiple purposes:
	 * The destination of any jumping instruction is found here,
	 * The instructions using RIP relative addressing are found by this
	 *  loop, e.g.: mov %rax, 0x36eb55d(%rip)
	 *
	 * Any instruction relying on the value of the RIP register can not
	 * be relocated ( including relative jumps, which naturally also
	 * rely on the RIP register ).
	 */
	for (uint8_t op_i = 0;
	    op_i < context->insn->detail->x86.op_count; ++op_i)
		check_op(&result, context->insn->detail->x86.operands + op_i,
		    code);

	result.is_lea_rip = (context->insn->id == X86_INS_LEA &&
			result.has_ip_relative_opr);

	if (result.is_lea_rip) {
		/*
		 * Extract the four bits from the encoding, which
		 * specify the destination register.
		 */

		/* one bit from the REX prefix */
		result.arg_register_bits = ((code[0] & 4) << 1);

		/* three bits from the ModRM byte */
		result.arg_register_bits |= ((code[2] >> 3) & 7);
	}

	result.is_set = true;

	return result;
}
