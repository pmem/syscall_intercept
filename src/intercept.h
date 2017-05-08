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
 * intercept.h - a few declarations used in libsyscall_intercept
 */

#ifndef INTERCEPT_INTERCEPT_H
#define INTERCEPT_INTERCEPT_H

#include <stdbool.h>
#include <elf.h>
#include <unistd.h>
#include <dlfcn.h>

#include "disasm_wrapper.h"

extern bool debug_dumps_on;
void debug_dump(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/*
 * Create wrapper functions to be called from glibc,
 * with an extra instruction taken from glibc
 * from before -- intercept_patch_with_prefix -- the syscall,
 * or after -- intercept_patch_with_postfix -- the syscall.
 */
void intercept_patch_with_prefix(unsigned char *syscall_addr);


void intercept_patch_with_postfix(unsigned char *syscall_addr,
				unsigned postfix_len);

#define INTERCEPTOR_EXIT_CODE 111

__attribute__((noreturn)) void xabort(void);

struct range {
	unsigned char *address;
	size_t size;
};

/*
 * The patch_list array stores some information on
 * whereabouts of patches made to glibc.
 * The syscall_addr pointer points to where a syscall
 *  instruction originally resided in glibc.
 * The asm_wrapper pointer points to the function
 *  called from glibc.
 * The glibc_call_patch pointer points to the exact
 *  location, where the new call instruction should
 *  be written.
 */
struct patch_desc {
	/* the original syscall instruction */
	unsigned char *syscall_addr;

	/* the offset of the original syscall instruction */
	unsigned long syscall_offset;

	/* the new asm wrapper created */
	unsigned char *asm_wrapper;

	/* the first byte overwritten in the code */
	unsigned char *dst_jmp_patch;

	/* the address to jump back to */
	unsigned char *return_address;

	/*
	 * Describe up to three instructions surrounding the original
	 * syscall instructions. Sometimes just overwritting the two
	 * direct neighbors of the syscall is not enough, ( e.g. if
	 * both the directly preceding, and the directly following are
	 * single byte instruction, that only gives 4 bytes of space ).
	 */
	struct intercept_disasm_result preceding_ins_2;
	struct intercept_disasm_result preceding_ins;
	struct intercept_disasm_result following_ins;
	bool uses_prev_ins_2;
	bool uses_prev_ins;
	bool uses_next_ins;

	bool uses_nop_trampoline;

	struct range nop_trampoline;
};

void patch_apply(struct patch_desc *patch);

struct section_list {
	Elf64_Half count;
	Elf64_Shdr headers[0x10];
};

struct intercept_desc {

	/*
	 * uses_trampoline_table - For now this is decided runtime
	 * to make it easy to compare the operation of the library
	 * with and without it. If it is ok, we can remove this
	 * flag, and just always use the trampoline table.
	 */
	bool uses_trampoline_table;

	/* Storing the Dl_info returned by dladdr(3) */
	Dl_info dlinfo;

	/*
	 * Some sections of the library from which information
	 * needs to be extracted.
	 * The text section is where the code to be hotpatched
	 * resides.
	 * The symtab, and dynsym sections provide information on
	 * the whereabouts of symbols, whose address in the text
	 * section.
	 */
	Elf64_Half text_section_index;
	Elf64_Shdr sh_text_section;

	struct section_list symbol_tables;
	struct section_list rela_tables;

	/* Where the text starts inside the shared object */
	unsigned long text_offset;

	/*
	 * Where the text starts and ends in the virtual memory seen by the
	 * current process.
	 */
	unsigned char *text_start;
	unsigned char *text_end;


	struct patch_desc *items;
	unsigned count;
	unsigned char *jump_table;

	size_t nop_count;
	size_t max_nop_count;
	struct range *nop_table;

	void *c_destination;
	void *c_destination_clone_child;

	unsigned char *trampoline_table;
	size_t trampoline_table_size;

	size_t skip_range_count;
	size_t max_skip_range_count;
	struct range *skip_ranges;

	unsigned char *next_trampoline;
};

bool has_jump(const struct intercept_desc *desc, unsigned char *addr);
void mark_jump(const struct intercept_desc *desc, const unsigned char *addr);

void allocate_trampoline_table(struct intercept_desc *desc);
void find_syscalls(struct intercept_desc *desc);

void init_patcher(void);
void create_patch_wrappers(struct intercept_desc *desc);
void mprotect_asm_wrappers(void);

/*
 * Actually overwrite instructions in glibc.
 */
void activate_patches(struct intercept_desc *desc);

#define SYSCALL_INS_SIZE 2
#define JUMP_INS_SIZE 5
#define CALL_OPCODE 0xe8
#define JMP_OPCODE 0xe9
#define SHORT_JMP_OPCODE 0xeb
#define PUSH_IMM_OPCODE 0x68
#define NOP_OPCODE 0x90
#define INT3_OPCODE 0xCC

bool is_overwritable_nop(const struct intercept_disasm_result *ins);

void create_jump(unsigned char opcode, unsigned char *from, void *to);

void intercept(void);

#endif
