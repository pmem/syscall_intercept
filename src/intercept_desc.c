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


#define _GNU_SOURCE
#include <assert.h>
#include <syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "intercept.h"
#include "intercept_util.h"
#include "disasm_wrapper.h"

/*
 * open_orig_file
 *
 * Instead of looking for the needed metadata in already mmap library,
 * all this information is read from the file, thus its original place,
 * the file where the library is in an FS. The loaded library is mmaped
 * already of course, but not necceseraly the whole file is mapped as one
 * readable mem mapping.
 */
static long
open_orig_file(const struct intercept_desc *desc)
{
	long fd;

	fd = syscall_no_intercept(SYS_open, desc->dlinfo.dli_fname, O_RDONLY);

	if (fd < 0)
		xabort();

	return fd;
}

/*
 * find_sections
 *
 * See: man elf
 */
static void
find_sections(struct intercept_desc *desc, long fd)
{
	const Elf64_Ehdr *elf_header;

	desc->has_symtab = false;
	desc->has_dynsym = false;

	elf_header = (const Elf64_Ehdr *)(desc->dlinfo.dli_fbase);

	Elf64_Shdr sec_headers[elf_header->e_shnum];

	xlseek(fd, elf_header->e_shoff, SEEK_SET);
	xread(fd, sec_headers, elf_header->e_shnum * sizeof(Elf64_Shdr));

	char sec_string_table[sec_headers[elf_header->e_shstrndx].sh_size];

	xlseek(fd, sec_headers[elf_header->e_shstrndx].sh_offset, SEEK_SET);
	xread(fd, sec_string_table,
	    sec_headers[elf_header->e_shstrndx].sh_size);

	bool text_section_found = false;

	for (Elf64_Half i = 0; i < elf_header->e_shnum; ++i) {
		Elf64_Shdr *section = &sec_headers[i];
		char *name = sec_string_table + section->sh_name;

		if (strcmp(name, ".text") == 0) {
			text_section_found = true;
			desc->text_offset = section->sh_offset;
			desc->text_start =
			    (unsigned char *)(desc->dlinfo.dli_fbase) +
			    section->sh_offset;
			desc->text_end =
			    desc->text_start + section->sh_size - 1;
			desc->text_section_index = i;
		} else if (strcmp(name, ".symtab") == 0) {
			desc->sh_symtab_section = *section;
			desc->has_symtab = true;
		} else if (strcmp(name, ".dynsym") == 0) {
			desc->sh_dynsym_section = *section;
			desc->has_dynsym = true;
		}
	}

	if (!text_section_found)
		xabort();
}

/*
 * allocate_jump_table
 *
 * Allocates a bitmap, where each bit represents a unique address in
 * the text section.
 */
static void
allocate_jump_table(struct intercept_desc *desc)
{
	/* How many bytes need to be addressed? */
	assert(desc->text_start < desc->text_end);
	size_t bytes = (size_t)(desc->text_end - desc->text_start + 1);

	/* Allocate 1 bit for each addressable byte */
	/* Plus one -- integer division can result a number too low */
	desc->jump_table = xmmap_anon(bytes / 8 + 1);
}

/*
 * has_jump - check if addr is known to be a destination of any
 * jump ( or subroutine call ) in the code. The address must be
 * the one seen by the current process, not the offset in the orignal
 * ELF file.
 */
bool
has_jump(const struct intercept_desc *desc, unsigned char *addr)
{
	if (addr >= desc->text_start && addr <= desc->text_end) {
		uint64_t offset = (uint64_t)(addr - desc->text_start);

		return desc->jump_table[offset / 8] & (1 << (offset % 8));
	} else {
		return false;
	}
}

/*
 * mark_jump - Mark an address as a jump destination, see has_jump above.
 */
static void
mark_jump(const struct intercept_desc *desc, const unsigned char *addr)
{
	if (addr >= desc->text_start && addr <= desc->text_end) {
		uint64_t offset = (uint64_t)(addr - desc->text_start);

		/*
		 * XXX This doesn't work with libraries that have
		 * over 4 gigabytes of code -- todo more checks.
		 */

		unsigned char tmp = (unsigned char)(1 << (offset % 8));
		desc->jump_table[offset / 8] |= tmp;
	}
}

/*
 * find_jumps_in_section_syms
 *
 * Read the .symtab or .dynsym section, which stores an array of Elf64_Sym
 * structs. Some of these symbols are functions in the .text section,
 * thus their entry points are jump destinations.
 * A symbol starts at offset st_value in the file, and this is its
 * exposed entry point as well.
 */
static void
find_jumps_in_section_syms(struct intercept_desc *desc, Elf64_Shdr *section,
				long fd)
{
	size_t sym_count = section->sh_size / sizeof(Elf64_Sym);

	Elf64_Sym syms[sym_count];

	xlseek(fd, section->sh_offset, SEEK_SET);
	xread(fd, &syms, section->sh_size);

	for (size_t i = 0; i < sym_count; ++i) {
		if (ELF64_ST_TYPE(syms[i].st_info) != STT_FUNC)
			continue; /* it is not a function */

		if (syms[i].st_shndx != desc->text_section_index)
			continue; /* it is not in the text section */

		/* a function entry point in .text, mark it */
		mark_jump(desc, syms[i].st_value +
		    (unsigned char *)desc->dlinfo.dli_fbase);
	}
}

static bool
has_pow2_count(const struct intercept_desc *desc)
{
	return (desc->count & (desc->count - 1)) == 0;
}

static struct patch_desc *
add_new_patch(struct intercept_desc *desc)
{
	if (desc->count == 0) {

		/* initial allocation */
		desc->items = xmmap_anon(sizeof(desc->items[0]));

	} else if (has_pow2_count(desc) == 0) {

		/* if count is a power of two, double the allocate space */
		size_t size = desc->count * sizeof(desc->items[0]);

		desc->items = xmremap(desc->items, size, 2 * size);
	}

	return &(desc->items[desc->count++]);
}

/*
 * padding_pinpoint
 * Check the padding bytes between two text section symbols
 * for JUMP_INS_SIZE number of bytes. These are meant to contain
 * a jump instruction, jumping to intercepting code. A short jump
 * instruction replacing the two bytes of a corresponding
 * syscall instruction can jump to this instruction.
 * Must check:
 *  - size of padding
 *  - distance of padding from the syscall instruction
 *  - conflict with padding bytes used for other syscalls
 *
 * The conflicts are currently avoided by using a monotonically increasing
 * pointer, that has holds invariant of pointing to the last padding byte
 * already used.
 */
static unsigned char *
padding_pinpoint(unsigned char *dl_base, unsigned char *syscall_addr,
		Elf64_Sym *sym, unsigned char *used)
{
	assert(sym->st_value % SALIGNMENT == 0);

	/*
	 * The destination of the short jump instruction should be
	 * in the padding bytes after the end of a symbol,
	 * and before the - aligned - start of the next symbol.
	 */
	unsigned char *bound_low;
	unsigned char *bound_high;

	if (sym->st_size % SALIGNMENT == 0)
		return NULL; /* no padding */

	/* bound_low - the lowest address in the padding */
	bound_low = dl_base + sym->st_value + sym->st_size;

	/* bound_high - the higher address in the padding */
	bound_high = (unsigned char *)((uintptr_t)bound_low | (SALIGNMENT - 1));

	if (bound_low <= used) { /* bytes in this padding are already used? */

		if (bound_high <= used)
			return NULL; /* the whole padding is used */

		bound_low = used + 1; /* exclude the used bytes */
	}

	if (((bound_high - bound_low) + 1) < JUMP_INS_SIZE)
		return NULL; /* can't fit a jump here */

	/*
	 * The source of said short jump determines what addresses
	 * the jump can reach. Only padding bytes in this range
	 * can be used as the jump destination i.e. the first byte
	 * of the newly created jump instruction must be in
	 * the [min_reach, max_reach] range.
	 *
	 * Thus, looking for JUMP_INS_SIZE number of consecutive
	 * bytes int [bound_low, bound_high] range, of which,
	 * this first byte also falls in the [min_reach, max_reach]
	 * range. ( this first byte needs to be in the
	 * [bound_low, bound_high - (JUMP_INS_SIZE -1)] range, to be
	 * sure JUMP_INS_SIZE number of bytes fit in there. If such
	 * an address is found, it is returned to serve as the address
	 * of newly created jump instruction.
	 */

	unsigned char *source = syscall_addr + SYSCALL_INS_SIZE;
	unsigned char *min_reach = source - 128;
	unsigned char *max_reach = source + 127;

	if (bound_low > max_reach) {
		/*
		 * Paddding bytes at higher addresses, than what a
		 * short jump can reach.
		 *
		 * ( lower addresses to the left, higher ones to the right )
		 *
		 *  ....<--------- j -------->....[...padding...]....
		 */
		return NULL;
	}

	if (bound_high - (JUMP_INS_SIZE - 1) < min_reach) {
		/*
		 * Paddding bytes at lower addresses, than what a
		 * short jump can reach.
		 *
		 *  ....[...padding...]....<--------- j -------->....
		 *
		 * There might be an intersection, but not enough
		 * to find it JUMP_INS_SIZE bytes.
		 *
		 *  ....[...padding.<-.]--------- j -------->....
		 */
		return NULL;
	}

	if (bound_low < min_reach)
		return min_reach;
	else
		return bound_low;
}

static unsigned char *
search_padding(unsigned char *syscall_addr, unsigned char *used)
{
	Elf64_Sym *symbol;
	Dl_info dlinfo;

	/* note: dladdr1 -- non portable, GNU specific  */
	if (!dladdr1(syscall_addr, &dlinfo, (void **)&symbol, RTLD_DL_SYMENT))
		return NULL;

	if (symbol == NULL)
		return NULL;


	unsigned char *dl_base = dlinfo.dli_fbase;
	unsigned char *sym_begin = dl_base + symbol->st_value;

	if (sym_begin > used + JUMP_INS_SIZE) {
		Elf64_Sym *prev_symbol;

		if (dladdr1(sym_begin - 0x10, &dlinfo,
		    (void **)&prev_symbol, RTLD_DL_SYMENT)) {
			if (prev_symbol != NULL) {
				unsigned char *padding =
					padding_pinpoint(dl_base, syscall_addr,
					prev_symbol, used);
				if (padding != NULL)
					return padding;
			}
		}
	}

	return padding_pinpoint(dl_base, syscall_addr, symbol, used);
}

/*
 * crawl_text
 * Crawl the text section, disassembling it all.
 * This routine collects information about potential addresses to patch.
 *
 * The addresses of all syscall instructions are stored, together with
 * a description of the preceding, and following instructions.
 *
 * A lookup table of all addresses which appear as jump destination is
 * generated, to help determine later, whether an instruction is suitable
 * for being overwritten -- of course, if an instruction is a jump destination,
 * it can not be merged with the preceding instruction to create a
 * new larger one.
 *
 * Every time a syscall instruction is found, the next and previous padding
 * bytes between routines are checked to find a potential space for an
 * extra jump instruction.
 *
 * Note: The actual patching can not yet be done in this disassembling phase,
 * as it is not known in advance, which addresses are jump destinations.
 */
static void
crawl_text(struct intercept_desc *desc)
{
	unsigned char *code = desc->text_start;
	unsigned char *padding_used = code;

	/*
	 * Remember the previous three instructions, while
	 * disassembling the code instruction by instruction in the
	 * while loop below.
	 */
	struct intercept_disasm_result prevs[3] = {};

	/*
	 * How many previous instructions were decoded before this one,
	 * and stored in the prevs array. Usually three, except for the
	 * beginning of the text section -- the first instruction naturally
	 * has no previous instruction.
	 */
	unsigned has_prevs = 0;
	struct intercept_disasm_context *context =
	    intercept_disasm_init(desc->text_start, desc->text_end);

	while (code <= desc->text_end) {
		struct intercept_disasm_result result;

		result = intercept_disasm_next_instruction(context, code);

		if (result.length == 0) {
			++code;
			continue;
		}

		if (result.has_ip_relative_opr)
			mark_jump(desc, result.rip_ref_addr);

		/*
		 * Generate a new patch description, if:
		 * - Information is available about a syscalls place
		 * - one following instruction
		 * - two preceding instructions
		 *
		 * So this is done only if instruction in the previous
		 * loop iteration was a syscall. Which means the currently
		 * decoded instruction is the 'following' instruction -- as
		 * in following the syscall.
		 * The two instructions from two iterations ago, and three
		 * iterations ago are going to be the two 'preceding'
		 * instructions stored in the patch description. Other fields
		 * of the struct patch_desc are not filled at this point yet.
		 *
		 * prevs[0]      ->     patch->preceding_ins_2
		 * prevs[1]      ->     patch->preceding_ins
		 * prevs[2]      ->     [syscall]
		 * current ins.  ->     patch->following_ins
		 *
		 *
		 * XXX -- this ignores the cases where the text section
		 * starts, or ends with a syscall instruction, or indeed, if
		 * the second instruction in the text section is a syscall.
		 * These implausible edge cases don't seem to be very important
		 * right now.
		 */
		if (has_prevs >= 2 && prevs[2].is_syscall) {
			struct patch_desc *patch = add_new_patch(desc);

			patch->preceding_ins_2 = prevs[0];
			patch->preceding_ins = prevs[1];
			patch->following_ins = result;
			patch->syscall_addr = code - SYSCALL_INS_SIZE;

			ptrdiff_t syscall_offset = patch->syscall_addr -
			    (desc->text_start - desc->text_offset);

			assert(syscall_offset >= 0);

			patch->syscall_offset = (unsigned long)syscall_offset;
			patch->padding_addr =
			    search_padding(patch->syscall_addr, padding_used);
			if (patch->padding_addr != NULL)
				padding_used =
				    patch->padding_addr + JUMP_INS_SIZE;
		}

		prevs[0] = prevs[1];
		prevs[1] = prevs[2];
		prevs[2] = result;
		if (has_prevs < 2)
			++has_prevs;

		code += result.length;
	}

	intercept_disasm_destroy(context);
}

static void
allocate_trampoline_table(struct intercept_desc *desc)
{
	char *e = getenv("INTERCEPT_NO_TRAMPOLINE");

	/* Use the extra trampoline table by default */
	desc->uses_trampoline_table = (e == NULL) || (e[0] == '0');

	if (!desc->uses_trampoline_table) {
		desc->trampoline_table = NULL;
		desc->trampoline_table_size = 0;
		desc->trampoline_table = NULL;
		return;
	}

	FILE *maps;
	char line[0x100];
	unsigned char *guess; /* Where we would like to allocate the table */
	size_t size;

	if ((uintptr_t)desc->text_end < (1u << 31)) {
		guess = 0;
	} else {
		guess = desc->text_end - (1u << 31);
		guess = (unsigned char *)(((uintptr_t)guess)
				& ~((uintptr_t)(0xfff)));
	}

	size = 64 * 0x1000; /* TODO: don't just guess */

	if ((maps = fopen("/proc/self/maps", "r")) == NULL)
		xabort();

	while ((fgets(line, sizeof(line), maps)) != NULL) {
		unsigned char *start;
		unsigned char *end;

		if (sscanf(line, "%p-%p", &start, &end) != 2)
			xabort();

		/*
		 * Let's see if an existing mapping overlaps
		 * with the guess!
		 */
		if (end < guess)
			continue; /* No overlap, let's see the next mapping */

		if (start >= guess + size) {
			/* The rest of the mappings can't possibly overlap */
			break;
		}

		/*
		 * The next guess is the page following the mapping seen
		 * just now.
		 */
		guess = end;

		if (guess + size >= desc->text_start + (1u << 31)) {
			/* Too far away */
			xabort();
		}
	}

	fclose(maps);

	desc->trampoline_table = mmap(guess, size,
					PROT_READ | PROT_WRITE | PROT_EXEC,
					MAP_FIXED | MAP_PRIVATE | MAP_ANON,
					-1, 0);

	if (desc->trampoline_table == MAP_FAILED)
		xabort();

	desc->trampoline_table_size = size;

	desc->next_trampoline = desc->trampoline_table;
}

void
find_syscalls(struct intercept_desc *desc, Dl_info *dl_info)
{
	desc->dlinfo = *dl_info;
	desc->count = 0;

	long fd = open_orig_file(desc);

	find_sections(desc, fd);
	allocate_trampoline_table(desc);
	allocate_jump_table(desc);

	if (desc->has_symtab)
		find_jumps_in_section_syms(desc, &desc->sh_symtab_section, fd);

	if (desc->has_dynsym)
		find_jumps_in_section_syms(desc, &desc->sh_dynsym_section, fd);

	syscall_no_intercept(SYS_close, fd);

	crawl_text(desc);
}
