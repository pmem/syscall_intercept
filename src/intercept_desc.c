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

#include <assert.h>
#include <syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
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

static void
add_table_info(struct section_list *list, const Elf64_Shdr *header)
{
	size_t max = sizeof(list->headers) / sizeof(list->headers[0]);

	if (list->count < max) {
		list->headers[list->count] = *header;
		list->count++;
	}
}

/*
 * add_text_info -- Fille the appropriate fields in an intercept_desc struct
 * about the corresponding code text.
 */
static void
add_text_info(struct intercept_desc *desc, const Elf64_Shdr *header,
		Elf64_Half index)
{
	desc->text_offset = header->sh_offset;
	desc->text_start =
	    (unsigned char *)(desc->dlinfo.dli_fbase) + header->sh_offset;
	desc->text_end = desc->text_start + header->sh_size - 1;
	desc->text_section_index = index;
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

	desc->symbol_tables.count = 0;
	desc->rela_tables.count = 0;

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
		const Elf64_Shdr *section = &sec_headers[i];
		char *name = sec_string_table + section->sh_name;

		debug_dump("looking at section: \"%s\" type: %ld\n",
		    name, (long)section->sh_type);
		if (strcmp(name, ".text") == 0) {
			text_section_found = true;
			add_text_info(desc, section, i);
		} else if (section->sh_type == SHT_SYMTAB ||
		    section->sh_type == SHT_DYNSYM) {
			debug_dump("found symbol table: %s\n", name);
			add_table_info(&desc->symbol_tables, section);
		} else if (section->sh_type == SHT_RELA) {
			debug_dump("found relocation table: %s\n", name);
			add_table_info(&desc->rela_tables, section);
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
 * calculate_table_count - estimate the number of entries
 * that might be used for nop table, skip range table.
 */
static size_t
calculate_table_count(const struct intercept_desc *desc)
{
	assert(desc->text_start < desc->text_end);

	/* how large is the text segment? */
	size_t bytes = (size_t)(desc->text_end - desc->text_start + 1);

	/*
	 * Guess: one entry per 64 bytes of machine code.
	 * This would result in zero entries for 63 bytes of text segment,
	 * so it is safer to have an absolute minimum. The 0x10000 value
	 * is just an arbitrary value.
	 * If more nops than this estimate are found (not likely), than the
	 * code just continues without remembering those nops - this does
	 * not break the patching process.
	 * Same is true about skip ranges.
	 */
	if (bytes > 0x10000)
		return bytes / 64;
	else
		return 1024;
}

/*
 * allocate_nop_table - allocates desc->nop_table
 */
static void
allocate_nop_table(struct intercept_desc *desc)
{
	desc->max_nop_count = calculate_table_count(desc);
	desc->nop_count = 0;
	desc->nop_table =
	    xmmap_anon(desc->max_nop_count * sizeof(desc->nop_table[0]));
}

/*
 * allocate_skip_ranges - allocates desc->skip_ranges
 */
static void
allocate_skip_ranges(struct intercept_desc *desc)
{
	desc->max_skip_range_count = calculate_table_count(desc);
	desc->skip_range_count = 0;
	desc->skip_ranges = xmmap_anon(
	    desc->max_skip_range_count * sizeof(desc->skip_ranges[0]));
}

/*
 * mark_skip_range - mark a range in a text section for skipping
 * This range is not going to be disassembled.
 */
static void
mark_skip_range(struct intercept_desc *desc,
	unsigned char *address, size_t size)
{
	if (desc->skip_range_count == desc->max_skip_range_count - 1)
		return;

	if (size == 0)
		return;

	if (desc->skip_range_count > 0) {
		struct range *last =
		    desc->skip_ranges + (desc->skip_range_count - 1);

		assert(last->address < address);
		assert(last->address + last->size <= address);

		if (last->address + last->size == address) {
			last->size += size;
			return;
		}
	}

	desc->skip_ranges[desc->skip_range_count].address = address;
	desc->skip_ranges[desc->skip_range_count].size = size;
	desc->skip_range_count++;
}

/*
 * has_no_syscall -
 * Returns true if the given memory range definitely
 * does not contain a syscall instruction.
 * Returning false does not necessarily mean there is at least a syscall
 * in the given memory range.
 */
static bool
has_no_syscall(unsigned char *address, size_t size)
{
	if (size <= 1)
		return false;

	while (size > 1 && (address[0] != 0x0f || address[1] != 0x05)) {
		++address;
		--size;
	}

	return size <= 1;
}

/*
 * mark_nop - mark an address in a text section as overwritable nop instruction
 */
static void
mark_nop(struct intercept_desc *desc, unsigned char *address, size_t size)
{
	if (desc->nop_count == desc->max_nop_count)
		return;

	desc->nop_table[desc->nop_count].address = address;
	desc->nop_table[desc->nop_count].size = size;
	desc->nop_count++;
}

/*
 * is_bit_set - check a bit in a bitmap
 */
static bool
is_bit_set(const unsigned char *table, uint64_t offset)
{
	return table[offset / 8] & (1 << (offset % 8));
}

/*
 * set_bit - set a bit in a bitmap
 */
static void
set_bit(unsigned char *table, uint64_t offset)
{
	unsigned char tmp = (unsigned char)(1 << (offset % 8));
	table[offset / 8] |= tmp;
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
	if (addr >= desc->text_start && addr <= desc->text_end)
		return is_bit_set(desc->jump_table,
		    (uint64_t)(addr - desc->text_start));
	else
		return false;
}

/*
 * mark_jump - Mark an address as a jump destination, see has_jump above.
 */
void
mark_jump(const struct intercept_desc *desc, const unsigned char *addr)
{
	if (addr >= desc->text_start && addr <= desc->text_end)
		set_bit(desc->jump_table, (uint64_t)(addr - desc->text_start));
}

/*
 * find_jumps_in_section_syms
 *
 * Read the .symtab or .dynsym section, which stores an array of Elf64_Sym
 * structs. Some of these symbols are functions in the .text section,
 * thus their entry points are jump destinations.
 * A symbol starts at offset st_value in the file, and this is its
 * exposed entry point as well.
 *
 * The format of the entries:
 *
 * typedef struct
 * {
 *   Elf64_Word	st_name;            Symbol name (string tbl index)
 *   unsigned char st_info;         Symbol type and binding
 *   unsigned char st_other;        Symbol visibility
 *   Elf64_Section st_shndx;        Section index
 *   Elf64_Addr	st_value;           Symbol value
 *   Elf64_Xword st_size;           Symbol size
 * } Elf64_Sym;
 *
 * The field st_value is offset of the symbol in the object file.
 */
static void
find_jumps_in_section_syms(struct intercept_desc *desc, Elf64_Shdr *section,
				long fd)
{
	assert(section->sh_type == SHT_SYMTAB ||
		section->sh_type == SHT_DYNSYM);

	size_t sym_count = section->sh_size / sizeof(Elf64_Sym);

	Elf64_Sym syms[sym_count];

	xlseek(fd, section->sh_offset, SEEK_SET);
	xread(fd, &syms, section->sh_size);

	for (size_t i = 0; i < sym_count; ++i) {
		if (ELF64_ST_TYPE(syms[i].st_info) != STT_FUNC)
			continue; /* it is not a function */

		if (syms[i].st_shndx != desc->text_section_index)
			continue; /* it is not in the text section */

		debug_dump("jump target: %lx\n",
		    (unsigned long)syms[i].st_value);

		unsigned char *address =
		    syms[i].st_value + (unsigned char *)desc->dlinfo.dli_fbase;

		/* a function entry point in .text, mark it */
		mark_jump(desc, address);

		/* a function's end in .text, mark it */
		if (syms[i].st_size != 0)
			mark_jump(desc, address + syms[i].st_size);
	}
}

/*
 * find_jumps_in_section_rela - look for offsets in relocation entries
 *
 * The constant SHT_RELA refers to "Relocation entries with addends" -- see the
 * elf.h header file.
 *
 * The format of the entries:
 *
 * typedef struct
 * {
 *   Elf64_Addr	r_offset;      Address
 *   Elf64_Xword r_info;       Relocation type and symbol index
 *   Elf64_Sxword r_addend;    Addend
 * } Elf64_Rela;
 *
 */
static void
find_jumps_in_section_rela(struct intercept_desc *desc, Elf64_Shdr *section,
				long fd)
{
	assert(section->sh_type == SHT_RELA);

	size_t sym_count = section->sh_size / sizeof(Elf64_Rela);

	Elf64_Rela syms[sym_count];

	xlseek(fd, section->sh_offset, SEEK_SET);
	xread(fd, &syms, section->sh_size);

	for (size_t i = 0; i < sym_count; ++i) {
		switch (ELF64_R_TYPE(syms[i].r_info)) {
			case R_X86_64_RELATIVE:
			case R_X86_64_RELATIVE64:
				/* Relocation type: "Adjust by program base" */

				debug_dump("jump target: %lx\n",
				    (unsigned long)syms[i].r_addend);

				unsigned char *address =
				    (unsigned char *)desc->dlinfo.dli_fbase +
				    syms[i].r_addend;

				mark_jump(desc, address);

				break;
		}
	}
}

/*
 * has_pow2_count
 * Checks if the number of patches in a struct intercept_desc
 * is a power of two or not.
 */
static bool
has_pow2_count(const struct intercept_desc *desc)
{
	return (desc->count & (desc->count - 1)) == 0;
}

/*
 * add_new_patch
 * Acquires a new patch entry, and allocates memory for it if
 * needed.
 */
static struct patch_desc *
add_new_patch(struct intercept_desc *desc)
{
	if (desc->count == 0) {

		/* initial allocation */
		desc->items = xmmap_anon(sizeof(desc->items[0]));

	} else if (has_pow2_count(desc)) {

		/* if count is a power of two, double the allocate space */
		size_t size = desc->count * sizeof(desc->items[0]);

		desc->items = xmremap(desc->items, size, 2 * size);
	}

	return &(desc->items[desc->count++]);
}

/*
 * is_overwritable_nop
 * Check if an instruction just disassembled is a NOP that can be
 * used for placing an extra jump instruction into it.
 * See the nop_trampoline usage in the patcher.c source file.
 * This instruction is usable only if it occupies at least seven bytes.
 * Two are needed for a short jump, and another 5 bytes for a trampoline
 * jump with 32 bit displacement.
 *
 * As in (where XXXX represents a 32 bit displacement):
 *                                Before      After
 *                                _______     _______
 * address of NOP instruction ->  | NOP |     | JMP | <- jumps to next
 *                                |     |     | +8  |     instruction
 *                                |     |     | JMP | <- 5 bytes of payload
 *                                |     |     |  X  |
 *                                |     |     |  X  |
 *                                |     |     |  X  |
 *                                |     |     |  X  |
 *                                |     |     |     |
 * address of next instruction -> -------     -------
 *
 */
bool
is_overwritable_nop(const struct intercept_disasm_result *ins)
{
	return ins->is_nop && ins->length >= 2 + 5;
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
 * Note: The actual patching can not yet be done in this disassembling phase,
 * as it is not known in advance, which addresses are jump destinations.
 */
static void
crawl_text(struct intercept_desc *desc)
{
	unsigned char *code = desc->text_start;

	/*
	 * Remember the previous three instructions, while
	 * disassembling the code instruction by instruction in the
	 * while loop below.
	 */
	struct intercept_disasm_result prevs[3] = {{0, }};

	/* an iterator pointing to a skip range */
	struct range *skip = desc->skip_ranges;

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
		/*
		 * First, check if the code pointer points to a range
		 * that can be skipped (as there can not be a syscall
		 * instruction in such a range).
		 */
		while (skip->address != NULL && code > skip->address)
			++skip; /* update the iterator for skip ranges */

		if (code == skip->address) {
			/*
			 * When at the start of a skippable range, just
			 * advance the code pointer - without disassembling
			 * anything in this range.
			 */
			if (skip->size > 0) {
				code += skip->size;
				has_prevs = 0;
				prevs[0].is_set = false;
				prevs[1].is_set = false;
				prevs[2].is_set = false;
			}
			++skip;
			continue;
		}

		assert(skip->address == NULL || code < skip->address);

		struct intercept_disasm_result result;

		result = intercept_disasm_next_instruction(context, code);

		if (result.length == 0) {
			++code;
			continue;
		}

		if (result.has_ip_relative_opr)
			mark_jump(desc, result.rip_ref_addr);

		if (is_overwritable_nop(&result))
			mark_nop(desc, code, result.length);

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
		if (has_prevs >= 1 && prevs[2].is_syscall) {
			struct patch_desc *patch = add_new_patch(desc);

			patch->preceding_ins_2 = prevs[0];
			patch->preceding_ins = prevs[1];
			patch->following_ins = result;
			patch->syscall_addr = code - SYSCALL_INS_SIZE;

			ptrdiff_t syscall_offset = patch->syscall_addr -
			    (desc->text_start - desc->text_offset);

			assert(syscall_offset >= 0);

			patch->syscall_offset = (unsigned long)syscall_offset;
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

/*
 * get_min_address
 * Looks for the lowest address that might be mmap-ed. This is
 * useful while looking for space for a trampoline table close
 * to some text section.
 */
static uintptr_t
get_min_address(void)
{
	static uintptr_t min_address;

	if (min_address != 0)
		return min_address;

	min_address = 0x10000; /* best guess */

	FILE *f = fopen("/proc/sys/vm/mmap_min_addr,", "r");

	if (f != NULL) {
		char line[64];
		if (fgets(line, sizeof(line), f) != NULL)
			min_address = (uintptr_t)atoll(line);

		fclose(f);
	}

	return min_address;
}

/*
 * allocate_trampoline_table
 * Allocates memory close to a text section (close enough
 * to be reachable with 32 bit displacements in jmp instructions).
 * Using mmap syscall with MAP_FIXED flag.
 */
void
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

	if ((uintptr_t)desc->text_end < INT32_MAX) {
		/* start from the bottom of memory */
		guess = (void *)0;
	} else {
		/*
		 * start from the lowest possible address, that can be reached
		 * from the text segment using a 32 bit displacement.
		 * Round up to a memory page boundary, as this address must be
		 * mappable.
		 */
		guess = desc->text_end - INT32_MAX;
		guess = (unsigned char *)(((uintptr_t)guess)
				& ~((uintptr_t)(0xfff))) + 0x1000;
	}

	if ((uintptr_t)guess < get_min_address())
		guess = (void *)get_min_address();

	size = 64 * 0x1000; /* XXX: don't just guess */

	if ((maps = fopen("/proc/self/maps", "r")) == NULL)
		xabort();

	while ((fgets(line, sizeof(line), maps)) != NULL) {
		unsigned char *start;
		unsigned char *end;

		if (sscanf(line, "%p-%p", (void **)&start, (void **)&end) != 2)
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

		if (guess + size >= desc->text_start + INT32_MAX) {
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

/*
 * dump_skip_ranges -- dump skip ranges as debug info
 */
static void
dump_skip_ranges(const struct intercept_desc *desc)
{
	if (!debug_dumps_on)
		return;

	size_t skip_sum = 0;
	size_t text_size = desc->text_end + 1 - desc->text_start;

	for (const struct range *r = desc->skip_ranges; r->address; ++r) {
		size_t offset =
		    r->address - (unsigned char *)(desc->dlinfo.dli_fbase);

		if (r->size > 0) {
			debug_dump("skip range at: %zx - %zx\n",
			    offset, offset + r->size);

			skip_sum += r->size;
		}
	}
	debug_dump("skip ranges: %zu bytes of %zu -- %zu%%\n",
	    skip_sum, text_size, (skip_sum * 100) / text_size);
}

/*
 * find_skip_ranges -- find ranges in the text that can be skipped during
 *  the disassembly phase
 */
static void
find_skip_ranges(struct intercept_desc *desc)
{
	size_t bytes = (size_t)(desc->text_end - desc->text_start + 1);

	size_t range_start = 0;
	size_t size;
	unsigned char vector = desc->jump_table[0];

	assert(bytes > 0);

	for (size_t i = 0; i < bytes; ) {
		if (i % 8 == 0) {
			vector = desc->jump_table[i / 8];
			if (vector == 0) {
				i += 8;
				continue;
			}
		}

		if (!(vector & (1 << (i % 8)))) {
			++i;
			continue;
		}

		unsigned char *start_address = desc->text_start + range_start;
		unsigned char *address = desc->text_start + i;

		debug_dump("looking at jump at: %tx\n",
		    address - (unsigned char *)desc->dlinfo.dli_fbase);

		size = i - range_start;

		if (size > 0)
			if (has_no_syscall(start_address, size))
				mark_skip_range(desc, start_address, size);

		range_start = i;
		++i;
	}

	size = bytes - range_start;
	unsigned char *start_address = desc->text_start + range_start;

	if (has_no_syscall(start_address, size))
		mark_skip_range(desc, start_address, size);

	desc->skip_ranges[desc->skip_range_count].address = NULL;
	desc->skip_ranges[desc->skip_range_count].size = 0;
}

/*
 * find_syscalls
 * The routine that disassembles a text section. Here is some higher level
 * logic for finding syscalls, finding overwritable NOP instructions, and
 * finding out what instructions around syscalls can be overwritten or not.
 * This code is intentionally independent of the disassembling library used,
 * such specific code is in wrapper functions in the disasm_wrapper.c source
 * file.
 */
void
find_syscalls(struct intercept_desc *desc)
{
	debug_dump("find_syscalls in %s\n", desc->dlinfo.dli_fname);

	desc->count = 0;

	long fd = open_orig_file(desc);

	find_sections(desc, fd);
	allocate_jump_table(desc);
	allocate_nop_table(desc);
	allocate_skip_ranges(desc);

	for (Elf64_Half i = 0; i < desc->symbol_tables.count; ++i)
		find_jumps_in_section_syms(desc,
		    desc->symbol_tables.headers + i, fd);

	for (Elf64_Half i = 0; i < desc->rela_tables.count; ++i)
		find_jumps_in_section_rela(desc,
		    desc->rela_tables.headers + i, fd);

	syscall_no_intercept(SYS_close, fd);

	find_skip_ranges(desc);

	dump_skip_ranges(desc);

	crawl_text(desc);
}
