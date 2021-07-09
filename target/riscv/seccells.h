/*
 * RISC-V SecCells.
 *
 * Copyright (c) 2021 Florian Hofhammer, florian.hofhammer@epfl.ch
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef SECCELLS_H
#define SECCELLS_H

/* Includes */

#include "cpu.h"
#include "cpu_bits.h"


/* Structs and datatypes */

#ifdef __SIZEOF_INT128__
/* Cells have 128 bits = 16 bytes */
typedef unsigned __int128 uint128_t;
#endif

typedef struct sc_meta {
    target_ulong N, /* number of SecCells                               */
                 M, /* number of SecDivs                                */
                 S, /* number of cache lines for cells                  */
                 T; /* number of cache lines for permissions per SecDiv */
} sc_meta_t;

typedef struct cell_loc {
    hwaddr paddr;     /* The actual physical address of the cell description */
    unsigned int idx; /* The index into the range table                      */
} cell_loc_t;


/* Functions */

int riscv_get_sc_meta(CPURISCVState *env, sc_meta_t *meta);
int riscv_find_cell_addr(CPURISCVState *env, cell_loc_t *cell,
                         target_ulong vaddr,
                         bool (*validator)(target_ulong, uint128_t, uint8_t));
int riscv_count(CPURISCVState *env, target_ulong *dest, target_ulong vaddr,
                target_ulong perms);
int riscv_inval(CPURISCVState *env, target_ulong vaddr);
int riscv_reval(CPURISCVState *env, target_ulong vaddr, target_ulong perms);

#endif /* SECCELLS_H */
