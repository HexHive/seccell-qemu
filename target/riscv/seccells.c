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

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "cpu.h"
#include "cpu_bits.h"
#include "seccells.h"
#include "qemu/main-loop.h"
#include "exec/exec-all.h"

/*
 * Load a cell from the range table
 */
int riscv_load_cell(CPURISCVState *env, hwaddr paddr, uint128_t *cell)
{
    MemTxResult res;
    MemTxAttrs attrs = MEMTXATTRS_UNSPECIFIED;
    CPUState *cs = env_cpu(env);

    /* Check PMP */
    int pmp_prot;
    int pmp_ret = riscv_cpu_get_physical_address_pmp(env, &pmp_prot, NULL,
                                                     paddr, sizeof(uint128_t),
                                                     MMU_DATA_LOAD, PRV_S);
    if (pmp_ret != TRANSLATE_SUCCESS) {
        return -RISCV_EXCP_LOAD_ACCESS_FAULT;
    }

    /* Actually load the cell */
    uint128_t cell_desc = address_space_ldq(cs->as, paddr + TARGET_LONG_SIZE,
                                            attrs, &res);
    if (res != MEMTX_OK) {
        return -RISCV_EXCP_LOAD_ACCESS_FAULT;
    }
    cell_desc <<= TARGET_LONG_BITS;
    cell_desc |= address_space_ldq(cs->as, paddr, attrs, &res);
    if (res != MEMTX_OK) {
        return -RISCV_EXCP_LOAD_ACCESS_FAULT;
    }

    /* Write back retrieved cell to caller location */
    *cell = cell_desc;

    return 0;
}

/*
 * Store a cell to the range table
 */
int riscv_store_cell(CPURISCVState *env, hwaddr paddr, uint128_t *cell)
{
    MemTxResult res;
    MemTxAttrs attrs = MEMTXATTRS_UNSPECIFIED;
    CPUState *cs = env_cpu(env);

    /* Check PMP */
    int pmp_prot;
    int pmp_ret = riscv_cpu_get_physical_address_pmp(env, &pmp_prot, NULL,
                                                     paddr, sizeof(uint128_t),
                                                     MMU_DATA_STORE, PRV_S);
    if (pmp_ret != TRANSLATE_SUCCESS) {
        return -RISCV_EXCP_STORE_AMO_ACCESS_FAULT;
    }

    /* Actually store the cell */
    address_space_stq(cs->as, paddr + TARGET_LONG_SIZE,
                      (uint64_t)(*cell >> TARGET_LONG_BITS),
                      attrs, &res);
    if (res != MEMTX_OK) {
        return -RISCV_EXCP_STORE_AMO_ACCESS_FAULT;
    }
    address_space_stq(cs->as, paddr, (uint64_t)*cell, attrs, &res);
    if (res != MEMTX_OK) {
        return -RISCV_EXCP_STORE_AMO_ACCESS_FAULT;
    }

    return 0;
}

/*
 * Load permissions from the permission table
 */
int riscv_load_perms(CPURISCVState *env, hwaddr paddr, uint8_t *perms)
{
    MemTxResult res;
    MemTxAttrs attrs = MEMTXATTRS_UNSPECIFIED;
    CPUState *cs = env_cpu(env);

    /* Check PMP */
    int pmp_prot;
    int pmp_ret = riscv_cpu_get_physical_address_pmp(env, &pmp_prot, NULL,
                                                     paddr, sizeof(uint8_t),
                                                     MMU_DATA_LOAD, PRV_S);
    if (pmp_ret != TRANSLATE_SUCCESS) {
        return -RISCV_EXCP_LOAD_ACCESS_FAULT;
    }

    /* Actually load the perms */
    uint8_t tmp_perms = address_space_ldub(cs->as, paddr, attrs, &res);
    if (res != MEMTX_OK) {
        return -RISCV_EXCP_LOAD_ACCESS_FAULT;
    }

    /* Write back retrieved perms to caller location */
    *perms = tmp_perms;

    return 0;
}

/*
 * Store permissions to the permission table
 */
int riscv_store_perms(CPURISCVState *env, hwaddr paddr, uint8_t *perms)
{
    MemTxResult res;
    MemTxAttrs attrs = MEMTXATTRS_UNSPECIFIED;
    CPUState *cs = env_cpu(env);

    /* Check PMP */
    int pmp_prot;
    int pmp_ret = riscv_cpu_get_physical_address_pmp(env, &pmp_prot, NULL,
                                                     paddr, sizeof(uint8_t),
                                                     MMU_DATA_STORE, PRV_S);
    if (pmp_ret != TRANSLATE_SUCCESS) {
        return -RISCV_EXCP_STORE_AMO_ACCESS_FAULT;
    }

    /* Actually store the perms */
    address_space_stb(cs->as, paddr, *perms, attrs, &res);
    if (res != MEMTX_OK) {
        return -RISCV_EXCP_STORE_AMO_ACCESS_FAULT;
    }

    return 0;
}

/*
 * Load a SecDiv/permission tuple from the grant table
 */
int riscv_load_grant(CPURISCVState *env, hwaddr paddr, uint32_t *sdid,
                     uint8_t *perms)
{
    MemTxResult res;
    MemTxAttrs attrs = MEMTXATTRS_UNSPECIFIED;
    CPUState *cs = env_cpu(env);

    /* Check PMP */
    int pmp_prot;
    int pmp_ret = riscv_cpu_get_physical_address_pmp(env, &pmp_prot, NULL,
                                                     paddr, sizeof(uint32_t),
                                                     MMU_DATA_LOAD, PRV_S);
    if (pmp_ret != TRANSLATE_SUCCESS) {
        return -RISCV_EXCP_LOAD_ACCESS_FAULT;
    }

    /* Actually load the perms */
    uint32_t grant = address_space_ldl(cs->as, paddr, attrs, &res);
    if (res != MEMTX_OK) {
        return -RISCV_EXCP_LOAD_ACCESS_FAULT;
    }

    /* Divide the grant table entry up into SecDiv ID and actual permission */
    *perms = (uint8_t)((grant >> RT_GT_PERM_SHIFT) & RT_GT_PERM_MASK);
    *sdid = (grant >> RT_GT_SDID_SHIFT) & RT_GT_SDID_MASK;

    return 0;
}

/*
 * Store a SecDiv/permission tuple to the grant table
 */
int riscv_store_grant(CPURISCVState *env, hwaddr paddr, uint32_t *sdid,
                      uint8_t *perms)
{
    MemTxResult res;
    MemTxAttrs attrs = MEMTXATTRS_UNSPECIFIED;
    CPUState *cs = env_cpu(env);

    /* Check PMP */
    int pmp_prot;
    int pmp_ret = riscv_cpu_get_physical_address_pmp(env, &pmp_prot, NULL,
                                                     paddr, sizeof(uint32_t),
                                                     MMU_DATA_STORE, PRV_S);
    if (pmp_ret != TRANSLATE_SUCCESS) {
        return -RISCV_EXCP_STORE_AMO_ACCESS_FAULT;
    }

    /* Construct the grant table entry from the given SecDiv ID and perms */
    uint32_t grant = ((*sdid & RT_GT_SDID_MASK) << RT_GT_SDID_SHIFT)
                     | ((*perms & RT_GT_PERM_MASK) << RT_GT_PERM_SHIFT);

    /* Actually store the grant table entry */
    address_space_stl(cs->as, paddr, grant, attrs, &res);
    if (res != MEMTX_OK) {
        return -RISCV_EXCP_STORE_AMO_ACCESS_FAULT;
    }

    return 0;
}

/*
 * Get a range table's metacell contents
 */
int riscv_get_sc_meta(CPURISCVState *env, sc_meta_t *meta)
{
    /* We already checked that we're on a 64bit machine when we arrive here,
     * using SATP64_PPN without platform check is therefore safe */
    hwaddr rt_base = (hwaddr)get_field(env->satp, SATP64_PPN) << PGSHIFT;

    /* Retrieve values from metacell */
    uint128_t metacell;
    int res = riscv_load_cell(env, rt_base, &metacell);
    if (res < 0) {
        /* Encountered an error => pass it on */
        return res;
    }

    meta->N = (metacell >> RT_META_N_SHIFT) & RT_META_N_MASK;
    meta->M = (metacell >> RT_META_M_SHIFT) & RT_META_M_MASK;
    meta->T = (metacell >> RT_META_T_SHIFT) & RT_META_T_MASK;
    meta->S = CELL_DESC_SZ * meta->T;
    meta->R = (metacell >> RT_META_R_SHIFT) & RT_META_R_MASK;
    meta->Q = meta->T * meta->R;

    return 0;
}

/*
 * Find the address of a cell that fulfills a certain validation criterion in
 * the range table
 */
int riscv_find_cell_addr(CPURISCVState *env, sc_meta_t *meta, cell_loc_t *cell,
                         target_ulong vaddr)
{
    /* We already checked that we're on a 64bit machine when we arrive here,
     * using SATP64_PPN without platform check is therefore safe */
    hwaddr rt_base = (hwaddr)get_field(env->satp, SATP64_PPN) << PGSHIFT;

    int va_bits = RT_VFN_SIZE + PGSHIFT;
    /* Remove sign-extended bits */
    vaddr &= (1ull << va_bits) - 1;

    size_t start_idx = 1;
    size_t end_idx = meta->N;

    /* Binary search for given vaddr */
    while (start_idx < end_idx) {
        /* Due to rounding towards zero, start_idx <= middle_idx < end_idx
           The below assignments thus guarantee progress and eventually loop
           termination */
        size_t middle_idx = start_idx + ((end_idx - start_idx) / 2);
        hwaddr cell_addr = rt_base + middle_idx * CELL_DESC_SZ;

        uint128_t cell_desc;
        int res = riscv_load_cell(env, cell_addr, &cell_desc);
        if (res < 0) {
            /* Encountered an error => pass it on */
            return res;
        }

        target_ulong vpn_start = (cell_desc >> RT_VA_START_SHIFT) & RT_VA_MASK;
        target_ulong vpn_end = (cell_desc >> RT_VA_END_SHIFT) & RT_VA_MASK;
        target_ulong addr_vpn = vaddr >> PGSHIFT;

        if (addr_vpn > vpn_end) {
            /* End address is lower => continue search after current cell */
            start_idx = middle_idx + 1;
        } else if (addr_vpn < vpn_start) {
            /* Start address is higher => continue search before current cell */
            end_idx = middle_idx;
        } else {
            /* Found the cell => end search */
            cell->idx = middle_idx;
            cell->paddr = cell_addr;
            return 0;
        }
    }

    /* Searched the whole range table without finding the requested address */
    /* Fancy bit-shifting and cast to sign-extend address */
    env->badaddr = (target_long)(vaddr << (64 - va_bits)) >> (64 - va_bits);
    return -RISCV_EXCP_SECCELL_ILL_ADDR;
}


/*
 * Grant permissions on a cell to another SecDiv
 */
int riscv_grant(CPURISCVState *env, target_ulong vaddr, target_ulong target,
                target_ulong perms)
{
    uint64_t satp_mode;
    if (riscv_cpu_mxl(env) == MXL_RV32) {
        satp_mode = SATP32_MODE;
    } else {
        satp_mode = SATP64_MODE;
    }
    /* The instruction is only allowed if using SecCells virtual memory mode */
    if (get_field(env->satp, satp_mode) != VM_SECCELL) {
        return -RISCV_EXCP_ILLEGAL_INST;
    }

    /* The permissions parameter is only allowed to have the RWX bits set,
     * perms cannot be zero */
    if ((0 != (perms & ~RT_PERMS)) || !perms) {
        env->badaddr = (!perms << 8) | perms;
        return -RISCV_EXCP_SECCELL_ILL_PERM;
    }

    sc_meta_t meta;
    int ret = riscv_get_sc_meta(env, &meta);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    target_ulong usid = env->usid;
    /* Check caller SecDiv ID => should never occur since USID is checked on
       SecDiv switch */
    assert(usid <= (meta.M - 1));

    /* Check target SecDiv ID */
    if (!target || (target > (meta.M - 1))) {
        /* Invalid / too high target SecDiv ID */
        env->badaddr = target;
        return -RISCV_EXCP_SECCELL_INV_SDID;
    }

    /* Retrieve the necessary addresses */
    cell_loc_t cell;
    ret = riscv_find_cell_addr(env, &meta, &cell, vaddr);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    /* We already checked that we're on a 64bit machine when we arrive here,
     * using SATP64_PPN without platform check is therefore safe */
    hwaddr rt_base = (hwaddr)get_field(env->satp, SATP64_PPN) << PGSHIFT;
    hwaddr source_perms_addr = rt_base + (meta.S * 64) + (meta.T * 64 * usid)
                               + cell.idx;
    hwaddr grant_entry_addr = rt_base + (meta.S * 64) + (meta.Q * 64)
                              + (meta.T * 256 * usid)
                              + (cell.idx * 4);

    /* Load and check cell */
    uint128_t cell_desc;
    ret = riscv_load_cell(env, cell.paddr, &cell_desc);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }
    if (!is_valid_cell(cell_desc)) {
        /* Cell is invalid */
        env->badaddr = 0;
        return -RISCV_EXCP_SECCELL_INV_CELL_STATE;
    }

    /* Load and check current SecDiv permissions */
    uint8_t source_perms;
    ret = riscv_load_perms(env, source_perms_addr, &source_perms);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    if ((0 == (source_perms & RT_V)) || (0 == (source_perms & RT_PERMS))) {
        /* Current SecDiv doesn't have access to the cell in question at all */
        env->badaddr = (2 << 8) | perms;
        return -RISCV_EXCP_SECCELL_ILL_PERM;
    }

    if ((perms | source_perms) != source_perms) {
        /* Provided permissions are not a subset of the current permissions */
        env->badaddr = (2 << 8) | perms;
        return -RISCV_EXCP_SECCELL_ILL_PERM;
    }

    /* Write (SDID, perm) tuple to grant table */
    ret = riscv_store_grant(env, grant_entry_addr, (uint32_t *)&target,
                            (uint8_t *)&perms);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    CPUState *cs = env_cpu(env);
    tlb_flush(cs);
    return 0;
}

/*
 * Restrict the current SecDiv's permissions on a cell
 */
int riscv_protect(CPURISCVState *env, target_ulong vaddr, target_ulong perms)
{
    uint64_t satp_mode;
    if (riscv_cpu_mxl(env) == MXL_RV32) {
        satp_mode = SATP32_MODE;
    } else {
        satp_mode = SATP64_MODE;
    }
    /* The instruction is only allowed if using SecCells virtual memory mode */
    if (get_field(env->satp, satp_mode) != VM_SECCELL) {
        return -RISCV_EXCP_ILLEGAL_INST;
    }

    /* The permissions parameter is only allowed to have the RWX bits set,
       perms can be explicitly 0 to drop all permissions */
    if (0 != (perms & ~RT_PERMS)) {
        env->badaddr = perms;
        return -RISCV_EXCP_SECCELL_ILL_PERM;
    }

    sc_meta_t meta;
    int ret = riscv_get_sc_meta(env, &meta);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    target_ulong usid = env->usid;
    /* Check caller SecDiv ID => should never occur since USID is checked on
       SecDiv switch */
    assert(usid <= (meta.M - 1));

    /* Retrieve the necessary addresses */
    cell_loc_t cell;
    ret = riscv_find_cell_addr(env, &meta, &cell, vaddr);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    /* We already checked that we're on a 64bit machine when we arrive here,
     * using SATP64_PPN without platform check is therefore safe */
    hwaddr rt_base = (hwaddr)get_field(env->satp, SATP64_PPN) << PGSHIFT;
    hwaddr perms_addr = rt_base + (meta.S * 64) + (meta.T * 64 * usid)
                        + cell.idx;

    /* Load and check cell */
    uint128_t cell_desc;
    ret = riscv_load_cell(env, cell.paddr, &cell_desc);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }
    if (!is_valid_cell(cell_desc)) {
        /* Cell is invalid */
        env->badaddr = 0;
        return -RISCV_EXCP_SECCELL_INV_CELL_STATE;
    }

    /* Load and check current SecDiv permissions */
    uint8_t current_perms;
    ret = riscv_load_perms(env, perms_addr, &current_perms);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    if ((0 == (current_perms & RT_V)) || (0 == (current_perms & RT_PERMS))) {
        /* Current SecDiv doesn't have access to the cell in question at all */
        env->badaddr = (2 << 8) | perms;
        return -RISCV_EXCP_SECCELL_ILL_PERM;
    }

    if ((perms | current_perms) != current_perms) {
        /* Provided permissions are not a subset of the current permissions */
        env->badaddr = (2 << 8) | perms;
        return -RISCV_EXCP_SECCELL_ILL_PERM;
    }

    /* Calculate and store new permissions for SecDiv */
    perms |= (current_perms & ~RT_PERMS);

    ret = riscv_store_perms(env, perms_addr, (uint8_t *)&perms);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    CPUState *cs = env_cpu(env);
    tlb_flush(cs);
    return 0;
}

/*
 * Grant permissions on a cell to another SecDiv and drop own permissions
 */
int riscv_tfer(CPURISCVState *env, target_ulong vaddr, target_ulong target,
                target_ulong perms)
{
    uint64_t satp_mode;
    if (riscv_cpu_mxl(env) == MXL_RV32) {
        satp_mode = SATP32_MODE;
    } else {
        satp_mode = SATP64_MODE;
    }
    /* The instruction is only allowed if using SecCells virtual memory mode */
    if (get_field(env->satp, satp_mode) != VM_SECCELL) {
        return -RISCV_EXCP_ILLEGAL_INST;
    }

    /* The permissions parameter is only allowed to have the RWX bits set,
     * perms cannot be zero */
    if ((0 != (perms & ~RT_PERMS)) || !perms) {
        env->badaddr = (!perms << 8) | perms;
        return -RISCV_EXCP_SECCELL_ILL_PERM;
    }

    sc_meta_t meta;
    int ret = riscv_get_sc_meta(env, &meta);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    target_ulong usid = env->usid;
    /* Check caller SecDiv ID => should never occur since USID is checked on
       SecDiv switch */
    assert(usid <= (meta.M - 1));

    /* Check target SecDiv ID */
    if (!target || (target > (meta.M - 1))) {
        /* Invalid / too high target SecDiv ID */
        env->badaddr = target;
        return -RISCV_EXCP_SECCELL_INV_SDID;
    }

    /* Retrieve the necessary addresses */
    cell_loc_t cell;
    ret = riscv_find_cell_addr(env, &meta, &cell, vaddr);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    /* We already checked that we're on a 64bit machine when we arrive here,
     * using SATP64_PPN without platform check is therefore safe */
    hwaddr rt_base = (hwaddr)get_field(env->satp, SATP64_PPN) << PGSHIFT;
    hwaddr source_perms_addr = rt_base + (meta.S * 64) + (meta.T * 64 * usid)
                               + cell.idx;
    hwaddr grant_entry_addr = rt_base + (meta.S * 64) + (meta.Q * 64)
                              + (meta.T * 256 * usid)
                              + (cell.idx * 4);

    /* Load and check cell */
    uint128_t cell_desc;
    ret = riscv_load_cell(env, cell.paddr, &cell_desc);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }
    if (!is_valid_cell(cell_desc)) {
        /* Cell is invalid */
        env->badaddr = 0;
        return -RISCV_EXCP_SECCELL_INV_CELL_STATE;
    }

    /* Load and check current SecDiv permissions */
    uint8_t source_perms;
    ret = riscv_load_perms(env, source_perms_addr, &source_perms);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    if ((0 == (source_perms & RT_V)) || (0 == (source_perms & RT_PERMS))) {
        /* Current SecDiv doesn't have access to the cell in question at all */
        env->badaddr = (2 << 8) | perms;
        return -RISCV_EXCP_SECCELL_ILL_PERM;
    }

    if ((perms | source_perms) != source_perms) {
        /* Provided permissions are not a subset of the current permissions */
        env->badaddr = (2 << 8) | perms;
        return -RISCV_EXCP_SECCELL_ILL_PERM;
    }

    /* Write (SDID, perm) tuple to grant table */
    ret = riscv_store_grant(env, grant_entry_addr, (uint32_t *)&target,
                            (uint8_t *)&perms);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    /* Drop permissions for source SecDiv */
    source_perms &= ~RT_PERMS;

    ret = riscv_store_perms(env, source_perms_addr, (uint8_t *)&source_perms);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    CPUState *cs = env_cpu(env);
    tlb_flush(cs);
    return 0;
}

/*
 * Receive permissions that were granted by another SecDiv
 */
int riscv_recv(CPURISCVState *env, target_ulong vaddr, target_ulong source,
               target_ulong perms)
{
    uint64_t satp_mode;
    if (riscv_cpu_mxl(env) == MXL_RV32) {
        satp_mode = SATP32_MODE;
    } else {
        satp_mode = SATP64_MODE;
    }
    /* The instruction is only allowed if using SecCells virtual memory mode */
    if (get_field(env->satp, satp_mode) != VM_SECCELL) {
        return -RISCV_EXCP_ILLEGAL_INST;
    }

    /* The permissions parameter is only allowed to have the RWX bits set,
     * perms cannot be zero */
    if ((0 != (perms & ~RT_PERMS)) || !perms) {
        env->badaddr = (!perms << 8) | perms;
        return -RISCV_EXCP_SECCELL_ILL_PERM;
    }

    sc_meta_t meta;
    int ret = riscv_get_sc_meta(env, &meta);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    target_ulong usid = env->usid;
    /* Check caller SecDiv ID => should never occur since USID is checked on
       SecDiv switch */
    assert(usid <= (meta.M - 1));

    /* Check source SecDiv ID */
    if (!source || (source > (meta.M - 1))) {
        /* Invalid / too high source SecDiv ID */
        env->badaddr = (0ul << 32) | source;
        return -RISCV_EXCP_SECCELL_INV_SDID;
    }

    /* Retrieve the necessary addresses */
    cell_loc_t cell;
    ret = riscv_find_cell_addr(env, &meta, &cell, vaddr);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    /* We already checked that we're on a 64bit machine when we arrive here,
     * using SATP64_PPN without platform check is therefore safe */
    hwaddr rt_base = (hwaddr)get_field(env->satp, SATP64_PPN) << PGSHIFT;
    hwaddr target_perms_addr = rt_base + (meta.S * 64) + (meta.T * 64 * usid)
                               + cell.idx;
    hwaddr grant_entry_addr = rt_base + (meta.S * 64) + (meta.Q * 64)
                              + (meta.T * 256 * source)
                              + (cell.idx * 4);

    /* Load and check cell */
    uint128_t cell_desc;
    ret = riscv_load_cell(env, cell.paddr, &cell_desc);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }
    if (!is_valid_cell(cell_desc)) {
        /* Cell is invalid */
        env->badaddr = 0;
        return -RISCV_EXCP_SECCELL_INV_CELL_STATE;
    }

    /* Load the SecDiv ID / permission tuple from the grant table */
    uint8_t grant_perms;
    uint32_t grant_sdid;
    ret = riscv_load_grant(env, grant_entry_addr, &grant_sdid, &grant_perms);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    /* Check parameter/grant table entry compliance */
    if (grant_sdid != usid) {
        /* SecDiv in the grant table is not the current SecDiv */
        env->badaddr = (1ul << 32) | usid;
        return -RISCV_EXCP_SECCELL_INV_SDID;
    }
    if ((perms | grant_perms) != grant_perms) {
        /* Provided permissions are not a subset of the granted permissions */
        env->badaddr = (3 << 8) | perms;
        return -RISCV_EXCP_SECCELL_ILL_PERM;
    }

    /* Update grant table */
    if (perms == grant_perms) {
        /* "Empty" the grant table entry */
        grant_perms = 0;
        grant_sdid = -1;
    } else {
        /* Remove the requested subset from the granted permissions */
        grant_perms &= ~perms;
    }
    /* Write back the updated (SDID, perm) tuple to the grant table */
    ret = riscv_store_grant(env, grant_entry_addr, (uint32_t *)&grant_sdid,
                            (uint8_t *)&grant_perms);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    /* Load the requesting SecDiv's current permissions */
    uint8_t curr_perms;
    ret = riscv_load_perms(env, target_perms_addr, &curr_perms);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    /* Update the permissions in the permission table */
    curr_perms |= perms;
    ret = riscv_store_perms(env, target_perms_addr, &curr_perms);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    CPUState *cs = env_cpu(env);
    tlb_flush(cs);
    return 0;
}

/*
 * Check whether the current SecDiv has exclusive access to the given address
 */
int riscv_excl(CPURISCVState *env, target_ulong *dest, target_ulong vaddr,
                target_ulong perms)
{
    uint64_t satp_mode;
    if (riscv_cpu_mxl(env) == MXL_RV32) {
        satp_mode = SATP32_MODE;
    } else {
        satp_mode = SATP64_MODE;
    }
    /* The instruction is only allowed if using SecCells virtual memory mode */
    if (get_field(env->satp, satp_mode) != VM_SECCELL) {
        return -RISCV_EXCP_ILLEGAL_INST;
    }

    /* The permissions parameter is only allowed to have the RWX bits set,
     * perms cannot be zero */
    if ((0 != (perms & ~RT_PERMS)) || !perms) {
        env->badaddr = (!perms << 8) | perms;
        return -RISCV_EXCP_SECCELL_ILL_PERM;
    }

    sc_meta_t meta;
    int ret = riscv_get_sc_meta(env, &meta);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    /* Check caller SecDiv ID => should never occur since USID is checked on
       SecDiv switch */
    target_ulong usid = env->usid;
    assert(usid <= (meta.M - 1));

    cell_loc_t cell;
    ret = riscv_find_cell_addr(env, &meta, &cell, vaddr);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    /* Load and check cell */
    uint128_t cell_desc;
    ret = riscv_load_cell(env, cell.paddr, &cell_desc);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }
    if (!is_valid_cell(cell_desc)) {
        /* Cell is invalid */
        env->badaddr = 0;
        return -RISCV_EXCP_SECCELL_INV_CELL_STATE;
    }

    /* We already checked that we're on a 64bit machine when we arrive here,
     * using SATP64_PPN without platform check is therefore safe */
    hwaddr rt_base = (hwaddr)get_field(env->satp, SATP64_PPN) << PGSHIFT;
    hwaddr source_perms_addr = rt_base + (meta.S * 64) + (meta.T * 64 * usid)
                               + cell.idx;

    /* Load and check current SecDiv permissions */
    uint8_t source_perms;
    ret = riscv_load_perms(env, source_perms_addr, &source_perms);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    if ((0 == (source_perms & RT_V)) || (0 == (source_perms & RT_PERMS))) {
        /* Current SecDiv doesn't have access to the cell in question at all */
        env->badaddr = (2 << 8) | perms;
        return -RISCV_EXCP_SECCELL_ILL_PERM;
    }

    if ((perms | source_perms) != source_perms) {
        /* Provided permissions are not a subset of the current permissions */
        env->badaddr = (2 << 8) | perms;
        return -RISCV_EXCP_SECCELL_ILL_PERM;
    }

    *dest = 0;
    /* Start at 1 because we exclude the supervisor with SecDiv ID 0 */
    for (unsigned int i = 1; i < meta.M; i++) {
        /* Only check for non-supervisor SecDivs different from the caller */
        if (i == usid) {
            continue;
        }

        hwaddr perms_addr = rt_base + (meta.S * 64) + (meta.T * 64 * i)
                            + cell.idx;
        hwaddr grant_addr = rt_base + (meta.S * 64) + (meta.Q * 64)
                            + (meta.T * 256 * i) + (cell.idx * 4);

        /* Load permissions from the permission table */
        uint8_t current_perms;
        ret = riscv_load_perms(env, perms_addr, &current_perms);
        if (ret < 0) {
            /* Encountered an error => pass it on */
            return ret;
        }
        /* Load outstanding permissions from the grant table */
        uint32_t grant_sdid;
        uint8_t grant_perms;
        ret = riscv_load_grant(env, grant_addr, &grant_sdid, &grant_perms);
        if (ret < 0) {
            /* Encountered an error => pass it on */
            return ret;
        }

        /* Check whether given permissions are subset of current or outstanding
           permissions */
        if (((perms | current_perms | grant_perms) ==
                (current_perms | grant_perms)) &&
            ((current_perms & RT_V) != 0)) {
            /* Found SecDiv s.t. perms subset existing/granted perms
               => no exclusivity */
            *dest = 1;
            break;
        }
    }
    return 0;
}

/*
 * Invalidate a cell
 */
int riscv_inval(CPURISCVState *env, target_ulong vaddr)
{
    uint64_t satp_mode;
    if (riscv_cpu_mxl(env) == MXL_RV32) {
        satp_mode = SATP32_MODE;
    } else {
        satp_mode = SATP64_MODE;
    }
    /* The instruction is only allowed if using SecCells virtual memory mode */
    if (get_field(env->satp, satp_mode) != VM_SECCELL) {
        return -RISCV_EXCP_ILLEGAL_INST;
    }

    sc_meta_t meta;
    int ret = riscv_get_sc_meta(env, &meta);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    target_ulong usid = env->usid;
    /* Check caller SecDiv ID => should never occur since USID is checked on
       SecDiv switch */
    assert(usid <= (meta.M - 1));

    /* Retrieve the necessary addresses */
    cell_loc_t cell;
    ret = riscv_find_cell_addr(env, &meta, &cell, vaddr);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    /* We already checked that we're on a 64bit machine when we arrive here,
     * using SATP64_PPN without platform check is therefore safe */
    hwaddr rt_base = (hwaddr)get_field(env->satp, SATP64_PPN) << PGSHIFT;
    hwaddr perms_addr = rt_base + (meta.S * 64) + (meta.T * 64 * usid)
                        + cell.idx;

    /* Load and check the cell to invalidate */
    uint128_t cell_desc;
    ret = riscv_load_cell(env, cell.paddr, &cell_desc);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }
    if (!is_valid_cell(cell_desc)) {
        /* Cell is invalid */
        env->badaddr = 0;
        return -RISCV_EXCP_SECCELL_INV_CELL_STATE;
    }

    /* Load and check current SecDiv permissions */
    uint8_t perms;
    ret = riscv_load_perms(env, perms_addr, &perms);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    if ((0 == (perms & RT_V)) || (0 == (perms & RT_PERMS))) {
        /* Current SecDiv doesn't have access to the cell in question at all */
        env->badaddr = (2 << 8) | perms;
        return -RISCV_EXCP_SECCELL_ILL_PERM;
    }

    /* Make sure that nobody else has permissions on this cell and that there
       are no outstanding permissions in the grant table for this cell */
    hwaddr grant_addr;
    uint32_t grant_sdid;
    uint8_t grant_perms;
    for (unsigned int i = 1; i < meta.M; i++) {
        /* Only check for non-supervisor SecDivs different from the caller */
        if (i == usid) {
            continue;
        }
        /* Here: i != supervisor or caller SecDiv ID */
        perms_addr = rt_base + (meta.S * 64) + (meta.T * 64 * i) + cell.idx;
        grant_addr = rt_base + (meta.S * 64) + (meta.Q * 64)
                     + (meta.T * 256 * i) + (cell.idx * 4);

        /* Check permission table for SecDiv i */
        ret = riscv_load_perms(env, perms_addr, &perms);
        if (ret < 0) {
            /* Encountered an error => pass it on */
            return ret;
        }
        if (((perms & RT_V) != 0) && ((perms & RT_PERMS) != 0)) {
            /* Some other SecDiv still has access => error out */
            env->badaddr = 2;
            return -RISCV_EXCP_SECCELL_INV_CELL_STATE;
        }

        /* Check grant table for SecDiv i */
        ret = riscv_load_grant(env, grant_addr, &grant_sdid, &grant_perms);
        if (ret < 0) {
            /* Encountered an error => pass it on */
            return ret;
        }
        if ((grant_sdid != RT_ID_INV) || (grant_perms != 0)) {
            /* Some other SecDiv granted permissions on the cell that haven't
               been received yet */
            env->badaddr = 3;
            return -RISCV_EXCP_SECCELL_INV_CELL_STATE;
        }

    }

    /* Clear valid bit and write back cell description */
    cell_desc &= ~((uint128_t)RT_VAL_MASK << RT_VAL_SHIFT);

    ret = riscv_store_cell(env, cell.paddr, &cell_desc);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    /* Clear and write back permissions for all SecDivs */
    for (unsigned int i = 0; i < meta.M; i++) {
        perms_addr = rt_base + (meta.S * 64) + (meta.T * 64 * i) + cell.idx;

        ret = riscv_load_perms(env, perms_addr, &perms);
        if (ret < 0) {
            /* Encountered an error => pass it on */
            return ret;
        }

        if (0 == i) {
            /* For supervisor: only clear valid bit, userspace shouldn't be able
               to modify supervisor permissions */
            perms &= ~(RT_V);
        } else {
            /* For non-supervisor: clear valid bit and all permissions */
            perms &= ~(RT_V | RT_PERMS);
        }

        ret = riscv_store_perms(env, perms_addr, &perms);
        if (ret < 0) {
            /* Encountered an error => pass it on */
            return ret;
        }
    }

    /* Clear and write back grant table entry for current SecDiv */
    grant_addr = rt_base + (meta.S * 64) + (meta.Q * 64)
                 + (meta.T * 256 * usid) + (cell.idx * 4);
    grant_sdid = RT_ID_INV;
    grant_perms = 0;
    ret = riscv_store_grant(env, grant_addr, &grant_sdid, &grant_perms);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    CPUState *cs = env_cpu(env);
    tlb_flush(cs);
    return 0;
}

/*
 * Revalidate a cell
 */
int riscv_reval(CPURISCVState *env, target_ulong vaddr, target_ulong perms)
{
    uint64_t satp_mode;
    if (riscv_cpu_mxl(env) == MXL_RV32) {
        satp_mode = SATP32_MODE;
    } else {
        satp_mode = SATP64_MODE;
    }
    /* The instruction is only allowed if using SecCells virtual memory mode */
    if (get_field(env->satp, satp_mode) != VM_SECCELL) {
        return -RISCV_EXCP_ILLEGAL_INST;
    }

    /* The permissions parameter is only allowed to have the RWX bits set,
     * perms cannot be zero */
    if ((0 != (perms & ~RT_PERMS)) || !perms) {
        env->badaddr = (!perms << 8) | perms;
        return -RISCV_EXCP_SECCELL_ILL_PERM;
    }

    sc_meta_t meta;
    int ret = riscv_get_sc_meta(env, &meta);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    target_ulong usid = env->usid;
    /* Check caller SecDiv ID => should never occur since USID is checked on
       SecDiv switch */
    assert(usid <= (meta.M - 1));

    /* Retrieve the necessary addresses */
    cell_loc_t cell;
    ret = riscv_find_cell_addr(env, &meta, &cell, vaddr);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    /* We already checked that we're on a 64bit machine when we arrive here,
     * using SATP64_PPN without platform check is therefore safe */
    hwaddr rt_base = (hwaddr)get_field(env->satp, SATP64_PPN) << PGSHIFT;

    /* Load and check cell to revalidate */
    uint128_t cell_desc;
    ret = riscv_load_cell(env, cell.paddr, &cell_desc);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }
    if (is_valid_cell(cell_desc)) {
        /* Cell is already valid */
        env->badaddr = 1;
        return -RISCV_EXCP_SECCELL_INV_CELL_STATE;
    }

    /* Set valid bit and write back cell_description */
    cell_desc |= ((uint128_t)RT_VAL_MASK << RT_VAL_SHIFT);

    ret = riscv_store_cell(env, cell.paddr, &cell_desc);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    /* Read, update and write back permissions */
    for (unsigned int i = 0; i < meta.M; i++) {
        hwaddr perms_addr = rt_base + (meta.S * 64) + (meta.T * 64 * i)
                            + cell.idx;

        uint8_t old_perms, new_perms = 0;
        ret = riscv_load_perms(env, perms_addr, &old_perms);
        if (ret < 0) {
            /* Encountered an error => pass it on */
            return ret;
        }

        if (i == usid) {
            /* For the requesting SecDiv: set perms to the requested perms */
            new_perms = old_perms | RT_V | perms;
        } else {
            /* For all other SecDivs: just set the valid bit again */
            new_perms = old_perms | RT_V;
        }

        ret = riscv_store_perms(env, perms_addr, &new_perms);
        if (ret < 0) {
            /* Encountered an error => pass it on */
            return ret;
        }
    }

    CPUState *cs = env_cpu(env);
    tlb_flush(cs);
    return 0;
}

int riscv_ckcell(CPURISCVState *env, target_ulong *res, target_ulong expect_vld, 
                target_ulong vaddr)
{
    sc_meta_t meta;
    int ret = riscv_get_sc_meta(env, &meta);
    assert(ret >= 0);
    

    target_ulong usid = env->usid;
    /* Check caller SecDiv ID => should never occur since USID is checked on
       SecDiv switch */
    assert(usid <= (meta.M - 1));

    /* Retrieve the necessary addresses */
    cell_loc_t cell;
    ret = riscv_find_cell_addr(env, &meta, &cell, vaddr);
    if (ret < 0) {
        /* Not found returns -1 */
        *res = -1;
        return 0;
    }

    /* Load cell */
    uint128_t cell_desc;
    ret = riscv_load_cell(env, cell.paddr, &cell_desc);
    assert (ret >= 0);

    bool vld = is_valid_cell(cell_desc);
    /* vld        is bool. 0 = invalid, 1 = valid 
     * expect_vld is also bool. 0 = invalid, 1 = valid */
    if(vld == (expect_vld & 0x1))
        *res = cell.idx;
    else
        *res = 0;
    return 0;
}

int riscv_celladdr(CPURISCVState *env, target_ulong *res, target_ulong ci)
{
    /* We already checked that we're on a 64bit machine when we arrive here,
     * using SATP64_PPN without platform check is therefore safe */
    hwaddr rt_base = (hwaddr)get_field(env->satp, SATP64_PPN) << PGSHIFT;
    
    *res = rt_base + (ci * sizeof(uint128_t));
    return 0;
}

#define SC_CACHELINESZ   64
int riscv_permaddr(CPURISCVState *env, target_ulong *res, target_ulong ci, 
                target_ulong sd)
{
    sc_meta_t meta;
    int ret = riscv_get_sc_meta(env, &meta);
    assert(ret >= 0);

    /* special indexing scheme, aligned with the hardware */
    sd = (sd >> 63) ? 0 : sd ? sd : env->usid;

    /* We already checked that we're on a 64bit machine when we arrive here,
     * using SATP64_PPN without platform check is therefore safe */
    hwaddr rt_base = (hwaddr)get_field(env->satp, SATP64_PPN) << PGSHIFT;
    
    *res = rt_base + (16 * meta.T * SC_CACHELINESZ) + (sd * meta.T * SC_CACHELINESZ) + ci;
    return 0;
}

int riscv_grantaddr(CPURISCVState *env, target_ulong *res, target_ulong ci, 
                target_ulong sd)
{
    sc_meta_t meta;
    int ret = riscv_get_sc_meta(env, &meta);
    assert(ret >= 0);

    /* special indexing scheme, aligned with the hardware */
    sd = (sd >> 63) ? 0 : sd ? sd : env->usid;

    /* We already checked that we're on a 64bit machine when we arrive here,
     * using SATP64_PPN without platform check is therefore safe */
    hwaddr rt_base = (hwaddr)get_field(env->satp, SATP64_PPN) << PGSHIFT;
    
    *res = rt_base 
            + (16 * meta.T * SC_CACHELINESZ) 
            + (meta.R * meta.T * SC_CACHELINESZ) 
            + (sd * 4 * meta.T * SC_CACHELINESZ) 
            + (4 * ci);
    return 0;
}

