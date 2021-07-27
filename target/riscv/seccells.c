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
 * Validate that a cell adheres to the criterion required by, e.g., inval, grant
 * Criterion: not deleted, valid, given vaddr contained in cell, some perms
 */
static bool valid_cell_validator(target_ulong vaddr, uint128_t cell,
                                 uint8_t perms)
{
    uint8_t del_flag = (cell >> RT_DEL_SHIFT) & RT_DEL_MASK;
    uint8_t val_flag = (cell >> RT_VAL_SHIFT) & RT_VAL_MASK;
    target_ulong va_start = ((cell >> RT_VA_START_SHIFT)
                                & RT_VA_MASK) << PGSHIFT;
    target_ulong va_end = ((cell >> RT_VA_END_SHIFT)
                                & RT_VA_MASK) << PGSHIFT;
    target_ulong addr_vpn = (vaddr >> PGSHIFT) << PGSHIFT;

    bool not_deleted = (0 == del_flag);
    bool valid = (0 != val_flag);
    bool vaddr_in_cell = ((addr_vpn >= va_start) && (addr_vpn <= va_end));
    bool has_access = ((0 != (perms & RT_V)) && (0 != (perms & RT_PERMS)));

    return not_deleted && valid && vaddr_in_cell && has_access;
}

/*
 * Validate that a cell adheres to the criterion required by reval
 * Criterion: not deleted, invalid, given vaddr contained in cell, no perms
 */
static bool reval_validator(target_ulong vaddr, uint128_t cell, uint8_t perms)
{
    uint8_t del_flag = (cell >> RT_DEL_SHIFT) & RT_DEL_MASK;
    uint8_t val_flag = (cell >> RT_VAL_SHIFT) & RT_VAL_MASK;
    target_ulong va_start = ((cell >> RT_VA_START_SHIFT)
                                & RT_VA_MASK) << PGSHIFT;
    target_ulong va_end = ((cell >> RT_VA_END_SHIFT)
                                & RT_VA_MASK) << PGSHIFT;
    target_ulong addr_vpn = (vaddr >> PGSHIFT) << PGSHIFT;

    bool not_deleted = (0 == del_flag);
    bool invalid = (0 == val_flag);
    bool vaddr_in_cell = ((addr_vpn >= va_start) && (addr_vpn <= va_end));
    bool has_no_access = (0 == (perms & (RT_V | RT_PERMS)));

    return not_deleted && invalid && vaddr_in_cell && has_no_access;
}

/*
 * Validate that a cell adheres to the criterion required by count
 * Criterion: not deleted, valid, given vaddr contained in cell
 */
static bool count_validator(target_ulong vaddr, uint128_t cell, uint8_t perms)
{
    uint8_t del_flag = (cell >> RT_DEL_SHIFT) & RT_DEL_MASK;
    uint8_t val_flag = (cell >> RT_VAL_SHIFT) & RT_VAL_MASK;
    target_ulong va_start = ((cell >> RT_VA_START_SHIFT)
                                & RT_VA_MASK) << PGSHIFT;
    target_ulong va_end = ((cell >> RT_VA_END_SHIFT)
                                & RT_VA_MASK) << PGSHIFT;
    target_ulong addr_vpn = (vaddr >> PGSHIFT) << PGSHIFT;

    bool not_deleted = (0 == del_flag);
    bool valid = (0 != val_flag);
    bool vaddr_in_cell = ((addr_vpn >= va_start) && (addr_vpn <= va_end));

    return not_deleted && valid && vaddr_in_cell;
}

/*
 * Load a cell from the range table
 */
static int load_cell(CPURISCVState *env, hwaddr paddr, uint128_t *cell)
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
static int store_cell(CPURISCVState *env, hwaddr paddr, uint128_t *cell)
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
 * Load permissions from the range table
 */
static int load_perms(CPURISCVState *env, hwaddr paddr, uint8_t *perms)
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
 * Store permissions to the range table
 */
static int store_perms(CPURISCVState *env, hwaddr paddr, uint8_t *perms)
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
 * Get a range table's metacell contents
 */
int riscv_get_sc_meta(CPURISCVState *env, sc_meta_t *meta)
{
    /* We already checked that we're on a 64bit machine when we arrive here,
     * using SATP64_PPN without platform check is therefore safe */
    hwaddr rt_base = (hwaddr)get_field(env->satp, SATP64_PPN) << PGSHIFT;

    /* Retrieve values from metacell */
    uint128_t metacell;
    int res = load_cell(env, rt_base, &metacell);
    if (res < 0) {
        /* Encountered an error => pass it on */
        return res;
    }

    meta->N = (metacell >> RT_META_N_SHIFT) & RT_META_N_MASK;
    meta->M = (metacell >> RT_META_M_SHIFT) & RT_META_M_MASK;
    meta->T = (metacell >> RT_META_T_SHIFT) & RT_META_T_MASK;
    meta->S = CELL_DESC_SZ * meta->T;

    return 0;
}

/*
 * Find the address of a cell that fulfills a certain validation criterion in
 * the range table
 */
int riscv_find_cell_addr(CPURISCVState *env, cell_loc_t *cell,
                         target_ulong vaddr,
                         bool (*validator)(target_ulong, uint128_t, uint8_t))
{
    hwaddr rt_base = (hwaddr)get_field(env->satp, SATP_PPN) << PGSHIFT;

    int va_bits = RT_VFN_SIZE + PGSHIFT;
    /* Remove sign-extended bits */
    vaddr &= (1ull << va_bits) - 1;

    sc_meta_t meta;
    int meta_ret = riscv_get_sc_meta(env, &meta);
    if (meta_ret < 0) {
        /* Encountered an error => pass it on */
        return meta_ret;
    }

    target_ulong usid = env->usid;
    if (usid > (meta.M - 1)) {
        /* Invalid / too high SecDiv ID */
        return -RISCV_EXCP_ILLEGAL_INST;
    }

    /* Find the requested cell */
    for (unsigned int i = 1; i < meta.N; i++) {
        hwaddr cell_addr = rt_base + i * CELL_DESC_SZ;
        hwaddr perm_addr = rt_base + (meta.S * 64) + (usid * meta.T * 64) + i;

        uint128_t cell_desc;
        int res = load_cell(env, cell_addr, &cell_desc);
        if (res < 0) {
            /* Encountered an error => pass it on */
            return res;
        }

        uint8_t perms;
        res = load_perms(env, perm_addr, &perms);
        if (res < 0) {
            /* Encountered an error => pass it on */
            return res;
        }

        if (!validator(vaddr, cell_desc, perms))
        {
            /* Cell doesn't have the desired properties/permissions */
            continue;
        }

        /* Found cell that we were looking for => return its address */
        cell->paddr = cell_addr;
        cell->idx = i;
        return 0;
    }
    /* Iterated through the whole list and couldn't find cell */
    return -RISCV_EXCP_LOAD_PAGE_FAULT;
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

    /* The permissions parameter is only allowed to have the RWX bits set */
    if (0 != (perms & ~RT_PERMS)) {
        return -RISCV_EXCP_ILLEGAL_INST;
    }

    cell_loc_t cell;
    int ret = riscv_find_cell_addr(env, &cell, vaddr, valid_cell_validator);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    sc_meta_t meta;
    ret = riscv_get_sc_meta(env, &meta);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    /* Calculate the necessary addresses */
    target_ulong usid = env->usid;
    if (usid > (meta.M - 1)) {
        /* Invalid / too high SecDiv ID */
        return -RISCV_EXCP_ILLEGAL_INST;
    }
    hwaddr rt_base = (hwaddr)get_field(env->satp, SATP_PPN) << PGSHIFT;
    hwaddr source_perms_addr = rt_base + (meta.S * 64) + (meta.T * 64 * usid)
                               + cell.idx;
    hwaddr target_perms_addr = rt_base + (meta.S * 64) + (meta.T * 64 * target)
                               + cell.idx;

    /* Load and check current SecDiv permissions */
    uint8_t source_perms;
    ret = load_perms(env, source_perms_addr, &source_perms);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    if ((perms | source_perms) != source_perms) {
        /* Provided permissions are not a subset of the current permissions */
        return -RISCV_EXCP_ILLEGAL_INST;
    }

    /* Load and check target SecDiv permissions */
    uint8_t target_perms;
    ret = load_perms(env, target_perms_addr, &target_perms);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    if (0 != (perms & target_perms)) {
        /* Current perms already contain at least parts of the new perms */
        return -RISCV_EXCP_ILLEGAL_INST;
    }

    /* Calculate and store new permissions for target SecDiv */
    target_perms |= perms | RT_V;

    ret = store_perms(env, target_perms_addr, &target_perms);
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

    /* The permissions parameter is only allowed to have the RWX bits set */
    if (0 != (perms & ~RT_PERMS)) {
        return -RISCV_EXCP_ILLEGAL_INST;
    }

    cell_loc_t cell;
    int ret = riscv_find_cell_addr(env, &cell, vaddr, valid_cell_validator);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    sc_meta_t meta;
    ret = riscv_get_sc_meta(env, &meta);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    /* Calculate the necessary address */
    target_ulong usid = env->usid;
    if (usid > (meta.M - 1)) {
        /* Invalid / too high SecDiv ID */
        return -RISCV_EXCP_ILLEGAL_INST;
    }
    hwaddr rt_base = (hwaddr)get_field(env->satp, SATP_PPN) << PGSHIFT;
    hwaddr perms_addr = rt_base + (meta.S * 64) + (meta.T * 64 * usid)
                        + cell.idx;

    /* Load and check current SecDiv permissions */
    uint8_t current_perms;
    ret = load_perms(env, perms_addr, &current_perms);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    if ((perms | current_perms) != current_perms) {
        /* Provided permissions are not a subset of the current permissions */
        return -RISCV_EXCP_ILLEGAL_INST;
    }

    /* Calculate and store new permissions for SecDiv */
    perms |= (current_perms & ~RT_PERMS);

    ret = store_perms(env, perms_addr, (uint8_t *)&perms);
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

    /* The permissions parameter is only allowed to have the RWX bits set */
    if (0 != (perms & ~RT_PERMS)) {
        return -RISCV_EXCP_ILLEGAL_INST;
    }

    cell_loc_t cell;
    int ret = riscv_find_cell_addr(env, &cell, vaddr, valid_cell_validator);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    sc_meta_t meta;
    ret = riscv_get_sc_meta(env, &meta);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    /* Calculate the necessary addresses */
    target_ulong usid = env->usid;
    if (usid > (meta.M - 1)) {
        /* Invalid / too high SecDiv ID */
        return -RISCV_EXCP_ILLEGAL_INST;
    }
    hwaddr rt_base = (hwaddr)get_field(env->satp, SATP_PPN) << PGSHIFT;
    hwaddr source_perms_addr = rt_base + (meta.S * 64) + (meta.T * 64 * usid)
                               + cell.idx;
    hwaddr target_perms_addr = rt_base + (meta.S * 64) + (meta.T * 64 * target)
                               + cell.idx;

    /* Load and check current SecDiv permissions */
    uint8_t source_perms;
    ret = load_perms(env, source_perms_addr, &source_perms);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    if ((perms | source_perms) != source_perms) {
        /* Provided permissions are not a subset of the current permissions */
        return -RISCV_EXCP_ILLEGAL_INST;
    }

    /* Load and check target SecDiv permissions */
    uint8_t target_perms;
    ret = load_perms(env, target_perms_addr, &target_perms);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    if (0 != (perms & target_perms)) {
        /* Current perms already contain at least parts of the new perms */
        return -RISCV_EXCP_ILLEGAL_INST;
    }

    /* Calculate and store new permissions for target SecDiv */
    target_perms |= perms | RT_V;

    ret = store_perms(env, target_perms_addr, &target_perms);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    /* Drop permissions for source SecDiv */
    perms &= ~RT_PERMS;

    ret = store_perms(env, source_perms_addr, (uint8_t *)&perms);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    CPUState *cs = env_cpu(env);
    tlb_flush(cs);
    return 0;
}

/*
 * Count the number of SecDivs having access to a cell with specified perms
 */
int riscv_count(CPURISCVState *env, target_ulong *dest, target_ulong vaddr,
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

    /* The permissions parameter is only allowed to have the RWX bits set */
    if (0 != (perms & ~RT_PERMS)) {
        return -RISCV_EXCP_ILLEGAL_INST;
    }

    cell_loc_t cell;
    int ret = riscv_find_cell_addr(env, &cell, vaddr, count_validator);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    sc_meta_t meta;
    ret = riscv_get_sc_meta(env, &meta);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    *dest = 0;
    /* We already checked that we're on a 64bit machine when we arrive here,
     * using SATP64_PPN without platform check is therefore safe */
    hwaddr rt_base = (hwaddr)get_field(env->satp, SATP64_PPN) << PGSHIFT;
    /* Start at 1 because we exclude the supervisor with SecDiv ID 0 */
    for (unsigned int i = 1; i < meta.M; i++) {
        hwaddr perms_addr = rt_base + (meta.S * 64) + (meta.T * 64 * i)
                            + cell.idx;

        uint8_t current_perms;
        ret = load_perms(env, perms_addr, &current_perms);
        if (ret < 0) {
            /* Encountered an error => pass it on */
            return ret;
        }

        if (((perms | current_perms) == current_perms) &&
            ((current_perms & RT_V) != 0)) {
            /* Found SecDiv s.t. perms subset current_perms => no exclusivity */
            (*dest)++;
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

    cell_loc_t cell;
    int ret = riscv_find_cell_addr(env, &cell, vaddr, valid_cell_validator);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    sc_meta_t meta;
    ret = riscv_get_sc_meta(env, &meta);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    hwaddr perms_addr;
    uint8_t perms;
    target_ulong usid = env->usid;
    if (usid > (meta.M - 1)) {
        /* Invalid / too high SecDiv ID */
        return -RISCV_EXCP_ILLEGAL_INST;
    }
    hwaddr rt_base = (hwaddr)get_field(env->satp, SATP_PPN) << PGSHIFT;
    /* Make sure that nobody else has permissions on this cell */
    for (unsigned int i = 1; i < meta.M; i++) {
        perms_addr = rt_base + (meta.S * 64) + (meta.T * 64 * i) + cell.idx;

        ret = load_perms(env, perms_addr, &perms);
        if (ret < 0) {
            /* Encountered an error => pass it on */
            return ret;
        }

        if ((i != usid) && ((perms & RT_V) != 0) && ((perms & RT_PERMS) != 0)) {
            /* Some other SecDiv still has access => error out */
            return -RISCV_EXCP_ILLEGAL_INST;
        }

    }

    /* Load the cell to invalidate */
    uint128_t cell_desc;
    ret = load_cell(env, cell.paddr, &cell_desc);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    /* Clear valid bit and write back cell description */
    cell_desc &= ~((uint128_t)RT_VAL_MASK << RT_VAL_SHIFT);

    ret = store_cell(env, cell.paddr, &cell_desc);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    /* Clear and write back permissions for all SecDivs */
    for (unsigned int i = 0; i < meta.M; i++) {
        perms_addr = rt_base + (meta.S * 64) + (meta.T * 64 * i) + cell.idx;

        ret = load_perms(env, perms_addr, &perms);
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

        ret = store_perms(env, perms_addr, &perms);
        if (ret < 0) {
            /* Encountered an error => pass it on */
            return ret;
        }
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

    /* The permissions parameter is only allowed to have the RWX bits set */
    if (0 != (perms & ~RT_PERMS)) {
        return -RISCV_EXCP_ILLEGAL_INST;
    }

    cell_loc_t cell;
    int ret = riscv_find_cell_addr(env, &cell, vaddr, reval_validator);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    /* Load cell to revalidate */
    uint128_t cell_desc;
    ret = load_cell(env, cell.paddr, &cell_desc);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    /* Set valid bit and write back cell_description */
    cell_desc |= ((uint128_t)RT_VAL_MASK << RT_VAL_SHIFT);

    ret = store_cell(env, cell.paddr, &cell_desc);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    sc_meta_t meta;
    ret = riscv_get_sc_meta(env, &meta);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    target_ulong usid = env->usid;
    if (usid > (meta.M - 1)) {
        /* Invalid / too high SecDiv ID */
        return -RISCV_EXCP_ILLEGAL_INST;
    }
    hwaddr rt_base = (hwaddr)get_field(env->satp, SATP_PPN) << PGSHIFT;

    /* Read, update and write back permissions */
    for (unsigned int i = 0; i < meta.M; i++) {
        hwaddr perms_addr = rt_base + (meta.S * 64) + (meta.T * 64 * i)
                            + cell.idx;

        uint8_t old_perms, new_perms = 0;
        ret = load_perms(env, perms_addr, &old_perms);
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

        ret = store_perms(env, perms_addr, &new_perms);
        if (ret < 0) {
            /* Encountered an error => pass it on */
            return ret;
        }
    }

    CPUState *cs = env_cpu(env);
    tlb_flush(cs);
    return 0;
}
