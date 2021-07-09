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
 * Validate that a cell adheres to the criterion required by inval
 * Criterion: not deleted, valid, given vaddr contained in cell, some perms
 */
static bool inval_validator(target_ulong vaddr, uint128_t cell, uint8_t perms)
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
    bool has_access = ((0 != (perms & RT_V)) &&
                       (0 != (perms & (RT_R | RT_W | RT_X))));

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
    bool has_no_access = (0 == (perms & (RT_V | RT_R | RT_W | RT_X)));

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
 * Get a range table's metacell contents
 */
int riscv_get_sc_meta(CPURISCVState *env, sc_meta_t *meta)
{
    MemTxResult res;
    MemTxAttrs attrs = MEMTXATTRS_UNSPECIFIED;
    CPUState *cs = env_cpu(env);

    hwaddr rt_base = (hwaddr)get_field(env->satp, SATP_PPN) << PGSHIFT;

    /* Check physical memory access */
    int pmp_prot;
    int pmp_ret = riscv_cpu_get_physical_address_pmp(env, &pmp_prot, NULL,
                                                     rt_base, sizeof(uint128_t),
                                                     MMU_DATA_LOAD, PRV_S);
    if (pmp_ret != TRANSLATE_SUCCESS) {
        return -RISCV_EXCP_LOAD_ACCESS_FAULT;
    }

    /* Retrieve values from metacell */
    uint128_t metacell = address_space_ldq(cs->as, rt_base + TARGET_LONG_SIZE,
                                           attrs, &res);
    if (res != MEMTX_OK) {
        return -RISCV_EXCP_LOAD_ACCESS_FAULT;
    }
    metacell <<= TARGET_LONG_BITS;
    metacell |= address_space_ldq(cs->as, rt_base, attrs, &res);
    if (res != MEMTX_OK) {
        return -RISCV_EXCP_LOAD_ACCESS_FAULT;
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
    MemTxResult res;
    MemTxAttrs attrs = MEMTXATTRS_UNSPECIFIED;
    CPUState *cs = env_cpu(env);

    hwaddr rt_base = (hwaddr)get_field(env->satp, SATP_PPN) << PGSHIFT;

    int va_bits = RT_VFN_SIZE + PGSHIFT;
    /* Remove sign-extended bits */
    vaddr &= (1ull << va_bits) - 1;

    sc_meta_t meta;
    int meta_ret = riscv_get_sc_meta(env, &meta);
    if (meta_ret < 0) {
        /* Error occured => pass the error on */
        return meta_ret;
    }
    target_ulong usid = env->usid;

    /* Find the requested cell */
    for (unsigned int i = 1; i < meta.N; i++) {
        hwaddr cell_addr = rt_base + i * CELL_DESC_SZ;
        hwaddr perm_addr = rt_base + (meta.S * 64) + (usid * meta.T * 64) + i;

        int pmp_prot;
        int pmp_ret = riscv_cpu_get_physical_address_pmp(env, &pmp_prot, NULL,
                                                         cell_addr,
                                                         sizeof(uint128_t),
                                                         MMU_DATA_LOAD, PRV_S);
        if (pmp_ret != TRANSLATE_SUCCESS) {
            return -RISCV_EXCP_LOAD_ACCESS_FAULT;
        }

        uint128_t cell_desc = address_space_ldq(cs->as,
                                                cell_addr + TARGET_LONG_SIZE,
                                                attrs, &res);
        if (res != MEMTX_OK) {
            return -RISCV_EXCP_LOAD_ACCESS_FAULT;
        }
        cell_desc <<= TARGET_LONG_BITS;
        cell_desc |= address_space_ldq(cs->as, cell_addr, attrs, &res);
        if (res != MEMTX_OK) {
            return -RISCV_EXCP_LOAD_ACCESS_FAULT;
        }

        pmp_ret = riscv_cpu_get_physical_address_pmp(env, &pmp_prot, NULL,
                                                     perm_addr,
                                                     sizeof(uint8_t),
                                                     MMU_DATA_LOAD, PRV_S);
        if (pmp_ret != TRANSLATE_SUCCESS) {
            return -RISCV_EXCP_LOAD_ACCESS_FAULT;
        }

        uint8_t perms = (uint8_t) address_space_ldub(cs->as, perm_addr,
                                                     attrs, &res);
        if (res != MEMTX_OK) {
            return -RISCV_EXCP_LOAD_ACCESS_FAULT;
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

    MemTxResult res;
    MemTxAttrs attrs = MEMTXATTRS_UNSPECIFIED;
    CPUState *cs = env_cpu(env);

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

        int pmp_prot;
        int pmp_ret = riscv_cpu_get_physical_address_pmp(env, &pmp_prot, NULL,
                                                         perms_addr,
                                                         sizeof(uint8_t),
                                                         MMU_DATA_LOAD, PRV_S);
        if (pmp_ret != TRANSLATE_SUCCESS) {
            return -RISCV_EXCP_LOAD_ACCESS_FAULT;
        }

        uint8_t current_perms = (uint8_t) address_space_ldub(cs->as, perms_addr,
                                                             attrs, &res);
        if (res != MEMTX_OK) {
            return -RISCV_EXCP_LOAD_ACCESS_FAULT;
        }

        /* Restrict to RWX for subset checks */
        perms &= (RT_R | RT_W | RT_X);
        current_perms &= (RT_R | RT_W | RT_X);
        if (((uint8_t)perms | current_perms) == current_perms) {
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

    MemTxResult res;
    MemTxAttrs attrs = MEMTXATTRS_UNSPECIFIED;
    CPUState *cs = env_cpu(env);

    cell_loc_t cell;
    int ret = riscv_find_cell_addr(env, &cell, vaddr, inval_validator);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    /* Don't need to check for PMP because riscv_find_cell already did */
    uint128_t cell_desc = address_space_ldq(cs->as,
                                            cell.paddr + TARGET_LONG_SIZE,
                                            attrs, &res);
    if (res != MEMTX_OK) {
        return -RISCV_EXCP_LOAD_ACCESS_FAULT;
    }
    cell_desc <<= TARGET_LONG_BITS;
    cell_desc |= address_space_ldq(cs->as, cell.paddr, attrs, &res);
    if (res != MEMTX_OK) {
        return -RISCV_EXCP_LOAD_ACCESS_FAULT;
    }


    /* Make sure that nobody else has permissions on this cell */
    sc_meta_t meta;
    ret = riscv_get_sc_meta(env, &meta);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    int pmp_prot, pmp_ret;
    hwaddr perms_addr;
    uint8_t perms;
    target_ulong usid = env->usid;
    hwaddr rt_base = (hwaddr)get_field(env->satp, SATP_PPN) << PGSHIFT;
    for (unsigned int i = 1; i < meta.M; i++) {
        hwaddr current_addr = rt_base + (meta.S * 64) + (meta.T * 64 * i)
                              + cell.idx;

        pmp_ret = riscv_cpu_get_physical_address_pmp(env, &pmp_prot,
                                                     NULL, current_addr,
                                                     sizeof(uint8_t),
                                                     MMU_DATA_LOAD, PRV_S);
        if (pmp_ret != TRANSLATE_SUCCESS) {
            return -RISCV_EXCP_LOAD_ACCESS_FAULT;
        }

        uint8_t current_perms = (uint8_t) address_space_ldub(cs->as,
                                                             current_addr,
                                                             attrs, &res);
        if (res != MEMTX_OK) {
            return -RISCV_EXCP_LOAD_ACCESS_FAULT;
        }

        if (i == usid) {
            /* Want to skip current SecDiv but first retrieve permissions */
            perms_addr = current_addr;
            perms = current_perms;
            continue;
        } else if ((current_perms & (RT_R | RT_W | RT_X)) != 0) {
            /* Some other SecDiv still has access => error out */
            return -RISCV_EXCP_ILLEGAL_INST;
        }

    }
    /* Clear valid bit and write back cell description */
    cell_desc &= ~((uint128_t)RT_VAL_MASK << RT_VAL_SHIFT);

    /* Need to check for PMP here since riscv_find_cell only checks for load */
    pmp_ret = riscv_cpu_get_physical_address_pmp(env, &pmp_prot, NULL,
                                                 cell.paddr, sizeof(uint128_t),
                                                 MMU_DATA_STORE, PRV_S);
    if (pmp_ret != TRANSLATE_SUCCESS) {
        return -RISCV_EXCP_STORE_AMO_ACCESS_FAULT;
    }

    address_space_stq(cs->as, cell.paddr + TARGET_LONG_SIZE,
                      (uint64_t)(cell_desc >> TARGET_LONG_BITS),
                      attrs, &res);
    if (res != MEMTX_OK) {
        return -RISCV_EXCP_STORE_AMO_ACCESS_FAULT;
    }
    address_space_stq(cs->as, cell.paddr, (uint64_t)cell_desc, attrs, &res);
    if (res != MEMTX_OK) {
        return -RISCV_EXCP_STORE_AMO_ACCESS_FAULT;
    }

    /* Clear and write back permissions */
    perms &= ~(RT_R | RT_W | RT_X);

    pmp_ret = riscv_cpu_get_physical_address_pmp(env, &pmp_prot, NULL,
                                                 perms_addr, sizeof(uint8_t),
                                                 MMU_DATA_STORE, PRV_S);
    if (pmp_ret != TRANSLATE_SUCCESS) {
        return -RISCV_EXCP_STORE_AMO_ACCESS_FAULT;
    }

    address_space_stb(cs->as, perms_addr, perms, attrs, &res);
    if (res != MEMTX_OK) {
        return -RISCV_EXCP_STORE_AMO_ACCESS_FAULT;
    }

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

    MemTxResult res;
    MemTxAttrs attrs = MEMTXATTRS_UNSPECIFIED;
    CPUState *cs = env_cpu(env);

    cell_loc_t cell;
    int ret = riscv_find_cell_addr(env, &cell, vaddr, reval_validator);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    /* Don't need to check for PMP because riscv_find_cell already did */
    uint128_t cell_desc = address_space_ldq(cs->as,
                                            cell.paddr + TARGET_LONG_SIZE,
                                            attrs, &res);
    if (res != MEMTX_OK) {
        return -RISCV_EXCP_LOAD_ACCESS_FAULT;
    }
    cell_desc <<= TARGET_LONG_BITS;
    cell_desc |= address_space_ldq(cs->as, cell.paddr, attrs, &res);
    if (res != MEMTX_OK) {
        return -RISCV_EXCP_LOAD_ACCESS_FAULT;
    }

    /* Set valid bit and write back cell_description */
    cell_desc |= ((uint128_t)RT_VAL_MASK << RT_VAL_SHIFT);

    /* Need to check for PMP here since riscv_find_cell only checks for load */
    int pmp_prot;
    int pmp_ret = riscv_cpu_get_physical_address_pmp(env, &pmp_prot, NULL,
                                                     cell.paddr,
                                                     sizeof(uint128_t),
                                                     MMU_DATA_STORE, PRV_S);
    if (pmp_ret != TRANSLATE_SUCCESS) {
        return -RISCV_EXCP_STORE_AMO_ACCESS_FAULT;
    }

    address_space_stq(cs->as, cell.paddr + TARGET_LONG_SIZE,
                      (uint64_t)(cell_desc >> TARGET_LONG_BITS),
                      attrs, &res);
    if (res != MEMTX_OK) {
        return -RISCV_EXCP_STORE_AMO_ACCESS_FAULT;
    }
    address_space_stq(cs->as, cell.paddr, (uint64_t)cell_desc, attrs, &res);
    if (res != MEMTX_OK) {
        return -RISCV_EXCP_STORE_AMO_ACCESS_FAULT;
    }

    /* Read, update and write back permissions */
    sc_meta_t meta;
    ret = riscv_get_sc_meta(env, &meta);
    if (ret < 0) {
        /* Encountered an error => pass it on */
        return ret;
    }

    target_ulong usid = env->usid;
    hwaddr rt_base = (hwaddr)get_field(env->satp, SATP_PPN) << PGSHIFT;
    hwaddr perms_addr = rt_base + (meta.S * 64) + (meta.T * 64 * usid)
                        + cell.idx;
    pmp_ret = riscv_cpu_get_physical_address_pmp(env, &pmp_prot,
                                                 NULL, perms_addr,
                                                 sizeof(uint8_t),
                                                 MMU_DATA_LOAD, PRV_S);
    if (pmp_ret != TRANSLATE_SUCCESS) {
        return -RISCV_EXCP_LOAD_ACCESS_FAULT;
    }

    uint8_t old_perms = (uint8_t) address_space_ldub(cs->as, perms_addr,
                                                     attrs, &res);

    perms = (perms & (RT_R | RT_W | RT_X)) | old_perms;

    pmp_ret = riscv_cpu_get_physical_address_pmp(env, &pmp_prot, NULL,
                                                 perms_addr, sizeof(uint8_t),
                                                 MMU_DATA_STORE, PRV_S);
    if (pmp_ret != TRANSLATE_SUCCESS) {
        return -RISCV_EXCP_STORE_AMO_ACCESS_FAULT;
    }

    address_space_stb(cs->as, perms_addr, perms, attrs, &res);
    if (res != MEMTX_OK) {
        return -RISCV_EXCP_STORE_AMO_ACCESS_FAULT;
    }

    return 0;
}
