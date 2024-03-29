/*
 * RISC-V Emulation Helpers for QEMU.
 *
 * Copyright (c) 2016-2017 Sagar Karandikar, sagark@eecs.berkeley.edu
 * Copyright (c) 2017-2018 SiFive, Inc.
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
#include "cpu.h"
#include "seccells.h"
#include "qemu/main-loop.h"
#include "exec/exec-all.h"
#include "exec/helper-proto.h"

/* Exceptions processing helpers */
void QEMU_NORETURN riscv_raise_exception(CPURISCVState *env,
                                          uint32_t exception, uintptr_t pc)
{
    CPUState *cs = env_cpu(env);
    cs->exception_index = exception;
    cpu_loop_exit_restore(cs, pc);
}

void helper_raise_exception(CPURISCVState *env, uint32_t exception)
{
    riscv_raise_exception(env, exception, 0);
}

target_ulong helper_csrr(CPURISCVState *env, int csr)
{
    target_ulong val = 0;
    RISCVException ret = riscv_csrrw(env, csr, &val, 0, 0);

    if (ret != RISCV_EXCP_NONE) {
        riscv_raise_exception(env, ret, GETPC());
    }
    return val;
}

void helper_csrw(CPURISCVState *env, int csr, target_ulong src)
{
    RISCVException ret = riscv_csrrw(env, csr, NULL, src, -1);

    if (ret != RISCV_EXCP_NONE) {
        riscv_raise_exception(env, ret, GETPC());
    }
}

target_ulong helper_csrrw(CPURISCVState *env, int csr,
                          target_ulong src, target_ulong write_mask)
{
    target_ulong val = 0;
    RISCVException ret = riscv_csrrw(env, csr, &val, src, write_mask);

    if (ret != RISCV_EXCP_NONE) {
        riscv_raise_exception(env, ret, GETPC());
    }
    return val;
}

void helper_sdswitch(CPURISCVState *env, target_ulong pc, target_ulong secdiv)
{
    CPUState *cs = env_cpu(env);
    /* Get metacell contents for target validity check */
    sc_meta_t meta;
    int ret = riscv_get_sc_meta(env, &meta);
    if (ret < 0) {
        riscv_raise_exception(env, -ret, GETPC());
    }
    
    if ((0 == secdiv) || (secdiv > (meta.M - 1))) {
        /* User tries to switch to supervisor SecDiv without trapping into
           supervisor mode or to switch to invalid SecDiv */
        env->badaddr = secdiv;
        riscv_raise_exception(env, RISCV_EXCP_SECCELL_INV_SDID, GETPC());
        /* Unreachable here */
    }

    /* 
     * We need the SDEntry check to respect the permission checks 
     * of the target secdiv, not the caller secdiv.
     * The following cpu_ldl_code can have the following outcomes:
     * - cpu_ldl_code fails due to incorrect permissions, goes directly to riscv_cpu_do_interrupt
     *   We handle correctly restoring usid in the riscv_cpu_do_interrupt
     * - cpu_ldl_code succeeds. 
     *   We restore correct usid immediately afterwards and flush TLB
     *   We can still trap if code read is not SDEntry
     * 
     * SDSwitch implicitly flushes TLB. 
     * First tlb_flush so that cpu_ldl_code does not read caller's permissions
     * Second tlb_flush for actually flushing TLB
     * Required in QEMU, not hardware: QEMU lacks ASID/USID-tagged TLBs
     * */
    tlb_flush(cs);
    env->sdswitch_caller = env->usid;
    env->usid = secdiv;
    target_ulong target_bytes = cpu_ldl_code(env, pc);
    env->usid = env->sdswitch_caller;
    env->sdswitch_caller = -1;
    tlb_flush(cs);

    if (target_bytes != 0x0000100b) {
        env->badaddr = pc;
        /* Next instruction is not an entry instruction as expected */
        riscv_raise_exception(env, RISCV_EXCP_SECCELL_ILL_TGT, GETPC());
        /* Unreachable here */
    } else {
        /* Next instruction is valid entry instruction => switch SecDiv */
        env->urid = env->usid;
        env->usid = secdiv;
    }
}

void helper_prot(CPURISCVState *env, target_ulong addr, target_ulong perms)
{
    int ret = riscv_protect(env, addr, perms);

    if (ret < 0) {
        riscv_raise_exception(env, -ret, GETPC());
    }
}

void helper_grant(CPURISCVState *env, target_ulong addr, target_ulong target,
        target_ulong perms)
{
    int ret = riscv_grant(env, addr, target, perms);

    if (ret < 0) {
        riscv_raise_exception(env, -ret, GETPC());
    }
}

void helper_tfer(CPURISCVState *env, target_ulong addr, target_ulong target,
        target_ulong perms)
{
    int ret = riscv_tfer(env, addr, target, perms);

    if (ret < 0) {
        riscv_raise_exception(env, -ret, GETPC());
    }
}

void helper_recv(CPURISCVState *env, target_ulong addr, target_ulong source,
        target_ulong perms)
{
    int ret = riscv_recv(env, addr, source, perms);

    if (ret < 0) {
        riscv_raise_exception(env, -ret, GETPC());
    }
}

target_ulong helper_excl(CPURISCVState *env, target_ulong addr,
        target_ulong perms)
{
    target_ulong val = 0;
    int ret = riscv_excl(env, &val, addr, perms);

    if (ret < 0) {
        riscv_raise_exception(env, -ret, GETPC());
    }
    return val;
}

void helper_inval(CPURISCVState *env, target_ulong addr)
{
    int ret = riscv_inval(env, addr);

    if (ret < 0) {
        riscv_raise_exception(env, -ret, GETPC());
    }
}

void helper_reval(CPURISCVState *env, target_ulong addr, target_ulong perms)
{
    int ret = riscv_reval(env, addr, perms);

    if (ret < 0) {
        riscv_raise_exception(env, -ret, GETPC());
    }
}

target_ulong helper_ckcell(CPURISCVState *env, target_ulong addr, target_ulong vld) {
    target_ulong val = 0;
    int ret = riscv_ckcell(env, &val, vld, addr);

    if(ret < 0) {
        riscv_raise_exception(env, -ret, GETPC());
    }
    return val;
}
target_ulong helper_celladdr(CPURISCVState *env, target_ulong ci) {
    target_ulong val = 0;
    int ret = riscv_celladdr(env, &val, ci);

    if(ret < 0) {
        riscv_raise_exception(env, -ret, GETPC());
    }
    return val;
}
target_ulong helper_permaddr(CPURISCVState *env, target_ulong ci, target_ulong sd) {
    target_ulong val = 0;
    int ret = riscv_permaddr(env, &val, ci, sd);

    if(ret < 0) {
        riscv_raise_exception(env, -ret, GETPC());
    }
    return val;
}
target_ulong helper_grantaddr(CPURISCVState *env, target_ulong ci, target_ulong sd) {
    target_ulong val = 0;
    int ret = riscv_grantaddr(env, &val, ci, sd);

    if(ret < 0) {
        riscv_raise_exception(env, -ret, GETPC());
    }
    return val;
}

void helper_traprinst(CPURISCVState *env, target_ulong rs1val, target_ulong rs2val, target_ulong rd) {
    env->mtirs1 = rs1val;
    env->mtirs2 = rs2val;
    env->mtird  = rd;

    riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
}

void helper_trapiinst(CPURISCVState *env, target_ulong rs1val, target_ulong immval, target_ulong rd) {
    env->mtirs1 = rs1val;
    env->mtiimm = immval;
    env->mtird  = rd;

    riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
}

void helper_trapsinst(CPURISCVState *env, target_ulong rs1val, target_ulong rs2val, target_ulong immval) {
    env->mtirs1 = rs1val;
    env->mtirs2 = rs2val;
    env->mtiimm = immval;

    riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
}
void helper_trapjinst(CPURISCVState *env, target_ulong immval, target_ulong rd) {
    env->mtiimm = immval;
    env->mtird  = rd;

    riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
}

#ifndef CONFIG_USER_ONLY

target_ulong helper_sret(CPURISCVState *env, target_ulong cpu_pc_deb)
{
    uint64_t mstatus;
    target_ulong prev_priv, prev_virt;

    if (!(env->priv >= PRV_S)) {
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
    }

    target_ulong retpc = env->sepc;
    if (!riscv_has_ext(env, RVC) && (retpc & 0x3)) {
        riscv_raise_exception(env, RISCV_EXCP_INST_ADDR_MIS, GETPC());
    }

    if (get_field(env->mstatus, MSTATUS_TSR) && !(env->priv >= PRV_M)) {
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
    }

    if (riscv_has_ext(env, RVH) && riscv_cpu_virt_enabled(env) &&
        get_field(env->hstatus, HSTATUS_VTSR)) {
        riscv_raise_exception(env, RISCV_EXCP_VIRT_INSTRUCTION_FAULT, GETPC());
    }

    mstatus = env->mstatus;

    if (riscv_has_ext(env, RVH) && !riscv_cpu_virt_enabled(env)) {
        /* We support Hypervisor extensions and virtulisation is disabled */
        target_ulong hstatus = env->hstatus;

        prev_priv = get_field(mstatus, MSTATUS_SPP);
        prev_virt = get_field(hstatus, HSTATUS_SPV);

        hstatus = set_field(hstatus, HSTATUS_SPV, 0);
        mstatus = set_field(mstatus, MSTATUS_SPP, 0);
        mstatus = set_field(mstatus, SSTATUS_SIE,
                            get_field(mstatus, SSTATUS_SPIE));
        mstatus = set_field(mstatus, SSTATUS_SPIE, 1);

        env->mstatus = mstatus;
        env->hstatus = hstatus;

        if (prev_virt) {
            riscv_cpu_swap_hypervisor_regs(env);
        }

        riscv_cpu_set_virt_enabled(env, prev_virt);
    } else {
        prev_priv = get_field(mstatus, MSTATUS_SPP);

        mstatus = set_field(mstatus, MSTATUS_SIE,
                            get_field(mstatus, MSTATUS_SPIE));
        mstatus = set_field(mstatus, MSTATUS_SPIE, 1);
        mstatus = set_field(mstatus, MSTATUS_SPP, PRV_U);
        env->mstatus = mstatus;
    }

    uint64_t satp_mode;
    if (riscv_cpu_mxl(env) == MXL_RV32) {
        satp_mode = SATP32_MODE;
    } else {
        satp_mode = SATP64_MODE;
    }
    int vm = get_field(env->satp, satp_mode);

    if(vm == VM_SECCELL) {
        /* Should not return to userspace with URID set to 0 */
        if ((env->urid == RT_ID_SUPERVISOR) && (prev_priv == PRV_U)) {
            env->badaddr = env->urid;
            riscv_raise_exception(env, RISCV_EXCP_SECCELL_INV_SDID, retpc);
        }
        env->usid = env->urid;
        env->urid = env->uxid;
        env->uxid = 0;
    }

    riscv_cpu_set_mode(env, prev_priv);

    return retpc;
}

target_ulong helper_mret(CPURISCVState *env, target_ulong cpu_pc_deb)
{
    if (!(env->priv >= PRV_M)) {
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
    }

    target_ulong retpc = env->mepc;
    if (!riscv_has_ext(env, RVC) && (retpc & 0x3)) {
        riscv_raise_exception(env, RISCV_EXCP_INST_ADDR_MIS, GETPC());
    }

    uint64_t mstatus = env->mstatus;
    target_ulong prev_priv = get_field(mstatus, MSTATUS_MPP);

    if (!pmp_get_num_rules(env) && (prev_priv != PRV_M)) {
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
    }

    target_ulong prev_virt = get_field(env->mstatus, MSTATUS_MPV);
    mstatus = set_field(mstatus, MSTATUS_MIE,
                        get_field(mstatus, MSTATUS_MPIE));
    mstatus = set_field(mstatus, MSTATUS_MPIE, 1);
    mstatus = set_field(mstatus, MSTATUS_MPP, PRV_U);
    mstatus = set_field(mstatus, MSTATUS_MPV, 0);
    if(env->mtirdval_valid) {
        env->gpr[env->mtird] = env->mtirdval;
        env->mtird = 0;
        env->mtirdval = 0;
        env->mtirdval_valid = 0;
    }
    env->mstatus = mstatus;
    riscv_cpu_set_mode(env, prev_priv);

    if (riscv_has_ext(env, RVH)) {
        if (prev_virt) {
            riscv_cpu_swap_hypervisor_regs(env);
        }

        riscv_cpu_set_virt_enabled(env, prev_virt);
    }

    return retpc;
}

void helper_wfi(CPURISCVState *env)
{
    CPUState *cs = env_cpu(env);
    bool rvs = riscv_has_ext(env, RVS);
    bool prv_u = env->priv == PRV_U;
    bool prv_s = env->priv == PRV_S;

    if (((prv_s || (!rvs && prv_u)) && get_field(env->mstatus, MSTATUS_TW)) ||
        (rvs && prv_u && !riscv_cpu_virt_enabled(env))) {
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
    } else if (riscv_cpu_virt_enabled(env) && (prv_u ||
        (prv_s && get_field(env->hstatus, HSTATUS_VTW)))) {
        riscv_raise_exception(env, RISCV_EXCP_VIRT_INSTRUCTION_FAULT, GETPC());
    } else {
        cs->halted = 1;
        cs->exception_index = EXCP_HLT;
        cpu_loop_exit(cs);
    }
}

void helper_tlb_flush(CPURISCVState *env)
{
    CPUState *cs = env_cpu(env);
    if (!(env->priv >= PRV_S) ||
        (env->priv == PRV_S &&
         get_field(env->mstatus, MSTATUS_TVM))) {
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
    } else if (riscv_has_ext(env, RVH) && riscv_cpu_virt_enabled(env) &&
               get_field(env->hstatus, HSTATUS_VTVM)) {
        riscv_raise_exception(env, RISCV_EXCP_VIRT_INSTRUCTION_FAULT, GETPC());
    } else {
        tlb_flush(cs);
    }
}

void helper_hyp_tlb_flush(CPURISCVState *env)
{
    CPUState *cs = env_cpu(env);

    if (env->priv == PRV_S && riscv_cpu_virt_enabled(env)) {
        riscv_raise_exception(env, RISCV_EXCP_VIRT_INSTRUCTION_FAULT, GETPC());
    }

    if (env->priv == PRV_M ||
        (env->priv == PRV_S && !riscv_cpu_virt_enabled(env))) {
        tlb_flush(cs);
        return;
    }

    riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
}

void helper_hyp_gvma_tlb_flush(CPURISCVState *env)
{
    if (env->priv == PRV_S && !riscv_cpu_virt_enabled(env) &&
        get_field(env->mstatus, MSTATUS_TVM)) {
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
    }

    helper_hyp_tlb_flush(env);
}

target_ulong helper_hyp_hlvx_hu(CPURISCVState *env, target_ulong address)
{
    int mmu_idx = cpu_mmu_index(env, true) | TB_FLAGS_PRIV_HYP_ACCESS_MASK;

    return cpu_lduw_mmuidx_ra(env, address, mmu_idx, GETPC());
}

target_ulong helper_hyp_hlvx_wu(CPURISCVState *env, target_ulong address)
{
    int mmu_idx = cpu_mmu_index(env, true) | TB_FLAGS_PRIV_HYP_ACCESS_MASK;

    return cpu_ldl_mmuidx_ra(env, address, mmu_idx, GETPC());
}

#endif /* !CONFIG_USER_ONLY */
