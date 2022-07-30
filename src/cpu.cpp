#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include "cpu.h"

void CPU::riscv_cpu_init64()
{
    m_pc       = 0x1000;
    m_priv     = PRV_M;
    m_cur_xlen = MAX_XLEN;
    m_mxl      = get_base_from_xlen(MAX_XLEN);
    m_mstatus  = ((uint64_t)m_mxl << MSTATUS_UXL_SHIFT) | ((uint64_t)m_mxl << MSTATUS_SXL_SHIFT);
    m_misa |= MCPUID_SUPER | MCPUID_USER | MCPUID_I | MCPUID_M | MCPUID_A;
    m_misa |= MCPUID_F;
    m_misa |= MCPUID_D;
    m_misa |= MCPUID_C;
    counts = 0;
    tlb_init();
}
void CPU::phys_write_u32(uint64_t addr, uint32_t val)
{
    PhysMemRange *pr = m_mem_map->get_phys_mem_range(addr);
    if (!pr || !pr->is_ram)
        return;
    *(uint32_t *)(pr->phys_mem + (uintptr_t)(addr - pr->addr)) = val;
}
uint32_t CPU::phys_read_u32(uint64_t addr)
{
    PhysMemRange *pr = m_mem_map->get_phys_mem_range(addr);
    if (!pr || !pr->is_ram)
        return 0;
    return *(uint32_t *)(pr->phys_mem + (uintptr_t)(addr - pr->addr));
}
void CPU::phys_write_u64(uint64_t addr, uint64_t val)
{
    PhysMemRange *pr = m_mem_map->get_phys_mem_range(addr);
    if (!pr || !pr->is_ram)
        return;
    *(uint64_t *)(pr->phys_mem + (uintptr_t)(addr - pr->addr)) = val;
}
uint64_t CPU::phys_read_u64(uint64_t addr)
{
    PhysMemRange *pr = m_mem_map->get_phys_mem_range(addr);
    if (!pr || !pr->is_ram)
        return 0;
    return *(uint64_t *)(pr->phys_mem + (uintptr_t)(addr - pr->addr));
}

int CPU::get_phys_addr(uint64_t *ppaddr, uint64_t vaddr, int access)
{
    int      mode, levels, pte_bits, pte_idx, pte_mask, pte_size_log2, xwr, _priv;
    int      need_write, vaddr_shift, i, pte_addr_bits;
    uint64_t pte_addr, pte, vaddr_mask, paddr;

    if ((m_mstatus & MSTATUS_MPRV) && access != ACCESS_CODE) {
        _priv = (m_mstatus >> MSTATUS_MPP_SHIFT) & 3;
    } else {
        _priv = m_priv;
    }

    if (_priv == PRV_M) {
        if (m_cur_xlen < MAX_XLEN) {
            *ppaddr = vaddr & (((uint64_t)1 << m_cur_xlen) - 1);
        } else {
            *ppaddr = vaddr;
        }
        return 0;
    }

    mode = (m_satp >> 60) & 0xf;
    if (mode == 0) {
        *ppaddr = vaddr;
        return 0;
    } else {
        levels        = mode - 8 + 3;
        pte_size_log2 = 3;
        vaddr_shift   = MAX_XLEN - (PG_SHIFT + levels * 9);
        if ((((int64_t)vaddr << vaddr_shift) >> vaddr_shift) != vaddr)
            return -1;
        pte_addr_bits = 44;
    }
    pte_addr = (m_satp & (((uint64_t)1 << pte_addr_bits) - 1)) << PG_SHIFT;
    pte_bits = 12 - pte_size_log2;
    pte_mask = (1 << pte_bits) - 1;
    for (i = 0; i < levels; i++) {
        vaddr_shift = PG_SHIFT + pte_bits * (levels - 1 - i);
        pte_idx     = (vaddr >> vaddr_shift) & pte_mask;
        pte_addr += pte_idx << pte_size_log2;
        if (pte_size_log2 == 2)
            pte = phys_read_u32(pte_addr);
        else
            pte = phys_read_u64(pte_addr);

        if (!(pte & PTE_V_MASK))
            return -1; /* invalid PTE */
        paddr = (pte >> 10) << PG_SHIFT;
        xwr   = (pte >> 1) & 7;
        if (xwr != 0) {
            if (xwr == 2 || xwr == 6)
                return -1;
            if (_priv == PRV_S) {
                if ((pte & PTE_U_MASK) && !(m_mstatus & MSTATUS_SUM))
                    return -1;
            } else {
                if (!(pte & PTE_U_MASK))
                    return -1;
            }

            if (m_mstatus & MSTATUS_MXR)
                xwr |= (xwr >> 2);

            if (((xwr >> access) & 1) == 0)
                return -1;
            need_write = !(pte & PTE_A_MASK) || (!(pte & PTE_D_MASK) && access == ACCESS_WRITE);
            pte |= PTE_A_MASK;
            if (access == ACCESS_WRITE)
                pte |= PTE_D_MASK;
            if (need_write) {
                if (pte_size_log2 == 2)
                    phys_write_u32(pte_addr, pte);
                else
                    phys_write_u64(pte_addr, pte);
            }
            vaddr_mask = ((uint64_t)1 << vaddr_shift) - 1;
            *ppaddr    = (vaddr & vaddr_mask) | (paddr & ~vaddr_mask);
            return 0;
        } else {
            pte_addr = paddr;
        }
    }
    return -1;
}
int CPU::riscv64_read_slow(uint64_t *pval, uint64_t addr, int size_log2)
{
    int           size, tlb_idx, err, al;
    uint64_t      paddr, offset;
    uint8_t      *ptr;
    PhysMemRange *pr;
    uint64_t      ret;

    size = 1 << size_log2;
    al   = addr & (size - 1);
    if (al != 0) {
        switch (size_log2) {
            case 1: {
                uint8_t v0, v1;
                err = target_read_u8(&v0, addr);
                if (err)
                    return err;
                err = target_read_u8(&v1, addr + 1);
                if (err)
                    return err;
                ret = v0 | (v1 << 8);
            } break;
            case 2: {
                uint32_t v0, v1;
                addr -= al;
                err = target_read_u32(&v0, addr);
                if (err)
                    return err;
                err = target_read_u32(&v1, addr + 4);
                if (err)
                    return err;
                ret = (v0 >> (al * 8)) | (v1 << (32 - al * 8));
            } break;
            case 3: {
                uint64_t v0, v1;
                addr -= al;
                err = target_read_u64(&v0, addr);
                if (err)
                    return err;
                err = target_read_u64(&v1, addr + 8);
                if (err)
                    return err;
                ret = (v0 >> (al * 8)) | (v1 << (64 - al * 8));
            } break;
            default:
                abort();
        }
    } else {
        if (get_phys_addr(&paddr, addr, ACCESS_READ)) {
            m_pending_tval      = addr;
            m_pending_exception = CAUSE_LOAD_PAGE_FAULT;
            return -1;
        }
        pr = m_mem_map->get_phys_mem_range(paddr);
        if (!pr) {
            return 0;
        } else if (pr->is_ram) {
            tlb_idx                        = (addr >> PG_SHIFT) & (TLB_SIZE - 1);
            ptr                            = pr->phys_mem + (uintptr_t)(paddr - pr->addr);
            m_tlb_read[tlb_idx].vaddr      = addr & ~PG_MASK;
            m_tlb_read[tlb_idx].mem_addend = (uintptr_t)ptr - addr;
            switch (size_log2) {
                case 0:
                    ret = *(uint8_t *)ptr;
                    break;
                case 1:
                    ret = *(uint16_t *)ptr;
                    break;
                case 2:
                    ret = *(uint32_t *)ptr;
                    break;
                case 3:
                    ret = *(uint64_t *)ptr;
                    break;
                default:
                    abort();
            }
        } else {
            offset = paddr - pr->addr;
            if (((pr->devio_flags >> size_log2) & 1) != 0) {
                ret = pr->read_func(pr->opaque, offset, size_log2);
            } else if ((pr->devio_flags & DEVIO_SIZE32) && size_log2 == 3) {
                /* emulate 64 bit access */
                ret = pr->read_func(pr->opaque, offset, 2);
                ret |= (uint64_t)pr->read_func(pr->opaque, offset + 4, 2) << 32;

            } else {
                ret = 0;
            }
        }
    }
    *pval = ret;
    return 0;
}
int CPU::riscv64_write_slow(uint64_t addr, uint64_t val, int size_log2)
{
    int           size, i, tlb_idx, err;
    uint64_t      paddr, offset;
    uint8_t      *ptr;
    PhysMemRange *pr;

    size = 1 << size_log2;
    if ((addr & (size - 1)) != 0) {
        for (i = 0; i < size; i++) {
            err = target_write_u8(addr + i, (val >> (8 * i)) & 0xff);
            if (err)
                return err;
        }
    } else {
        if (get_phys_addr(&paddr, addr, ACCESS_WRITE)) {
            m_pending_tval      = addr;
            m_pending_exception = CAUSE_STORE_PAGE_FAULT;
            return -1;
        }
        pr = m_mem_map->get_phys_mem_range(paddr);
        if (!pr) {

        } else if (pr->is_ram) {
            pr->phys_mem_set_dirty_bit(paddr - pr->addr);
            tlb_idx                         = (addr >> PG_SHIFT) & (TLB_SIZE - 1);
            ptr                             = pr->phys_mem + (uintptr_t)(paddr - pr->addr);
            m_tlb_write[tlb_idx].vaddr      = addr & ~PG_MASK;
            m_tlb_write[tlb_idx].mem_addend = (uintptr_t)ptr - addr;
            switch (size_log2) {
                case 0:
                    *(uint8_t *)ptr = val;
                    break;
                case 1:
                    *(uint16_t *)ptr = val;
                    break;
                case 2:
                    *(uint32_t *)ptr = val;
                    break;
                case 3:
                    *(uint64_t *)ptr = val;
                    break;
                default:
                    abort();
            }
        } else {
            offset = paddr - pr->addr;
            if (((pr->devio_flags >> size_log2) & 1) != 0) {
                pr->write_func(pr->opaque, offset, val, size_log2);
            } else if ((pr->devio_flags & DEVIO_SIZE32) && size_log2 == 3) {
                pr->write_func(pr->opaque, offset, val & 0xffffffff, 2);
                pr->write_func(pr->opaque, offset + 4, (val >> 32) & 0xffffffff, 2);
            } else {
            }
        }
    }
    return 0;
}

uint32_t CPU::get_insn32(uint8_t *ptr)
{
    return ((struct unaligned_u32 *)ptr)->u32;
}
int CPU::target_read_insn_slow(uint8_t **pptr, uint64_t addr)
{
    int           tlb_idx;
    uint64_t      paddr;
    uint8_t      *ptr;
    PhysMemRange *pr;

    if (get_phys_addr(&paddr, addr, ACCESS_CODE)) {
        m_pending_tval      = addr;
        m_pending_exception = CAUSE_FETCH_PAGE_FAULT;
        return -1;
    }
    pr = m_mem_map->get_phys_mem_range(paddr);
    if (!pr || !pr->is_ram) {
        m_pending_tval      = addr;
        m_pending_exception = CAUSE_FAULT_FETCH;
        return -1;
    }
    tlb_idx                        = (addr >> PG_SHIFT) & (TLB_SIZE - 1);
    ptr                            = pr->phys_mem + (uintptr_t)(paddr - pr->addr);
    m_tlb_code[tlb_idx].vaddr      = addr & ~PG_MASK;
    m_tlb_code[tlb_idx].mem_addend = (uintptr_t)ptr - addr;
    *pptr                          = ptr;
    return 0;
}
int CPU::target_read_insn_u16(uint16_t *pinsn, uint64_t addr)
{
    uint8_t *ptr;
    uint32_t tlb_idx = (addr >> PG_SHIFT) & (TLB_SIZE - 1);
    if (likely(m_tlb_code[tlb_idx].vaddr == (addr & ~PG_MASK))) {
        ptr = (uint8_t *)(m_tlb_code[tlb_idx].mem_addend + (uintptr_t)addr);
    } else {
        if (target_read_insn_slow(&ptr, addr))
            return -1;
    }
    *pinsn = *(uint16_t *)ptr;
    return 0;
}
void CPU::tlb_init()
{
    for (int i = 0; i < TLB_SIZE; i++) {
        m_tlb_read[i].vaddr  = -1;
        m_tlb_write[i].vaddr = -1;
        m_tlb_code[i].vaddr  = -1;
    }
}
void CPU::tlb_flush_all()
{
    tlb_init();
}
void CPU::tlb_flush_vaddr(uint64_t vaddr)
{
    tlb_flush_all();
}
void CPU::riscv_cpu_flush_tlb_write_range_ram64(uint8_t *ram_ptr, size_t ram_size)
{
    uint8_t *ptr, *ram_end;
    ram_end = ram_ptr + ram_size;
    for (int i = 0; i < TLB_SIZE; i++) {
        if (m_tlb_write[i].vaddr != -1) {
            ptr = (uint8_t *)(m_tlb_write[i].mem_addend + (uintptr_t)m_tlb_write[i].vaddr);
            if (ptr >= ram_ptr && ptr < ram_end) {
                m_tlb_write[i].vaddr = -1;
            }
        }
    }
}
uint64_t CPU::get_mstatus(uint64_t mask)
{
    uint64_t val = m_mstatus | (m_fs << MSTATUS_FS_SHIFT);
    val &= mask;
    BOOL sd = ((val & MSTATUS_FS) == MSTATUS_FS) | ((val & MSTATUS_XS) == MSTATUS_XS);
    if (sd)
        val |= (uint64_t)1 << (m_cur_xlen - 1);
    return val;
}
int CPU::get_base_from_xlen(int xlen)
{
    if (xlen == 32)
        return 1;
    else if (xlen == 64)
        return 2;
    else
        return 3;
}
void CPU::set_mstatus(uint64_t val)
{
    uint64_t mod = m_mstatus ^ val;
    if ((mod & (MSTATUS_MPRV | MSTATUS_SUM | MSTATUS_MXR)) != 0 ||
        ((m_mstatus & MSTATUS_MPRV) && (mod & MSTATUS_MPP) != 0)) {
        tlb_flush_all();
    }
    m_fs = (val >> MSTATUS_FS_SHIFT) & 3;

    uint64_t mask = MSTATUS_MASK & ~MSTATUS_FS;
    {
        int uxl = (val >> MSTATUS_UXL_SHIFT) & 3;
        if (uxl >= 1 && uxl <= get_base_from_xlen(MAX_XLEN))
            mask |= MSTATUS_UXL_MASK;
        int sxl = (val >> MSTATUS_UXL_SHIFT) & 3;
        if (sxl >= 1 && sxl <= get_base_from_xlen(MAX_XLEN))
            mask |= MSTATUS_SXL_MASK;
    }
    m_mstatus = (m_mstatus & ~mask) | (val & mask);
}
int CPU::csr_read(uint64_t *pval, uint32_t csr, BOOL will_write)
{
    uint64_t val;

    if (((csr & 0xc00) == 0xc00) && will_write)
        return -1; /* read-only CSR */
    if (m_priv < ((csr >> 8) & 3))
        return -1; /* not enough priviledge */

    switch (csr) {
        case 0x001: /* fflags */
            if (m_fs == 0)
                return -1;
            val = m_fflags;
            break;
        case 0x002: /* frm */
            if (m_fs == 0)
                return -1;
            val = m_frm;
            break;
        case 0x003:
            if (m_fs == 0)
                return -1;
            val = m_fflags | (m_frm << 5);
            break;
        case 0xc00: /* ucycle */
        case 0xc02: /* uinstret */
        {
            uint32_t counteren;
            if (m_priv < PRV_M) {
                if (m_priv < PRV_S)
                    counteren = m_scounteren;
                else
                    counteren = m_mcounteren;
                if (((counteren >> (csr & 0x1f)) & 1) == 0)
                    goto invalid_csr;
            }
        }
            val = (int64_t)m_insn_counter;
            break;
        case 0xc80: /* mcycleh */
        case 0xc82: /* minstreth */
            if (m_cur_xlen != 32)
                goto invalid_csr;
            {
                uint32_t counteren;
                if (m_priv < PRV_M) {
                    if (m_priv < PRV_S)
                        counteren = m_scounteren;
                    else
                        counteren = m_mcounteren;
                    if (((counteren >> (csr & 0x1f)) & 1) == 0)
                        goto invalid_csr;
                }
            }
            val = m_insn_counter >> 32;
            break;

        case 0x100:
            val = get_mstatus(SSTATUS_MASK);
            break;
        case 0x104: /* sie */
            val = m_mie & m_mideleg;
            break;
        case 0x105:
            val = m_stvec;
            break;
        case 0x106:
            val = m_scounteren;
            break;
        case 0x140:
            val = m_sscratch;
            break;
        case 0x141:
            val = m_sepc;
            break;
        case 0x142:
            val = m_scause;
            break;
        case 0x143:
            val = m_stval;
            break;
        case 0x144: /* sip */
            val = m_mip & m_mideleg;
            break;
        case 0x180:
            val = m_satp;
            break;
        case 0x300:
            val = get_mstatus((uint64_t)-1);
            break;
        case 0x301:
            val = m_misa;
            val |= (uint64_t)m_mxl << (m_cur_xlen - 2);
            break;
        case 0x302:
            val = m_medeleg;
            break;
        case 0x303:
            val = m_mideleg;
            break;
        case 0x304:
            val = m_mie;
            break;
        case 0x305:
            val = m_mtvec;
            break;
        case 0x306:
            val = m_mcounteren;
            break;
        case 0x340:
            val = m_mscratch;
            break;
        case 0x341:
            val = m_mepc;
            break;
        case 0x342:
            val = m_mcause;
            break;
        case 0x343:
            val = m_mtval;
            break;
        case 0x344:
            val = m_mip;
            break;
        case 0xb00: /* mcycle */
        case 0xb02: /* minstret */
            val = (int64_t)m_insn_counter;
            break;
        case 0xb80: /* mcycleh */
        case 0xb82: /* minstreth */
            if (m_cur_xlen != 32)
                goto invalid_csr;
            val = m_insn_counter >> 32;
            break;
        case 0xf14:
            val = m_mhartid;
            break;
        default:
        invalid_csr:

            *pval = 0;
            return -1;
    }
    *pval = val;
    return 0;
}
void CPU::set_frm(unsigned int val)
{
    if (val >= 5)
        val = 0;
    m_frm = val;
}
int CPU::get_insn_rm(unsigned int rm)
{
    if (rm == 7)
        return m_frm;
    if (rm >= 5)
        return -1;
    else
        return rm;
}
int CPU::csr_write(uint32_t csr, uint64_t val)
{
    uint64_t mask;

    switch (csr) {
        case 0x001: /* fflags */
            m_fflags = val & 0x1f;
            m_fs     = 3;
            break;
        case 0x002: /* frm */
            set_frm(val & 7);
            m_fs = 3;
            break;
        case 0x003: /* fcsr */
            set_frm((val >> 5) & 7);
            m_fflags = val & 0x1f;
            m_fs     = 3;
            break;
        case 0x100: /* sstatus */
            set_mstatus((m_mstatus & ~SSTATUS_MASK) | (val & SSTATUS_MASK));
            break;
        case 0x104: /* sie */
            mask  = m_mideleg;
            m_mie = (m_mie & ~mask) | (val & mask);
            break;
        case 0x105:
            m_stvec = val & ~3;
            break;
        case 0x106:
            m_scounteren = val & COUNTEREN_MASK;
            break;
        case 0x140:
            m_sscratch = val;
            break;
        case 0x141:
            m_sepc = val & ~1;
            break;
        case 0x142:
            m_scause = val;
            break;
        case 0x143:
            m_stval = val;
            break;
        case 0x144: /* sip */
            mask  = m_mideleg;
            m_mip = (m_mip & ~mask) | (val & mask);
            break;
        case 0x180: {
            int mode, new_mode;
            mode     = m_satp >> 60;
            new_mode = (val >> 60) & 0xf;
            if (new_mode == 0 || (new_mode >= 8 && new_mode <= 9))
                mode = new_mode;
            m_satp = (val & (((uint64_t)1 << 44) - 1)) | ((uint64_t)mode << 60);
            tlb_flush_all();
            return 2;
        }
        case 0x300:
            set_mstatus(val);
            break;
        case 0x301: /* misa */
        {
            int new_mxl = (val >> (m_cur_xlen - 2)) & 3;
            if (new_mxl >= 1 && new_mxl <= get_base_from_xlen(MAX_XLEN)) {
                if (m_mxl != new_mxl) {
                    m_mxl      = new_mxl;
                    m_cur_xlen = 1 << (new_mxl + 4);
                    return 1;
                }
            }
        } break;
        case 0x302:
            mask      = (1 << (CAUSE_STORE_PAGE_FAULT + 1)) - 1;
            m_medeleg = (m_medeleg & ~mask) | (val & mask);
            break;
        case 0x303:
            mask      = MIP_SSIP | MIP_STIP | MIP_SEIP;
            m_mideleg = (m_mideleg & ~mask) | (val & mask);
            break;
        case 0x304:
            mask  = MIP_MSIP | MIP_MTIP | MIP_SSIP | MIP_STIP | MIP_SEIP;
            m_mie = (m_mie & ~mask) | (val & mask);
            break;
        case 0x305:
            m_mtvec = val & ~3;
            break;
        case 0x306:
            m_mcounteren = val & COUNTEREN_MASK;
            break;
        case 0x340:
            m_mscratch = val;
            break;
        case 0x341:
            m_mepc = val & ~1;
            break;
        case 0x342:
            m_mcause = val;
            break;
        case 0x343:
            m_mtval = val;
            break;
        case 0x344:
            mask  = MIP_SSIP | MIP_STIP;
            m_mip = (m_mip & ~mask) | (val & mask);
            break;
        default:
            return -1;
    }
    return 0;
}
void CPU::set_priv(int _priv)
{
    if (m_priv != _priv) {
        tlb_flush_all();
        int _mxl;
        if (_priv == PRV_S)
            _mxl = (m_mstatus >> MSTATUS_SXL_SHIFT) & 3;
        else if (_priv == PRV_U)
            _mxl = (m_mstatus >> MSTATUS_UXL_SHIFT) & 3;
        else
            _mxl = m_mxl;
        m_cur_xlen = 1 << (4 + _mxl);
        m_priv     = _priv;
    }
}
void CPU::raise_exception(uint32_t cause, uint64_t tval)
{
    BOOL deleg;

    if (m_priv <= PRV_S) {
        if (cause & CAUSE_INTERRUPT)
            deleg = (m_mideleg >> (cause & (MAX_XLEN - 1))) & 1;
        else
            deleg = (m_medeleg >> cause) & 1;
    } else {
        deleg = 0;
    }

    uint64_t causel = cause & 0x7fffffff;
    if (cause & CAUSE_INTERRUPT)
        causel |= (uint64_t)1 << (m_cur_xlen - 1);

    if (deleg) {
        m_scause  = causel;
        m_sepc    = m_pc;
        m_stval   = tval;
        m_mstatus = (m_mstatus & ~MSTATUS_SPIE) | (((m_mstatus >> m_priv) & 1) << MSTATUS_SPIE_SHIFT);
        m_mstatus = (m_mstatus & ~MSTATUS_SPP) | (m_priv << MSTATUS_SPP_SHIFT);
        m_mstatus &= ~MSTATUS_SIE;
        set_priv(PRV_S);
        m_pc = m_stvec;
    } else {
        m_mcause  = causel;
        m_mepc    = m_pc;
        m_mtval   = tval;
        m_mstatus = (m_mstatus & ~MSTATUS_MPIE) | (((m_mstatus >> m_priv) & 1) << MSTATUS_MPIE_SHIFT);
        m_mstatus = (m_mstatus & ~MSTATUS_MPP) | (m_priv << MSTATUS_MPP_SHIFT);
        m_mstatus &= ~MSTATUS_MIE;
        set_priv(PRV_M);
        m_pc = m_mtvec;
    }
}
void CPU::handle_sret()
{
    int spp   = (m_mstatus >> MSTATUS_SPP_SHIFT) & 1;
    int spie  = (m_mstatus >> MSTATUS_SPIE_SHIFT) & 1;
    m_mstatus = (m_mstatus & ~(1 << spp)) | (spie << spp);
    m_mstatus |= MSTATUS_SPIE;
    m_mstatus &= ~MSTATUS_SPP;
    set_priv(spp);
    m_pc = m_sepc;
}
void CPU::handle_mret()
{
    int mpp   = (m_mstatus >> MSTATUS_MPP_SHIFT) & 3;
    int mpie  = (m_mstatus >> MSTATUS_MPIE_SHIFT) & 1;
    m_mstatus = (m_mstatus & ~(1 << mpp)) | (mpie << mpp);
    m_mstatus |= MSTATUS_MPIE;
    m_mstatus &= ~MSTATUS_MPP;
    set_priv(mpp);
    m_pc = m_mepc;
}
uint32_t CPU::get_pending_irq_mask()
{
    uint32_t pending_ints = m_mip & m_mie;
    if (pending_ints == 0)
        return 0;

    uint32_t enabled_ints = 0;
    switch (m_priv) {
        case PRV_M:
            if (m_mstatus & MSTATUS_MIE)
                enabled_ints = ~m_mideleg;
            break;
        case PRV_S:
            enabled_ints = ~m_mideleg;
            if (m_mstatus & MSTATUS_SIE)
                enabled_ints |= m_mideleg;
            break;
        default:
        case PRV_U:
            enabled_ints = -1;
            break;
    }
    return pending_ints & enabled_ints;
}
int CPU::raise_interrupt()
{
    uint32_t mask = get_pending_irq_mask();
    if (mask == 0)
        return 0;
    int irq_num = ctz32(mask);
    raise_exception(irq_num | CAUSE_INTERRUPT, 0);
    return -1;
}
int32_t CPU::sext(int32_t val, int n)
{
    return (val << (32 - n)) >> (32 - n);
}
uint32_t CPU::get_field1(uint32_t val, int src_pos, int dst_pos, int dst_pos_max)
{
    assert(dst_pos_max >= dst_pos);
    int mask = ((1 << (dst_pos_max - dst_pos + 1)) - 1) << dst_pos;
    if (dst_pos >= src_pos)
        return (val << (dst_pos - src_pos)) & mask;
    else
        return (val >> (src_pos - dst_pos)) & mask;
}
int64_t CPU::div64(int64_t a, int64_t b)
{
    if (b == 0) {
        return -1;
    } else if (a == ((int64_t)1 << (XLEN - 1)) && b == -1) {
        return a;
    } else {
        return a / b;
    }
}
uint64_t CPU::divu64(uint64_t a, uint64_t b)
{
    if (b == 0) {
        return -1;
    } else {
        return a / b;
    }
}
int64_t CPU::rem64(int64_t a, int64_t b)
{
    if (b == 0) {
        return a;
    } else if (a == ((int64_t)1 << (XLEN - 1)) && b == -1) {
        return 0;
    } else {
        return a % b;
    }
}
uint64_t CPU::remu64(uint64_t a, uint64_t b)
{
    if (b == 0) {
        return a;
    } else {
        return a % b;
    }
}
uint64_t CPU::mulhu64(uint64_t a, uint64_t b)
{
    UHALF a0 = a;
    UHALF a1 = a >> UHALF_LEN;
    UHALF b0 = b;
    UHALF b1 = b >> UHALF_LEN;

    uint64_t r00 = (uint64_t)a0 * (uint64_t)b0;
    uint64_t r01 = (uint64_t)a0 * (uint64_t)b1;
    uint64_t r10 = (uint64_t)a1 * (uint64_t)b0;
    uint64_t r11 = (uint64_t)a1 * (uint64_t)b1;

    uint64_t c = (r00 >> UHALF_LEN) + (UHALF)r01 + (UHALF)r10;
    c          = (c >> UHALF_LEN) + (r01 >> UHALF_LEN) + (r10 >> UHALF_LEN) + (UHALF)r11;
    UHALF r2   = c;
    UHALF r3   = (c >> UHALF_LEN) + (r11 >> UHALF_LEN);
    return ((uint64_t)r3 << UHALF_LEN) | r2;
}
uint64_t CPU::mulh64(int64_t a, int64_t b)
{
    uint64_t r1 = mulhu64(a, b);
    if (a < 0)
        r1 -= a;
    if (b < 0)
        r1 -= b;
    return r1;
}
uint64_t CPU::mulhsu64(int64_t a, uint64_t b)
{
    uint64_t r1 = mulhu64(a, b);
    if (a < 0)
        r1 -= a;
    return r1;
}
uint64_t CPU::riscv_cpu_get_cycles64()
{
    return m_insn_counter;
}
void CPU::riscv_cpu_set_mip64(uint32_t mask)
{
    m_mip |= mask;
    if (m_power_down_flag && (m_mip & m_mie) != 0)
        m_power_down_flag = FALSE;
}
void CPU::riscv_cpu_reset_mip64(uint32_t mask)
{
    m_mip &= ~mask;
}
uint32_t CPU::riscv_cpu_get_mip64()
{
    return m_mip;
}
BOOL CPU::riscv_cpu_get_power_down64()
{
    return m_power_down_flag;
}

int CPU::target_read_u8(uint8_t *pval, uint64_t addr)
{
    uint32_t tlb_idx = (addr >> PG_SHIFT) & (TLB_SIZE - 1);
    if (likely(m_tlb_read[tlb_idx].vaddr == (addr & ~(PG_MASK & ~((8 / 8) - 1))))) {
        *pval = *(uint8_t *)(m_tlb_read[tlb_idx].mem_addend + (uintptr_t)addr);
    } else {
        uint64_t val;
        int      ret;
        ret = riscv64_read_slow(&val, addr, 0);
        if (ret)
            return ret;
        *pval = val;
    }
    return 0;
}
int CPU::target_read_u16(uint16_t *pval, uint64_t addr)
{
    uint32_t tlb_idx = (addr >> PG_SHIFT) & (TLB_SIZE - 1);
    if (likely(m_tlb_read[tlb_idx].vaddr == (addr & ~(PG_MASK & ~((16 / 8) - 1))))) {
        *pval = *(uint16_t *)(m_tlb_read[tlb_idx].mem_addend + (uintptr_t)addr);
    } else {
        uint64_t val;
        int      ret;
        ret = riscv64_read_slow(&val, addr, 1);
        if (ret)
            return ret;
        *pval = val;
    }
    return 0;
}
int CPU::target_read_u32(uint32_t *pval, uint64_t addr)
{
    uint32_t tlb_idx = (addr >> PG_SHIFT) & (TLB_SIZE - 1);
    if (likely(m_tlb_read[tlb_idx].vaddr == (addr & ~(PG_MASK & ~((32 / 8) - 1))))) {
        *pval = *(uint32_t *)(m_tlb_read[tlb_idx].mem_addend + (uintptr_t)addr);
    } else {
        uint64_t val;
        int      ret;
        ret = riscv64_read_slow(&val, addr, 2);
        if (ret)
            return ret;
        *pval = val;
    }
    return 0;
}
int CPU::target_read_u64(uint64_t *pval, uint64_t addr)
{
    uint32_t tlb_idx = (addr >> PG_SHIFT) & (TLB_SIZE - 1);
    if (likely(m_tlb_read[tlb_idx].vaddr == (addr & ~(PG_MASK & ~((64 / 8) - 1))))) {
        *pval = *(uint64_t *)(m_tlb_read[tlb_idx].mem_addend + (uintptr_t)addr);
    } else {
        uint64_t val;
        int      ret;
        ret = riscv64_read_slow(&val, addr, 3);
        if (ret)
            return ret;
        *pval = val;
    }
    return 0;
}

int CPU::target_write_u8(uint64_t addr, uint8_t val)
{
    uint32_t tlb_idx = (addr >> PG_SHIFT) & (TLB_SIZE - 1);
    if (likely(m_tlb_write[tlb_idx].vaddr == (addr & ~(PG_MASK & ~((8 / 8) - 1))))) {
        *(uint8_t *)(m_tlb_write[tlb_idx].mem_addend + (uintptr_t)addr) = val;
        return 0;
    } else {
        return riscv64_write_slow(addr, val, 0);
    }
}
int CPU::target_write_u16(uint64_t addr, uint16_t val)
{
    uint32_t tlb_idx = (addr >> PG_SHIFT) & (TLB_SIZE - 1);
    if (likely(m_tlb_write[tlb_idx].vaddr == (addr & ~(PG_MASK & ~((16 / 8) - 1))))) {
        *(uint16_t *)(m_tlb_write[tlb_idx].mem_addend + (uintptr_t)addr) = val;
        return 0;
    } else {
        return riscv64_write_slow(addr, val, 1);
    }
}
int CPU::target_write_u32(uint64_t addr, uint32_t val)
{
    uint32_t tlb_idx = (addr >> PG_SHIFT) & (TLB_SIZE - 1);
    if (likely(m_tlb_write[tlb_idx].vaddr == (addr & ~(PG_MASK & ~((32 / 8) - 1))))) {
        *(uint32_t *)(m_tlb_write[tlb_idx].mem_addend + (uintptr_t)addr) = val;
        return 0;
    } else {
        return riscv64_write_slow(addr, val, 2);
    }
}
int CPU::target_write_u64(uint64_t addr, uint64_t val)
{
    uint32_t tlb_idx = (addr >> PG_SHIFT) & (TLB_SIZE - 1);
    if (likely(m_tlb_write[tlb_idx].vaddr == (addr & ~(PG_MASK & ~((64 / 8) - 1))))) {
        *(uint64_t *)(m_tlb_write[tlb_idx].mem_addend + (uintptr_t)addr) = val;
        return 0;
    } else {
        return riscv64_write_slow(addr, val, 3);
    }
}

void CPU::riscv_cpu_end64()
{
}
uint32_t CPU::riscv_cpu_get_misa64()
{
    return m_misa;
}
void CPU::riscv_cpu_interp64(int n_cycles1)
{
    uint32_t insn;
    uint64_t addr, val, val2;
    int32_t  rm = 0;

    if (n_cycles1 == 0)
        return;

    uint64_t insn_counter_addend = m_insn_counter + n_cycles1;
    m_n_cycles                   = n_cycles1;
    m_pending_exception          = -1;
    uint8_t *code_ptr            = NULL;
    uint8_t *code_end            = NULL;
    uint64_t code_to_pc_addend   = m_pc;

    for (;;) {
        if (unlikely((m_mip & m_mie) != 0)) {
            if (raise_interrupt()) {
                m_n_cycles--;
                goto done_interp;
            }
        }

        if (unlikely(code_ptr >= code_end)) {
            uint32_t tlb_idx;
            uint16_t insn_high;
            uint8_t *ptr;

            m_pc = GET_PC();
            if (unlikely(m_n_cycles <= 0))
                goto the_end;

            if (unlikely((m_mip & m_mie) != 0)) {
                if (raise_interrupt()) {
                    m_n_cycles--;
                    goto the_end;
                }
            }

            addr    = m_pc;
            tlb_idx = (addr >> PG_SHIFT) & (TLB_SIZE - 1);
            if (likely(m_tlb_code[tlb_idx].vaddr == (addr & ~PG_MASK))) {
                ptr = (uint8_t *)(m_tlb_code[tlb_idx].mem_addend + (uintptr_t)addr);
            } else {
                if (unlikely(target_read_insn_slow(&ptr, addr)))
                    goto mmu_exception;
            }
            code_ptr          = ptr;
            code_end          = ptr + (PG_MASK - 1 - (addr & PG_MASK));
            code_to_pc_addend = addr - (uintptr_t)code_ptr;
            if (unlikely(code_ptr >= code_end)) {
                insn = *(uint16_t *)code_ptr;
                if ((insn & 3) == 3) {
                    if (unlikely(target_read_insn_u16(&insn_high, addr + 2)))
                        goto mmu_exception;
                    insn |= insn_high << 16;
                }
            } else {
                insn = get_insn32(code_ptr);
            }
        } else {
            insn = get_insn32(code_ptr);
        }
        m_n_cycles--;

        int32_t  imm, cond, err;
        uint32_t funct3 = 0;
        uint32_t opcode = insn & 0x7f;
        uint32_t rd     = (insn >> 7) & 0x1f;
        uint32_t rs1    = (insn >> 15) & 0x1f;
        uint32_t rs2    = (insn >> 20) & 0x1f;
        counts++;
        if (counts == 2449 || counts == 41512000) {    // linux boot 41512000
            // printf(" ");
        }

        switch (opcode) {
            case (0 << 2):
            case (1 << 2):
            case (2 << 2):
            case (3 << 2):
            case (4 << 2):
            case (5 << 2):
            case (6 << 2):
            case (7 << 2):
            case (8 << 2):
            case (9 << 2):
            case (10 << 2):
            case (11 << 2):
            case (12 << 2):
            case (13 << 2):
            case (14 << 2):
            case (15 << 2):
            case (16 << 2):
            case (17 << 2):
            case (18 << 2):
            case (19 << 2):
            case (20 << 2):
            case (21 << 2):
            case (22 << 2):
            case (23 << 2):
            case (24 << 2):
            case (25 << 2):
            case (26 << 2):
            case (27 << 2):
            case (28 << 2):
            case (29 << 2):
            case (30 << 2):
            case (31 << 2):

                funct3 = (insn >> 13) & 7;
                rd     = ((insn >> 2) & 7) | 8;
                switch (funct3) {
                    case 0: /* c.addi4spn */
                        imm = get_field1(insn, 11, 4, 5) | get_field1(insn, 7, 6, 9) | get_field1(insn, 6, 2, 2) |
                              get_field1(insn, 5, 3, 3);
                        if (imm == 0)
                            goto illegal_insn;
                        m_reg[rd] = (intx_t)(m_reg[2] + imm);
                        break;

                    case 1: /* c.fld */
                    {
                        uint64_t rval;
                        if (m_fs == 0)
                            goto illegal_insn;
                        imm  = get_field1(insn, 10, 3, 5) | get_field1(insn, 5, 6, 7);
                        rs1  = ((insn >> 7) & 7) | 8;
                        addr = (intx_t)(m_reg[rs1] + imm);
                        if (target_read_u64(&rval, addr))
                            goto mmu_exception;
                        m_fp_reg[rd] = rval | F64_HIGH;
                        m_fs         = 3;
                    } break;
                    case 2: /* c.lw */
                    {
                        uint32_t rval;
                        imm  = get_field1(insn, 10, 3, 5) | get_field1(insn, 6, 2, 2) | get_field1(insn, 5, 6, 6);
                        rs1  = ((insn >> 7) & 7) | 8;
                        addr = (intx_t)(m_reg[rs1] + imm);
                        if (target_read_u32(&rval, addr))
                            goto mmu_exception;
                        m_reg[rd] = (int32_t)rval;
                    } break;
                    case 3: /* c.ld */
                    {
                        uint64_t rval;
                        imm  = get_field1(insn, 10, 3, 5) | get_field1(insn, 5, 6, 7);
                        rs1  = ((insn >> 7) & 7) | 8;
                        addr = (intx_t)(m_reg[rs1] + imm);
                        if (target_read_u64(&rval, addr))
                            goto mmu_exception;
                        m_reg[rd] = (int64_t)rval;
                    } break;

                    case 5: /* c.fsd */
                        if (m_fs == 0)
                            goto illegal_insn;
                        imm  = get_field1(insn, 10, 3, 5) | get_field1(insn, 5, 6, 7);
                        rs1  = ((insn >> 7) & 7) | 8;
                        addr = (intx_t)(m_reg[rs1] + imm);
                        if (target_write_u64(addr, m_fp_reg[rd]))
                            goto mmu_exception;
                        break;
                    case 6: /* c.sw */
                        imm  = get_field1(insn, 10, 3, 5) | get_field1(insn, 6, 2, 2) | get_field1(insn, 5, 6, 6);
                        rs1  = ((insn >> 7) & 7) | 8;
                        addr = (intx_t)(m_reg[rs1] + imm);
                        val  = m_reg[rd];
                        if (target_write_u32(addr, val))
                            goto mmu_exception;
                        break;
                    case 7: /* c.sd */
                        imm  = get_field1(insn, 10, 3, 5) | get_field1(insn, 5, 6, 7);
                        rs1  = ((insn >> 7) & 7) | 8;
                        addr = (intx_t)(m_reg[rs1] + imm);
                        val  = m_reg[rd];
                        if (target_write_u64(addr, val))
                            goto mmu_exception;
                        break;
                    default:
                        goto illegal_insn;
                }
                code_ptr += 2;
                break;

            case 1 + (0 << 2):
            case 1 + (1 << 2):
            case 1 + (2 << 2):
            case 1 + (3 << 2):
            case 1 + (4 << 2):
            case 1 + (5 << 2):
            case 1 + (6 << 2):
            case 1 + (7 << 2):
            case 1 + (8 << 2):
            case 1 + (9 << 2):
            case 1 + (10 << 2):
            case 1 + (11 << 2):
            case 1 + (12 << 2):
            case 1 + (13 << 2):
            case 1 + (14 << 2):
            case 1 + (15 << 2):
            case 1 + (16 << 2):
            case 1 + (17 << 2):
            case 1 + (18 << 2):
            case 1 + (19 << 2):
            case 1 + (20 << 2):
            case 1 + (21 << 2):
            case 1 + (22 << 2):
            case 1 + (23 << 2):
            case 1 + (24 << 2):
            case 1 + (25 << 2):
            case 1 + (26 << 2):
            case 1 + (27 << 2):
            case 1 + (28 << 2):
            case 1 + (29 << 2):
            case 1 + (30 << 2):
            case 1 + (31 << 2):

                funct3 = (insn >> 13) & 7;
                switch (funct3) {
                    case 0: /* c.addi/c.nop */
                        if (rd != 0) {
                            imm       = sext(get_field1(insn, 12, 5, 5) | get_field1(insn, 2, 0, 4), 6);
                            m_reg[rd] = (intx_t)(m_reg[rd] + imm);
                        }
                        break;

                    case 1: /* c.addiw */
                        if (rd != 0) {
                            imm       = sext(get_field1(insn, 12, 5, 5) | get_field1(insn, 2, 0, 4), 6);
                            m_reg[rd] = (int32_t)(m_reg[rd] + imm);
                        }
                        break;
                    case 2: /* c.li */
                        if (rd != 0) {
                            imm       = sext(get_field1(insn, 12, 5, 5) | get_field1(insn, 2, 0, 4), 6);
                            m_reg[rd] = imm;
                        }
                        break;
                    case 3:
                        if (rd == 2) {
                            imm = sext(get_field1(insn, 12, 9, 9) | get_field1(insn, 6, 4, 4) |
                                           get_field1(insn, 5, 6, 6) | get_field1(insn, 3, 7, 8) |
                                           get_field1(insn, 2, 5, 5),
                                       10);
                            if (imm == 0)
                                goto illegal_insn;
                            m_reg[2] = (intx_t)(m_reg[2] + imm);
                        } else if (rd != 0) {
                            /* c.lui */
                            imm       = sext(get_field1(insn, 12, 17, 17) | get_field1(insn, 2, 12, 16), 18);
                            m_reg[rd] = imm;
                        }
                        break;
                    case 4:
                        funct3 = (insn >> 10) & 3;
                        rd     = ((insn >> 7) & 7) | 8;
                        switch (funct3) {
                            case 0: /* c.srli */
                            case 1: /* c.srai */
                                imm = get_field1(insn, 12, 5, 5) | get_field1(insn, 2, 0, 4);
                                if (funct3 == 0)
                                    m_reg[rd] = (intx_t)((uintx_t)m_reg[rd] >> imm);
                                else
                                    m_reg[rd] = (intx_t)m_reg[rd] >> imm;

                                break;
                            case 2: /* c.andi */
                                imm = sext(get_field1(insn, 12, 5, 5) | get_field1(insn, 2, 0, 4), 6);
                                m_reg[rd] &= imm;
                                break;
                            case 3:
                                rs2    = ((insn >> 2) & 7) | 8;
                                funct3 = ((insn >> 5) & 3) | ((insn >> (12 - 2)) & 4);
                                switch (funct3) {
                                    case 0: /* c.sub */
                                        m_reg[rd] = (intx_t)(m_reg[rd] - m_reg[rs2]);
                                        break;
                                    case 1: /* c.xor */
                                        m_reg[rd] = m_reg[rd] ^ m_reg[rs2];
                                        break;
                                    case 2: /* c.or */
                                        m_reg[rd] = m_reg[rd] | m_reg[rs2];
                                        break;
                                    case 3: /* c.and */
                                        m_reg[rd] = m_reg[rd] & m_reg[rs2];
                                        break;
                                    case 4: /* c.subw */
                                        m_reg[rd] = (int32_t)(m_reg[rd] - m_reg[rs2]);
                                        break;
                                    case 5: /* c.addw */
                                        m_reg[rd] = (int32_t)(m_reg[rd] + m_reg[rs2]);
                                        break;
                                    default:
                                        goto illegal_insn;
                                }
                                break;
                        }
                        break;
                    case 5: /* c.j */
                        imm =
                            sext(get_field1(insn, 12, 11, 11) | get_field1(insn, 11, 4, 4) | get_field1(insn, 9, 8, 9) |
                                     get_field1(insn, 8, 10, 10) | get_field1(insn, 7, 6, 6) |
                                     get_field1(insn, 6, 7, 7) | get_field1(insn, 3, 1, 3) | get_field1(insn, 2, 5, 5),
                                 12);
                        m_pc = (intx_t)(GET_PC() + imm);
                        do {
                            code_ptr          = NULL;
                            code_end          = NULL;
                            code_to_pc_addend = m_pc;
                            goto jump_insn;
                        } while (0);
                    case 6: /* c.beqz */
                        rs1 = ((insn >> 7) & 7) | 8;
                        imm = sext(get_field1(insn, 12, 8, 8) | get_field1(insn, 10, 3, 4) | get_field1(insn, 5, 6, 7) |
                                       get_field1(insn, 3, 1, 2) | get_field1(insn, 2, 5, 5),
                                   9);
                        if (m_reg[rs1] == 0) {
                            m_pc = (intx_t)(GET_PC() + imm);
                            do {
                                code_ptr          = NULL;
                                code_end          = NULL;
                                code_to_pc_addend = m_pc;
                                goto jump_insn;
                            } while (0);
                        }
                        break;
                    case 7: /* c.bnez */
                        rs1 = ((insn >> 7) & 7) | 8;
                        imm = sext(get_field1(insn, 12, 8, 8) | get_field1(insn, 10, 3, 4) | get_field1(insn, 5, 6, 7) |
                                       get_field1(insn, 3, 1, 2) | get_field1(insn, 2, 5, 5),
                                   9);
                        if (m_reg[rs1] != 0) {
                            m_pc = (intx_t)(GET_PC() + imm);
                            do {
                                code_ptr          = NULL;
                                code_end          = NULL;
                                code_to_pc_addend = m_pc;
                                goto jump_insn;
                            } while (0);
                        }
                        break;
                    default:
                        goto illegal_insn;
                }
                code_ptr += 2;
                break;
            case 2 + (0 << 2):
            case 2 + (1 << 2):
            case 2 + (2 << 2):
            case 2 + (3 << 2):
            case 2 + (4 << 2):
            case 2 + (5 << 2):
            case 2 + (6 << 2):
            case 2 + (7 << 2):
            case 2 + (8 << 2):
            case 2 + (9 << 2):
            case 2 + (10 << 2):
            case 2 + (11 << 2):
            case 2 + (12 << 2):
            case 2 + (13 << 2):
            case 2 + (14 << 2):
            case 2 + (15 << 2):
            case 2 + (16 << 2):
            case 2 + (17 << 2):
            case 2 + (18 << 2):
            case 2 + (19 << 2):
            case 2 + (20 << 2):
            case 2 + (21 << 2):
            case 2 + (22 << 2):
            case 2 + (23 << 2):
            case 2 + (24 << 2):
            case 2 + (25 << 2):
            case 2 + (26 << 2):
            case 2 + (27 << 2):
            case 2 + (28 << 2):
            case 2 + (29 << 2):
            case 2 + (30 << 2):
            case 2 + (31 << 2):
                funct3 = (insn >> 13) & 7;
                rs2    = (insn >> 2) & 0x1f;
                switch (funct3) {
                    case 0: /* c.slli */
                        imm = get_field1(insn, 12, 5, 5) | rs2;
                        if (rd != 0)
                            m_reg[rd] = (intx_t)(m_reg[rd] << imm);
                        break;

                    case 1: /* c.fldsp */
                    {
                        uint64_t rval;
                        if (m_fs == 0)
                            goto illegal_insn;
                        imm  = get_field1(insn, 12, 5, 5) | (rs2 & (3 << 3)) | get_field1(insn, 2, 6, 8);
                        addr = (intx_t)(m_reg[2] + imm);
                        if (target_read_u64(&rval, addr))
                            goto mmu_exception;
                        m_fp_reg[rd] = rval | F64_HIGH;
                        m_fs         = 3;
                    } break;
                    case 2: /* c.lwsp */
                    {
                        uint32_t rval;
                        imm  = get_field1(insn, 12, 5, 5) | (rs2 & (7 << 2)) | get_field1(insn, 2, 6, 7);
                        addr = (intx_t)(m_reg[2] + imm);
                        if (target_read_u32(&rval, addr))
                            goto mmu_exception;
                        if (rd != 0)
                            m_reg[rd] = (int32_t)rval;
                    } break;
                    case 3: /* c.ldsp */
                    {
                        uint64_t rval;
                        imm  = get_field1(insn, 12, 5, 5) | (rs2 & (3 << 3)) | get_field1(insn, 2, 6, 8);
                        addr = (intx_t)(m_reg[2] + imm);
                        if (target_read_u64(&rval, addr))
                            goto mmu_exception;
                        if (rd != 0)
                            m_reg[rd] = (int64_t)rval;
                    } break;
                    case 4:
                        if (((insn >> 12) & 1) == 0) {
                            if (rs2 == 0) {
                                /* c.jr */
                                if (rd == 0)
                                    goto illegal_insn;
                                m_pc = m_reg[rd] & ~1;
                                do {
                                    code_ptr          = NULL;
                                    code_end          = NULL;
                                    code_to_pc_addend = m_pc;
                                    goto jump_insn;
                                } while (0);
                            } else {
                                /* c.mv */
                                if (rd != 0)
                                    m_reg[rd] = m_reg[rs2];
                            }
                        } else {
                            if (rs2 == 0) {
                                if (rd == 0) {
                                    /* c.ebreak */
                                    m_pending_exception = CAUSE_BREAKPOINT;
                                    goto exception;
                                } else {
                                    /* c.jalr */
                                    val      = GET_PC() + 2;
                                    m_pc     = m_reg[rd] & ~1;
                                    m_reg[1] = val;
                                    do {
                                        code_ptr          = NULL;
                                        code_end          = NULL;
                                        code_to_pc_addend = m_pc;
                                        goto jump_insn;
                                    } while (0);
                                }
                            } else {
                                if (rd != 0) {
                                    m_reg[rd] = (intx_t)(m_reg[rd] + m_reg[rs2]);
                                }
                            }
                        }
                        break;

                    case 5: /* c.fsdsp */
                        if (m_fs == 0)
                            goto illegal_insn;
                        imm  = get_field1(insn, 10, 3, 5) | get_field1(insn, 7, 6, 8);
                        addr = (intx_t)(m_reg[2] + imm);
                        if (target_write_u64(addr, m_fp_reg[rs2]))
                            goto mmu_exception;
                        break;
                    case 6: /* c.swsp */
                        imm  = get_field1(insn, 9, 2, 5) | get_field1(insn, 7, 6, 7);
                        addr = (intx_t)(m_reg[2] + imm);
                        if (target_write_u32(addr, m_reg[rs2]))
                            goto mmu_exception;
                        break;
                    case 7: /* c.sdsp */
                        imm  = get_field1(insn, 10, 3, 5) | get_field1(insn, 7, 6, 8);
                        addr = (intx_t)(m_reg[2] + imm);
                        if (target_write_u64(addr, m_reg[rs2]))
                            goto mmu_exception;
                        break;
                    default:
                        goto illegal_insn;
                }
                code_ptr += 2;
                break;

            case 0x37: /* lui */
                if (rd != 0)
                    m_reg[rd] = (int32_t)(insn & 0xfffff000);
                code_ptr += 4;
                break;
            case 0x17: /* auipc */
                if (rd != 0)
                    m_reg[rd] = (intx_t)(GET_PC() + (int32_t)(insn & 0xfffff000));
                code_ptr += 4;
                break;
            case 0x6f: /* jal */
                imm = ((insn >> (31 - 20)) & (1 << 20)) | ((insn >> (21 - 1)) & 0x7fe) |
                      ((insn >> (20 - 11)) & (1 << 11)) | (insn & 0xff000);
                imm = (imm << 11) >> 11;
                if (rd != 0)
                    m_reg[rd] = GET_PC() + 4;
                m_pc = (intx_t)(GET_PC() + imm);
                do {
                    code_ptr          = NULL;
                    code_end          = NULL;
                    code_to_pc_addend = m_pc;
                    goto jump_insn;
                } while (0);
            case 0x67: /* jalr */
                imm  = (int32_t)insn >> 20;
                val  = GET_PC() + 4;
                m_pc = (intx_t)(m_reg[rs1] + imm) & ~1;
                if (rd != 0)
                    m_reg[rd] = val;
                do {
                    code_ptr          = NULL;
                    code_end          = NULL;
                    code_to_pc_addend = m_pc;
                    goto jump_insn;
                } while (0);
            case 0x63:
                funct3 = (insn >> 12) & 7;
                switch (funct3 >> 1) {
                    case 0: /* beq/bne */
                        cond = (m_reg[rs1] == m_reg[rs2]);
                        break;
                    case 2: /* blt/bge */
                        cond = ((int64_t)m_reg[rs1] < (int64_t)m_reg[rs2]);
                        break;
                    case 3: /* bltu/bgeu */
                        cond = (m_reg[rs1] < m_reg[rs2]);
                        break;
                    default:
                        goto illegal_insn;
                }
                cond ^= (funct3 & 1);
                if (cond) {
                    imm = ((insn >> (31 - 12)) & (1 << 12)) | ((insn >> (25 - 5)) & 0x7e0) |
                          ((insn >> (8 - 1)) & 0x1e) | ((insn << (11 - 7)) & (1 << 11));
                    imm  = (imm << 19) >> 19;
                    m_pc = (intx_t)(GET_PC() + imm);
                    do {
                        code_ptr          = NULL;
                        code_end          = NULL;
                        code_to_pc_addend = m_pc;
                        goto jump_insn;
                    } while (0);
                }
                code_ptr += 4;
                break;
            case 0x03: /* load */
                funct3 = (insn >> 12) & 7;
                imm    = (int32_t)insn >> 20;
                addr   = m_reg[rs1] + imm;
                switch (funct3) {
                    case 0: /* lb */
                    {
                        uint8_t rval;
                        if (target_read_u8(&rval, addr))
                            goto mmu_exception;
                        val = (int8_t)rval;
                    } break;
                    case 1: /* lh */
                    {
                        uint16_t rval;
                        if (target_read_u16(&rval, addr))
                            goto mmu_exception;
                        val = (int16_t)rval;
                    } break;
                    case 2: /* lw */
                    {
                        uint32_t rval;
                        if (target_read_u32(&rval, addr))
                            goto mmu_exception;
                        val = (int32_t)rval;
                    } break;
                    case 4: /* lbu */
                    {
                        uint8_t rval;
                        if (target_read_u8(&rval, addr))
                            goto mmu_exception;
                        val = rval;
                    } break;
                    case 5: /* lhu */
                    {
                        uint16_t rval;
                        if (target_read_u16(&rval, addr))
                            goto mmu_exception;
                        val = rval;
                    } break;
                    case 3: /* ld */
                    {
                        uint64_t rval;
                        if (target_read_u64(&rval, addr))
                            goto mmu_exception;
                        val = (int64_t)rval;
                    } break;
                    case 6: /* lwu */
                    {
                        uint32_t rval;
                        if (target_read_u32(&rval, addr))
                            goto mmu_exception;
                        val = rval;
                    } break;
                    default:
                        goto illegal_insn;
                }
                if (rd != 0)
                    m_reg[rd] = val;
                code_ptr += 4;
                break;
            case 0x23: /* store */
                funct3 = (insn >> 12) & 7;
                imm    = rd | ((insn >> (25 - 5)) & 0xfe0);
                imm    = (imm << 20) >> 20;
                addr   = m_reg[rs1] + imm;
                val    = m_reg[rs2];
                switch (funct3) {
                    case 0: /* sb */
                        if (target_write_u8(addr, val))
                            goto mmu_exception;
                        break;
                    case 1: /* sh */
                        if (target_write_u16(addr, val))
                            goto mmu_exception;
                        break;
                    case 2: /* sw */
                        if (target_write_u32(addr, val))
                            goto mmu_exception;
                        break;
                    case 3: /* sd */
                        if (target_write_u64(addr, val))
                            goto mmu_exception;
                        break;
                    default:
                        goto illegal_insn;
                }
                code_ptr += 4;
                break;
            case 0x13:
                funct3 = (insn >> 12) & 7;
                imm    = (int32_t)insn >> 20;
                switch (funct3) {
                    case 0: /* addi */
                        val = (intx_t)(m_reg[rs1] + imm);
                        break;
                    case 1: /* slli */
                        if ((imm & ~(XLEN - 1)) != 0)
                            goto illegal_insn;
                        val = (intx_t)(m_reg[rs1] << (imm & (XLEN - 1)));
                        break;
                    case 2: /* slti */
                        val = (int64_t)m_reg[rs1] < (int64_t)imm;
                        break;
                    case 3: /* sltiu */
                        val = m_reg[rs1] < (uint64_t)imm;
                        break;
                    case 4: /* xori */
                        val = m_reg[rs1] ^ imm;
                        break;
                    case 5: /* srli/srai */
                        if ((imm & ~((XLEN - 1) | 0x400)) != 0)
                            goto illegal_insn;
                        if (imm & 0x400)
                            val = (intx_t)m_reg[rs1] >> (imm & (XLEN - 1));
                        else
                            val = (intx_t)((uintx_t)m_reg[rs1] >> (imm & (XLEN - 1)));
                        break;
                    case 6: /* ori */
                        val = m_reg[rs1] | imm;
                        break;
                    default:
                    case 7: /* andi */
                        val = m_reg[rs1] & imm;
                        break;
                }
                if (rd != 0)
                    m_reg[rd] = val;
                code_ptr += 4;
                break;
            case 0x1b: /* OP-IMM-32 */
                funct3 = (insn >> 12) & 7;
                imm    = (int32_t)insn >> 20;
                val    = m_reg[rs1];
                switch (funct3) {
                    case 0: /* addiw */
                        val = (int32_t)(val + imm);
                        break;
                    case 1: /* slliw */
                        if ((imm & ~31) != 0)
                            goto illegal_insn;
                        val = (int32_t)(val << (imm & 31));
                        break;
                    case 5: /* srliw/sraiw */
                        if ((imm & ~(31 | 0x400)) != 0)
                            goto illegal_insn;
                        if (imm & 0x400)
                            val = (int32_t)val >> (imm & 31);
                        else
                            val = (int32_t)((uint32_t)val >> (imm & 31));
                        break;
                    default:
                        goto illegal_insn;
                }
                if (rd != 0)
                    m_reg[rd] = val;
                code_ptr += 4;
                break;
            case 0x33:
                imm  = insn >> 25;
                val  = m_reg[rs1];
                val2 = m_reg[rs2];
                if (imm == 1) {
                    funct3 = (insn >> 12) & 7;
                    switch (funct3) {
                        case 0: /* mul */
                            val = (intx_t)((intx_t)val * (intx_t)val2);
                            break;
                        case 1: /* mulh */
                            val = (intx_t)mulh64(val, val2);
                            break;
                        case 2: /* mulhsu */
                            val = (intx_t)mulhsu64(val, val2);
                            break;
                        case 3: /* mulhu */
                            val = (intx_t)mulhu64(val, val2);
                            break;
                        case 4: /* div */
                            val = div64(val, val2);
                            break;
                        case 5: /* divu */
                            val = (intx_t)divu64(val, val2);
                            break;
                        case 6: /* rem */
                            val = rem64(val, val2);
                            break;
                        case 7: /* remu */
                            val = (intx_t)remu64(val, val2);
                            break;
                        default:
                            goto illegal_insn;
                    }
                } else {
                    if (imm & ~0x20)
                        goto illegal_insn;
                    funct3 = ((insn >> 12) & 7) | ((insn >> (30 - 3)) & (1 << 3));
                    switch (funct3) {
                        case 0: /* add */
                            val = (intx_t)(val + val2);
                            break;
                        case 0 | 8: /* sub */
                            val = (intx_t)(val - val2);
                            break;
                        case 1: /* sll */
                            val = (intx_t)(val << (val2 & (XLEN - 1)));
                            break;
                        case 2: /* slt */
                            val = (int64_t)val < (int64_t)val2;
                            break;
                        case 3: /* sltu */
                            val = val < val2;
                            break;
                        case 4: /* xor */
                            val = val ^ val2;
                            break;
                        case 5: /* srl */
                            val = (intx_t)((uintx_t)val >> (val2 & (XLEN - 1)));
                            break;
                        case 5 | 8: /* sra */
                            val = (intx_t)val >> (val2 & (XLEN - 1));
                            break;
                        case 6: /* or */
                            val = val | val2;
                            break;
                        case 7: /* and */
                            val = val & val2;
                            break;
                        default:
                            goto illegal_insn;
                    }
                }
                if (rd != 0)
                    m_reg[rd] = val;
                code_ptr += 4;
                break;
            case 0x3b: /* OP-32 */
                imm  = insn >> 25;
                val  = m_reg[rs1];
                val2 = m_reg[rs2];
                if (imm == 1) {
                    funct3 = (insn >> 12) & 7;
                    switch (funct3) {
                        case 0: /* mulw */
                            val = (int32_t)((int32_t)val * (int32_t)val2);
                            break;
                        case 4: /* divw */
                            val = div64(val, val2);
                            break;
                        case 5: /* divuw */
                            val = (intx_t)divu64(val, val2);
                            break;
                        case 6: /* remw */
                            val = rem64(val, val2);
                            break;
                        case 7: /* remuw */
                            val = (intx_t)remu64(val, val2);
                            break;
                        default:
                            goto illegal_insn;
                    }
                } else {
                    if (imm & ~0x20)
                        goto illegal_insn;
                    funct3 = ((insn >> 12) & 7) | ((insn >> (30 - 3)) & (1 << 3));
                    switch (funct3) {
                        case 0: /* addw */
                            val = (int32_t)(val + val2);
                            break;
                        case 0 | 8: /* subw */
                            val = (int32_t)(val - val2);
                            break;
                        case 1: /* sllw */
                            val = (int32_t)((uint32_t)val << (val2 & 31));
                            break;
                        case 5: /* srlw */
                            val = (int32_t)((uint32_t)val >> (val2 & 31));
                            break;
                        case 5 | 8: /* sraw */
                            val = (int32_t)val >> (val2 & 31);
                            break;
                        default:
                            goto illegal_insn;
                    }
                }
                if (rd != 0)
                    m_reg[rd] = val;
                code_ptr += 4;
                break;
            case 0x73:
                funct3 = (insn >> 12) & 7;
                imm    = insn >> 20;
                if (funct3 & 4)
                    val = rs1;
                else
                    val = m_reg[rs1];
                funct3 &= 3;
                switch (funct3) {
                    case 1: /* csrrw */
                        m_insn_counter = GET_INSN_COUNTER();
                        if (csr_read(&val2, imm, TRUE))
                            goto illegal_insn;
                        val2 = (intx_t)val2;
                        err  = csr_write(imm, val);
                        if (err < 0)
                            goto illegal_insn;
                        if (rd != 0)
                            m_reg[rd] = val2;
                        if (err > 0) {
                            m_pc = GET_PC() + 4;
                            if (err == 2)
                                do {
                                    code_ptr          = NULL;
                                    code_end          = NULL;
                                    code_to_pc_addend = m_pc;
                                    goto jump_insn;
                                } while (0);
                            else
                                goto done_interp;
                        }
                        break;
                    case 2: /* csrrs */
                    case 3: /* csrrc */
                        m_insn_counter = GET_INSN_COUNTER();
                        if (csr_read(&val2, imm, (rs1 != 0)))
                            goto illegal_insn;
                        val2 = (intx_t)val2;
                        if (rs1 != 0) {
                            if (funct3 == 2)
                                val = val2 | val;
                            else
                                val = val2 & ~val;
                            err = csr_write(imm, val);
                            if (err < 0)
                                goto illegal_insn;
                        } else {
                            err = 0;
                        }
                        if (rd != 0)
                            m_reg[rd] = val2;
                        if (err > 0) {
                            m_pc = GET_PC() + 4;
                            if (err == 2)
                                do {
                                    code_ptr          = NULL;
                                    code_end          = NULL;
                                    code_to_pc_addend = m_pc;
                                    goto jump_insn;
                                } while (0);
                            else
                                goto done_interp;
                        }
                        break;
                    case 0:
                        switch (imm) {
                            case 0x000: /* ecall */
                                if (insn & 0x000fff80)
                                    goto illegal_insn;
                                m_pending_exception = CAUSE_USER_ECALL + m_priv;
                                goto exception;
                            case 0x001: /* ebreak */
                                if (insn & 0x000fff80)
                                    goto illegal_insn;
                                m_pending_exception = CAUSE_BREAKPOINT;
                                goto exception;
                            case 0x102: /* sret */
                            {
                                if (insn & 0x000fff80)
                                    goto illegal_insn;
                                if (m_priv < PRV_S)
                                    goto illegal_insn;
                                m_pc = GET_PC();
                                handle_sret();
                                goto done_interp;
                            } break;
                            case 0x302: /* mret */
                            {
                                if (insn & 0x000fff80)
                                    goto illegal_insn;
                                if (m_priv < PRV_M)
                                    goto illegal_insn;
                                m_pc = GET_PC();
                                handle_mret();
                                goto done_interp;
                            } break;
                            case 0x105: /* wfi */
                                if (insn & 0x00007f80)
                                    goto illegal_insn;
                                if (m_priv == PRV_U)
                                    goto illegal_insn;

                                if ((m_mip & m_mie) == 0) {
                                    m_power_down_flag = TRUE;
                                    m_pc              = GET_PC() + 4;
                                    goto done_interp;
                                }
                                break;
                            default:
                                if ((imm >> 5) == 0x09) {
                                    /* sfence.vma */
                                    if (insn & 0x00007f80)
                                        goto illegal_insn;
                                    if (m_priv == PRV_U)
                                        goto illegal_insn;
                                    if (rs1 == 0) {
                                        tlb_flush_all();
                                    } else {
                                        tlb_flush_vaddr(m_reg[rs1]);
                                    }
                                    /* the current code TLB may have been flushed */
                                    m_pc = GET_PC() + 4;
                                    do {
                                        code_ptr          = NULL;
                                        code_end          = NULL;
                                        code_to_pc_addend = m_pc;
                                        goto jump_insn;
                                    } while (0);
                                } else {
                                    goto illegal_insn;
                                }
                                break;
                        }
                        break;
                    default:
                        goto illegal_insn;
                }
                code_ptr += 4;
                break;
            case 0x0f: /* misc-mem */
                funct3 = (insn >> 12) & 7;
                switch (funct3) {
                    case 0: /* fence */
                        if (insn & 0xf00fff80)
                            goto illegal_insn;
                        break;
                    case 1: /* fence.i */
                        if (insn != 0x0000100f)
                            goto illegal_insn;
                        break;
                    default:
                        goto illegal_insn;
                }
                code_ptr += 4;
                break;
            case 0x2f:
                funct3 = (insn >> 12) & 7;
                switch (funct3) {
                    case 2: {
                        uint32_t rval = 0;
                        addr          = m_reg[rs1];
                        funct3        = insn >> 27;
                        switch (funct3) {
                            case 2: /* lr.w */
                                if (rs2 != 0)
                                    goto illegal_insn;
                                if (target_read_u32(&rval, addr))
                                    goto mmu_exception;
                                val        = (int32_t)rval;
                                m_load_res = addr;
                                break;
                            case 3: /* sc.w */
                                if (m_load_res == addr) {
                                    if (target_write_u32(addr, m_reg[rs2]))
                                        goto mmu_exception;
                                    val = 0;
                                } else {
                                    val = 1;
                                }
                                break;
                            case 1:    /* amiswap.w */
                            case 0:    /* amoadd.w */
                            case 4:    /* amoxor.w */
                            case 0xc:  /* amoand.w */
                            case 0x8:  /* amoor.w */
                            case 0x10: /* amomin.w */
                            case 0x14: /* amomax.w */
                            case 0x18: /* amominu.w */
                            case 0x1c: /* amomaxu.w */
                                if (target_read_u32(&rval, addr))
                                    goto mmu_exception;
                                val  = (int32_t)rval;
                                val2 = m_reg[rs2];
                                switch (funct3) {
                                    case 1: /* amiswap.w */
                                        break;
                                    case 0: /* amoadd.w */
                                        val2 = (int32_t)(val + val2);
                                        break;
                                    case 4: /* amoxor.w */
                                        val2 = (int32_t)(val ^ val2);
                                        break;
                                    case 0xc: /* amoand.w */
                                        val2 = (int32_t)(val & val2);
                                        break;
                                    case 0x8: /* amoor.w */
                                        val2 = (int32_t)(val | val2);
                                        break;
                                    case 0x10: /* amomin.w */
                                        if ((int32_t)val < (int32_t)val2)
                                            val2 = (int32_t)val;
                                        break;
                                    case 0x14: /* amomax.w */
                                        if ((int32_t)val > (int32_t)val2)
                                            val2 = (int32_t)val;
                                        break;
                                    case 0x18: /* amominu.w */
                                        if ((uint32_t)val < (uint32_t)val2)
                                            val2 = (int32_t)val;
                                        break;
                                    case 0x1c: /* amomaxu.w */
                                        if ((uint32_t)val > (uint32_t)val2)
                                            val2 = (int32_t)val;
                                        break;
                                    default:
                                        goto illegal_insn;
                                }
                                if (target_write_u32(addr, val2))
                                    goto mmu_exception;
                                break;
                            default:
                                goto illegal_insn;
                        }
                    } break;

                    case 3: {
                        uint64_t rval = 0;
                        addr          = m_reg[rs1];
                        funct3        = insn >> 27;
                        switch (funct3) {
                            case 2: /* lr.w */
                                if (rs2 != 0)
                                    goto illegal_insn;
                                if (target_read_u64(&rval, addr))
                                    goto mmu_exception;
                                val        = (int64_t)rval;
                                m_load_res = addr;
                                break;
                            case 3: /* sc.w */
                                if (m_load_res == addr) {
                                    if (target_write_u64(addr, m_reg[rs2]))
                                        goto mmu_exception;
                                    val = 0;
                                } else {
                                    val = 1;
                                }
                                break;
                            case 1:    /* amiswap.w */
                            case 0:    /* amoadd.w */
                            case 4:    /* amoxor.w */
                            case 0xc:  /* amoand.w */
                            case 0x8:  /* amoor.w */
                            case 0x10: /* amomin.w */
                            case 0x14: /* amomax.w */
                            case 0x18: /* amominu.w */
                            case 0x1c: /* amomaxu.w */
                                if (target_read_u64(&rval, addr))
                                    goto mmu_exception;
                                val  = (int64_t)rval;
                                val2 = m_reg[rs2];
                                switch (funct3) {
                                    case 1: /* amiswap.w */
                                        break;
                                    case 0: /* amoadd.w */
                                        val2 = (int64_t)(val + val2);
                                        break;
                                    case 4: /* amoxor.w */
                                        val2 = (int64_t)(val ^ val2);
                                        break;
                                    case 0xc: /* amoand.w */
                                        val2 = (int64_t)(val & val2);
                                        break;
                                    case 0x8: /* amoor.w */
                                        val2 = (int64_t)(val | val2);
                                        break;
                                    case 0x10: /* amomin.w */
                                        if ((int64_t)val < (int64_t)val2)
                                            val2 = (int64_t)val;
                                        break;
                                    case 0x14: /* amomax.w */
                                        if ((int64_t)val > (int64_t)val2)
                                            val2 = (int64_t)val;
                                        break;
                                    case 0x18: /* amominu.w */
                                        if ((uint64_t)val < (uint64_t)val2)
                                            val2 = (int64_t)val;
                                        break;
                                    case 0x1c: /* amomaxu.w */
                                        if ((uint64_t)val > (uint64_t)val2)
                                            val2 = (int64_t)val;
                                        break;
                                    default:
                                        goto illegal_insn;
                                }
                                if (target_write_u64(addr, val2))
                                    goto mmu_exception;
                                break;
                            default:
                                goto illegal_insn;
                        }
                    } break;
                    default:
                        goto illegal_insn;
                }
                if (rd != 0)
                    m_reg[rd] = val;
                code_ptr += 4;
                break;
                /* FPU */
            case 0x07: /* fp load */
                if (m_fs == 0)
                    goto illegal_insn;
                funct3 = (insn >> 12) & 7;
                imm    = (int32_t)insn >> 20;
                addr   = m_reg[rs1] + imm;
                switch (funct3) {
                    case 2: /* flw */
                    {
                        uint32_t rval;
                        if (target_read_u32(&rval, addr))
                            goto mmu_exception;
                        m_fp_reg[rd] = rval | F32_HIGH;
                    } break;
                    case 3: /* fld */
                    {
                        uint64_t rval;
                        if (target_read_u64(&rval, addr))
                            goto mmu_exception;
                        m_fp_reg[rd] = rval | F64_HIGH;
                    } break;
                    default:
                        goto illegal_insn;
                }
                m_fs = 3;
                code_ptr += 4;
                break;
            case 0x27: /* fp store */
                if (m_fs == 0)
                    goto illegal_insn;
                funct3 = (insn >> 12) & 7;
                imm    = rd | ((insn >> (25 - 5)) & 0xfe0);
                imm    = (imm << 20) >> 20;
                addr   = m_reg[rs1] + imm;
                switch (funct3) {
                    case 2: /* fsw */
                        if (target_write_u32(addr, m_fp_reg[rs2]))
                            goto mmu_exception;
                        break;
                    case 3: /* fsd */
                        if (target_write_u64(addr, m_fp_reg[rs2]))
                            goto mmu_exception;
                        break;
                    default:
                        goto illegal_insn;
                }
                code_ptr += 4;
                break;
            case 0x43: /* fmadd */
            case 0x47: /* fmsub */
            case 0x4b: /* fnmsub */
            case 0x4f: /* fnmadd */
            case 0x53:
                if (m_fs == 0)
                    goto illegal_insn;
                imm = insn >> 25;
                rm  = (insn >> 12) & 7;
                switch (imm) {
                    case (0x00 << 2):
                    case (0x01 << 2):
                    case (0x02 << 2):
                    case (0x03 << 2):
                    case (0x0b << 2):
                    case (0x04 << 2):
                    case (0x05 << 2):
                    case (0x18 << 2):
                    case (0x14 << 2):
                    case (0x1a << 2):
                    case (0x08 << 2):
                    case (0x1c << 2):
                    case (0x1e << 2): /* fmv.s.x */
                    case (0x00 << 2) | 1:
                    case (0x01 << 2) | 1:
                    case (0x02 << 2) | 1:
                    case (0x03 << 2) | 1:
                    case (0x0b << 2) | 1:
                    case (0x04 << 2) | 1:
                    case (0x05 << 2) | 1:
                    case (0x18 << 2) | 1:
                    case (0x14 << 2) | 1:
                    case (0x1a << 2) | 1:
                    case (0x08 << 2) | 1:
                    case (0x1c << 2) | 1:
                    case (0x1e << 2) | 1: /* fmv.s.x */
                        // todo
                        break;
                    default:
                        goto illegal_insn;
                }
                code_ptr += 4;
                break;
            default:
                goto illegal_insn;
        }
    jump_insn:;
    }

illegal_insn:
    m_pending_exception = CAUSE_ILLEGAL_INSTRUCTION;
    m_pending_tval      = insn;
mmu_exception:
exception:
    m_pc = GET_PC();
    if (m_pending_exception >= 0) {
        m_n_cycles--;
        raise_exception(m_pending_exception, m_pending_tval);
    }
done_interp:
the_end:
    m_insn_counter = GET_INSN_COUNTER();
}
