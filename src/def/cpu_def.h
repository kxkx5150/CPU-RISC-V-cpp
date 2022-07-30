
#ifndef RISCV_CPU_H
#include <cstdint>

#define FLEN                  64
#define XLEN                  64
#define MAX_XLEN              64
#define CONFIG_RISCV_MAX_XLEN 64

#define MIP_USIP (1 << 0)
#define MIP_SSIP (1 << 1)
#define MIP_HSIP (1 << 2)
#define MIP_MSIP (1 << 3)
#define MIP_UTIP (1 << 4)
#define MIP_STIP (1 << 5)
#define MIP_HTIP (1 << 6)
#define MIP_MTIP (1 << 7)
#define MIP_UEIP (1 << 8)
#define MIP_SEIP (1 << 9)
#define MIP_HEIP (1 << 10)
#define MIP_MEIP (1 << 11)

#define F32_HIGH ((uint64_t)-1 << 32)
#define F64_HIGH 0
#define MLEN     64
#define TLB_SIZE 256

#define CAUSE_MISALIGNED_FETCH    0x0
#define CAUSE_FAULT_FETCH         0x1
#define CAUSE_ILLEGAL_INSTRUCTION 0x2
#define CAUSE_BREAKPOINT          0x3
#define CAUSE_MISALIGNED_LOAD     0x4
#define CAUSE_FAULT_LOAD          0x5
#define CAUSE_MISALIGNED_STORE    0x6
#define CAUSE_FAULT_STORE         0x7
#define CAUSE_USER_ECALL          0x8
#define CAUSE_SUPERVISOR_ECALL    0x9
#define CAUSE_HYPERVISOR_ECALL    0xa
#define CAUSE_MACHINE_ECALL       0xb
#define CAUSE_FETCH_PAGE_FAULT    0xc
#define CAUSE_LOAD_PAGE_FAULT     0xd
#define CAUSE_STORE_PAGE_FAULT    0xf

#define CAUSE_INTERRUPT ((uint32_t)1 << 31)

#define PRV_U 0
#define PRV_S 1
#define PRV_H 2
#define PRV_M 3

#define MCPUID_SUPER (1 << ('S' - 'A'))
#define MCPUID_USER  (1 << ('U' - 'A'))
#define MCPUID_I     (1 << ('I' - 'A'))
#define MCPUID_M     (1 << ('M' - 'A'))
#define MCPUID_A     (1 << ('A' - 'A'))
#define MCPUID_F     (1 << ('F' - 'A'))
#define MCPUID_D     (1 << ('D' - 'A'))
#define MCPUID_Q     (1 << ('Q' - 'A'))
#define MCPUID_C     (1 << ('C' - 'A'))

#define MSTATUS_SPIE_SHIFT 5
#define MSTATUS_MPIE_SHIFT 7
#define MSTATUS_SPP_SHIFT  8
#define MSTATUS_MPP_SHIFT  11
#define MSTATUS_FS_SHIFT   13
#define MSTATUS_UXL_SHIFT  32
#define MSTATUS_SXL_SHIFT  34

#define MSTATUS_UIE      (1 << 0)
#define MSTATUS_SIE      (1 << 1)
#define MSTATUS_HIE      (1 << 2)
#define MSTATUS_MIE      (1 << 3)
#define MSTATUS_UPIE     (1 << 4)
#define MSTATUS_SPIE     (1 << MSTATUS_SPIE_SHIFT)
#define MSTATUS_HPIE     (1 << 6)
#define MSTATUS_MPIE     (1 << MSTATUS_MPIE_SHIFT)
#define MSTATUS_SPP      (1 << MSTATUS_SPP_SHIFT)
#define MSTATUS_HPP      (3 << 9)
#define MSTATUS_MPP      (3 << MSTATUS_MPP_SHIFT)
#define MSTATUS_FS       (3 << MSTATUS_FS_SHIFT)
#define MSTATUS_XS       (3 << 15)
#define MSTATUS_MPRV     (1 << 17)
#define MSTATUS_SUM      (1 << 18)
#define MSTATUS_MXR      (1 << 19)
#define MSTATUS_UXL_MASK ((uint64_t)3 << MSTATUS_UXL_SHIFT)
#define MSTATUS_SXL_MASK ((uint64_t)3 << MSTATUS_SXL_SHIFT)

#define PG_SHIFT 12
#define PG_MASK  ((1 << PG_SHIFT) - 1)

#define FLEN                  64
#define XLEN                  64
#define MAX_XLEN              64
#define F_SIZE                64
#define CONFIG_RISCV_MAX_XLEN 64

#define uintx_t   uint64_t
#define intx_t    int64_t
#define UHALF     uint32_t
#define UHALF_LEN 32

#define PTE_V_MASK (1 << 0)
#define PTE_U_MASK (1 << 4)
#define PTE_A_MASK (1 << 6)
#define PTE_D_MASK (1 << 7)

#define ACCESS_READ  0
#define ACCESS_WRITE 1
#define ACCESS_CODE  2

#define DUP2(F, n)  F(n) F(n + 1)
#define DUP4(F, n)  DUP2(F, n) DUP2(F, n + 2)
#define DUP8(F, n)  DUP4(F, n) DUP4(F, n + 4)
#define DUP16(F, n) DUP8(F, n) DUP8(F, n + 8)
#define DUP32(F, n) DUP16(F, n) DUP16(F, n + 16)

#define GET_PC()           (uint64_t)((uintptr_t)code_ptr + code_to_pc_addend)
#define GET_INSN_COUNTER() (insn_counter_addend - m_n_cycles)

#define SSTATUS_MASK0                                                                                                  \
    (MSTATUS_UIE | MSTATUS_SIE | MSTATUS_UPIE | MSTATUS_SPIE | MSTATUS_SPP | MSTATUS_FS | MSTATUS_XS | MSTATUS_SUM |   \
     MSTATUS_MXR)
#define SSTATUS_MASK (SSTATUS_MASK0 | MSTATUS_UXL_MASK)
#define MSTATUS_MASK                                                                                                   \
    (MSTATUS_UIE | MSTATUS_SIE | MSTATUS_MIE | MSTATUS_UPIE | MSTATUS_SPIE | MSTATUS_MPIE | MSTATUS_SPP |              \
     MSTATUS_MPP | MSTATUS_FS | MSTATUS_MPRV | MSTATUS_SUM | MSTATUS_MXR)

#define COUNTEREN_MASK ((1 << 0) | (1 << 2))
typedef struct
{
    uint64_t  vaddr;
    uintptr_t mem_addend;
} TLBEntry;
struct __attribute__((packed)) unaligned_u32
{
    uint32_t u32;
};
#endif