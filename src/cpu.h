#ifndef RCPU_H
#define RCPU_H
#include "iomem.h"
#include "def/cpu_def.h"

class CPU {
  public:
    uint64_t m_pc;
    uint64_t m_reg[32];
    uint64_t m_fp_reg[32];

    uint32_t m_fflags = 0;
    uint8_t  m_frm    = 0;

    uint8_t m_cur_xlen = 0; /* current XLEN value, <= MAX_XLEN */
    uint8_t m_priv     = 0; /* see PRV_x */
    uint8_t m_fs       = 0; /* MSTATUS_FS value */
    uint8_t m_mxl      = 0; /* MXL field in MISA register */

    uint64_t m_n_cycles          = 0; /* only used inside the CPU loop */
    uint64_t m_insn_counter      = 0;
    BOOL     m_power_down_flag   = FALSE;
    int      m_pending_exception = 0; /* used during MMU exception handling */
    uint64_t m_pending_tval      = 0;

    uint64_t m_mstatus    = 0;
    uint64_t m_mtvec      = 0;
    uint64_t m_mscratch   = 0;
    uint64_t m_mepc       = 0;
    uint64_t m_mcause     = 0;
    uint64_t m_mtval      = 0;
    uint64_t m_mhartid    = 0; /* ro */
    uint32_t m_misa       = 0;
    uint32_t m_mie        = 0;
    uint32_t m_mip        = 0;
    uint32_t m_medeleg    = 0;
    uint32_t m_mideleg    = 0;
    uint32_t m_mcounteren = 0;

    uint64_t m_stvec    = 0;
    uint64_t m_sscratch = 0;
    uint64_t m_sepc     = 0;
    uint64_t m_scause   = 0;
    uint64_t m_stval    = 0;

    uint64_t m_satp       = 0; /* currently 64 bit physical addresses max */
    uint32_t m_scounteren = 0;

    uint64_t m_load_res = 0; /* for atomic LR/SC */

    PhysMemMap *m_mem_map;
    TLBEntry    m_tlb_read[TLB_SIZE];
    TLBEntry    m_tlb_write[TLB_SIZE];
    TLBEntry    m_tlb_code[TLB_SIZE];

    uint64_t counts = 0;

  public:
    CPU(PhysMemMap *_m_mem_map)
    {
        m_mem_map = _m_mem_map;
        for (int i = 0; i < 31; i++) {
            m_reg[i]    = 0;
            m_fp_reg[i] = 0;
        }
    }


    int target_read_u8(uint8_t *pval, uint64_t addr);
    int target_read_u16(uint16_t *pval, uint64_t addr);
    int target_read_u32(uint32_t *pval, uint64_t addr);
    int target_read_u64(uint64_t *pval, uint64_t addr);

    int target_write_u8(uint64_t addr, uint8_t val);
    int target_write_u16(uint64_t addr, uint16_t val);
    int target_write_u32(uint64_t addr, uint32_t val);
    int target_write_u64(uint64_t addr, uint64_t val);

    void     phys_write_u32(uint64_t addr, uint32_t val);
    uint32_t phys_read_u32(uint64_t addr);
    void     phys_write_u64(uint64_t addr, uint64_t val);
    uint64_t phys_read_u64(uint64_t addr);

    int      get_phys_addr(uint64_t *ppaddr, uint64_t vaddr, int access);
    int      riscv64_read_slow(uint64_t *pval, uint64_t addr, int size_log2);
    int      riscv64_write_slow(uint64_t addr, uint64_t val, int size_log2);
    uint32_t get_insn32(uint8_t *ptr);
    int      target_read_insn_slow(uint8_t **pptr, uint64_t addr);
    int      target_read_insn_u16(uint16_t *pinsn, uint64_t addr);

    void tlb_init();
    void tlb_flush_all();
    void tlb_flush_vaddr(uint64_t vaddr);
    void riscv_cpu_flush_tlb_write_range_ram64(uint8_t *ram_ptr, size_t ram_size);

    uint64_t get_mstatus(uint64_t mask);
    int      get_base_from_xlen(int xlen);
    void     set_mstatus(uint64_t val);
    int      csr_read(uint64_t *pval, uint32_t csr, BOOL will_write);
    int      csr_write(uint32_t csr, uint64_t val);

    void set_frm(unsigned int val);
    int  get_insn_rm(unsigned int rm);
    void set_priv(int _priv);
    void raise_exception(uint32_t cause, uint64_t tval);
    int  raise_interrupt();

    void handle_sret();
    void handle_mret();

    uint32_t get_pending_irq_mask();
    int32_t  sext(int32_t val, int n);
    uint32_t get_field1(uint32_t val, int src_pos, int dst_pos, int dst_pos_max);

    int64_t  div64(int64_t a, int64_t b);
    uint64_t divu64(uint64_t a, uint64_t b);
    int64_t  rem64(int64_t a, int64_t b);
    uint64_t remu64(uint64_t a, uint64_t b);
    uint64_t mulhu64(uint64_t a, uint64_t b);
    uint64_t mulh64(int64_t a, int64_t b);
    uint64_t mulhsu64(int64_t a, uint64_t b);

    uint64_t riscv_cpu_get_cycles64();
    void     riscv_cpu_set_mip64(uint32_t mask);
    void     riscv_cpu_reset_mip64(uint32_t mask);
    uint32_t riscv_cpu_get_mip64();
    BOOL     riscv_cpu_get_power_down64();
    void     riscv_cpu_init64();
    void     riscv_cpu_end64();
    uint32_t riscv_cpu_get_misa64();
    void     riscv_cpu_interp64(int n_cycles1);
};

#endif /* RCPU_H */
