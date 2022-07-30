#ifndef IOMEM_H
#define IOMEM_H

#include <cstdio>
#include "utils/utils.h"

#define DEVIO_SIZE8    (1 << 0)
#define DEVIO_SIZE16   (1 << 1)
#define DEVIO_SIZE32   (1 << 2)
#define DEVIO_DISABLED (1 << 4)

#define DEVRAM_FLAG_ROM        (1 << 0)
#define DEVRAM_FLAG_DIRTY_BITS (1 << 1)
#define DEVRAM_FLAG_DISABLED   (1 << 2)
#define DEVRAM_PAGE_SIZE_LOG2  12
#define DEVRAM_PAGE_SIZE       (1 << DEVRAM_PAGE_SIZE_LOG2)
#define PHYS_MEM_RANGE_MAX     32

typedef void     SetIRQFunc(void *opaque, int irq_num, int level);
typedef void     DeviceWriteFunc(void *opaque, uint32_t offset, uint32_t val, int size_log2);
typedef uint32_t DeviceReadFunc(void *opaque, uint32_t offset, int size_log2);

class PhysMemMap;
class PhysMemRange {
  public:
    PhysMemMap *map             = nullptr;
    uint64_t    addr            = 0;
    uint64_t    org_size        = 0; /* original size */
    uint64_t    size            = 0; /* =org_size or 0 if the mapping is disabled */
    BOOL        is_ram          = FALSE;
    int         devram_flags    = 0;
    uint8_t    *phys_mem        = 0;
    int         dirty_bits_size = 0; /* in bytes */
    uint32_t   *dirty_bits      = 0; /* NULL if not used */
    uint32_t   *dirty_bits_tab[2];
    int         dirty_bits_index = 0; /* 0-1 */
    void       *opaque           = nullptr;
    int         devio_flags      = 0;

  public:
    DeviceReadFunc  *read_func;
    DeviceWriteFunc *write_func;

    void phys_mem_set_dirty_bit(size_t offset)
    {
        size_t   page_index;
        uint32_t mask, *dirty_bits_ptr;
        if (dirty_bits) {
            page_index     = offset >> DEVRAM_PAGE_SIZE_LOG2;
            mask           = 1 << (page_index & 0x1f);
            dirty_bits_ptr = dirty_bits + (page_index >> 5);
            *dirty_bits_ptr |= mask;
        }
    }
};
class PhysMemMap {


  public:
    int   n_phys_mem_range = 0;
    void *opaque           = nullptr;

    PhysMemRange phys_mem_range[PHYS_MEM_RANGE_MAX];

  public:
    void (*flush_tlb_write_range)(void *opaque, uint8_t *ram_addr, std::size_t ram_size);

    PhysMemRange *register_ram(PhysMemMap *s, uint64_t addr, uint64_t size, int devram_flags)
    {
        PhysMemRange *pr;
        pr           = register_ram_entry(s, addr, size, devram_flags);
        pr->phys_mem = (uint8_t *)mallocz(size);
        if (!pr->phys_mem) {
            fprintf(stderr, "Could not allocate VM memory\n");
            exit(1);
        }

        if (devram_flags & DEVRAM_FLAG_DIRTY_BITS) {
            std::size_t nb_pages;
            nb_pages             = size >> DEVRAM_PAGE_SIZE_LOG2;
            pr->dirty_bits_size  = ((nb_pages + 31) / 32) * sizeof(uint32_t);
            pr->dirty_bits_index = 0;
            for (int i = 0; i < 2; i++) {
                pr->dirty_bits_tab[i] = (uint32_t *)mallocz(pr->dirty_bits_size);
            }
            pr->dirty_bits = pr->dirty_bits_tab[pr->dirty_bits_index];
        }
        return pr;
    }
    PhysMemRange *register_ram_entry(PhysMemMap *s, uint64_t addr, uint64_t size, int devram_flags)
    {
        PhysMemRange *pr;
        pr               = &s->phys_mem_range[s->n_phys_mem_range++];
        pr->map          = s;
        pr->is_ram       = TRUE;
        pr->devram_flags = devram_flags & ~DEVRAM_FLAG_DISABLED;
        pr->addr         = addr;
        pr->org_size     = size;
        if (devram_flags & DEVRAM_FLAG_DISABLED)
            pr->size = 0;
        else
            pr->size = pr->org_size;
        pr->phys_mem   = NULL;
        pr->dirty_bits = NULL;
        return pr;
    }
    void free_ram(PhysMemMap *s, PhysMemRange *pr)
    {
        free(pr->phys_mem);
    }

    uint32_t *get_dirty_bits(PhysMemMap *map, PhysMemRange *pr)
    {
        uint32_t *dirty_bits;
        BOOL      has_dirty_bits;
        size_t    n, i;
        dirty_bits     = pr->dirty_bits;
        has_dirty_bits = FALSE;

        n = pr->dirty_bits_size / sizeof(uint32_t);
        for (i = 0; i < n; i++) {
            if (dirty_bits[i] != 0) {
                has_dirty_bits = TRUE;
                break;
            }
        }
        if (has_dirty_bits && pr->size != 0) {
            map->flush_tlb_write_range(map->opaque, pr->phys_mem, pr->org_size);
        }

        pr->dirty_bits_index ^= 1;
        pr->dirty_bits = pr->dirty_bits_tab[pr->dirty_bits_index];
        memset(pr->dirty_bits, 0, pr->dirty_bits_size);
        return dirty_bits;
    }

    void set_ram_addr(PhysMemMap *map, PhysMemRange *pr, uint64_t addr, BOOL enabled)
    {
        if (enabled) {
            if (pr->size == 0 || pr->addr != addr) {
                if (pr->is_ram) {
                    map->flush_tlb_write_range(map->opaque, pr->phys_mem, pr->org_size);
                }
                pr->addr = addr;
                pr->size = pr->org_size;
            }
        } else {
            if (pr->size != 0) {
                if (pr->is_ram) {
                    map->flush_tlb_write_range(map->opaque, pr->phys_mem, pr->org_size);
                }
                pr->addr = 0;
                pr->size = 0;
            }
        }
    }

    PhysMemRange *get_phys_mem_range(uint64_t paddr)
    {
        PhysMemRange *pr;
        int           i;
        for (i = 0; i < n_phys_mem_range; i++) {
            pr = &phys_mem_range[i];
            if (paddr >= pr->addr && paddr < pr->addr + pr->size)
                return pr;
        }
        return NULL;
    }

    uint8_t *phys_mem_get_ram_ptr(uint64_t paddr, BOOL is_rw)
    {
        PhysMemRange *pr = get_phys_mem_range(paddr);
        uintptr_t     offset;
        if (!pr || !pr->is_ram)
            return NULL;
        offset = paddr - pr->addr;
        if (is_rw)
            pr->phys_mem_set_dirty_bit(offset);
        return pr->phys_mem + (uintptr_t)offset;
    }

    PhysMemRange *cpu_register_device(uint64_t addr, uint64_t size, void *opaque, DeviceReadFunc *read_func,
                                      DeviceWriteFunc *write_func, int devio_flags)
    {
        PhysMemRange *pr = &phys_mem_range[n_phys_mem_range++];
        pr->map          = this;
        pr->addr         = addr;
        pr->org_size     = size;
        if (devio_flags & DEVIO_DISABLED)
            pr->size = 0;
        else
            pr->size = pr->org_size;
        pr->is_ram      = FALSE;
        pr->opaque      = opaque;
        pr->read_func   = read_func;
        pr->write_func  = write_func;
        pr->devio_flags = devio_flags;
        return pr;
    }
};
class IRQSignal {
  public:
    SetIRQFunc *set_irq;
    void       *opaque  = nullptr;
    int         irq_num = 0;

    void irq_init(SetIRQFunc *_set_irq, void *_opaque, int _irq_num)
    {
        set_irq = _set_irq;
        opaque  = _opaque;
        irq_num = _irq_num;
    }
    void set_irqval(int level)
    {
        set_irq(opaque, irq_num, level);
    }
};
#endif
