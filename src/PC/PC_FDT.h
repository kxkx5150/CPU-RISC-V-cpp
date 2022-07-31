#ifndef PCFDT_H
#define PCFDT_H
#include "PC.h"
#include "../def/PC_def.h"


static void fdt_alloc_len(FDTState *s, int len)
{
    int new_size;
    if (unlikely(len > s->tab_size)) {
        new_size    = max_int(len, s->tab_size * 3 / 2);
        s->tab      = (uint32_t *)realloc(s->tab, new_size * sizeof(uint32_t));
        s->tab_size = new_size;
    }
}
static void fdt_put32(FDTState *s, int v)
{
    fdt_alloc_len(s, s->tab_len + 1);
    s->tab[s->tab_len++] = __bswap_32(v);
}
static void fdt_put_data(FDTState *s, const uint8_t *data, int len)
{
    int len1;

    len1 = (len + 3) / 4;
    fdt_alloc_len(s, s->tab_len + len1);
    memcpy(s->tab + s->tab_len, data, len);
    memset((uint8_t *)(s->tab + s->tab_len) + len, 0, -len & 3);
    s->tab_len += len1;
}
static void fdt_begin_node(FDTState *s, const char *name)
{
    fdt_put32(s, FDT_BEGIN_NODE);
    fdt_put_data(s, (uint8_t *)name, strlen(name) + 1);
    s->open_node_count++;
}
static void fdt_begin_node_num(FDTState *s, const char *name, uint64_t n)
{
    char buf[256];
    snprintf(buf, sizeof(buf), "%s@%" PRIx64, name, n);
    fdt_begin_node(s, buf);
}
static void fdt_end_node(FDTState *s)
{
    fdt_put32(s, FDT_END_NODE);
    s->open_node_count--;
}
static int fdt_get_string_offset(FDTState *s, const char *name)
{
    int pos, new_size, name_size, new_len;

    pos = 0;
    while (pos < s->string_table_len) {
        if (!strcmp(s->string_table + pos, name))
            return pos;
        pos += strlen(s->string_table + pos) + 1;
    }
    /* add a new string */
    name_size = strlen(name) + 1;
    new_len   = s->string_table_len + name_size;
    if (new_len > s->string_table_size) {
        new_size             = max_int(new_len, s->string_table_size * 3 / 2);
        s->string_table      = (char *)realloc(s->string_table, new_size);
        s->string_table_size = new_size;
    }
    pos = s->string_table_len;
    memcpy(s->string_table + pos, name, name_size);
    s->string_table_len = new_len;
    return pos;
}
static void fdt_prop(FDTState *s, const char *prop_name, const void *data, int data_len)
{
    fdt_put32(s, FDT_PROP);
    fdt_put32(s, data_len);
    fdt_put32(s, fdt_get_string_offset(s, prop_name));
    fdt_put_data(s, (uint8_t *)data, data_len);
}
static void fdt_prop_tab_u32(FDTState *s, const char *prop_name, uint32_t *tab, int tab_len)
{
    int i;
    fdt_put32(s, FDT_PROP);
    fdt_put32(s, tab_len * sizeof(uint32_t));
    fdt_put32(s, fdt_get_string_offset(s, prop_name));
    for (i = 0; i < tab_len; i++)
        fdt_put32(s, tab[i]);
}
static void fdt_prop_u32(FDTState *s, const char *prop_name, uint32_t val)
{
    fdt_prop_tab_u32(s, prop_name, &val, 1);
}
static void fdt_prop_tab_u64(FDTState *s, const char *prop_name, uint64_t v0)
{
    uint32_t tab[2];
    tab[0] = v0 >> 32;
    tab[1] = v0;
    fdt_prop_tab_u32(s, prop_name, tab, 2);
}
static void fdt_prop_tab_u64_2(FDTState *s, const char *prop_name, uint64_t v0, uint64_t v1)
{
    uint32_t tab[4];
    tab[0] = v0 >> 32;
    tab[1] = v0;
    tab[2] = v1 >> 32;
    tab[3] = v1;
    fdt_prop_tab_u32(s, prop_name, tab, 4);
}
static void fdt_prop_str(FDTState *s, const char *prop_name, const char *str)
{
    fdt_prop(s, prop_name, str, strlen(str) + 1);
}
static void fdt_prop_tab_str(FDTState *s, const char *prop_name, ...)
{
    va_list ap;
    int     size, str_size;
    char   *ptr, *tab;

    va_start(ap, prop_name);
    size = 0;
    for (;;) {
        ptr = va_arg(ap, char *);
        if (!ptr)
            break;
        str_size = strlen(ptr) + 1;
        size += str_size;
    }
    va_end(ap);

    tab = (char *)malloc(size);
    va_start(ap, prop_name);
    size = 0;
    for (;;) {
        ptr = va_arg(ap, char *);
        if (!ptr)
            break;
        str_size = strlen(ptr) + 1;
        memcpy(tab + size, ptr, str_size);
        size += str_size;
    }
    va_end(ap);

    fdt_prop(s, prop_name, tab, size);
    free(tab);
}
inline int fdt_output(FDTState *s, uint8_t *dst)
{
    struct fdt_header        *h;
    struct fdt_reserve_entry *re;
    int                       dt_struct_size;
    int                       dt_strings_size;
    int                       pos;

    fdt_put32(s, FDT_END);

    dt_struct_size  = s->tab_len * sizeof(uint32_t);
    dt_strings_size = s->string_table_len;

    h                    = (struct fdt_header *)dst;
    h->magic             = __bswap_32(FDT_MAGIC);
    h->version           = __bswap_32(FDT_VERSION);
    h->last_comp_version = __bswap_32(16);
    h->boot_cpuid_phys   = __bswap_32(0);
    h->size_dt_strings   = __bswap_32(dt_strings_size);
    h->size_dt_struct    = __bswap_32(dt_struct_size);

    pos = sizeof(struct fdt_header);

    h->off_dt_struct = __bswap_32(pos);
    memcpy(dst + pos, s->tab, dt_struct_size);
    pos += dt_struct_size;

    while ((pos & 7) != 0) {
        dst[pos++] = 0;
    }
    h->off_mem_rsvmap = __bswap_32(pos);
    re                = (struct fdt_reserve_entry *)(dst + pos);
    re->address       = 0; /* no reserved entry */
    re->size          = 0;
    pos += sizeof(struct fdt_reserve_entry);

    h->off_dt_strings = __bswap_32(pos);
    memcpy(dst + pos, s->string_table, dt_strings_size);
    pos += dt_strings_size;

    while ((pos & 7) != 0) {
        dst[pos++] = 0;
    }

    h->totalsize = __bswap_32(pos);
    return pos;
}
inline void fdt_end(FDTState *s)
{
    free(s->tab);
    free(s->string_table);
    free(s);
}
static int build_fdt(PC *m, uint8_t *dst, uint64_t kernel_start, uint64_t kernel_size, uint64_t initrd_start,
                     uint64_t initrd_size, const char *cmd_line)
{
    FDTState *s;
    int       size, max_xlen, i, cur_phandle, intc_phandle, plic_phandle;
    char      isa_string[128], *q;
    uint32_t  misa;
    uint32_t  tab[4];
    FBDevice *fb_dev;
    s = (FDTState *)mallocz(sizeof(*s));

    cur_phandle = 1;

    fdt_begin_node(s, "");
    fdt_prop_u32(s, "#address-cells", 2);
    fdt_prop_u32(s, "#size-cells", 2);
    fdt_prop_str(s, "compatible", "ucbbar,riscvemu-bar_dev");
    fdt_prop_str(s, "model", "ucbbar,riscvemu-bare");

    /* CPU list */
    fdt_begin_node(s, "cpus");
    fdt_prop_u32(s, "#address-cells", 1);
    fdt_prop_u32(s, "#size-cells", 0);
    fdt_prop_u32(s, "timebase-frequency", RTC_FREQ);

    /* cpu */
    fdt_begin_node_num(s, "cpu", 0);
    fdt_prop_str(s, "device_type", "cpu");
    fdt_prop_u32(s, "reg", 0);
    fdt_prop_str(s, "status", "okay");
    fdt_prop_str(s, "compatible", "riscv");

    max_xlen = m->max_xlen;
    misa     = m->cpu->riscv_cpu_get_misa64();

    q = isa_string;
    q += snprintf(isa_string, sizeof(isa_string), "rv%d", max_xlen);
    for (i = 0; i < 26; i++) {
        if (misa & (1 << i))
            *q++ = 'a' + i;
    }
    *q = '\0';
    fdt_prop_str(s, "riscv,isa", isa_string);

    fdt_prop_str(s, "mmu-type", max_xlen <= 32 ? "riscv,sv32" : "riscv,sv48");
    fdt_prop_u32(s, "clock-frequency", 2000000000);

    fdt_begin_node(s, "interrupt-controller");
    fdt_prop_u32(s, "#interrupt-cells", 1);
    fdt_prop(s, "interrupt-controller", NULL, 0);
    fdt_prop_str(s, "compatible", "riscv,cpu-intc");
    intc_phandle = cur_phandle++;
    fdt_prop_u32(s, "phandle", intc_phandle);
    fdt_end_node(s); /* interrupt-controller */

    fdt_end_node(s); /* cpu */
    fdt_end_node(s); /* cpus */

    fdt_begin_node_num(s, "memory", RAM_BASE_ADDR);
    fdt_prop_str(s, "device_type", "memory");
    tab[0] = (uint64_t)RAM_BASE_ADDR >> 32;
    tab[1] = RAM_BASE_ADDR;
    tab[2] = m->ram_size >> 32;
    tab[3] = m->ram_size;
    fdt_prop_tab_u32(s, "reg", tab, 4);

    fdt_end_node(s); /* memory */

    fdt_begin_node(s, "htif");
    fdt_prop_str(s, "compatible", "ucb,htif0");
    fdt_end_node(s); /* htif */

    fdt_begin_node(s, "soc");
    fdt_prop_u32(s, "#address-cells", 2);
    fdt_prop_u32(s, "#size-cells", 2);
    fdt_prop_tab_str(s, "compatible", "ucbbar,riscvemu-bar-soc", "simple-bus", NULL);
    fdt_prop(s, "ranges", NULL, 0);

    fdt_begin_node_num(s, "clint", CLINT_BASE_ADDR);
    fdt_prop_str(s, "compatible", "riscv,clint0");

    tab[0] = intc_phandle;
    tab[1] = 3; /* M IPI irq */
    tab[2] = intc_phandle;
    tab[3] = 7; /* M timer irq */
    fdt_prop_tab_u32(s, "interrupts-extended", tab, 4);

    fdt_prop_tab_u64_2(s, "reg", CLINT_BASE_ADDR, CLINT_SIZE);

    fdt_end_node(s); /* clint */

    fdt_begin_node_num(s, "plic", PLIC_BASE_ADDR);
    fdt_prop_u32(s, "#interrupt-cells", 1);
    fdt_prop(s, "interrupt-controller", NULL, 0);
    fdt_prop_str(s, "compatible", "riscv,plic0");
    fdt_prop_u32(s, "riscv,ndev", 31);
    fdt_prop_tab_u64_2(s, "reg", PLIC_BASE_ADDR, PLIC_SIZE);

    tab[0] = intc_phandle;
    tab[1] = 9; /* S ext irq */
    tab[2] = intc_phandle;
    tab[3] = 11; /* M ext irq */
    fdt_prop_tab_u32(s, "interrupts-extended", tab, 4);

    plic_phandle = cur_phandle++;
    fdt_prop_u32(s, "phandle", plic_phandle);
    fdt_end_node(s); /* plic */

    for (i = 0; i < m->virtio_count; i++) {
        fdt_begin_node_num(s, "virtio", VIRTIO_BASE_ADDR + i * VIRTIO_SIZE);
        fdt_prop_str(s, "compatible", "virtio,mmio");
        fdt_prop_tab_u64_2(s, "reg", VIRTIO_BASE_ADDR + i * VIRTIO_SIZE, VIRTIO_SIZE);
        tab[0] = plic_phandle;
        tab[1] = VIRTIO_IRQ + i;
        fdt_prop_tab_u32(s, "interrupts-extended", tab, 2);
        fdt_end_node(s); /* virtio */
    }

    fdt_end_node(s); /* soc */
    fdt_begin_node(s, "chosen");
    fdt_prop_str(s, "bootargs", cmd_line ? cmd_line : "");
    if (kernel_size > 0) {
        fdt_prop_tab_u64(s, "riscv,kernel-start", kernel_start);
        fdt_prop_tab_u64(s, "riscv,kernel-end", kernel_start + kernel_size);
    }
    if (initrd_size > 0) {
        fdt_prop_tab_u64(s, "linux,initrd-start", initrd_start);
        fdt_prop_tab_u64(s, "linux,initrd-end", initrd_start + initrd_size);
    }

    fdt_end_node(s); /* chosen */
    fdt_end_node(s); /* / */
    size = fdt_output(s, dst);
    fdt_end(s);
    return size;
}
#endif
