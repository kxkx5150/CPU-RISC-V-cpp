#include "PC.h"
#include <byteswap.h>



static int64_t bf_get_sector_count(BlockDevice *bs)
{
    BlockDeviceFile *bf = (BlockDeviceFile *)bs->opaque;
    return bf->nb_sectors;
}
static int bf_read_async(BlockDevice *bs, uint64_t sector_num, uint8_t *buf, int n, BlockDeviceCompletionFunc *cb,
                         void *opaque)
{
    BlockDeviceFile *bf = (BlockDeviceFile *)bs->opaque;
    if (!bf->f)
        return -1;
    if (bf->mode == BF_MODE_SNAPSHOT) {
        int i;
        for (i = 0; i < n; i++) {
            if (!bf->sector_table[sector_num]) {
                fseek(bf->f, sector_num * SECTOR_SIZE, SEEK_SET);
                auto _ = fread(buf, 1, SECTOR_SIZE, bf->f);
            } else {
                memcpy(buf, bf->sector_table[sector_num], SECTOR_SIZE);
            }
            sector_num++;
            buf += SECTOR_SIZE;
        }
    } else {
        fseek(bf->f, sector_num * SECTOR_SIZE, SEEK_SET);
        auto _ = fread(buf, 1, n * SECTOR_SIZE, bf->f);
    }
    /* synchronous read */
    return 0;
}
static int bf_write_async(BlockDevice *bs, uint64_t sector_num, const uint8_t *buf, int n,
                          BlockDeviceCompletionFunc *cb, void *opaque)
{
    BlockDeviceFile *bf = (BlockDeviceFile *)bs->opaque;
    int              ret;

    switch (bf->mode) {
        case BF_MODE_RO:
            ret = -1; /* error */
            break;
        case BF_MODE_RW:
            fseek(bf->f, sector_num * SECTOR_SIZE, SEEK_SET);
            fwrite(buf, 1, n * SECTOR_SIZE, bf->f);
            ret = 0;
            break;
        case BF_MODE_SNAPSHOT: {
            int i;
            if ((sector_num + n) > bf->nb_sectors)
                return -1;
            for (i = 0; i < n; i++) {
                if (!bf->sector_table[sector_num]) {
                    bf->sector_table[sector_num] = (uint8_t *)malloc(SECTOR_SIZE);
                }
                memcpy(bf->sector_table[sector_num], buf, SECTOR_SIZE);
                sector_num++;
                buf += SECTOR_SIZE;
            }
            ret = 0;
        } break;
        default:
            abort();
    }

    return ret;
}
inline BlockDevice *PC::block_device_init(const char *filename, BlockDeviceModeEnum mode)
{
    BlockDevice     *bs;
    BlockDeviceFile *bf;
    int64_t          file_size;
    FILE            *f;
    const char      *mode_str;

    if (mode == BF_MODE_RW) {
        mode_str = "r+b";
    } else {
        mode_str = "rb";
    }

    f = fopen(filename, mode_str);
    if (!f) {
        perror(filename);
        exit(1);
    }
    fseek(f, 0, SEEK_END);
    file_size = ftello(f);

    bs             = (BlockDevice *)mallocz(sizeof(*bs));
    bf             = (BlockDeviceFile *)mallocz(sizeof(*bf));
    bf->mode       = mode;
    bf->nb_sectors = file_size / 512;
    bf->f          = f;

    if (mode == BF_MODE_SNAPSHOT) {
        bf->sector_table = (uint8_t **)mallocz(sizeof(bf->sector_table[0]) * bf->nb_sectors);
    }

    bs->opaque           = bf;
    bs->get_sector_count = bf_get_sector_count;
    bs->read_async       = bf_read_async;
    bs->write_async      = bf_write_async;
    return bs;
}



static void term_init(BOOL allow_ctrlc)
{
    struct termios tty;
    memset(&tty, 0, sizeof(tty));
    tcgetattr(0, &tty);

    tty.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
    tty.c_oflag |= OPOST;
    tty.c_lflag &= ~(ECHO | ECHONL | ICANON | IEXTEN);
    if (!allow_ctrlc)
        tty.c_lflag &= ~ISIG;
    tty.c_cflag &= ~(CSIZE | PARENB);
    tty.c_cflag |= CS8;
    tty.c_cc[VMIN]  = 1;
    tty.c_cc[VTIME] = 0;

    tcsetattr(0, TCSANOW, &tty);
}
static void console_write(void *opaque, const uint8_t *buf, int len)
{
    fwrite(buf, 1, len, stdout);
    fflush(stdout);
}
static void console_get_size(STDIODevice *s, int *pw, int *ph)
{
    struct winsize ws;
    int            width, height;
    width  = 80;
    height = 25;
    if (ioctl(s->stdin_fd, TIOCGWINSZ, &ws) == 0 && ws.ws_col >= 4 && ws.ws_row >= 4) {
        width  = ws.ws_col;
        height = ws.ws_row;
    }
    *pw = width;
    *ph = height;
}
inline CharacterDevice *PC::console_init(BOOL allow_ctrlc)
{
    CharacterDevice *dev;
    STDIODevice     *s;
    term_init(allow_ctrlc);

    dev         = (CharacterDevice *)mallocz(sizeof(*dev));
    s           = (STDIODevice *)mallocz(sizeof(*s));
    s->stdin_fd = 0;
    fcntl(s->stdin_fd, F_SETFL, O_NONBLOCK);

    s->resize_pending = TRUE;

    dev->opaque     = s;
    dev->write_data = console_write;
    return dev;
}





static void plic_update_mip(PC *s)
{
    uint32_t mask;
    mask = s->plic_pending_irq & ~s->plic_served_irq;
    if (mask) {
        s->cpu->riscv_cpu_set_mip64(MIP_MEIP | MIP_SEIP);
    } else {
        s->cpu->riscv_cpu_reset_mip64(MIP_MEIP | MIP_SEIP);
    }
}
static uint32_t plic_read(void *opaque, uint32_t offset, int size_log2)
{
    PC      *s = (PC *)opaque;
    uint32_t val, mask;
    int      i;
    assert(size_log2 == 2);
    switch (offset) {
        case PLIC_HART_BASE:
            val = 0;
            break;
        case PLIC_HART_BASE + 4:
            mask = s->plic_pending_irq & ~s->plic_served_irq;
            if (mask != 0) {
                i = ctz32(mask);
                s->plic_served_irq |= 1 << i;
                plic_update_mip(s);
                val = i + 1;
            } else {
                val = 0;
            }
            break;
        default:
            val = 0;
            break;
    }
    return val;
}
static void plic_write(void *opaque, uint32_t offset, uint32_t val, int size_log2)
{
    PC *s = (PC *)opaque;
    assert(size_log2 == 2);
    switch (offset) {
        case PLIC_HART_BASE + 4:
            val--;
            if (val < 32) {
                s->plic_served_irq &= ~(1 << val);
                plic_update_mip(s);
            }
            break;
        default:
            break;
    }
}
static void plic_set_irq(void *opaque, int irq_num, int state)
{
    PC *s = (PC *)opaque;

    uint32_t mask = 1 << (irq_num - 1);
    if (state)
        s->plic_pending_irq |= mask;
    else
        s->plic_pending_irq &= ~mask;
    plic_update_mip(s);
}




static uint32_t htif_read(void *opaque, uint32_t offset, int size_log2)
{
    PC      *s = (PC *)opaque;
    uint32_t val;

    assert(size_log2 == 2);
    switch (offset) {
        case 0:
            val = s->htif_tohost;
            break;
        case 4:
            val = s->htif_tohost >> 32;
            break;
        case 8:
            val = s->htif_fromhost;
            break;
        case 12:
            val = s->htif_fromhost >> 32;
            break;
        default:
            val = 0;
            break;
    }
    return val;
}
static void htif_handle_cmd(PC *s)
{
    uint32_t device, cmd;

    device = s->htif_tohost >> 56;
    cmd    = (s->htif_tohost >> 48) & 0xff;
    if (s->htif_tohost == 1) {
        /* shuthost */
        printf("\nPower off.\n");
        exit(0);
    } else if (device == 1 && cmd == 1) {
        uint8_t buf[1];
        buf[0] = s->htif_tohost & 0xff;
        s->console->write_data(s->console->opaque, buf, 1);
        s->htif_tohost   = 0;
        s->htif_fromhost = ((uint64_t)device << 56) | ((uint64_t)cmd << 48);
    } else if (device == 1 && cmd == 0) {
        s->htif_tohost = 0;
    } else {
        printf("HTIF: unsupported tohost=0x%016" PRIx64 "\n", s->htif_tohost);
    }
}
static void htif_write(void *opaque, uint32_t offset, uint32_t val, int size_log2)
{
    PC *s = (PC *)opaque;

    assert(size_log2 == 2);
    switch (offset) {
        case 0:
            s->htif_tohost = (s->htif_tohost & ~0xffffffff) | val;
            break;
        case 4:
            s->htif_tohost = (s->htif_tohost & 0xffffffff) | ((uint64_t)val << 32);
            htif_handle_cmd(s);
            break;
        case 8:
            s->htif_fromhost = (s->htif_fromhost & ~0xffffffff) | val;
            break;
        case 12:
            s->htif_fromhost = (s->htif_fromhost & 0xffffffff) | (uint64_t)val << 32;
            break;
        default:
            break;
    }
}
static uint8_t *get_ram_ptr(PC *s, uint64_t paddr, BOOL is_rw)
{
    return s->mem_map->phys_mem_get_ram_ptr(paddr, is_rw);
}










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
    s->tab[s->tab_len++] = bswap_32(v);
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

    assert(s->open_node_count == 0);

    fdt_put32(s, FDT_END);

    dt_struct_size  = s->tab_len * sizeof(uint32_t);
    dt_strings_size = s->string_table_len;

    h                    = (struct fdt_header *)dst;
    h->magic             = bswap_32(FDT_MAGIC);
    h->version           = bswap_32(FDT_VERSION);
    h->last_comp_version = bswap_32(16);
    h->boot_cpuid_phys   = bswap_32(0);
    h->size_dt_strings   = bswap_32(dt_strings_size);
    h->size_dt_struct    = bswap_32(dt_struct_size);

    pos = sizeof(struct fdt_header);

    h->off_dt_struct = bswap_32(pos);
    memcpy(dst + pos, s->tab, dt_struct_size);
    pos += dt_struct_size;

    while ((pos & 7) != 0) {
        dst[pos++] = 0;
    }
    h->off_mem_rsvmap = bswap_32(pos);
    re                = (struct fdt_reserve_entry *)(dst + pos);
    re->address       = 0; /* no reserved entry */
    re->size          = 0;
    pos += sizeof(struct fdt_reserve_entry);

    h->off_dt_strings = bswap_32(pos);
    memcpy(dst + pos, s->string_table, dt_strings_size);
    pos += dt_strings_size;

    while ((pos & 7) != 0) {
        dst[pos++] = 0;
    }

    h->totalsize = bswap_32(pos);
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
