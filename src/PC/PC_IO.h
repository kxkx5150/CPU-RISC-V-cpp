#ifndef PCIO_H
#define PCIO_H

#include "PC.h"
#include <byteswap.h>

static void console_write(void *opaque, const uint8_t *buf, int len)
{
    fwrite(buf, 1, len, stdout);
    fflush(stdout);
}
inline void PC::term_init(BOOL allow_ctrlc)
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
inline CharDev *PC::console_init(BOOL allow_ctrlc)
{
    CharDev     *dev;
    STDIODevice *s;
    term_init(allow_ctrlc);

    dev         = (CharDev *)mallocz(sizeof(*dev));
    s           = (STDIODevice *)mallocz(sizeof(*s));
    s->stdin_fd = 0;
    fcntl(s->stdin_fd, F_SETFL, O_NONBLOCK);

    s->resize_pending = TRUE;

    dev->opaque     = s;
    dev->write_data = console_write;
    return dev;
}
static int64_t bf_get_sector_count(BlockDev *bs)
{
    BlockDevFile *bf = (BlockDevFile *)bs->opaque;
    return bf->nb_sectors;
}
static int bf_read_async(BlockDev *bs, uint64_t sector_num, uint8_t *buf, int n, BlockDevCompFunc *cb, void *opaque)
{
    BlockDevFile *bf = (BlockDevFile *)bs->opaque;
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

    return 0;
}
static int bf_write_async(BlockDev *bs, uint64_t sector_num, const uint8_t *buf, int n, BlockDevCompFunc *cb,
                          void *opaque)
{
    BlockDevFile *bf = (BlockDevFile *)bs->opaque;
    int           ret;

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
inline BlockDev *PC::block_device_init(const char *filename, BlockDevModeEnum mode)
{
    BlockDev     *bs;
    BlockDevFile *bf;
    int64_t       file_size;
    FILE         *f;
    const char   *mode_str;

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

    bs             = (BlockDev *)mallocz(sizeof(*bs));
    bf             = (BlockDevFile *)mallocz(sizeof(*bf));
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
static uint32_t plic_read(void *opaque, uint32_t offset, int size_log2)
{
    PC      *s = (PC *)opaque;
    uint32_t val, mask;
    int      i;
    switch (offset) {
        case PLIC_HART_BASE:
            val = 0;
            break;
        case PLIC_HART_BASE + 4:
            mask = s->plic_pending_irq & ~s->plic_served_irq;
            if (mask != 0) {
                i = ctz32(mask);
                s->plic_served_irq |= 1 << i;
                s->plic_update_mip();
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
    switch (offset) {
        case PLIC_HART_BASE + 4:
            val--;
            if (val < 32) {
                s->plic_served_irq &= ~(1 << val);
                s->plic_update_mip();
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
    s->plic_update_mip();
}
inline void PC::plic_update_mip()
{
    uint32_t mask = plic_pending_irq & ~plic_served_irq;
    if (mask) {
        cpu->riscv_cpu_set_mip64(MIP_MEIP | MIP_SEIP);
    } else {
        cpu->riscv_cpu_reset_mip64(MIP_MEIP | MIP_SEIP);
    }
}
static uint32_t htif_read(void *opaque, uint32_t offset, int size_log2)
{
    PC      *s = (PC *)opaque;
    uint32_t val;

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
static void htif_write(void *opaque, uint32_t offset, uint32_t val, int size_log2)
{
    PC *s = (PC *)opaque;

    switch (offset) {
        case 0:
            s->htif_tohost = (s->htif_tohost & ~0xffffffff) | val;
            break;
        case 4:
            s->htif_tohost = (s->htif_tohost & 0xffffffff) | ((uint64_t)val << 32);
            s->htif_handle_cmd();
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
inline void PC::htif_handle_cmd()
{
    uint32_t device = htif_tohost >> 56;
    uint32_t cmd    = (htif_tohost >> 48) & 0xff;
    if (htif_tohost == 1) {
        printf("\nPower off.\n");
        exit(0);
    } else if (device == 1 && cmd == 1) {
        uint8_t buf[1];
        buf[0] = htif_tohost & 0xff;
        console->write_data(console->opaque, buf, 1);
        htif_tohost   = 0;
        htif_fromhost = ((uint64_t)device << 56) | ((uint64_t)cmd << 48);
    } else if (device == 1 && cmd == 0) {
        htif_tohost = 0;
    } else {
        printf("HTIF: unsupported tohost=0x%016" PRIx64 "\n", htif_tohost);
    }
}
inline uint8_t *PC::get_ram_ptr(uint64_t paddr, BOOL is_rw)
{
    return mem_map->phys_mem_get_ram_ptr(paddr, is_rw);
}
#endif
