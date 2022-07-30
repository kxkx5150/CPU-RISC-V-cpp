#include <cstdint>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>
#include <stdarg.h>
#include "virtio.h"


typedef int      VIRTIODeviceRecvFunc(VIRTIODevice *s1, int queue_idx, int desc_idx, int read_size, int write_size);
typedef uint8_t *VIRTIOGetRAMPtrFunc(VIRTIODevice *s, uint64_t paddr, BOOL is_rw);

struct VIRTIODevice
{
    PhysMemMap          *mem_map;
    PhysMemRange        *mem_range;
    IRQSignal           *irq;
    VIRTIOGetRAMPtrFunc *get_ram_ptr;
    int                  debug;

    uint32_t   int_status;
    uint32_t   status;
    uint32_t   device_features_sel;
    uint32_t   queue_sel; /* currently selected queue */
    QueueState queue[MAX_QUEUE];

    uint32_t              device_id;
    uint32_t              vendor_id;
    uint32_t              device_features;
    VIRTIODeviceRecvFunc *device_recv;
    void (*config_write)(VIRTIODevice *s); /* called after the config
                                              is written */
    uint32_t config_space_size;            /* in bytes, must be multiple of 4 */
    uint8_t  config_space[MAX_CONFIG_SPACE_SIZE];
};

typedef struct
{
    uint32_t type;
    uint8_t *buf;
    int      write_size;
    int      queue_idx;
    int      desc_idx;
} BlockRequest;

typedef struct VIRTIOBlockDevice
{
    VIRTIODevice common;
    BlockDevice *bs;

    BOOL         req_in_progress;
    BlockRequest req; /* request in progress */
} VIRTIOBlockDevice;

typedef struct
{
    uint32_t type;
    uint32_t ioprio;
    uint64_t sector_num;
} BlockRequestHeader;

typedef struct VIRTIOConsoleDevice
{
    VIRTIODevice     common;
    CharacterDevice *cs;
} VIRTIOConsoleDevice;

static uint32_t virtio_mmio_read(void *opaque, uint32_t offset1, int size_log2);
static void     virtio_mmio_write(void *opaque, uint32_t offset, uint32_t val, int size_log2);





static void virtio_reset(VIRTIODevice *s)
{
    int i;

    s->status              = 0;
    s->queue_sel           = 0;
    s->device_features_sel = 0;
    s->int_status          = 0;
    for (i = 0; i < MAX_QUEUE; i++) {
        QueueState *qs     = &s->queue[i];
        qs->ready          = 0;
        qs->num            = MAX_QUEUE_NUM;
        qs->desc_addr      = 0;
        qs->avail_addr     = 0;
        qs->used_addr      = 0;
        qs->last_avail_idx = 0;
    }
}
static uint8_t *virtio_mmio_get_ram_ptr(VIRTIODevice *s, uint64_t paddr, BOOL is_rw)
{
    return s->mem_map->phys_mem_get_ram_ptr(paddr, is_rw);
}
static void virtio_init(VIRTIODevice *s, VIRTIOBusDef *bus, uint32_t device_id, int config_space_size,
                        VIRTIODeviceRecvFunc *device_recv)
{
    memset(s, 0, sizeof(*s));

    if (FALSE) {    // bus->pci_bu
    } else {
        /* MMIO case */
        s->mem_map     = bus->mem_map;
        s->irq         = bus->irq;
        s->mem_range   = s->mem_map->cpu_register_device(bus->addr, VIRTIO_PAGE_SIZE, s, virtio_mmio_read,
                                                         virtio_mmio_write, DEVIO_SIZE8 | DEVIO_SIZE16 | DEVIO_SIZE32);
        s->get_ram_ptr = virtio_mmio_get_ram_ptr;
    }

    s->device_id         = device_id;
    s->vendor_id         = 0xffff;
    s->config_space_size = config_space_size;
    s->device_recv       = device_recv;
    virtio_reset(s);
}
static uint16_t virtio_read16(VIRTIODevice *s, uint64_t addr)
{
    uint8_t *ptr;
    if (addr & 1)
        return 0; /* unaligned access are not supported */
    ptr = s->get_ram_ptr(s, addr, FALSE);
    if (!ptr)
        return 0;
    return *(uint16_t *)ptr;
}
static void virtio_write16(VIRTIODevice *s, uint64_t addr, uint16_t val)
{
    uint8_t *ptr;
    if (addr & 1)
        return; /* unaligned access are not supported */
    ptr = s->get_ram_ptr(s, addr, TRUE);
    if (!ptr)
        return;
    *(uint16_t *)ptr = val;
}
static void virtio_write32(VIRTIODevice *s, uint64_t addr, uint32_t val)
{
    uint8_t *ptr;
    if (addr & 3)
        return; /* unaligned access are not supported */
    ptr = s->get_ram_ptr(s, addr, TRUE);
    if (!ptr)
        return;
    *(uint32_t *)ptr = val;
}
static int virtio_memcpy_from_ram(VIRTIODevice *s, uint8_t *buf, uint64_t addr, int count)
{
    uint8_t *ptr;
    int      l;

    while (count > 0) {
        l   = min_int(count, VIRTIO_PAGE_SIZE - (addr & (VIRTIO_PAGE_SIZE - 1)));
        ptr = s->get_ram_ptr(s, addr, FALSE);
        if (!ptr)
            return -1;
        memcpy(buf, ptr, l);
        addr += l;
        buf += l;
        count -= l;
    }
    return 0;
}
static int virtio_memcpy_to_ram(VIRTIODevice *s, uint64_t addr, const uint8_t *buf, int count)
{
    uint8_t *ptr;
    int      l;

    while (count > 0) {
        l   = min_int(count, VIRTIO_PAGE_SIZE - (addr & (VIRTIO_PAGE_SIZE - 1)));
        ptr = s->get_ram_ptr(s, addr, TRUE);
        if (!ptr)
            return -1;
        memcpy(ptr, buf, l);
        addr += l;
        buf += l;
        count -= l;
    }
    return 0;
}
static int get_desc(VIRTIODevice *s, VIRTIODesc *desc, int queue_idx, int desc_idx)
{
    QueueState *qs = &s->queue[queue_idx];
    return virtio_memcpy_from_ram(s, (uint8_t *)desc, qs->desc_addr + desc_idx * sizeof(VIRTIODesc),
                                  sizeof(VIRTIODesc));
}
static int memcpy_to_from_queue(VIRTIODevice *s, uint8_t *buf, int queue_idx, int desc_idx, int offset, int count,
                                BOOL to_queue)
{
    VIRTIODesc desc;
    int        l, f_write_flag;

    if (count == 0)
        return 0;

    get_desc(s, &desc, queue_idx, desc_idx);

    if (to_queue) {
        f_write_flag = VRING_DESC_F_WRITE;
        /* find the first write descriptor */
        for (;;) {
            if ((desc.flags & VRING_DESC_F_WRITE) == f_write_flag)
                break;
            if (!(desc.flags & VRING_DESC_F_NEXT))
                return -1;
            desc_idx = desc.next;
            get_desc(s, &desc, queue_idx, desc_idx);
        }
    } else {
        f_write_flag = 0;
    }

    for (;;) {
        if ((desc.flags & VRING_DESC_F_WRITE) != f_write_flag)
            return -1;
        if (offset < desc.len)
            break;
        if (!(desc.flags & VRING_DESC_F_NEXT))
            return -1;
        desc_idx = desc.next;
        offset -= desc.len;
        get_desc(s, &desc, queue_idx, desc_idx);
    }

    for (;;) {
        l = min_int(count, desc.len - offset);
        if (to_queue)
            virtio_memcpy_to_ram(s, desc.addr + offset, buf, l);
        else
            virtio_memcpy_from_ram(s, buf, desc.addr + offset, l);
        count -= l;
        if (count == 0)
            break;
        offset += l;
        buf += l;
        if (offset == desc.len) {
            if (!(desc.flags & VRING_DESC_F_NEXT))
                return -1;
            desc_idx = desc.next;
            get_desc(s, &desc, queue_idx, desc_idx);
            if ((desc.flags & VRING_DESC_F_WRITE) != f_write_flag)
                return -1;
            offset = 0;
        }
    }
    return 0;
}
static int memcpy_from_queue(VIRTIODevice *s, void *buf, int queue_idx, int desc_idx, int offset, int count)
{
    return memcpy_to_from_queue(s, (uint8_t *)buf, queue_idx, desc_idx, offset, count, FALSE);
}
static int memcpy_to_queue(VIRTIODevice *s, int queue_idx, int desc_idx, int offset, const void *buf, int count)
{
    return memcpy_to_from_queue(s, (uint8_t *)buf, queue_idx, desc_idx, offset, count, TRUE);
}
static void virtio_consume_desc(VIRTIODevice *s, int queue_idx, int desc_idx, int desc_len)
{
    QueueState *qs = &s->queue[queue_idx];
    uint64_t    addr;
    uint32_t    index;

    addr  = qs->used_addr + 2;
    index = virtio_read16(s, addr);
    virtio_write16(s, addr, index + 1);

    addr = qs->used_addr + 4 + (index & (qs->num - 1)) * 8;
    virtio_write32(s, addr, desc_idx);
    virtio_write32(s, addr + 4, desc_len);

    s->int_status |= 1;
    s->irq->set_irqval(1);
}
static int get_desc_rw_size(VIRTIODevice *s, int *pread_size, int *pwrite_size, int queue_idx, int desc_idx)
{
    VIRTIODesc desc;
    int        read_size, write_size;

    read_size  = 0;
    write_size = 0;
    get_desc(s, &desc, queue_idx, desc_idx);

    for (;;) {
        if (desc.flags & VRING_DESC_F_WRITE)
            break;
        read_size += desc.len;
        if (!(desc.flags & VRING_DESC_F_NEXT))
            goto done;
        desc_idx = desc.next;
        get_desc(s, &desc, queue_idx, desc_idx);
    }

    for (;;) {
        if (!(desc.flags & VRING_DESC_F_WRITE))
            return -1;
        write_size += desc.len;
        if (!(desc.flags & VRING_DESC_F_NEXT))
            break;
        desc_idx = desc.next;
        get_desc(s, &desc, queue_idx, desc_idx);
    }

done:
    *pread_size  = read_size;
    *pwrite_size = write_size;
    return 0;
}
static void queue_notify(VIRTIODevice *s, int queue_idx)
{
    QueueState *qs = &s->queue[queue_idx];
    uint16_t    avail_idx;
    int         desc_idx, read_size, write_size;

    if (qs->manual_recv)
        return;

    avail_idx = virtio_read16(s, qs->avail_addr + 2);
    while (qs->last_avail_idx != avail_idx) {
        desc_idx = virtio_read16(s, qs->avail_addr + 4 + (qs->last_avail_idx & (qs->num - 1)) * 2);
        if (!get_desc_rw_size(s, &read_size, &write_size, queue_idx, desc_idx)) {
            if (s->device_recv(s, queue_idx, desc_idx, read_size, write_size) < 0)
                break;
        }
        qs->last_avail_idx++;
    }
}
static uint32_t virtio_config_read(VIRTIODevice *s, uint32_t offset, int size_log2)
{
    uint32_t val;
    switch (size_log2) {
        case 0:
            if (offset < s->config_space_size) {
                val = s->config_space[offset];
            } else {
                val = 0;
            }
            break;
        case 1:
            if (offset < (s->config_space_size - 1)) {
                val = get_le16(&s->config_space[offset]);
            } else {
                val = 0;
            }
            break;
        case 2:
            if (offset < (s->config_space_size - 3)) {
                val = get_le32(s->config_space + offset);
            } else {
                val = 0;
            }
            break;
        default:
            abort();
    }
    return val;
}
static void virtio_config_write(VIRTIODevice *s, uint32_t offset, uint32_t val, int size_log2)
{
    switch (size_log2) {
        case 0:
            if (offset < s->config_space_size) {
                s->config_space[offset] = val;
                if (s->config_write)
                    s->config_write(s);
            }
            break;
        case 1:
            if (offset < s->config_space_size - 1) {
                put_le16(s->config_space + offset, val);
                if (s->config_write)
                    s->config_write(s);
            }
            break;
        case 2:
            if (offset < s->config_space_size - 3) {
                put_le32(s->config_space + offset, val);
                if (s->config_write)
                    s->config_write(s);
            }
            break;
    }
}
static uint32_t virtio_mmio_read(void *opaque, uint32_t offset, int size_log2)
{
    VIRTIODevice *s = (VIRTIODevice *)opaque;
    uint32_t      val;

    if (offset >= VIRTIO_MMIO_CONFIG) {
        return virtio_config_read(s, offset - VIRTIO_MMIO_CONFIG, size_log2);
    }

    if (size_log2 == 2) {
        switch (offset) {
            case VIRTIO_MMIO_MAGIC_VALUE:
                val = 0x74726976;
                break;
            case VIRTIO_MMIO_VERSION:
                val = 2;
                break;
            case VIRTIO_MMIO_DEVICE_ID:
                val = s->device_id;
                break;
            case VIRTIO_MMIO_VENDOR_ID:
                val = s->vendor_id;
                break;
            case VIRTIO_MMIO_DEVICE_FEATURES:
                switch (s->device_features_sel) {
                    case 0:
                        val = s->device_features;
                        break;
                    case 1:
                        val = 1; /* version 1 */
                        break;
                    default:
                        val = 0;
                        break;
                }
                break;
            case VIRTIO_MMIO_DEVICE_FEATURES_SEL:
                val = s->device_features_sel;
                break;
            case VIRTIO_MMIO_QUEUE_SEL:
                val = s->queue_sel;
                break;
            case VIRTIO_MMIO_QUEUE_NUM_MAX:
                val = MAX_QUEUE_NUM;
                break;
            case VIRTIO_MMIO_QUEUE_NUM:
                val = s->queue[s->queue_sel].num;
                break;
            case VIRTIO_MMIO_QUEUE_DESC_LOW:
                val = s->queue[s->queue_sel].desc_addr;
                break;
            case VIRTIO_MMIO_QUEUE_AVAIL_LOW:
                val = s->queue[s->queue_sel].avail_addr;
                break;
            case VIRTIO_MMIO_QUEUE_USED_LOW:
                val = s->queue[s->queue_sel].used_addr;
                break;
            case VIRTIO_MMIO_QUEUE_DESC_HIGH:
                val = s->queue[s->queue_sel].desc_addr >> 32;
                break;
            case VIRTIO_MMIO_QUEUE_AVAIL_HIGH:
                val = s->queue[s->queue_sel].avail_addr >> 32;
                break;
            case VIRTIO_MMIO_QUEUE_USED_HIGH:
                val = s->queue[s->queue_sel].used_addr >> 32;
                break;
            case VIRTIO_MMIO_QUEUE_READY:
                val = s->queue[s->queue_sel].ready;
                break;
            case VIRTIO_MMIO_INTERRUPT_STATUS:
                val = s->int_status;
                break;
            case VIRTIO_MMIO_STATUS:
                val = s->status;
                break;
            case VIRTIO_MMIO_CONFIG_GENERATION:
                val = 0;
                break;
            default:
                val = 0;
                break;
        }
    } else {
        val = 0;
    }
    return val;
}
static void set_low32(uint64_t *paddr, uint32_t val)
{
    *paddr = (*paddr & ~(uint64_t)0xffffffff) | val;
}
static void set_high32(uint64_t *paddr, uint32_t val)
{
    *paddr = (*paddr & 0xffffffff) | ((uint64_t)val << 32);
}
static void virtio_mmio_write(void *opaque, uint32_t offset, uint32_t val, int size_log2)
{
    VIRTIODevice *s = (VIRTIODevice *)opaque;

    if (offset >= VIRTIO_MMIO_CONFIG) {
        virtio_config_write(s, offset - VIRTIO_MMIO_CONFIG, val, size_log2);
        return;
    }

    if (size_log2 == 2) {
        switch (offset) {
            case VIRTIO_MMIO_DEVICE_FEATURES_SEL:
                s->device_features_sel = val;
                break;
            case VIRTIO_MMIO_QUEUE_SEL:
                if (val < MAX_QUEUE)
                    s->queue_sel = val;
                break;
            case VIRTIO_MMIO_QUEUE_NUM:
                if ((val & (val - 1)) == 0 && val > 0) {
                    s->queue[s->queue_sel].num = val;
                }
                break;
            case VIRTIO_MMIO_QUEUE_DESC_LOW:
                set_low32(&s->queue[s->queue_sel].desc_addr, val);
                break;
            case VIRTIO_MMIO_QUEUE_AVAIL_LOW:
                set_low32(&s->queue[s->queue_sel].avail_addr, val);
                break;
            case VIRTIO_MMIO_QUEUE_USED_LOW:
                set_low32(&s->queue[s->queue_sel].used_addr, val);
                break;
            case VIRTIO_MMIO_QUEUE_DESC_HIGH:
                set_high32(&s->queue[s->queue_sel].desc_addr, val);
                break;
            case VIRTIO_MMIO_QUEUE_AVAIL_HIGH:
                set_high32(&s->queue[s->queue_sel].avail_addr, val);
                break;
            case VIRTIO_MMIO_QUEUE_USED_HIGH:
                set_high32(&s->queue[s->queue_sel].used_addr, val);
                break;

            case VIRTIO_MMIO_STATUS:
                s->status = val;
                if (val == 0) {
                    /* reset */
                    s->irq->set_irqval(0);
                    virtio_reset(s);
                }
                break;
            case VIRTIO_MMIO_QUEUE_READY:
                s->queue[s->queue_sel].ready = val & 1;
                break;
            case VIRTIO_MMIO_QUEUE_NOTIFY:
                if (val < MAX_QUEUE)
                    queue_notify(s, val);
                break;
            case VIRTIO_MMIO_INTERRUPT_ACK:
                s->int_status &= ~val;
                if (s->int_status == 0) {
                    s->irq->set_irqval(0);
                }
                break;
        }
    }
}
static void virtio_config_change_notify(VIRTIODevice *s)
{
    /* INT_CONFIG interrupt */
    s->int_status |= 2;
    s->irq->set_irqval(1);
}
static void virtio_block_req_end(VIRTIODevice *s, int ret)
{
    VIRTIOBlockDevice *s1 = (VIRTIOBlockDevice *)s;
    int                write_size;
    int                queue_idx = s1->req.queue_idx;
    int                desc_idx  = s1->req.desc_idx;
    uint8_t           *buf, buf1[1];

    switch (s1->req.type) {
        case VIRTIO_BLK_T_IN:
            write_size = s1->req.write_size;
            buf        = s1->req.buf;
            if (ret < 0) {
                buf[write_size - 1] = VIRTIO_BLK_S_IOERR;
            } else {
                buf[write_size - 1] = VIRTIO_BLK_S_OK;
            }
            memcpy_to_queue(s, queue_idx, desc_idx, 0, buf, write_size);
            free(buf);
            virtio_consume_desc(s, queue_idx, desc_idx, write_size);
            break;
        case VIRTIO_BLK_T_OUT:
            if (ret < 0)
                buf1[0] = VIRTIO_BLK_S_IOERR;
            else
                buf1[0] = VIRTIO_BLK_S_OK;
            memcpy_to_queue(s, queue_idx, desc_idx, 0, buf1, sizeof(buf1));
            virtio_consume_desc(s, queue_idx, desc_idx, 1);
            break;
        default:
            abort();
    }
}
static void virtio_block_req_cb(void *opaque, int ret)
{
    VIRTIODevice      *s  = (VIRTIODevice *)opaque;
    VIRTIOBlockDevice *s1 = (VIRTIOBlockDevice *)s;
    virtio_block_req_end(s, ret);
    s1->req_in_progress = FALSE;
    queue_notify((VIRTIODevice *)s, s1->req.queue_idx);
}
static int virtio_block_recv_request(VIRTIODevice *s, int queue_idx, int desc_idx, int read_size, int write_size)
{
    VIRTIOBlockDevice *s1 = (VIRTIOBlockDevice *)s;
    BlockDevice       *bs = s1->bs;
    BlockRequestHeader h;
    uint8_t           *buf;
    int                len, ret;

    if (s1->req_in_progress)
        return -1;

    if (memcpy_from_queue(s, &h, queue_idx, desc_idx, 0, sizeof(h)) < 0)
        return 0;
    s1->req.type      = h.type;
    s1->req.queue_idx = queue_idx;
    s1->req.desc_idx  = desc_idx;
    switch (h.type) {
        case VIRTIO_BLK_T_IN:
            s1->req.buf        = (uint8_t *)malloc(write_size);
            s1->req.write_size = write_size;
            ret = bs->read_async(bs, h.sector_num, s1->req.buf, (write_size - 1) / SECTOR_SIZE, virtio_block_req_cb, s);
            if (ret > 0) {
                /* asyncronous read */
                s1->req_in_progress = TRUE;
            } else {
                virtio_block_req_end(s, ret);
            }
            break;
        case VIRTIO_BLK_T_OUT:
            assert(write_size >= 1);
            len = read_size - sizeof(h);
            buf = (uint8_t *)malloc(len);
            memcpy_from_queue(s, buf, queue_idx, desc_idx, sizeof(h), len);
            ret = bs->write_async(bs, h.sector_num, buf, len / SECTOR_SIZE, virtio_block_req_cb, s);
            free(buf);
            if (ret > 0) {
                /* asyncronous write */
                s1->req_in_progress = TRUE;
            } else {
                virtio_block_req_end(s, ret);
            }
            break;
        default:
            break;
    }
    return 0;
}
VIRTIODevice *virtio_block_init(VIRTIOBusDef *bus, BlockDevice *bs)
{
    VIRTIOBlockDevice *s;
    uint64_t           nb_sectors;

    s = (VIRTIOBlockDevice *)mallocz(sizeof(*s));
    virtio_init(&s->common, bus, 2, 8, virtio_block_recv_request);
    s->bs = bs;

    nb_sectors = bs->get_sector_count(bs);
    put_le32(s->common.config_space, nb_sectors);
    put_le32(s->common.config_space + 4, nb_sectors >> 32);

    return (VIRTIODevice *)s;
}
static int virtio_console_recv_request(VIRTIODevice *s, int queue_idx, int desc_idx, int read_size, int write_size)
{
    VIRTIOConsoleDevice *s1 = (VIRTIOConsoleDevice *)s;
    CharacterDevice     *cs = s1->cs;
    uint8_t             *buf;

    if (queue_idx == 1) {
        /* send to console */
        buf = (uint8_t *)malloc(read_size);
        memcpy_from_queue(s, buf, queue_idx, desc_idx, 0, read_size);
        cs->write_data(cs->opaque, buf, read_size);
        free(buf);
        virtio_consume_desc(s, queue_idx, desc_idx, 0);
    }
    return 0;
}
BOOL virtio_console_can_write_data(VIRTIODevice *s)
{
    QueueState *qs = &s->queue[0];
    uint16_t    avail_idx;

    if (!qs->ready)
        return FALSE;
    avail_idx = virtio_read16(s, qs->avail_addr + 2);
    return qs->last_avail_idx != avail_idx;
}
void virtio_console_resize_event(VIRTIODevice *s, int width, int height)
{
    /* indicate the console size */
    put_le16(s->config_space + 0, width);
    put_le16(s->config_space + 2, height);

    virtio_config_change_notify(s);
}
VIRTIODevice *virtio_console_init(VIRTIOBusDef *bus, CharacterDevice *cs)
{
    VIRTIOConsoleDevice *s;

    s = (VIRTIOConsoleDevice *)mallocz(sizeof(*s));
    virtio_init(&s->common, bus, 3, 4, virtio_console_recv_request);
    s->common.device_features      = (1 << 0); /* VIRTIO_CONSOLE_F_SIZE */
    s->common.queue[0].manual_recv = TRUE;

    s->cs = cs;
    return (VIRTIODevice *)s;
}
