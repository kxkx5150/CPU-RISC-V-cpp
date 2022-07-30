#include <cstdint>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>
#include <stdarg.h>
#include "virtio.h"




void VIRTIODevice::virtio_reset()
{
    int i;
    status              = 0;
    queue_sel           = 0;
    device_features_sel = 0;
    int_status          = 0;
    for (i = 0; i < MAX_QUEUE; i++) {
        QueueState *qs     = &queue[i];
        qs->ready          = 0;
        qs->num            = MAX_QUEUE_NUM;
        qs->desc_addr      = 0;
        qs->avail_addr     = 0;
        qs->used_addr      = 0;
        qs->last_avail_idx = 0;
    }
}
uint8_t *VIRTIODevice::virtio_mmio_get_ram_ptr(uint64_t paddr, BOOL is_rw)
{
    return mem_map->phys_mem_get_ram_ptr(paddr, is_rw);
}
uint16_t VIRTIODevice::virtio_read16(uint64_t addr)
{
    uint8_t *ptr;
    if (addr & 1)
        return 0;
    ptr = virtio_mmio_get_ram_ptr(addr, FALSE);
    if (!ptr)
        return 0;
    return *(uint16_t *)ptr;
}
void VIRTIODevice::virtio_write16(uint64_t addr, uint16_t val)
{
    uint8_t *ptr;
    if (addr & 1)
        return;
    ptr = virtio_mmio_get_ram_ptr(addr, TRUE);
    if (!ptr)
        return;
    *(uint16_t *)ptr = val;
}
void VIRTIODevice::virtio_write32(uint64_t addr, uint32_t val)
{
    uint8_t *ptr;
    if (addr & 3)
        return;
    ptr = virtio_mmio_get_ram_ptr(addr, TRUE);
    if (!ptr)
        return;
    *(uint32_t *)ptr = val;
}
int VIRTIODevice::virtio_memcpy_from_ram(uint8_t *buf, uint64_t addr, int count)
{
    uint8_t *ptr;
    int      l;

    while (count > 0) {
        l   = min_int(count, VIRTIO_PAGE_SIZE - (addr & (VIRTIO_PAGE_SIZE - 1)));
        ptr = virtio_mmio_get_ram_ptr(addr, FALSE);
        if (!ptr)
            return -1;
        memcpy(buf, ptr, l);
        addr += l;
        buf += l;
        count -= l;
    }
    return 0;
}
int VIRTIODevice::virtio_memcpy_to_ram(uint64_t addr, const uint8_t *buf, int count)
{
    uint8_t *ptr;
    int      l;

    while (count > 0) {
        l   = min_int(count, VIRTIO_PAGE_SIZE - (addr & (VIRTIO_PAGE_SIZE - 1)));
        ptr = virtio_mmio_get_ram_ptr(addr, TRUE);
        if (!ptr)
            return -1;
        memcpy(ptr, buf, l);
        addr += l;
        buf += l;
        count -= l;
    }
    return 0;
}
int VIRTIODevice::get_desc(VIRTIODesc *desc, int queue_idx, int desc_idx)
{
    QueueState *qs = &queue[queue_idx];
    return virtio_memcpy_from_ram(s, (uint8_t *)desc, qs->desc_addr + desc_idx * sizeof(VIRTIODesc),
                                  sizeof(VIRTIODesc));
}
int VIRTIODevice::memcpy_to_from_queue(uint8_t *buf, int queue_idx, int desc_idx, int offset, int count, BOOL to_queue)
{
    VIRTIODesc desc;
    int        l, f_write_flag;

    if (count == 0)
        return 0;

    get_desc(&desc, queue_idx, desc_idx);

    if (to_queue) {
        f_write_flag = VRING_DESC_F_WRITE;

        for (;;) {
            if ((desc.flags & VRING_DESC_F_WRITE) == f_write_flag)
                break;
            if (!(desc.flags & VRING_DESC_F_NEXT))
                return -1;
            desc_idx = desc.next;
            get_desc(&desc, queue_idx, desc_idx);
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
        get_desc(&desc, queue_idx, desc_idx);
    }

    for (;;) {
        l = min_int(count, desc.len - offset);
        if (to_queue)
            virtio_memcpy_to_ram(desc.addr + offset, buf, l);
        else
            virtio_memcpy_from_ram(buf, desc.addr + offset, l);

        count -= l;
        if (count == 0)
            break;
        offset += l;
        buf += l;
        if (offset == desc.len) {
            if (!(desc.flags & VRING_DESC_F_NEXT))
                return -1;
            desc_idx = desc.next;
            get_desc(&desc, queue_idx, desc_idx);
            if ((desc.flags & VRING_DESC_F_WRITE) != f_write_flag)
                return -1;
            offset = 0;
        }
    }
    return 0;
}
int VIRTIODevice::memcpy_from_queue(void *buf, int queue_idx, int desc_idx, int offset, int count)
{
    return memcpy_to_from_queue((uint8_t *)buf, queue_idx, desc_idx, offset, count, FALSE);
}
int VIRTIODevice::memcpy_to_queue(int queue_idx, int desc_idx, int offset, const void *buf, int count)
{
    return memcpy_to_from_queue((uint8_t *)buf, queue_idx, desc_idx, offset, count, TRUE);
}
void VIRTIODevice::virtio_consume_desc(int queue_idx, int desc_idx, int desc_len)
{
    QueueState *qs = &queue[queue_idx];
    uint64_t    addr;
    uint32_t    index;

    addr  = qs->used_addr + 2;
    index = virtio_read16(addr);
    virtio_write16(addr, index + 1);

    addr = qs->used_addr + 4 + (index & (qs->num - 1)) * 8;
    virtio_write32(addr, desc_idx);
    virtio_write32(addr + 4, desc_len);

    int_status |= 1;
    irq->set_irqval(1);
}
int VIRTIODevice::get_desc_rw_size(int *pread_size, int *pwrite_size, int queue_idx, int desc_idx)
{
    VIRTIODesc desc;
    int        read_size, write_size;

    read_size  = 0;
    write_size = 0;
    get_desc(&desc, queue_idx, desc_idx);

    for (;;) {
        if (desc.flags & VRING_DESC_F_WRITE)
            break;
        read_size += desc.len;
        if (!(desc.flags & VRING_DESC_F_NEXT))
            goto done;
        desc_idx = desc.next;
        get_desc(&desc, queue_idx, desc_idx);
    }

    for (;;) {
        if (!(desc.flags & VRING_DESC_F_WRITE))
            return -1;
        write_size += desc.len;
        if (!(desc.flags & VRING_DESC_F_NEXT))
            break;
        desc_idx = desc.next;
        get_desc(&desc, queue_idx, desc_idx);
    }

done:
    *pread_size  = read_size;
    *pwrite_size = write_size;
    return 0;
}
void VIRTIODevice::queue_notify(int queue_idx)
{
    QueueState *qs = &queue[queue_idx];
    uint16_t    avail_idx;
    int         desc_idx, read_size, write_size;

    if (qs->manual_recv)
        return;

    avail_idx = virtio_read16(qs->avail_addr + 2);
    while (qs->last_avail_idx != avail_idx) {
        desc_idx = virtio_read16(qs->avail_addr + 4 + (qs->last_avail_idx & (qs->num - 1)) * 2);
        if (!get_desc_rw_size(&read_size, &write_size, queue_idx, desc_idx)) {
            if (device_recv(queue_idx, desc_idx, read_size, write_size) < 0)
                break;
        }
        qs->last_avail_idx++;
    }
}
uint32_t VIRTIODevice::virtio_config_read(uint32_t offset, int size_log2)
{
    uint32_t val;
    switch (size_log2) {
        case 0:
            if (offset < config_space_size) {
                val = config_space[offset];
            } else {
                val = 0;
            }
            break;
        case 1:
            if (offset < (config_space_size - 1)) {
                val = get_le16(&config_space[offset]);
            } else {
                val = 0;
            }
            break;
        case 2:
            if (offset < (config_space_size - 3)) {
                val = get_le32(config_space + offset);
            } else {
                val = 0;
            }
            break;
        default:
            abort();
    }
    return val;
}
void VIRTIODevice::virtio_config_write(uint32_t offset, uint32_t val, int size_log2)
{
    switch (size_log2) {
        case 0:
            if (offset < config_space_size) {
                config_space[offset] = val;
                if (config_write)
                    config_write();
            }
            break;
        case 1:
            if (offset < config_space_size - 1) {
                put_le16(config_space + offset, val);
                if (config_write)
                    config_write();
            }
            break;
        case 2:
            if (offset < config_space_size - 3) {
                put_le32(config_space + offset, val);
                if (config_write)
                    config_write();
            }
            break;
    }
}
void VIRTIODevice::set_low32(uint64_t *paddr, uint32_t val)
{
    *paddr = (*paddr & ~(uint64_t)0xffffffff) | val;
}
void VIRTIODevice::set_high32(uint64_t *paddr, uint32_t val)
{
    *paddr = (*paddr & 0xffffffff) | ((uint64_t)val << 32);
}
void VIRTIODevice::virtio_config_change_notify()
{
    int_status |= 2;
    irq->set_irqval(1);
}
void VIRTIODevice::virtio_block_req_end(int ret)
{
    VIRTIOBlockDevice *s1 = (VIRTIOBlockDevice *)this;
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
            memcpy_to_queue(queue_idx, desc_idx, 0, buf, write_size);
            free(buf);
            virtio_consume_desc(queue_idx, desc_idx, write_size);
            break;
        case VIRTIO_BLK_T_OUT:
            if (ret < 0)
                buf1[0] = VIRTIO_BLK_S_IOERR;
            else
                buf1[0] = VIRTIO_BLK_S_OK;
            memcpy_to_queue(queue_idx, desc_idx, 0, buf1, sizeof(buf1));
            virtio_consume_desc(queue_idx, desc_idx, 1);
            break;
        default:
            abort();
    }
}
static void virtio_block_req_cb(void *opaque, int ret)
{
    VIRTIODevice      *s  = (VIRTIODevice *)opaque;
    VIRTIOBlockDevice *s1 = (VIRTIOBlockDevice *)s;
    s->virtio_block_req_end(ret);
    s1->req_in_progress = FALSE;
    s->queue_notify(s1->req.queue_idx);
}
int VIRTIODevice::virtio_block_recv_request(int queue_idx, int desc_idx, int read_size, int write_size)
{
    VIRTIOBlockDevice *s1 = (VIRTIOBlockDevice *)this;
    BlockDevice       *bs = s1->bs;
    BlockRequestHeader h;
    uint8_t           *buf;
    int                len, ret;

    if (s1->req_in_progress)
        return -1;

    if (memcpy_from_queue(&h, queue_idx, desc_idx, 0, sizeof(h)) < 0)
        return 0;

    s1->req.type      = h.type;
    s1->req.queue_idx = queue_idx;
    s1->req.desc_idx  = desc_idx;
    switch (h.type) {
        case VIRTIO_BLK_T_IN:
            s1->req.buf        = (uint8_t *)malloc(write_size);
            s1->req.write_size = write_size;
            ret = bs->read_async(bs, h.sector_num, s1->req.buf, (write_size - 1) / SECTOR_SIZE, virtio_block_req_cb,
                                 this);
            if (ret > 0) {
                s1->req_in_progress = TRUE;
            } else {
                virtio_block_req_end(ret);
            }
            break;
        case VIRTIO_BLK_T_OUT:
            assert(write_size >= 1);
            len = read_size - sizeof(h);
            buf = (uint8_t *)malloc(len);
            memcpy_from_queue(buf, queue_idx, desc_idx, sizeof(h), len);
            ret = bs->write_async(bs, h.sector_num, buf, len / SECTOR_SIZE, virtio_block_req_cb, this);
            free(buf);
            if (ret > 0) {
                s1->req_in_progress = TRUE;
            } else {
                virtio_block_req_end(ret);
            }
            break;
        default:
            break;
    }
    return 0;
}
int VIRTIODevice::virtio_console_recv_request(int queue_idx, int desc_idx, int read_size, int write_size)
{
    VIRTIOConsoleDevice *s1 = (VIRTIOConsoleDevice *)this;
    CharacterDevice     *cs = s1->cs;
    uint8_t             *buf;

    if (queue_idx == 1) {
        buf = (uint8_t *)malloc(read_size);
        memcpy_from_queue(buf, queue_idx, desc_idx, 0, read_size);
        cs->write_data(cs->opaque, buf, read_size);
        free(buf);
        virtio_consume_desc(queue_idx, desc_idx, 0);
    }
    return 0;
}
static uint32_t virtio_mmio_read(void *opaque, uint32_t offset, int size_log2)
{
    uint32_t      val;
    VIRTIODevice *s = (VIRTIODevice *)opaque;

    if (offset >= VIRTIO_MMIO_CONFIG) {
        return virtio_config_read(offset - VIRTIO_MMIO_CONFIG, size_log2);
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
                val = device_id;
                break;
            case VIRTIO_MMIO_VENDOR_ID:
                val = vendor_id;
                break;
            case VIRTIO_MMIO_DEVICE_FEATURES:
                switch (device_features_sel) {
                    case 0:
                        val = device_features;
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
                val = device_features_sel;
                break;
            case VIRTIO_MMIO_QUEUE_SEL:
                val = queue_sel;
                break;
            case VIRTIO_MMIO_QUEUE_NUM_MAX:
                val = MAX_QUEUE_NUM;
                break;
            case VIRTIO_MMIO_QUEUE_NUM:
                val = queue[queue_sel].num;
                break;
            case VIRTIO_MMIO_QUEUE_DESC_LOW:
                val = queue[queue_sel].desc_addr;
                break;
            case VIRTIO_MMIO_QUEUE_AVAIL_LOW:
                val = queue[queue_sel].avail_addr;
                break;
            case VIRTIO_MMIO_QUEUE_USED_LOW:
                val = queue[queue_sel].used_addr;
                break;
            case VIRTIO_MMIO_QUEUE_DESC_HIGH:
                val = queue[queue_sel].desc_addr >> 32;
                break;
            case VIRTIO_MMIO_QUEUE_AVAIL_HIGH:
                val = queue[queue_sel].avail_addr >> 32;
                break;
            case VIRTIO_MMIO_QUEUE_USED_HIGH:
                val = queue[queue_sel].used_addr >> 32;
                break;
            case VIRTIO_MMIO_QUEUE_READY:
                val = queue[queue_sel].ready;
                break;
            case VIRTIO_MMIO_INTERRUPT_STATUS:
                val = int_status;
                break;
            case VIRTIO_MMIO_STATUS:
                val = status;
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
static void virtio_mmio_write(void *opaque, uint32_t offset, uint32_t val, int size_log2)
{
    VIRTIODevice *s = (VIRTIODevice *)opaque;

    if (offset >= VIRTIO_MMIO_CONFIG) {
        virtio_config_write(offset - VIRTIO_MMIO_CONFIG, val, size_log2);
        return;
    }

    if (size_log2 == 2) {
        switch (offset) {
            case VIRTIO_MMIO_DEVICE_FEATURES_SEL:
                device_features_sel = val;
                break;
            case VIRTIO_MMIO_QUEUE_SEL:
                if (val < MAX_QUEUE)
                    queue_sel = val;
                break;
            case VIRTIO_MMIO_QUEUE_NUM:
                if ((val & (val - 1)) == 0 && val > 0) {
                    queue[queue_sel].num = val;
                }
                break;
            case VIRTIO_MMIO_QUEUE_DESC_LOW:
                set_low32(&queue[queue_sel].desc_addr, val);
                break;
            case VIRTIO_MMIO_QUEUE_AVAIL_LOW:
                set_low32(&queue[queue_sel].avail_addr, val);
                break;
            case VIRTIO_MMIO_QUEUE_USED_LOW:
                set_low32(&queue[queue_sel].used_addr, val);
                break;
            case VIRTIO_MMIO_QUEUE_DESC_HIGH:
                set_high32(&queue[queue_sel].desc_addr, val);
                break;
            case VIRTIO_MMIO_QUEUE_AVAIL_HIGH:
                set_high32(&queue[queue_sel].avail_addr, val);
                break;
            case VIRTIO_MMIO_QUEUE_USED_HIGH:
                set_high32(&queue[queue_sel].used_addr, val);
                break;

            case VIRTIO_MMIO_STATUS:
                status = val;
                if (val == 0) {
                    /* reset */
                    irq->set_irqval(0);
                    virtio_reset();
                }
                break;
            case VIRTIO_MMIO_QUEUE_READY:
                queue[queue_sel].ready = val & 1;
                break;
            case VIRTIO_MMIO_QUEUE_NOTIFY:
                if (val < MAX_QUEUE)
                    queue_notify(s, val);
                break;
            case VIRTIO_MMIO_INTERRUPT_ACK:
                int_status &= ~val;
                if (int_status == 0) {
                    irq->set_irqval(0);
                }
                break;
        }
    }
}
void VIRTIODevice::virtio_init(VIRTIOBusDef *bus, uint32_t _device_id, int _config_space_size,
                               VIRTIODeviceRecvFunc *_device_recv)
{
    if (FALSE) {    // bus->pci_bu
    } else {
        mem_map   = bus->mem_map;
        irq       = bus->irq;
        mem_range = mem_map->cpu_register_device(bus->addr, VIRTIO_PAGE_SIZE, s, virtio_mmio_read, virtio_mmio_write,
                                                 DEVIO_SIZE8 | DEVIO_SIZE16 | DEVIO_SIZE32);
    }
    device_id         = _device_id;
    vendor_id         = 0xffff;
    config_space_size = _config_space_size;
    device_recv       = _device_recv;
    virtio_reset();
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