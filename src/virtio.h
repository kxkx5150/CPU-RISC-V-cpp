#ifndef VIRTIO_H
#define VIRTIO_H

#include <sys/select.h>
#include "def/virtio_def.h"

typedef int      VIRTIODeviceRecvFunc(VIRTIODevice *s, int queue_idx, int desc_idx, int read_size, int write_size);
typedef uint8_t *VIRTIOGetRAMPtrFunc(uint64_t paddr, BOOL is_rw);

class VIRTIODevice {
  public:
    PhysMemMap   *mem_map;
    PhysMemRange *mem_range;
    IRQSignal    *irq;

    int      debug;
    uint32_t int_status          = 0;
    uint32_t status              = 0;
    uint32_t device_features_sel = 0;
    uint32_t queue_sel           = 0;

    uint32_t device_id = 0;
    uint32_t vendor_id;
    uint32_t device_features   = 0;
    uint32_t config_space_size = 0;

    uint8_t    config_space[MAX_CONFIG_SPACE_SIZE];
    QueueState queue[MAX_QUEUE];

  public:
    void (*config_write)();
    VIRTIODeviceRecvFunc *device_recv;

    uint16_t virtio_read16(uint64_t addr);
    void     virtio_write16(uint64_t addr, uint16_t val);
    void     virtio_write32(uint64_t addr, uint32_t val);
    void     set_low32(uint64_t *paddr, uint32_t val);
    void     set_high32(uint64_t *paddr, uint32_t val);

    int      virtio_memcpy_from_ram(uint8_t *buf, uint64_t addr, int count);
    void     virtio_consume_desc(int queue_idx, int desc_idx, int desc_len);
    int      get_desc_rw_size(int *pread_size, int *pwrite_size, int queue_idx, int desc_idx);
    void     queue_notify(int queue_idx);
    uint32_t virtio_config_read(uint32_t offset, int size_log2);
    void     virtio_config_write(uint32_t offset, uint32_t val, int size_log2);

    int      get_desc(VIRTIODesc *desc, int queue_idx, int desc_idx);
    int      virtio_memcpy_to_ram(uint64_t addr, const uint8_t *buf, int count);
    int      memcpy_to_queue(int queue_idx, int desc_idx, int offset, const void *buf, int count);
    int      memcpy_from_queue(void *buf, int queue_idx, int desc_idx, int offset, int count);
    int      memcpy_to_from_queue(uint8_t *buf, int queue_idx, int desc_idx, int offset, int count, BOOL to_queue);
    uint8_t *virtio_mmio_get_ram_ptr(uint64_t paddr, BOOL is_rw);
    void     virtio_config_change_notify();
    void     virtio_block_req_end(int ret);
    void     virtio_reset();

    void virtio_init(VIRTIOBusDef *bus, uint32_t _device_id, int _config_space_size,
                     VIRTIODeviceRecvFunc *_device_recv);
};
class VIRTIOConsoleDevice : public VIRTIODevice {
  public:
    CharDev *cs;

  public:
    VIRTIOConsoleDevice(VIRTIOBusDef *bus, CharDev *_cs);
};
class VIRTIOBlockDev : public VIRTIODevice {
  public:
    BlockDev    *bs;
    BOOL         req_in_progress;
    BlockRequest req;

  public:
    VIRTIOBlockDev(VIRTIOBusDef *bus, BlockDev *_bs);
};

#endif