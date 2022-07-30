#ifndef VIRTIO_H
#define VIRTIO_H

#include <sys/select.h>
#include "iomem.h"

#define VIRTIO_PAGE_SIZE 4096
#define VIRTIO_ADDR_BITS 64

#define VIRTIO_DEBUG_IO (1 << 0)
#define VIRTIO_DEBUG_9P (1 << 1)

#define VIRTIO_MMIO_MAGIC_VALUE         0x000
#define VIRTIO_MMIO_VERSION             0x004
#define VIRTIO_MMIO_DEVICE_ID           0x008
#define VIRTIO_MMIO_VENDOR_ID           0x00c
#define VIRTIO_MMIO_DEVICE_FEATURES     0x010
#define VIRTIO_MMIO_DEVICE_FEATURES_SEL 0x014
#define VIRTIO_MMIO_DRIVER_FEATURES     0x020
#define VIRTIO_MMIO_DRIVER_FEATURES_SEL 0x024
#define VIRTIO_MMIO_GUEST_PAGE_SIZE     0x028
#define VIRTIO_MMIO_QUEUE_SEL           0x030
#define VIRTIO_MMIO_QUEUE_NUM_MAX       0x034
#define VIRTIO_MMIO_QUEUE_NUM           0x038
#define VIRTIO_MMIO_QUEUE_ALIGN         0x03c
#define VIRTIO_MMIO_QUEUE_PFN           0x040
#define VIRTIO_MMIO_QUEUE_READY         0x044
#define VIRTIO_MMIO_QUEUE_NOTIFY        0x050
#define VIRTIO_MMIO_INTERRUPT_STATUS    0x060
#define VIRTIO_MMIO_INTERRUPT_ACK       0x064
#define VIRTIO_MMIO_STATUS              0x070
#define VIRTIO_MMIO_QUEUE_DESC_LOW      0x080
#define VIRTIO_MMIO_QUEUE_DESC_HIGH     0x084
#define VIRTIO_MMIO_QUEUE_AVAIL_LOW     0x090
#define VIRTIO_MMIO_QUEUE_AVAIL_HIGH    0x094
#define VIRTIO_MMIO_QUEUE_USED_LOW      0x0a0
#define VIRTIO_MMIO_QUEUE_USED_HIGH     0x0a4
#define VIRTIO_MMIO_CONFIG_GENERATION   0x0fc
#define VIRTIO_MMIO_CONFIG              0x100

#define VIRTIO_PCI_DEVICE_FEATURE_SEL 0x000
#define VIRTIO_PCI_DEVICE_FEATURE     0x004
#define VIRTIO_PCI_GUEST_FEATURE_SEL  0x008
#define VIRTIO_PCI_GUEST_FEATURE      0x00c
#define VIRTIO_PCI_MSIX_CONFIG        0x010
#define VIRTIO_PCI_NUM_QUEUES         0x012
#define VIRTIO_PCI_DEVICE_STATUS      0x014
#define VIRTIO_PCI_CONFIG_GENERATION  0x015
#define VIRTIO_PCI_QUEUE_SEL          0x016
#define VIRTIO_PCI_QUEUE_SIZE         0x018
#define VIRTIO_PCI_QUEUE_MSIX_VECTOR  0x01a
#define VIRTIO_PCI_QUEUE_ENABLE       0x01c
#define VIRTIO_PCI_QUEUE_NOTIFY_OFF   0x01e
#define VIRTIO_PCI_QUEUE_DESC_LOW     0x020
#define VIRTIO_PCI_QUEUE_DESC_HIGH    0x024
#define VIRTIO_PCI_QUEUE_AVAIL_LOW    0x028
#define VIRTIO_PCI_QUEUE_AVAIL_HIGH   0x02c
#define VIRTIO_PCI_QUEUE_USED_LOW     0x030
#define VIRTIO_PCI_QUEUE_USED_HIGH    0x034

#define VIRTIO_PCI_CFG_OFFSET    0x0000
#define VIRTIO_PCI_ISR_OFFSET    0x1000
#define VIRTIO_PCI_CONFIG_OFFSET 0x2000
#define VIRTIO_PCI_NOTIFY_OFFSET 0x3000

#define VIRTIO_PCI_CAP_LEN 16

#define MAX_QUEUE             8
#define MAX_CONFIG_SPACE_SIZE 256
#define MAX_QUEUE_NUM         16

#define VRING_DESC_F_NEXT     1
#define VRING_DESC_F_WRITE    2
#define VRING_DESC_F_INDIRECT 4

#define VIRTIO_INPUT_EV_SYN 0x00
#define VIRTIO_INPUT_EV_KEY 0x01
#define VIRTIO_INPUT_EV_REL 0x02
#define VIRTIO_INPUT_EV_ABS 0x03
#define VIRTIO_INPUT_EV_REP 0x14

#define BTN_LEFT      0x110
#define BTN_RIGHT     0x111
#define BTN_MIDDLE    0x112
#define BTN_GEAR_DOWN 0x150
#define BTN_GEAR_UP   0x151

#define REL_X     0x00
#define REL_Y     0x01
#define REL_Z     0x02
#define REL_WHEEL 0x08

#define ABS_X 0x00
#define ABS_Y 0x01
#define ABS_Z 0x02

#define VIRTIO_BLK_T_IN        0
#define VIRTIO_BLK_T_OUT       1
#define VIRTIO_BLK_T_FLUSH     4
#define VIRTIO_BLK_T_FLUSH_OUT 5

#define VIRTIO_BLK_S_OK     0
#define VIRTIO_BLK_S_IOERR  1
#define VIRTIO_BLK_S_UNSUPP 2
#define SECTOR_SIZE         512

typedef struct
{
    PhysMemMap *mem_map;
    uint64_t    addr;
    IRQSignal  *irq;
} VIRTIOBusDef;

typedef struct VIRTIODevice VIRTIODevice;

typedef struct
{
    uint32_t ready; /* 0 or 1 */
    uint32_t num;
    uint16_t last_avail_idx;
    uint64_t desc_addr;
    uint64_t avail_addr;
    uint64_t used_addr;
    BOOL     manual_recv;
} QueueState;

typedef struct
{
    uint64_t addr;
    uint32_t len;
    uint16_t flags; /* VRING_DESC_F_x */
    uint16_t next;
} VIRTIODesc;


typedef void               BlockDeviceCompletionFunc(void *opaque, int ret);
typedef struct BlockDevice BlockDevice;

struct BlockDevice
{
    int64_t (*get_sector_count)(BlockDevice *bs);
    int (*read_async)(BlockDevice *bs, uint64_t sector_num, uint8_t *buf, int n, BlockDeviceCompletionFunc *cb,
                      void *opaque);
    int (*write_async)(BlockDevice *bs, uint64_t sector_num, const uint8_t *buf, int n, BlockDeviceCompletionFunc *cb,
                       void *opaque);
    void *opaque;
};

VIRTIODevice *virtio_block_init(VIRTIOBusDef *bus, BlockDevice *bs);

/* console device */

typedef struct
{
    void *opaque;
    void (*write_data)(void *opaque, const uint8_t *buf, int len);
    int (*read_data)(void *opaque, uint8_t *buf, int len);
} CharacterDevice;

VIRTIODevice *virtio_console_init(VIRTIOBusDef *bus, CharacterDevice *cs);
BOOL          virtio_console_can_write_data(VIRTIODevice *s);
void          virtio_console_resize_event(VIRTIODevice *s, int width, int height);

#endif /* VIRTIO_H */
