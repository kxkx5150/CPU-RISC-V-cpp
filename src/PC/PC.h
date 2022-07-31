#ifndef PC_H
#define PC_H

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <getopt.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/stat.h>
#include <signal.h>
#include <string>

#include "../iomem.h"
#include "../def/PC_def.h"
#include "../cpu.h"
#include "../virtio.h"

class PC {
  public:
    uint64_t ram_size = 134217728;
    uint8_t  max_xlen = 64;

    uint64_t rtc_real_time  = 0;
    uint64_t rtc_start_time = 0;

    uint32_t plic_pending_irq = 0;
    uint32_t plic_served_irq  = 0;

    uint64_t   htif_tohost   = 0;
    uint64_t   htif_fromhost = 0;
    IRQSignal *plic_irq[32];

    int      drive_count = 0;
    uint8_t *ddl         = nullptr;
    uint8_t *krnl        = nullptr;
    uint8_t *fsys        = nullptr;

    uint64_t ddllen  = 0;
    uint64_t krnllen = 0;
    uint64_t fsyslen = 0;

    uint32_t kernel_base = 0;
    uint32_t initrd_base = 0;

    CPU          *cpu         = nullptr;
    BlockDev     *drive       = nullptr;
    PhysMemMap   *mem_map     = nullptr;
    CharDev      *console     = nullptr;
    VIRTIODevice *console_dev = nullptr;
    VMDriveEntry  tab_drive[MAX_DRIVE_DEVICE];

    int virtio_count = 0;

  public:
    PC();
    ~PC();

    void init();
    void load(int binno, std::string path);
    void start();
    void run();

    BlockDev *block_device_init(const char *filename, BlockDevModeEnum mode);

    CharDev *console_init(BOOL allow_ctrlc);
    void     term_init(BOOL allow_ctrlc);
    void     plic_update_mip();
    uint8_t *get_ram_ptr(uint64_t paddr, BOOL is_rw);
    void     htif_handle_cmd();
};
#endif
