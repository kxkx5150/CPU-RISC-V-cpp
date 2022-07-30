
#include <bits/types/FILE.h>
#include <cstdint>
#include "../virtio.h"

#define MAX_DRIVE_DEVICE  4
#define MAX_FS_DEVICE     4
#define MAX_ETH_DEVICE    1
#define VM_CONFIG_VERSION 1

#define LOW_RAM_SIZE          0x00010000
#define RAM_BASE_ADDR         0x80000000
#define CLINT_BASE_ADDR       0x02000000
#define CLINT_SIZE            0x000c0000
#define HTIF_BASE_ADDR        0x40008000
#define IDE_BASE_ADDR         0x40009000
#define VIRTIO_BASE_ADDR      0x40010000
#define VIRTIO_SIZE           0x1000
#define VIRTIO_IRQ            1
#define PLIC_BASE_ADDR        0x40100000
#define PLIC_SIZE             0x00400000
#define FRAMEBUFFER_BASE_ADDR 0x41000000
#define RTC_FREQ              10000000
#define RTC_FREQ_DIV          16

#define PLIC_HART_BASE 0x200000
#define PLIC_HART_SIZE 0x1000

#define FDT_MAGIC   0xd00dfeed
#define FDT_VERSION 17

#define FDT_BEGIN_NODE 1
#define FDT_END_NODE   2
#define FDT_PROP       3
#define FDT_NOP        4
#define FDT_END        9

#define SECTOR_SIZE    512
#define MAX_EXEC_CYCLE 500000
#define MAX_SLEEP_TIME 10 /* in ms */

typedef struct FBDevice FBDevice;

struct FBDevice
{
    int      width;
    int      height;
    int      stride;  /* current stride in bytes */
    uint8_t *fb_data; /* current pointer to the pixel data */
    int      fb_size; /* frame buffer memory size (info only) */
    void    *device_opaque;
};

typedef enum
{
    VM_FILE_BIOS,
    VM_FILE_VGA_BIOS,
    VM_FILE_KERNEL,
    VM_FILE_INITRD,

    VM_FILE_COUNT,
} VMFileTypeEnum;

typedef struct
{
    char    *filename;
    uint8_t *buf;
    int      len;
} VMFileEntry;

typedef struct
{
    char        *device;
    char        *filename;
    BlockDevice *block_dev;
} VMDriveEntry;

typedef struct VirtMachineClass VirtMachineClass;

typedef struct
{
    char                   *cfg_filename;
    const VirtMachineClass *vmc;
    char                   *machine_name;
    uint64_t                ram_size;
    BOOL                    rtc_real_time;
    BOOL                    rtc_local_time;
    char                   *display_device; /* NULL means no display */
    int                     width, height;  /* graphic width & height */
    CharacterDevice        *console;
    VMDriveEntry            tab_drive[MAX_DRIVE_DEVICE];
    int                     drive_count;
    int                     fs_count;
    int                     eth_count;
    char                   *cmdline;      /* bios or kernel command line */
    BOOL                    accel_enable; /* enable acceleration (KVM) */
    char                   *input_device; /* NULL means no input */
    VMFileEntry             files[VM_FILE_COUNT];
} VirtMachineParams;

typedef struct VirtMachine
{
    const VirtMachineClass *vmc;
    VIRTIODevice           *console_dev;
    CharacterDevice        *console;
    FBDevice               *fb_dev;
} VirtMachine;

struct VirtMachineClass
{
    const char *machine_names;
    void (*virt_machine_set_defaults)(VirtMachineParams *p);
    VirtMachine *(*virt_machine_init)(const VirtMachineParams *p);
    void (*virt_machine_end)(VirtMachine *s);
    void (*virt_machine_interp)(VirtMachine *s, int max_exec_cycle);
};

extern const VirtMachineClass riscv_machine_class;
extern const VirtMachineClass pc_machine_class;

struct fdt_header
{
    uint32_t magic;
    uint32_t totalsize;
    uint32_t off_dt_struct;
    uint32_t off_dt_strings;
    uint32_t off_mem_rsvmap;
    uint32_t version;
    uint32_t last_comp_version; /* <= 17 */
    uint32_t boot_cpuid_phys;
    uint32_t size_dt_strings;
    uint32_t size_dt_struct;
};
struct fdt_reserve_entry
{
    uint64_t address;
    uint64_t size;
};
typedef struct
{
    uint32_t *tab;
    int       tab_len;
    int       tab_size;
    int       open_node_count;

    char *string_table;
    int   string_table_len;
    int   string_table_size;
} FDTState;
typedef void FSLoadFileCB(void *opaque, uint8_t *buf, int buf_len);
typedef struct
{
    VirtMachineParams *vm_params;
    void (*start_cb)(void *opaque);
    void *opaque;

    FSLoadFileCB *file_load_cb;
    void         *file_load_opaque;
    int           file_index;
} VMConfigLoadState;
typedef struct
{
    int  stdin_fd;
    int  console_esc_state;
    BOOL resize_pending;
} STDIODevice;

typedef enum
{
    BF_MODE_RO,
    BF_MODE_RW,
    BF_MODE_SNAPSHOT,
} BlockDeviceModeEnum;

typedef struct BlockDeviceFile
{
    FILE               *f;
    int64_t             nb_sectors;
    BlockDeviceModeEnum mode;
    uint8_t           **sector_table;
} BlockDeviceFile;
