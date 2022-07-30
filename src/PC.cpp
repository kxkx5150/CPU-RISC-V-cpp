#include <byteswap.h>
#include "PC.h"
#include "PC_IO.h"

PC::PC()
{
    mem_map = new PhysMemMap();
    cpu     = new CPU(mem_map);
    cpu->riscv_cpu_init64();
}
PC::~PC()
{
    delete cpu;
}
void PC::init()
{
    VIRTIODevice *blk_dev;
    VIRTIOBusDef  vbus_s, *vbus = &vbus_s;

    drive                  = block_device_init("bin/root-riscv64.bin", BF_MODE_SNAPSHOT);
    tab_drive[0].block_dev = drive;
    drive_count++;

    console       = console_init(0);
    rtc_real_time = 0;

    mem_map->register_ram(mem_map, RAM_BASE_ADDR, ram_size, 0);
    mem_map->register_ram(mem_map, 0x00000000, LOW_RAM_SIZE, 0);

    mem_map->cpu_register_device(PLIC_BASE_ADDR, PLIC_SIZE, this, plic_read, plic_write, DEVIO_SIZE32);
    for (int i = 1; i < 32; i++) {
        plic_irq[i] = new IRQSignal();
        plic_irq[i]->irq_init(plic_set_irq, this, i);
    }
    mem_map->cpu_register_device(HTIF_BASE_ADDR, 16, this, htif_read, htif_write, DEVIO_SIZE32);

    memset(vbus, 0, sizeof(*vbus));
    vbus->mem_map = mem_map;
    vbus->addr    = VIRTIO_BASE_ADDR;
    int irq_num   = VIRTIO_IRQ;

    if (console) {
        vbus->irq   = plic_irq[irq_num];
        console_dev = (VIRTIODevice *)new VIRTIOConsoleDevice(vbus, console);
        vbus->addr += VIRTIO_SIZE;
        irq_num++;
        virtio_count++;
    }

    for (int i = 0; i < drive_count; i++) {
        vbus->irq = plic_irq[irq_num];
        blk_dev   = (VIRTIODevice *)new VIRTIOBlockDevice(vbus, tab_drive[i].block_dev);
        (void)blk_dev;
        vbus->addr += VIRTIO_SIZE;
        irq_num++;
        virtio_count++;
    }

    load(0, "bin/bbl64.bin");
    load(1, "bin/kernel-riscv64.bin");
    load(2, "bin/kernel-riscv64.bin");
    start();
}
void PC::load(int binno, std::string path)
{
    FILE *f = fopen(path.c_str(), "rb");
    fseek(f, 0, SEEK_END);
    const int size = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buffer = new uint8_t[size];
    auto     _      = fread(buffer, size, 1, f);

    uint8_t *ram_ptr = mem_map->phys_mem_get_ram_ptr(RAM_BASE_ADDR, TRUE);

    if (binno == 0) {
        ddl    = buffer;
        ddllen = size;
        memcpy(ram_ptr, buffer, size);
    } else if (binno == 1) {
        krnl           = buffer;
        krnllen        = size;
        uint32_t align = 2 << 20;
        kernel_base    = (ddllen + align - 1) & ~(align - 1);
        memcpy(ram_ptr + kernel_base, buffer, krnllen);
        if (krnllen + kernel_base > ram_size) {
            fclose(f);
            exit(1);
        }
    } else if (binno == 2) {
        fsys        = buffer;
        fsyslen     = size;
        initrd_base = ram_size / 2;
        if (initrd_base > (128 << 20))
            initrd_base = 128 << 20;

        memcpy(ram_ptr + initrd_base, fsys, fsyslen);
        if (size + initrd_base > ram_size) {
            fclose(f);
            exit(1);
        }
    }

    fclose(f);
}
void PC::start()
{
    std::string cmd_line = "console=hvc0 root=/dev/vda rw";
    uint8_t    *ram_ptr  = get_ram_ptr(this, 0, TRUE);
    uint32_t    fdt_addr = 0x1000 + 8 * 8;
    build_fdt(this, ram_ptr + fdt_addr, RAM_BASE_ADDR + kernel_base, krnllen, RAM_BASE_ADDR + initrd_base, fsyslen,
              cmd_line.c_str());

    uint32_t *q;
    q    = (uint32_t *)(ram_ptr + 0x1000);
    q[0] = 0x297 + 0x80000000 - 0x1000;      /* auipc t0, jump_addr */
    q[1] = 0x597;                            /* auipc a1, dtb */
    q[2] = 0x58593 + ((fdt_addr - 4) << 20); /* addi a1, a1, dtb */
    q[3] = 0xf1402573;                       /* csrr a0, mhartid */
    q[4] = 0x00028067;
}
void PC::run()
{
    fd_set         rfds, wfds, efds;
    int            fd_max, ret, delay;
    struct timeval tv;
    int            stdin_fd;

    delay  = 0;
    fd_max = -1;
    cpu->riscv_cpu_interp64(MAX_EXEC_CYCLE);
}
