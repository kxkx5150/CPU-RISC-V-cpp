#ifndef MALLOCZ_H
#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>

inline void *mallocz(size_t size)
{
    void *ptr;
    ptr = malloc(size);
    if (!ptr)
        return NULL;
    memset(ptr, 0, size);
    return ptr;
}
static inline int max_int(int a, int b)
{
    if (a > b)
        return a;
    else
        return b;
}
static inline int min_int(int a, int b)
{
    if (a < b)
        return a;
    else
        return b;
}
static inline int ctz32(uint32_t a)
{
    int i;
    if (a == 0)
        return 32;
    for (i = 0; i < 32; i++) {
        if ((a >> i) & 1)
            return i;
    }
    return 32;
}

static inline uint16_t get_le16(const uint8_t *ptr)
{
    return ptr[0] | (ptr[1] << 8);
}
static inline uint32_t get_le32(const uint8_t *ptr)
{
    return ptr[0] | (ptr[1] << 8) | (ptr[2] << 16) | (ptr[3] << 24);
}

static inline void put_le16(uint8_t *ptr, uint16_t v)
{
    ptr[0] = v;
    ptr[1] = v >> 8;
}
static inline void put_le32(uint8_t *ptr, uint32_t v)
{
    ptr[0] = v;
    ptr[1] = v >> 8;
    ptr[2] = v >> 16;
    ptr[3] = v >> 24;
}
static inline void put_le64(uint8_t *ptr, uint64_t v)
{
    put_le32(ptr, v);
    put_le32(ptr + 4, v >> 32);
}

#define unlikely(x) __builtin_expect(!!(x), 0)
#define likely(x)   __builtin_expect(!!(x), 1)
#ifndef _BOOL_defined
#define _BOOL_defined
#undef FALSE
#undef TRUE
typedef int BOOL;
enum
{
    FALSE = 0,
    TRUE  = 1,
};
#endif
#endif