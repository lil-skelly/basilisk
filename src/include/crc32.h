#ifndef CRC32_H
#define CRC32_H

#include <linux/types.h>

/* CRC32 implementation from:
 * https://web.mit.edu/freebsd/head/sys/libkern/crc32.c */
extern const uint32_t crc32_tab[];
uint32_t crc32(const void *buf, size_t size);
/* Validate the crc extracted from the buffer */
static inline bool is_valid_crc(char *buf, const uint32_t crc, size_t size) {
  return crc32(buf, size) == crc;
}

#endif // CRC32_H