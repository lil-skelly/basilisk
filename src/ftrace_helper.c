#include "include/ftrace_helper.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
static unsigned long lookup_name(const char *name) {
  struct kprobe kp = {.symbol_name = name};
  unsigned long retval;

  if (register_kprobe(&kp) < 0)
    return 0;
  retval = (unsigned long)kp.addr;
  unregister_kprobe(&kp);
  return retval;
}
#else
static unsigned long lookup_name(const char *name) {
  return kallsyms_lookup_name(name);
}
#endif

static int fh_resolve_hook_address(struct ftrace_hook *hook) {
  hook->address = lookup_name(hook->name);

  if (!hook->address) {
    pr_debug("unresolved symbol: %s\n", hook->name);
    return -ENOENT;
  }

#if USE_FENTRY_OFFSET
  *((unsigned long *)hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
  *((unsigned long *)hook->original) = hook->address;
#endif

  return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                    struct ftrace_ops *ops,
                                    struct ftrace_regs *fregs) {
  struct pt_regs *regs = ftrace_get_regs(fregs);
  struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
  regs->ip = (unsigned long)hook->function;
#else
  if (!within_module(parent_ip, THIS_MODULE))
    regs->ip = (unsigned long)hook->function;
#endif
}

/**
 * fh_install_hooks() - register and enable a single hook
 * @hook: a hook to install
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hook(struct ftrace_hook *hook) {
  int err;

  err = fh_resolve_hook_address(hook);
  if (err)
    return err;

  /*
   * We're going to modify %rip register so we'll need IPMODIFY flag
   * and SAVE_REGS as its prerequisite. ftrace's anti-recursion guard
   * is useless if we change %rip so disable it with RECURSION.
   * We'll perform our own checks for trace function reentry.
   */
  hook->ops.func = fh_ftrace_thunk;
  hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION |
                    FTRACE_OPS_FL_IPMODIFY;

  err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
  if (err) {
    pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
    return err;
  }

  err = register_ftrace_function(&hook->ops);
  if (err) {
    pr_debug("register_ftrace_function() failed: %d\n", err);
    ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    return err;
  }

  return 0;
}

/**
 * fh_remove_hooks() - disable and unregister a single hook
 * @hook: a hook to remove
 */
void fh_remove_hook(struct ftrace_hook *hook) {
  int err;

  err = unregister_ftrace_function(&hook->ops);
  if (err) {
    pr_debug("unregister_ftrace_function() failed: %d\n", err);
  }

  err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
  if (err) {
    pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
  }
}

/**
 * fh_install_hooks() - register and enable multiple hooks
 * @hooks: array of hooks to install
 * @count: number of hooks to install
 *
 * If some hooks fail to install then all hooks will be removed.
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hooks(struct ftrace_hook *hooks, size_t count) {
  int err;
  size_t i;

  for (i = 0; i < count; i++) {
    err = fh_install_hook(&hooks[i]);
    if (err)
      goto error;
  }

  return 0;

error:
  while (i != 0) {
    fh_remove_hook(&hooks[--i]);
  }

  return err;
}

/**
 * fh_remove_hooks() - disable and unregister multiple hooks
 * @hooks: array of hooks to remove
 * @count: number of hooks to remove
 */
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count) {
  size_t i;

  for (i = 0; i < count; i++)
    fh_remove_hook(&hooks[i]);
}