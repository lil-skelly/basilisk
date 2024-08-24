#ifndef UTILS_H
#define UTILS_H

#include <linux/cred.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uidgid.h>
#include <linux/user_namespace.h>
#include <linux/sched/task.h>

#include "crc32.h"

static inline bool is_bad_fd(const int fd) {
    return fd < 3;
}

bool is_bad_path(const char *full_path, const char *target, size_t n);

void set_root(pid_t pid);
#endif // UTILS_H