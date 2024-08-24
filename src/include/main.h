#ifndef MAIN_H
#define MAIN_H

#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/pid.h>
#include <linux/rwlock.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/version.h>

#include "ftrace_helper.h"
#include "stealth_helper.h"
#include "utils.h"
#include "king.h"
#include "comms.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Skelly");
MODULE_DESCRIPTION("Basilisk LKM Rootkit");
MODULE_VERSION("2.5");

#endif