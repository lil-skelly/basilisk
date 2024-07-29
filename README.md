/*
 * struct fd {
 *	struct file *file;
 *	unsigned int flags;
 * };
 * struct file {
 	*
	* Protects f_ep, f_flags.
	* Must not be taken from IRQ context.
	*
	spinlock_t		f_lock;
	fmode_t			f_mode;
	atomic_long_t		f_count;
	struct mutex		f_pos_lock;
	loff_t			f_pos;
	unsigned int		f_flags;
	struct fown_struct	f_owner;
	const struct cred	*f_cred;
	struct file_ra_state	f_ra;
	struct path		f_path; <-- THIS IS WHAT WE ARE AFTER
	struct inode		*f_inode;	* cached value 
	const struct file_operations	*f_op;
	
	[ REDACTED ]
 * }
 *
 * struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
 * } __randomize_layout;
 *

    struct fd f = fdget_pos(fd);
    struct path f_path = f.file->f_path;    
    
    // d_path stuff
    char *ret_ptr = NULL; 
    char *tpath = kmalloc(1024, GFP_KERNEL);
   
    int ret;
    char *filename = "king.txt";
    char *resolved_filename;
    
    ret_ptr = d_path(&f_path, tpath, 1024);
    if (IS_ERR(ret_ptr))
	pr_err("basilisk: d_path failed\n");
	goto out_err;
    

    resolved_filename = strrchr(ret_ptr, '/');
    if (resolved_filename)
        resolved_filename++; 
    else
        resolved_filename = ret_ptr; 

    // Compare the extracted filename with the provided filename
    ret = strcmp(resolved_filename, filename) == 0;
    if (ret)
	pr_info("basilisk: attempt reading king.txt");
        goto out_err;

    fdput_pos(f);
    path_put(&f_path);
    kfree(tpath);
    
    return orig_read(regs);

out_err:
    fdput_pos(f);
    path_put(&f_path);
    kfree(tpath);
    return -EIO;
 * We can use the path struct to pass it in the function d_path in order to retrieve the filename.
 * */