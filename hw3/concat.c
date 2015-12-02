#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include "jobs.h"

static DEFINE_MUTEX(flock_mutex);

int validate_user_concat_args(concat *user_param)
{
	int i;

	if(user_param == NULL || IS_ERR(user_param) ||
		unlikely(!access_ok(VERIFY_READ, user_param, sizeof(user_param)))) {
		pr_err("user parameters are not valid!\n");
		return -EFAULT;
	}


	for(i = 0; i <= user_param->infile_count; i++) {
		if(user_param->infiles[i] == NULL || IS_ERR(user_param->infiles[i]) ||
			unlikely(!access_ok(VERIFY_READ, user_param->infiles[i],
				sizeof(user_param->infiles[i])))) {
			pr_err("user parameters are not valid!\n");
			return -EINVAL;
		}

		if(!(strlen_user(user_param->infiles[i]) <= MAX_FILE_NAME_LENGTH)) {
			pr_err("The maximum size of filename allowed is 255 "
				"characters One of your file name exceeds the allowed "
				"limit.\n");
			return -1;
		}
	}

	if(user_param->outfile == NULL || IS_ERR(user_param->outfile) ||
		unlikely(!access_ok(VERIFY_WRITE, user_param->outfile,
			sizeof(user_param->outfile)))) {
		pr_err("user parameters are not valid!\n");
		return -EINVAL;
	}

	if(!(user_param->infile_count > 2)) {
		pr_err("user parameters are not valid!\n");
		return -EINVAL;
	}

	if(!(strlen_user(user_param->outfile) <= MAX_FILE_NAME_LENGTH)) {
		return -ENAMETOOLONG;
	}

	return 0;
}

int copy_concat_data_to_kernel(concat *user_param, concat *kernel_param)
{
	int rc = 0, i;

	kernel_param->infiles = kzalloc(sizeof(char*) * user_param->infile_count,
		GFP_KERNEL);
	if (!kernel_param->infiles) {
		rc = -ENOMEM;
		goto out;
	}

	for(i = 0; i < user_param->infile_count; i++) {
		kernel_param->infiles[i] = kzalloc(strlen(user_param->infiles[i]) + 1,
			GFP_KERNEL);
		if (!kernel_param->infiles[i]) {
			rc = -ENOMEM;
			goto out;
		}
		rc = copy_from_user(kernel_param->infiles[i], user_param->infiles[i],
			strlen(user_param->infiles[i]));
		if (rc) {
			printk("Copying of input file failed.\n");
			goto free_infiles;
		}
	}

	kernel_param->outfile = kzalloc(strlen(user_param->outfile) + 1,
		GFP_KERNEL);
	if (!kernel_param->outfile) {
		rc = -ENOMEM;
		goto free_infiles;
	}
	rc = copy_from_user(kernel_param->outfile, user_param->outfile,
		strlen(user_param->outfile));
	if (rc) {
		printk("Copying of output file failed.\n");
		goto free_outfile;
	}

	rc = copy_from_user(&kernel_param->infile_count, &user_param->infile_count,
		sizeof(int));
	if (rc) {
		printk("Copying of key buffer length failed.\n");
		goto free_outfile;
	}

	return 0;

	free_outfile:
		kfree(kernel_param->outfile);
	free_infiles:
		for(i = 0; i < user_param->infile_count; i++) {
			kfree(kernel_param->infiles[i]);
		}
		kfree(kernel_param->infiles);
	out:
		return rc;
}

int do_concat(concat *concat_obj)
{
	int rc = 0, out_exist = 0, i, bytes, sleep_time = 500, obtained_lock = 0;
	char infilp_lock_name[256], outfilp_lock_name[256];
	char *buffer;
	char *tmpfilp_name = "concataa6b5d17e373744f14c07f71b22f9549.tmp";
	struct file *infilp = NULL, *outfilp, *tmpfilp, *infilp_lock = NULL, *outfilp_lock = NULL;
	mode_t mode;
	struct kstat stat;
	struct inode *del_inode;
	mm_segment_t oldfs;

	sprintf(outfilp_lock_name, "%s.lock", concat_obj->outfile);

	while(!obtained_lock) {
		mutex_lock(&flock_mutex);
		if(vfs_stat(outfilp_lock_name, &stat) != 0) {
			outfilp_lock = filp_open(outfilp_lock_name, O_WRONLY|O_CREAT, 0444);
			obtained_lock = 1;
			mutex_unlock(&flock_mutex);
		} else {
			mutex_unlock(&flock_mutex);
			if(sleep_time > 10000) {
				rc = -EBUSY;
				pr_err("Couldn't get lock even after waiting for more "
					"than 30 seconds! Exiting.\n");
				goto out;
			}
			sleep_time = sleep_time * 2;
			printk("Cannot get lock on output file. Sleeping for %d "
				"msec!\n", sleep_time);
			msleep(sleep_time);
		}
	}

	buffer = (char *)kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buffer) {
		rc = -ENOMEM;
		goto out;
	}

	mode = 0644;
	tmpfilp = filp_open(tmpfilp_name, O_WRONLY|O_CREAT, mode);
	rc = validate_file(tmpfilp, 0);
	if(rc) {
		goto close_tmpfilp;
	}
    tmpfilp->f_pos = 0;		/* start offset */

	out_exist = vfs_stat(concat_obj->outfile, &stat);
    outfilp = filp_open(concat_obj->outfile, O_WRONLY|O_CREAT, mode);
	rc = validate_file(outfilp, 0);
	if(rc) {
		goto close_outfilp;
	}
    outfilp->f_pos = 0;		/* start offset */
	if(tmpfilp->f_path.dentry->d_inode->i_ino ==
		outfilp->f_path.dentry->d_inode->i_ino) {
		rc = -EPERM;
		goto close_outfilp;
	}

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	for (i = 0; i < concat_obj->infile_count; i++) {
		obtained_lock = 0;
		sleep_time = 500;
		sprintf(infilp_lock_name, "%s.lock", concat_obj->infiles[i]);
		while(!obtained_lock) {
			mutex_lock(&flock_mutex);
			if(vfs_stat(infilp_lock_name, &stat) != 0) {
				infilp_lock = filp_open(infilp_lock_name, O_WRONLY|O_CREAT, 0444);
				obtained_lock = 1;
				mutex_unlock(&flock_mutex);
			} else {
				mutex_unlock(&flock_mutex);
				if(sleep_time > 10000) {
					rc = -EBUSY;
					pr_err("Couldn't get lock even after waiting for more "
						"than 30 seconds! Exiting.\n");
					goto reset_fs;
				}
				sleep_time = sleep_time * 2;
				printk("Cannot get lock on input file. Sleeping for %d "
					"msec!\n", sleep_time);
				msleep(sleep_time);
			}
		}

		infilp = filp_open(concat_obj->infiles[i], O_RDONLY, 0);
		rc = validate_file(infilp, 1);
		if(rc) {
			goto reset_fs;
		}
	    infilp->f_pos = 0;		/* start offset */

	    if(infilp->f_path.dentry->d_inode->i_ino ==
			outfilp->f_path.dentry->d_inode->i_ino) {
			rc = -EPERM;
			goto reset_fs;
		}
		if(infilp->f_path.dentry->d_inode->i_ino ==
			tmpfilp->f_path.dentry->d_inode->i_ino) {
			rc = -EPERM;
			goto reset_fs;
		}

		while ((bytes = infilp->f_op->read(infilp, buffer, PAGE_SIZE,
			&infilp->f_pos)) > 0) {
			tmpfilp->f_op->write(tmpfilp, buffer, bytes, &tmpfilp->f_pos);
		}

		if (infilp && !IS_ERR(infilp)) {
			filp_close(infilp, NULL);
			infilp = NULL;
		}

		if (infilp_lock && !IS_ERR(infilp_lock)) {
			if(infilp_lock->f_path.dentry != NULL &&
				infilp_lock->f_path.dentry->d_parent->d_inode != NULL) {
				vfs_unlink(infilp_lock->f_path.dentry->d_parent->d_inode,
					infilp_lock->f_path.dentry, &del_inode);
			}
			infilp_lock = NULL;
		}
	}

	rc = vfs_rename(tmpfilp->f_path.dentry->d_parent->d_inode,
		tmpfilp->f_path.dentry, outfilp->f_path.dentry->d_parent->d_inode,
		outfilp->f_path.dentry, NULL, 0);

reset_fs:
	set_fs(oldfs);
	if (infilp && !IS_ERR(infilp))
		filp_close(infilp, NULL);
close_outfilp:
	if(out_exist && rc < 0) {
		vfs_unlink(outfilp->f_path.dentry->d_parent->d_inode,
			outfilp->f_path.dentry, &del_inode);
		outfilp = NULL;
	}
	if (outfilp != NULL && !IS_ERR(outfilp)) {
		filp_close(outfilp, NULL);
	}
close_tmpfilp:
	if (rc < 0 && tmpfilp != NULL && !IS_ERR(tmpfilp)) {
		if(tmpfilp->f_path.dentry != NULL &&
			tmpfilp->f_path.dentry->d_parent->d_inode != NULL) {
			vfs_unlink(tmpfilp->f_path.dentry->d_parent->d_inode,
				tmpfilp->f_path.dentry, &del_inode);
		}
		tmpfilp = NULL;
	}
	if (tmpfilp != NULL && !IS_ERR(tmpfilp))
		filp_close(tmpfilp, NULL);
	kfree(buffer);
out:
	if (infilp_lock && !IS_ERR(infilp_lock)) {
		if(infilp_lock->f_path.dentry != NULL &&
			infilp_lock->f_path.dentry->d_parent->d_inode != NULL) {
			vfs_unlink(infilp_lock->f_path.dentry->d_parent->d_inode,
				infilp_lock->f_path.dentry, &del_inode);
		}
		infilp_lock = NULL;
	}
	if (outfilp_lock && !IS_ERR(outfilp_lock)) {
		if(outfilp_lock->f_path.dentry != NULL &&
			outfilp_lock->f_path.dentry->d_parent->d_inode != NULL) {
			vfs_unlink(outfilp_lock->f_path.dentry->d_parent->d_inode,
				outfilp_lock->f_path.dentry, &del_inode);
		}
		outfilp_lock = NULL;
	}

	return rc;
}
