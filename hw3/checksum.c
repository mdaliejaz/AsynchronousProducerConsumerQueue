#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <crypto/hash.h>
#include "jobs.h"

static DEFINE_MUTEX(checksum_mutex);
static DEFINE_MUTEX(checksum_flock_mutex);

int validate_user_checksum_args(checksum *user_param)
{
	if (user_param == NULL || IS_ERR(user_param) ||
		unlikely(!access_ok(VERIFY_READ, user_param,
			sizeof(user_param)))) {
		pr_err("user parameters are not valid!\n");
		return -EFAULT;
	}

	if (user_param->infile == NULL || IS_ERR(user_param->infile) ||
		unlikely(!access_ok(VERIFY_READ, user_param->infile,
			sizeof(user_param->infile)))) {
		pr_err("user parameters are not valid!\n");
		return -EINVAL;
	}

	if (user_param->algo == NULL || IS_ERR(user_param->algo) ||
		unlikely(!access_ok(VERIFY_READ, user_param->algo,
			sizeof(user_param->algo)))) {
		pr_err("user parameters are not valid!\n");
		return -EINVAL;
	}

	if (!(strlen_user(user_param->infile) <= MAX_FILE_NAME_LENGTH))
		return -ENAMETOOLONG;
	return 0;
}

int copy_checksum_data_to_kernel(checksum *user_param, checksum *kernel_param)
{
	int rc = 0;

	kernel_param->infile = kzalloc(strlen(user_param->infile) + 1,
		GFP_KERNEL);
	if (!kernel_param->infile) {
		rc = -ENOMEM;
		goto out;
	}
	rc = copy_from_user(kernel_param->infile, user_param->infile,
		strlen(user_param->infile));
	if (rc) {
		pr_err("Copying of input file failed.\n");
		goto free_infile;
	}
	kernel_param->algo = kzalloc(strlen(user_param->algo) + 1, GFP_KERNEL);
	if (!kernel_param->algo) {
		rc = -ENOMEM;
		goto free_infile;
	}
	rc = copy_from_user(kernel_param->algo, user_param->algo,
		strlen(user_param->algo));
	if (rc) {
		pr_err("Copying of input algorithm failed.\n");
		goto free_algo;
	}

	return 0;

free_infile:
	kfree(kernel_param->infile);
free_algo:
	kfree(kernel_param->algo);
out:
	return rc;
}

int do_checksum(checksum *checksum_obj, char *checksum_result)
{
	int rc = 0, size, bytes, i, obtained_lock = 0, sleep_time = 500;
	char *read_buffer, infilp_lock_name[270];
	struct shash_desc *sdescmd5;
	struct crypto_shash *shash;
	struct file *infilp = NULL, *infilp_lock = NULL;
	struct kstat stat;
	struct inode *del_inode;
	unsigned char pass_hash[MD5_DIGEST_LENGTH];

	if (strcmp(checksum_obj->algo, "rmd320") == 0) {
		pr_err("'rmd320' shash algorithm is not supported.\n");
		rc = -EINVAL;
		goto out;
	}

	shash = crypto_alloc_shash(checksum_obj->algo, 0, 0);
	if (shash == NULL || IS_ERR(shash)) {
		pr_err("crypto_alloc_shash failed! Check if the checksum "
			"algorithm is correct.\n");
		rc = -EINVAL;
		goto out;
	}

	sprintf(infilp_lock_name, "%s.lock", checksum_obj->infile);
	while (!obtained_lock) {
		mutex_lock(&checksum_flock_mutex);
		if (vfs_stat(infilp_lock_name, &stat) != 0) {
			infilp_lock = filp_open(infilp_lock_name,
				O_WRONLY|O_CREAT, 0444);
			obtained_lock = 1;
			pr_debug("Obtained lock!\n");
			mutex_unlock(&checksum_flock_mutex);
		} else {
			mutex_unlock(&checksum_flock_mutex);
			if (sleep_time > 10000) {
				rc = -EBUSY;
				pr_err("Couldn't get lock even after waiting for more "
					"than 30 seconds! Exiting.\n");
				goto free_shash;
			}
			sleep_time = sleep_time * 2;
			pr_debug("Cannot get lock on input file. Sleeping for %d "
				"msec!\n", sleep_time);
			msleep(sleep_time);
		}
	}

	read_buffer = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!read_buffer) {
		rc = -ENOMEM;
		goto release_lock;
	}

	infilp = filp_open(checksum_obj->infile, O_RDONLY, 0);
	rc = validate_file(infilp, 1);
	if (rc)
		goto free_read_buffer;
	infilp->f_pos = 0;		/* start offset */

	size = sizeof(struct shash_desc) + crypto_shash_descsize(shash);
	sdescmd5 = kzalloc(size, GFP_KERNEL);
	if (!sdescmd5) {
		rc = -ENOMEM;
		goto close_infilp;
	}

	sdescmd5->tfm = shash;
	sdescmd5->flags = 0x0;

	rc = crypto_shash_init(sdescmd5);
	if (rc)
		goto symlink_hash_err;

	mutex_lock(&checksum_mutex);
	while ((bytes = infilp->f_op->read(infilp, read_buffer, PAGE_SIZE,
			&infilp->f_pos)) != 0) {
		rc = crypto_shash_update(sdescmd5, (const char *) read_buffer,
			bytes);
		if (rc)
			goto symlink_hash_err;
	}
	mutex_unlock(&checksum_mutex);

	rc = crypto_shash_final(sdescmd5, pass_hash);
	if (rc)
		goto symlink_hash_err;

	for (i = 0; i < 16; i++)
		sprintf(&checksum_result[i*2], "%02x",
			(unsigned int)pass_hash[i]);

symlink_hash_err:
	kfree(sdescmd5);
close_infilp:
	if (infilp && !IS_ERR(infilp))
		filp_close(infilp, NULL);
free_read_buffer:
	kfree(read_buffer);
release_lock:
	if (infilp_lock && !IS_ERR(infilp_lock)) {
		if (infilp_lock->f_path.dentry != NULL &&
			infilp_lock->f_path.dentry->d_parent->d_inode != NULL) {
			vfs_unlink(infilp_lock->f_path.dentry->d_parent->d_inode,
				infilp_lock->f_path.dentry, &del_inode);
		}
		infilp_lock = NULL;
	}
free_shash:
	if (shash)
		crypto_free_shash(shash);
out:
	return rc;
}
