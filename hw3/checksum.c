#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <crypto/hash.h>
#include "jobs.h"

static DEFINE_MUTEX(checksum_mutex);

int validate_user_checksum_args(checksum *user_param)
{
	if(user_param == NULL || IS_ERR(user_param) ||
		unlikely(!access_ok(VERIFY_READ, user_param, sizeof(user_param)))) {
		pr_err("user parameters are not valid!\n");
		return -EFAULT;
	}

	if(user_param->infile == NULL || IS_ERR(user_param->infile) ||
		unlikely(!access_ok(VERIFY_READ, user_param->infile,
			sizeof(user_param->infile)))) {
		pr_err("user parameters are not valid!\n");
		return -EINVAL;
	}

	if(!(strlen_user(user_param->infile) <= MAX_FILE_NAME_LENGTH)) {
		return -ENAMETOOLONG;
	}
	return 0;
}

int copy_checksum_data_to_kernel(checksum *user_param, checksum *kernel_param)
{
	int rc = 0;

	kernel_param->infile = kzalloc(strlen(user_param->infile) + 1, GFP_KERNEL);
	if (!kernel_param->infile) {
		rc = -ENOMEM;
		goto out;
	}
	rc = copy_from_user(kernel_param->infile, user_param->infile,
		strlen(user_param->infile));
	if (rc) {
		printk("Copying of input file failed.\n");
		goto free_infile;
	}

	return 0;

	free_infile:
		kfree(kernel_param->infile);
	out:
		return rc;
}

int do_checksum(checksum *checksum_obj, char *checksum_result) {
	int rc = 0, size, bytes, i;
	char *read_buffer;
	struct shash_desc *sdescmd5;
	struct crypto_shash *md5;
	struct file *infilp;
	unsigned char pass_hash[MD5_DIGEST_LENGTH];
	/*
	 * This MD5_HASH generation algorithm is inspired by symlink_hash(...)
	 * in http://lxr.fsl.cs.sunysb.edu/linux/source/fs/cifs/link.c#L57
	*/

	read_buffer = (char *)kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!read_buffer) {
		rc = -ENOMEM;
		goto out;
	}

	infilp = filp_open(checksum_obj->infile, O_RDONLY, 0);
	rc = validate_file(infilp, 1);
	if(rc) {
		goto free_read_buffer;
	}
    infilp->f_pos = 0;		/* start offset */

	mutex_lock(&checksum_mutex);
	md5 = crypto_alloc_shash("md5", 0, 0);
	if (md5 == NULL || IS_ERR(md5)) {
		rc = PTR_ERR(md5);
		goto close_infilp;
	}
	size = sizeof(struct shash_desc) + crypto_shash_descsize(md5);
	sdescmd5 = kzalloc(size, GFP_KERNEL);
	if (!sdescmd5) {
		rc = -ENOMEM;
		goto free_shash;
	}

	sdescmd5->tfm = md5;
	sdescmd5->flags = 0x0;

	rc = crypto_shash_init(sdescmd5);
	if (rc){
		goto symlink_hash_err;
	}

	while ((bytes = infilp->f_op->read(infilp, read_buffer, PAGE_SIZE,
			&infilp->f_pos)) != 0) {
		rc = crypto_shash_update(sdescmd5,(const char *) read_buffer, bytes);
		if(rc)
			goto symlink_hash_err;
	}

	if (rc){
		goto symlink_hash_err;
	}

	rc = crypto_shash_final(sdescmd5, pass_hash);
	if (rc){
		goto symlink_hash_err;
	}
	mutex_unlock(&checksum_mutex);

	for(i = 0; i < 16; i++) {
		sprintf(&checksum_result[i*2], "%02x", (unsigned int)pass_hash[i]);
	}

	symlink_hash_err:
		kfree(sdescmd5);
	free_shash:
		crypto_free_shash(md5);
	close_infilp:
		if (infilp && !IS_ERR(infilp))
			filp_close(infilp, NULL);
	free_read_buffer:
		kfree(read_buffer);
	out:
		return rc;
}
