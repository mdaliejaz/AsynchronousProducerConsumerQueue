#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/delay.h>
#include <linux/crypto.h>
#include <linux/fs.h>
#include "jobs.h"

static DEFINE_MUTEX(compr_mutex);
static DEFINE_MUTEX(dcompr_mutex);

int validate_user_xpress_args(xpress *user_param)
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

	if(user_param->outfile == NULL || IS_ERR(user_param->outfile) ||
		unlikely(!access_ok(VERIFY_WRITE, user_param->outfile,
			sizeof(user_param->outfile)))) {
		pr_err("user parameters are not valid!\n");
		return -EINVAL;
	}

	if(user_param->algo == NULL || IS_ERR(user_param->algo) ||
		unlikely(!access_ok(VERIFY_READ, user_param->algo,
			sizeof(user_param->algo)))) {
		pr_err("user parameters are not valid!\n");
		return -EINVAL;
	}

	if(!(user_param->flag == COMPRESS || user_param->flag == DEFLATE)) {
		pr_err("user parameters are not valid!\n");
		return -EINVAL;
	}

	if(!(strlen_user(user_param->infile) <= MAX_FILE_NAME_LENGTH ||
		strlen_user(user_param->outfile) <= MAX_FILE_NAME_LENGTH)) {
		return -ENAMETOOLONG;
	}
	return 0;
}

int copy_xpress_data_to_kernel(xpress *user_param, xpress *kernel_param)
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

	kernel_param->outfile = kzalloc(strlen(user_param->outfile) + 1,
		GFP_KERNEL);
	if (!kernel_param->outfile) {
		rc = -ENOMEM;
		goto free_infile;
	}
	rc = copy_from_user(kernel_param->outfile, user_param->outfile,
		strlen(user_param->outfile));
	if (rc) {
		printk("Copying of output file failed.\n");
		goto free_outfile;
	}

	kernel_param->algo = kzalloc(strlen(user_param->algo) + 1,
		GFP_KERNEL);
	if (!kernel_param->algo) {
		rc = -ENOMEM;
		goto free_outfile;
	}
	rc = copy_from_user(kernel_param->algo, user_param->algo,
		strlen(user_param->algo));
	if (rc) {
		printk("Copying of cipher name failed.\n");
		goto free_algo;
	}

	rc = copy_from_user(&kernel_param->flag, &user_param->flag, sizeof(int));
	if (rc) {
		printk("Copying of encryption/decryption flag failed.\n");
		goto free_algo;
	}

	return 0;

	free_algo:
		kfree(kernel_param->algo);
	free_outfile:
		kfree(kernel_param->outfile);
	free_infile:
		kfree(kernel_param->infile);
	out:
		return rc;
}

int compress(void *in_buf, void *out_buf, size_t in_len, size_t *out_len,
	char* compr_name) {
	int rc = 0;

	struct crypto_comp *cc = crypto_alloc_comp(compr_name, 0, 0);

	if (IS_ERR(cc)) {
		printk("crypto_alloc_comp failed! Check if the cipher "
			"algorithm is correct.\n");
		return PTR_ERR(cc);
	}

	// compression algorithm
	// COMPR_LZO "lzo"
	// COMPR_ZLIB "deflate"
	if (strcmp(compr_name, "lzo") && strcmp(compr_name, "deflate")) {
		rc = -EINVAL;
		pr_err("unrecognized compression algorithm!\n");
		goto out;
	}

	mutex_lock(&compr_mutex);
	rc = crypto_comp_compress(cc, in_buf, in_len, out_buf,
		(unsigned int *)out_len);
	mutex_unlock(&compr_mutex);
	if (unlikely(rc)) {
		pr_err("cannot compress %d bytes, compressor %s, error %d, "
			"leave data uncompressed.\n", in_len, compr_name, rc);
		memcpy(out_buf, in_buf, in_len);
		*out_len = in_len;
		goto out;
	}

	// /*
	//  * If the data compressed only slightly, it is better to leave it
	//  * uncompressed to improve read speed.
	//  */
	if (in_len - *out_len < 64) {
		printk("same!\n");
		memcpy(out_buf, in_buf, in_len);
		*out_len = in_len;
	}

	out:
		crypto_free_comp(cc);
	return rc;
}

int deflate(void *in_buf, void *out_buf, size_t in_len, size_t *out_len,
	char* dcompr_name) {
	int rc;
	struct crypto_comp *cc = crypto_alloc_comp(dcompr_name, 0, 0);

	if (IS_ERR(cc)) {
		printk("crypto_alloc_comp failed! Check if the cipher "
			"algorithm is correct.\n");
		return PTR_ERR(cc);
	}

	// compression algorithm
	// COMPR_LZO "lzo"
	// COMPR_ZLIB "deflate"
	if (strcmp(dcompr_name, "lzo") && strcmp(dcompr_name, "deflate")) {
		rc = -EINVAL;
		pr_err("unrecognized compression algorithm!\n");
		goto out;
	}

	printk("in_len = %d\n", in_len);
	printk("out_len = %d\n", *out_len);
	mutex_lock(&dcompr_mutex);
	rc = crypto_comp_decompress(cc, in_buf, in_len, out_buf,
		(unsigned int *)out_len);
	mutex_unlock(&dcompr_mutex);
	if (unlikely(rc)) {
		pr_err("cannot decompress %d bytes, decompressor %s, error %d, "
			"leave data uncompressed.\n", in_len, dcompr_name, rc);
		goto out;
	}

	out:
		crypto_free_comp(cc);
	return rc;
}

int do_xpress(xpress *xpress_obj)
{
	int rc = 0, out_exist = 0;
	char *in_buffer, *out_buffer;
	char *tmpfilp_name = "xpressaa6b5d17e373744f14c07f71b22f9549.tmp";
	struct file *infilp, *outfilp, *tmpfilp;
	struct inode *del_inode;
	size_t infile_size, outfile_size;
	struct kstat stat;
	umode_t infile_mode;
	mm_segment_t oldfs;

	// open in/output files the files
	infilp = filp_open(xpress_obj->infile, O_RDONLY, 0);
	rc = validate_file(infilp, 1);
	if(rc) {
		goto close_infilp;
	}
    infilp->f_pos = 0;		/* start offset */
	infile_mode = infilp->f_path.dentry->d_inode->i_mode;
	infile_size = infilp->f_path.dentry->d_inode->i_size;
	outfile_size = infile_size;

	tmpfilp = filp_open(tmpfilp_name, O_WRONLY|O_CREAT, infile_mode);
	rc = validate_file(tmpfilp, 0);
	if(rc) {
		goto close_tmpfilp;
	}
    tmpfilp->f_pos = 0;		/* start offset */
	if(infilp->f_path.dentry->d_inode->i_ino ==
		tmpfilp->f_path.dentry->d_inode->i_ino) {
		rc = -EPERM;
		goto close_tmpfilp;
	}

	out_exist = vfs_stat(xpress_obj->outfile, &stat);
    outfilp = filp_open(xpress_obj->outfile, O_WRONLY|O_CREAT, infile_mode);
	rc = validate_file(outfilp, 0);
	if(rc) {
		goto close_outfilp;
	}
    outfilp->f_pos = 0;		/* start offset */
	if(infilp->f_path.dentry->d_inode->i_ino ==
		outfilp->f_path.dentry->d_inode->i_ino) {
		rc = -EPERM;
		goto close_outfilp;
	}
	if(tmpfilp->f_path.dentry->d_inode->i_ino ==
		outfilp->f_path.dentry->d_inode->i_ino) {
		rc = -EPERM;
		goto close_outfilp;
	}

		// create the buffers
	in_buffer = (char *)kzalloc(infile_size, GFP_KERNEL);
	if (!in_buffer) {
		rc = -ENOMEM;
		goto close_outfilp;
	}
	out_buffer = (char *) kzalloc(infile_size*3, GFP_KERNEL);
	if (!out_buffer) {
		rc = -ENOMEM;
		goto free_in_buffer;
	}

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	switch(xpress_obj->flag) {
	case COMPRESS:
		infilp->f_op->read(infilp, in_buffer, infile_size, &infilp->f_pos);
		rc = compress(in_buffer, out_buffer,
					infile_size, &outfile_size, xpress_obj->algo);
		tmpfilp->f_op->write(tmpfilp, out_buffer, outfile_size,
					&tmpfilp->f_pos);
		// 	&infilp->f_pos)
		// while ((bytes = infilp->f_op->read(infilp, in_buffer, PAGE_SIZE,
		// 	&infilp->f_pos)) > 0) {
		// 	if(bytes < PAGE_SIZE) {
		// 		rc = compress(in_buffer, out_buffer,
		// 			bytes, bytes, xpress_obj->algo);
		// 		tmpfilp->f_op->write(tmpfilp, out_buffer, bytes,
		// 			&tmpfilp->f_pos);
		// 	} else {
		// 		rc = compress(in_buffer, out_buffer,
		// 			PAGE_SIZE, PAGE_SIZE, xpress_obj->algo);
		// 		tmpfilp->f_op->write(tmpfilp, out_buffer, PAGE_SIZE,
		// 			&tmpfilp->f_pos);
		// 	}
		// 	if(rc) {
		// 		printk("Failed while compressing the file.\n");
		// 		goto reset_fs;
		// 	}
		// }
		break;
	case DEFLATE:
		printk("in deflate\n");
		infilp->f_op->read(infilp, in_buffer, infile_size, &infilp->f_pos);
		printk("infile_size = %d\n", infile_size);
		printk("outfile_size = %d\n", outfile_size);
		rc = deflate(in_buffer, out_buffer,
					infile_size, &outfile_size, xpress_obj->algo);
		printk("outfile_size = %d\n", outfile_size);
		tmpfilp->f_op->write(tmpfilp, out_buffer, outfile_size,
					&tmpfilp->f_pos);
	// 	while ((bytes = infilp->f_op->read(infilp, in_buffer, PAGE_SIZE,
	// 		&infilp->f_pos)) > 0) {
	// 		if(bytes < PAGE_SIZE) {
	// 			rc = deflate(in_buffer, out_buffer,
	// 				bytes, bytes, xpress_obj->algo);
	// 			tmpfilp->f_op->write(tmpfilp, out_buffer, bytes,
	// 				&tmpfilp->f_pos);
	// 		} else {
	// 			rc = deflate(in_buffer, out_buffer,
	// 				PAGE_SIZE, PAGE_SIZE, xpress_obj->algo);
	// 			tmpfilp->f_op->write(tmpfilp, out_buffer, PAGE_SIZE,
	// 				&tmpfilp->f_pos);
	// 		}
	// 		if(rc) {
	// 			printk("Failed while deflating the file.\n");
	// 			goto reset_fs;
	// 		}
	// 	}
		break;
	default:
		printk("Unknown Flag!\n");
		goto reset_fs;
	}

	rc = vfs_rename(tmpfilp->f_path.dentry->d_parent->d_inode,
		tmpfilp->f_path.dentry, outfilp->f_path.dentry->d_parent->d_inode,
		outfilp->f_path.dentry, NULL, 0);

	reset_fs:
		set_fs(oldfs);
	kfree(out_buffer);
	free_in_buffer:
		kfree(in_buffer);
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
		if (tmpfilp != NULL && !IS_ERR(tmpfilp)) {
			filp_close(tmpfilp, NULL);
		}
	close_infilp:
		if (infilp && !IS_ERR(infilp))
			filp_close(infilp, NULL);
	return rc;
}
