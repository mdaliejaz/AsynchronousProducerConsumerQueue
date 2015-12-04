#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/fs.h>
#include <crypto/hash.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <asm/string.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include "jobs.h"

#define CEPH_AES_IV "muhammadaliejazz"

const u8 *aes_iv = (u8 *) CEPH_AES_IV;

static DEFINE_MUTEX(md5_mutex);
static DEFINE_MUTEX(encrypt_mutex);
static DEFINE_MUTEX(decrypt_mutex);
static DEFINE_MUTEX(xcrypt_flock_mutex);

int validate_user_xcrypt_args(xcrypt *user_param)
{
	if(user_param == NULL || IS_ERR(user_param) ||
		unlikely(!access_ok(VERIFY_READ, user_param, sizeof(user_param)))) {
		pr_err("En/Decryption User Parameters are Not Valid!\n");
		return -EFAULT;
	}

	if(user_param->infile == NULL || IS_ERR(user_param->infile) ||
		unlikely(!access_ok(VERIFY_READ, user_param->infile,
			sizeof(user_param->infile)))) {
		pr_err("En/Decryption Input File Parameter is Not Valid!\n");
		return -EINVAL;
	}

	if(user_param->outfile == NULL || IS_ERR(user_param->outfile) ||
		unlikely(!access_ok(VERIFY_WRITE, user_param->outfile,
			sizeof(user_param->outfile)))) {
		pr_err("En/Decryption Output File Parameter is Not Valid!\n");
		return -EINVAL;
	}

	if(user_param->cipher == NULL || IS_ERR(user_param->cipher) ||
		unlikely(!access_ok(VERIFY_READ, user_param->cipher,
			sizeof(user_param->cipher)))) {
		pr_err("En/Decryption Cipher Parameter is Not Valid!\n");
		return -EINVAL;
	}

	if(user_param->keybuf == NULL || IS_ERR(user_param->keybuf) ||
		unlikely(!access_ok(VERIFY_READ, user_param->keybuf,
			sizeof(user_param->keybuf)))) {
		pr_err("En/Decryption Passphrase Parameter is Not Valid!\n");
		return -EINVAL;
	}

	if(!(user_param->flag == 1 || user_param->flag == 2)) {
		pr_err("En/Decryption User Parameters are Not Valid!\n");
		return -EINVAL;
	}

	if(!(strlen_user(user_param->infile) <= MAX_FILE_NAME_LENGTH ||
		strlen_user(user_param->outfile) <= MAX_FILE_NAME_LENGTH)) {
		pr_err("En/Decryption Input/Output File is too long!\n");
		return -ENAMETOOLONG;
	}

	return 0;
}

int copy_xcrypt_data_to_kernel(xcrypt *user_param, xcrypt *kernel_param)
{
	int rc = 0;

	kernel_param->infile = kzalloc(strlen(user_param->infile) + 1, GFP_KERNEL);
	if (!kernel_param->infile) {
		pr_err("En/Decryption Input File: Failed to allocate memeory.\n");
		rc = -ENOMEM;
		goto out;
	}
	rc = copy_from_user(kernel_param->infile, user_param->infile,
		strlen(user_param->infile));
	if (rc) {
		printk("En/Decryption: Copying of input file failed.\n");
		goto free_infile;
	}

	kernel_param->outfile = kzalloc(strlen(user_param->outfile) + 1,
		GFP_KERNEL);
	if (!kernel_param->outfile) {
		pr_err("En/Decryption Output File: Failed to allocate memeory.\n");
		rc = -ENOMEM;
		goto free_infile;
	}
	rc = copy_from_user(kernel_param->outfile, user_param->outfile,
		strlen(user_param->outfile));
	if (rc) {
		printk("En/Decryption: Copying of output file failed.\n");
		goto free_outfile;
	}

	kernel_param->cipher = kzalloc(strlen(user_param->cipher) + 1,
		GFP_KERNEL);
	if (!kernel_param->cipher) {
		pr_err("En/Decryption Cipher: Failed to allocate memeory.\n");
		rc = -ENOMEM;
		goto free_outfile;
	}
	rc = copy_from_user(kernel_param->cipher, user_param->cipher,
		strlen(user_param->cipher));
	if (rc) {
		printk("En/Decryption: Copying of cipher name failed.\n");
		goto free_cipher;
	}

	kernel_param->keybuf = kzalloc(strlen(user_param->keybuf) + 1,
		GFP_KERNEL);
	if (!kernel_param->keybuf) {
		pr_err("En/Decryption Passphrase: Failed to allocate memeory.\n");
		rc = -ENOMEM;
		goto free_cipher;
	}
	rc = copy_from_user(kernel_param->keybuf, user_param->keybuf,
		strlen(user_param->keybuf));
	if (rc) {
		printk("En/Decryption: Copying of Passphrase failed.\n");
		goto free_keybuf;
	}

	rc = copy_from_user(&kernel_param->keylen, &user_param->keylen,
		sizeof(int));
	if (rc) {
		printk("En/Decryption: Copying of key buffer length failed.\n");
		goto free_keybuf;
	}

	rc = copy_from_user(&kernel_param->flag, &user_param->flag, sizeof(int));
	if (rc) {
		printk("En/Decryption: Copying of encryption/decryption flag "
			"failed.\n");
		goto free_keybuf;
	}

	goto out;

free_keybuf:
	if(kernel_param->keybuf)
		kfree(kernel_param->keybuf);
free_cipher:
	if(kernel_param->cipher)
		kfree(kernel_param->cipher);
free_outfile:
	if(kernel_param->outfile)
		kfree(kernel_param->outfile);
free_infile:
	if(kernel_param->infile)
		kfree(kernel_param->infile);
out:
	return rc;
}

int getMD5Hash(char *str, u8 *md5_hash)
{
	int rc = 0, size;
	struct shash_desc *sdescmd5;
	struct crypto_shash *md5;
	/*
	 * This MD5_HASH generation algorithm is copied from symlink_hash(...)
	 * in http://lxr.fsl.cs.sunysb.edu/linux/source/fs/cifs/link.c#L57
	 * There are some changes that I've done in this method to suit my needs.
	 */
	/* ********* MD5_HASH generating ****** */

	mutex_lock(&md5_mutex);
	md5 = crypto_alloc_shash("md5", 0, 0);
	if (md5 == NULL || IS_ERR(md5)) {
		rc = PTR_ERR(md5);
		goto out;
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

	rc = crypto_shash_update(sdescmd5,(const char *) str, strlen(str));
	if (rc){
		goto symlink_hash_err;
	}

	rc = crypto_shash_final(sdescmd5, md5_hash);
	if (rc){
		goto symlink_hash_err;
	}
	mutex_unlock(&md5_mutex);
	/* ********* MD5_HASH generated ****** */
symlink_hash_err:
	kfree(sdescmd5);
free_shash:
	crypto_free_shash(md5);
out:
	return rc;
}

int do_encryption(const char *algo, const void *key, int key_len,
                            void *dst, size_t *dst_len,
                            const void *src, size_t src_len)
{
	int ret;
	void *iv;
	int ivsize;
	size_t zero_padding = (0x10 - (src_len & 0x0f));
	char pad[16];
	struct scatterlist sg_in[2], sg_out[1];

	struct crypto_blkcipher *tfm = crypto_alloc_blkcipher(algo, 0,
		CRYPTO_ALG_ASYNC);
	struct blkcipher_desc desc = { .tfm = tfm, .flags = 0 };

	if (IS_ERR(tfm)) {
		printk("crypto_alloc_blkcipher failed! Check if the cipher "
			"algorithm is correct.\n");
		return -EINVAL;
	}

	memset(pad, zero_padding, zero_padding);
        
	*dst_len = src_len + zero_padding;

	sg_init_table(sg_in, 2);
	sg_set_buf(&sg_in[0], src, src_len);
	sg_set_buf(&sg_in[1], pad, zero_padding);

    crypto_blkcipher_setkey((void *)tfm, key, key_len);

	sg_init_table(sg_out, 1);
	sg_set_buf(sg_out, dst, *dst_len);

	iv = crypto_blkcipher_crt(tfm)->iv;
	ivsize = crypto_blkcipher_ivsize(tfm);
	memcpy(iv, aes_iv, ivsize);

	mutex_lock(&encrypt_mutex);
	ret = crypto_blkcipher_encrypt(&desc, sg_out, sg_in,
				       src_len + zero_padding);
	mutex_unlock(&encrypt_mutex);
	crypto_free_blkcipher(tfm);
	if (ret < 0){
		printk("crypto_blkcipher_encrypt failed!\n");
		return ret;
	}
	return 0;
}

int do_decryption(const char *algo, const void *key, int key_len,
                            void *dst, size_t *dst_len,
                            const void *src, size_t src_len)
{
	int ret;
	void *iv;
	int ivsize;
	char pad[16];
	int last_byte;
	struct scatterlist sg_in[1], sg_out[2];

	struct crypto_blkcipher *tfm = crypto_alloc_blkcipher(algo, 0,
		CRYPTO_ALG_ASYNC);
	struct blkcipher_desc desc = { .tfm = tfm};

	if (IS_ERR(tfm)) {
		printk("crypto_alloc_blkcipher failed! Check if the cipher "
			"algorithm is correct.\n");
		return -EINVAL;
	}

	crypto_blkcipher_setkey((void *)tfm, key, key_len);
	sg_init_table(sg_in, 1);
	sg_init_table(sg_out, 2);
	sg_set_buf(sg_in, src, src_len);
	sg_set_buf(&sg_out[0], dst, *dst_len);
	sg_set_buf(&sg_out[1], pad, sizeof(pad));

	iv = crypto_blkcipher_crt(tfm)->iv;
	ivsize = crypto_blkcipher_ivsize(tfm);
	memcpy(iv, aes_iv, ivsize);

	mutex_lock(&decrypt_mutex);
	ret = crypto_blkcipher_decrypt(&desc, sg_out, sg_in, src_len);
	mutex_unlock(&decrypt_mutex);
	crypto_free_blkcipher(tfm);
	
	if (ret < 0){
		printk("crypto_blkcipher_decrypt failed!\n");
		return ret;
	}

	if (src_len <= *dst_len) {
		last_byte = ((char *)dst)[src_len - 1];
	} else {
		last_byte = pad[src_len - *dst_len - 1];
	}

	if (last_byte <= 16 && src_len >= last_byte) {
		*dst_len = src_len - last_byte;
	}

    return 0;
}

int do_xcrypt(xcrypt *xcrypt_obj)
{
	int rc = 0, out_exist = 0, to_pad, bytes, len = PAGE_SIZE, sleep_time = 500;
	int decrypt_pad_len = 32, encrypt_pad_len = 32, obtained_lock = 0;
	char *read_buffer, *key_buffer, *write_buffer, *pad_buffer, pad_size[3];
	char cipher_algo[16], preamble_hash_key[48], *decrypt_key_buffer;
	char tmpfilp_name[256];
	char infilp_lock_name[256], outfilp_lock_name[256];
	struct file *infilp, *outfilp, *tmpfilp, *infilp_lock = NULL, *outfilp_lock = NULL;
	struct inode *outfilp_inode = NULL, *tmpfilp_inode = NULL;
	struct dentry *outfilp_dentry = NULL, *tmpfilp_dentry = NULL;
	struct inode *del_inode;
	size_t infile_size;
	struct kstat stat;
	u8 *md5_hash = NULL;
	umode_t infile_mode;
	mm_segment_t oldfs;

	sprintf(cipher_algo, "cbc(%s)", xcrypt_obj->cipher);
	pr_debug("cipher_algo passed = %s\n", cipher_algo);
	xcrypt_obj->keybuf[16] = 0;
    sprintf(preamble_hash_key, "%s-%s", xcrypt_obj->keybuf,
    	xcrypt_obj->cipher);

    sprintf(tmpfilp_name, "%s.tmp", xcrypt_obj->infile);
    sprintf(infilp_lock_name, "%s.lock", xcrypt_obj->infile);
    sprintf(outfilp_lock_name, "%s.lock", xcrypt_obj->outfile);

	while(!obtained_lock) {
		mutex_lock(&xcrypt_flock_mutex);
		if(vfs_stat(infilp_lock_name, &stat) != 0) {
			infilp_lock = filp_open(infilp_lock_name, O_WRONLY|O_CREAT, 0444);
			if(vfs_stat(outfilp_lock_name, &stat) != 0) {
				outfilp_lock = filp_open(outfilp_lock_name, O_WRONLY|O_CREAT, 0444);
				obtained_lock = 1;
				pr_debug("Obtained lock!\n");
				mutex_unlock(&xcrypt_flock_mutex);
			} else {
				if (infilp_lock && !IS_ERR(infilp_lock)) {
					if(infilp_lock->f_path.dentry != NULL &&
						infilp_lock->f_path.dentry->d_parent->d_inode != NULL) {
						vfs_unlink(infilp_lock->f_path.dentry->d_parent->d_inode,
							infilp_lock->f_path.dentry, &del_inode);
					}
					infilp_lock = NULL;
				}
				mutex_unlock(&xcrypt_flock_mutex);
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
		} else {
			mutex_unlock(&xcrypt_flock_mutex);
			if(sleep_time > 10000) {
				rc = -EBUSY;
				pr_err("Couldn't get lock even after waiting for more "
					"than 30 seconds! Exiting.\n");
				goto out;
			}
			sleep_time = sleep_time * 2;
			printk("Cannot get lock on input file. Sleeping for %d "
				"msec!\n", sleep_time);
			msleep(sleep_time);
		}
	}

	md5_hash = kzalloc(AES_BLOCK_SIZE, GFP_KERNEL);
	if (!md5_hash) {
		rc = -ENOMEM;
		goto out;
	}
	rc = getMD5Hash(preamble_hash_key, md5_hash);
	if(rc) {
		rc = -EINVAL;
		goto free_md5_hash;
	}

	// create all the buffers
	read_buffer = (char *)kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!read_buffer) {
		rc = -ENOMEM;
		goto free_md5_hash;
	}
	key_buffer = (char *)kzalloc(xcrypt_obj->keylen, GFP_KERNEL);
	if (!key_buffer) {
		rc = -ENOMEM;
		goto free_read_buffer;
	}
	write_buffer = (char *) kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!write_buffer) {
		rc = -ENOMEM;
		goto free_key_buffer;
	}
	pad_buffer = (char *)kzalloc(2 * AES_BLOCK_SIZE, GFP_KERNEL);
	if (!pad_buffer) {
		rc = -ENOMEM;
		goto free_write_buffer;
	}
	decrypt_key_buffer = (char *)kzalloc(2 * AES_BLOCK_SIZE, GFP_KERNEL);
	if (!decrypt_key_buffer) {
		rc = -ENOMEM;
		goto free_pad_buffer;
	}

	// open all the files to read or write as required
	infilp = filp_open(xcrypt_obj->infile, O_RDONLY, 0);
	rc = validate_file(infilp, 1);
	if(rc) {
		goto close_infilp;
	}
    infilp->f_pos = 0;		/* start offset */
	infile_mode = infilp->f_path.dentry->d_inode->i_mode;

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
	tmpfilp_inode = tmpfilp->f_path.dentry->d_parent->d_inode;
	tmpfilp_dentry = tmpfilp->f_path.dentry;

	out_exist = vfs_stat(xcrypt_obj->outfile, &stat);
    outfilp = filp_open(xcrypt_obj->outfile, O_WRONLY|O_CREAT, infile_mode);
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
	outfilp_inode = outfilp->f_path.dentry->d_parent->d_inode;
	outfilp_dentry = outfilp->f_path.dentry;

    // Calculate length of padding, if required
    infile_size = infilp->f_path.dentry->d_inode->i_size;
    if (infile_size % AES_BLOCK_SIZE == 0) {
		to_pad = 0;
    } else {
		to_pad = AES_BLOCK_SIZE - (infile_size % AES_BLOCK_SIZE);
	}

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	switch(xcrypt_obj->flag) {
	case ENCRYPT:
		// Copy the padding info in buffer to be written in output file
		if(to_pad<10)
			sprintf(pad_size, "0%d", to_pad);
		else
			sprintf(pad_size, "%d", to_pad);
		pad_size[2] = '\0';
    	memcpy(pad_buffer, pad_size, 2);

		tmpfilp->f_op->write(tmpfilp, md5_hash, AES_BLOCK_SIZE, &tmpfilp->f_pos);

		rc = do_encryption(cipher_algo, xcrypt_obj->keybuf, AES_BLOCK_SIZE,
			write_buffer, &encrypt_pad_len, pad_buffer, 2 * AES_BLOCK_SIZE);
		if (rc) {
			printk("Failed while encrypting the padding info.\n");
			goto reset_fs;
		}
		tmpfilp->f_op->write(tmpfilp, write_buffer, 2 * AES_BLOCK_SIZE,
			&tmpfilp->f_pos);

		while ((bytes = infilp->f_op->read(infilp, read_buffer, PAGE_SIZE,
			&infilp->f_pos)) > 0) {
			if(bytes < PAGE_SIZE) {
				len = bytes + to_pad;
				rc = do_encryption(cipher_algo, xcrypt_obj->keybuf, AES_BLOCK_SIZE,
					write_buffer, &len, read_buffer, bytes + to_pad);
				tmpfilp->f_op->write(tmpfilp, write_buffer, bytes + to_pad,
					&tmpfilp->f_pos);
			} else {
				rc = do_encryption(cipher_algo, xcrypt_obj->keybuf, AES_BLOCK_SIZE,
					write_buffer, &len, read_buffer, PAGE_SIZE);
				tmpfilp->f_op->write(tmpfilp, write_buffer, PAGE_SIZE,
					&tmpfilp->f_pos);
			}
			if(rc) {
				printk("Failed while encrypting the file.\n");
				goto reset_fs;
			}
		}
		break;
	case DECRYPT:
		infilp->f_op->read(infilp, key_buffer, AES_BLOCK_SIZE, &infilp->f_pos);
		if(memcmp(md5_hash, key_buffer, AES_BLOCK_SIZE)) {
			printk("Oops. Wrong Key or Cipher Algorithm.\n");
			rc = -EPERM;
			goto reset_fs;
		}

	    infilp->f_op->read(infilp, decrypt_key_buffer, 2 * AES_BLOCK_SIZE,
	    	&infilp->f_pos);
	    rc = do_decryption(cipher_algo, xcrypt_obj->keybuf, AES_BLOCK_SIZE,
	    	pad_buffer, &decrypt_pad_len, decrypt_key_buffer,
	    	2 * AES_BLOCK_SIZE);
	    if (rc) {
	    	printk("Failed while decrypting the padding info.\n");
	    	goto reset_fs;
	    }

		memcpy(pad_size, pad_buffer, 2);
		pad_size[2] = '\0';
	    to_pad = simple_strtol(pad_size, NULL, 10);

		while ((bytes = infilp->f_op->read(infilp, read_buffer, PAGE_SIZE,
			&infilp->f_pos)) > 0) {
			if(bytes < PAGE_SIZE) {
				len = bytes;
				rc = do_decryption(cipher_algo, xcrypt_obj->keybuf,
					AES_BLOCK_SIZE, write_buffer, &len, read_buffer, bytes);
				len = bytes - to_pad;
				tmpfilp->f_op->write(tmpfilp, write_buffer, len,
					&tmpfilp->f_pos);
			} else {
				rc = do_decryption(cipher_algo, xcrypt_obj->keybuf,
					AES_BLOCK_SIZE, write_buffer, &len, read_buffer, PAGE_SIZE);
				tmpfilp->f_op->write(tmpfilp, write_buffer, PAGE_SIZE,
					&tmpfilp->f_pos);
			}
			if(rc) {
				printk("Failed while decrypting the file.\n");
				goto reset_fs;
			}
		}
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
	kfree(decrypt_key_buffer);
free_pad_buffer:
	kfree(pad_buffer);
free_write_buffer:
	kfree(write_buffer);
free_key_buffer:
	kfree(key_buffer);
free_read_buffer:
	kfree(read_buffer);
free_md5_hash:
	kfree(md5_hash);
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
