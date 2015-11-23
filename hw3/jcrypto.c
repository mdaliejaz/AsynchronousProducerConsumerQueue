#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/fs.h>
#include <crypto/hash.h>
#include <linux/uaccess.h>
#include <asm/string.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include "jobs.h"

#define CEPH_AES_IV "muhammadaliejazz"

const u8 *aes_iv = (u8 *) CEPH_AES_IV;

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

	rc = crypto_shash_update(sdescmd5,(const char *) str,
		strlen(str));
	if (rc){
		goto symlink_hash_err;
	}

	rc = crypto_shash_final(sdescmd5, md5_hash);
	if (rc){
		goto symlink_hash_err;
	}
	/* ********* MD5_HASH generated ****** */
	symlink_hash_err:
		kfree(sdescmd5);
	free_shash:
		crypto_free_shash(md5);
	out:
		return rc;
}

int validate_file(struct file *f, int flag) {
	int rc = 0;
	// check if valid file pointer
	if (!f) {
		printk("File does not Exist/Bad File. err = %d\n", (int) PTR_ERR(f));
		rc = -EBADF;
		goto return_rc;
	}
	// check if error in file pointer
	if (IS_ERR(f)) {
        printk("File error : %d\n", (int) PTR_ERR(f));
		rc = -ENOENT;
		goto return_rc;
	}
	// check if file is regular or not
	if ((!S_ISREG(f->f_path.dentry->d_inode->i_mode))) {
		printk("Input Or Output File is not regular.\n");
		rc = -EIO;
		goto return_rc; 
    }
    if(flag) {  // flag =1 => input file
    	// check file read permission
    	if (!(f->f_mode & FMODE_READ)) {
			printk("Input file not accessible to be read.\n");
			rc = -EIO;
			goto return_rc;
		}
		// check if file can be read
	    if (!f->f_op->read) {
			printk("File System does not allow reads.\n");
			rc = -EACCES; 
			goto return_rc;
	    }
	} else {  // check for output file
		// check file write permission
		if (!(f->f_mode & FMODE_WRITE)) {
			printk("Output File not accessible to be written.\n");
			rc = -EIO;
			goto return_rc;
		}
		// check if file can be written
		if (!f->f_op->write) {
			printk("File System does not allow writes.\n");
			rc = -EACCES; 
			goto return_rc;
		}
	}
	return_rc:
		return rc;
}

int do_encryption(const char *algo, const void *key, int key_len,
                            void *dst, size_t *dst_len,
                            const void *src, size_t src_len)
{
	struct scatterlist sg_in[2], sg_out[1];
	struct crypto_blkcipher *tfm = crypto_alloc_blkcipher(algo, 0,
		CRYPTO_ALG_ASYNC);
	struct blkcipher_desc desc = { .tfm = tfm, .flags = 0 };
	int ret;
	void *iv;
	int ivsize;
	size_t zero_padding = (0x10 - (src_len & 0x0f));
	char pad[16];

	if (IS_ERR(tfm)) {
		printk("crypto_alloc_blkcipher failed! Check if the cipher "
			"algorithm is correct.\n");
		return PTR_ERR(tfm);
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

	ret = crypto_blkcipher_encrypt(&desc, sg_out, sg_in,
				       src_len + zero_padding);
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
	struct scatterlist sg_in[1], sg_out[2];
	struct crypto_blkcipher *tfm = crypto_alloc_blkcipher(algo, 0,
		CRYPTO_ALG_ASYNC);
	struct blkcipher_desc desc = { .tfm = tfm};
	int ret;
	void *iv;
	int ivsize;
	char pad[16];
	int last_byte;

	if (IS_ERR(tfm)) {
		printk("crypto_alloc_blkcipher failed! Check if the cipher "
			"algorithm is correct.\n");
		return PTR_ERR(tfm);
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

	ret = crypto_blkcipher_decrypt(&desc, sg_out, sg_in, src_len);
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

int jcrypt(jcipher *jcipher_obj)
{
	int rc = 0, to_pad, bytes, len = PAGE_SIZE, encrypt_pad_len = 32;
	int decrypt_pad_len = 32;
	char *read_buffer, *key_buffer, *write_buffer, *pad_buffer, pad_size[3];
	char cipher_algo[16], preamble_hash_key[48], *decrypt_key_buffer;
	char *tmpfilp_name = "/usr/src/hw3-mejaz/hw3/jcryptoaa6b5d17e373744f14c07f71b22f9549.tmp";
	struct file *infilp, *outfilp, *tmpfilp;
	struct inode *outfilp_inode = NULL, *tmpfilp_inode = NULL;
	struct dentry *outfilp_dentry = NULL, *tmpfilp_dentry = NULL;
	size_t infile_size;
	u8 *md5_hash = NULL;
	umode_t infile_mode;
	mm_segment_t oldfs;

	sprintf(cipher_algo, "cbc(%s)", jcipher_obj->cipher);
	pr_debug("cipher_algo passed = %s\n", cipher_algo);
	jcipher_obj->keybuf[16] = 0;
    sprintf(preamble_hash_key, "%s-%s", jcipher_obj->keybuf,
    	jcipher_obj->cipher);

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
	key_buffer = (char *)kzalloc(jcipher_obj->keylen, GFP_KERNEL);
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
	infilp = filp_open(jcipher_obj->infile, O_RDONLY, 0);
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

    outfilp = filp_open(jcipher_obj->outfile, O_WRONLY|O_CREAT, infile_mode);
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

	switch(jcipher_obj->flag) {
	case ENCRYPT:
		// Copy the padding info in buffer to be written in output file
		if(to_pad<10)
			sprintf(pad_size, "0%d", to_pad);
		else
			sprintf(pad_size, "%d", to_pad);
		pad_size[2] = '\0';
    	memcpy(pad_buffer, pad_size, 2);

		tmpfilp->f_op->write(tmpfilp, md5_hash, AES_BLOCK_SIZE, &tmpfilp->f_pos);

		rc = do_encryption(cipher_algo, jcipher_obj->keybuf, AES_BLOCK_SIZE,
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
				rc = do_encryption(cipher_algo, jcipher_obj->keybuf, AES_BLOCK_SIZE,
					write_buffer, &len, read_buffer, bytes + to_pad);
				tmpfilp->f_op->write(tmpfilp, write_buffer, bytes + to_pad,
					&tmpfilp->f_pos);
			} else {
				rc = do_encryption(cipher_algo, jcipher_obj->keybuf, AES_BLOCK_SIZE,
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
	    rc = do_decryption(cipher_algo, jcipher_obj->keybuf, AES_BLOCK_SIZE,
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
				rc = do_decryption(cipher_algo, jcipher_obj->keybuf,
					AES_BLOCK_SIZE, write_buffer, &len, read_buffer, bytes);
				len = bytes - to_pad;
				tmpfilp->f_op->write(tmpfilp, write_buffer, len,
					&tmpfilp->f_pos);
			} else {
				rc = do_decryption(cipher_algo, jcipher_obj->keybuf,
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
		printk("error!\n");
		goto reset_fs;
	}
	rc = vfs_rename(tmpfilp->f_path.dentry->d_parent->d_inode,
		tmpfilp->f_path.dentry, outfilp->f_path.dentry->d_parent->d_inode,
		outfilp->f_path.dentry, NULL, 0);

	reset_fs:
		set_fs(oldfs);
	close_outfilp:
		if (outfilp && !IS_ERR(outfilp))
			filp_close(outfilp, NULL);
	close_tmpfilp:
		if(rc) {
			if(tmpfilp_dentry != NULL && tmpfilp_inode != NULL) {
				vfs_unlink(tmpfilp_inode, tmpfilp_dentry, NULL);
			}
		}
		if (tmpfilp && !IS_ERR(tmpfilp))
			filp_close(tmpfilp, NULL);
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
		return rc;
}
