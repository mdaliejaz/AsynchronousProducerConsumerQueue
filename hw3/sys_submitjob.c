#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include "jobs.h"

asmlinkage extern long (*sysptr)(void *arg);


long validate_user_args(submit_job *user_param) {
	if (user_param == NULL || IS_ERR(user_param) ||
		unlikely(!access_ok(VERIFY_READ, user_param, sizeof(user_param)))) {
		pr_err("user parameters are not valid!\n");
		return -EFAULT;
	}
	if (user_param->work == NULL || IS_ERR(user_param->work) ||
		unlikely(!access_ok(VERIFY_READ, user_param->work,
			sizeof(user_param->work)))) {
		pr_err("user parameters are not valid!\n");
		return -EINVAL;
	}
	return 0;
}

long validate_user_jcipher_args(jcipher *user_param) {
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

	if(user_param->cipher == NULL || IS_ERR(user_param->cipher) ||
		unlikely(!access_ok(VERIFY_READ, user_param->cipher,
			sizeof(user_param->cipher)))) {
		pr_err("user parameters are not valid!\n");
		return -EINVAL;
	}

	if(user_param->keybuf == NULL || IS_ERR(user_param->keybuf) ||
		unlikely(!access_ok(VERIFY_READ, user_param->keybuf,
			sizeof(user_param->keybuf)))) {
		pr_err("user parameters are not valid!\n");
		return -EINVAL;
	}

	if(!(user_param->flag == 0 || user_param->flag == 1)) {
		pr_err("user parameters are not valid!\n");
		return -EINVAL;
	}

	if(!(strlen_user(user_param->infile) <= MAX_FILE_NAME_LENGTH ||
		strlen_user(user_param->outfile) <= MAX_FILE_NAME_LENGTH)) {
		return -ENAMETOOLONG;
	}

	return 0;
}

long copy_jcipher_data_to_kernel(jcipher *user_param, jcipher *kernel_param)
{
	long rc = 0;

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

	kernel_param->cipher = kzalloc(strlen(user_param->cipher) + 1,
		GFP_KERNEL);
	if (!kernel_param->cipher) {
		rc = -ENOMEM;
		goto free_outfile;
	}
	rc = copy_from_user(kernel_param->cipher, user_param->cipher,
		strlen(user_param->cipher));
	if (rc) {
		printk("Copying of cipher name failed.\n");
		goto free_cipher;
	}

	kernel_param->keybuf = kzalloc(strlen(user_param->keybuf) + 1,
		GFP_KERNEL);
	if (!kernel_param->keybuf) {
		rc = -ENOMEM;
		goto free_cipher;
	}
	rc = copy_from_user(kernel_param->keybuf, user_param->keybuf,
		strlen(user_param->keybuf));
	if (rc) {
		printk("Copying of key buffer failed.\n");
		goto free_keybuf;
	}

	rc = copy_from_user(&kernel_param->keylen, &user_param->keylen,
		sizeof(int));
	if (rc) {
		printk("Copying of key buffer length failed.\n");
		goto free_keybuf;
	}

	rc = copy_from_user(&kernel_param->flag, &user_param->flag, sizeof(int));
	if (rc) {
		printk("Copying of encryption/decryption flag failed.\n");
		goto free_keybuf;
	}

	return 0;

	free_keybuf:
		kfree(kernel_param->keybuf);
	free_cipher:
		kfree(kernel_param->cipher);
	free_outfile:
		kfree(kernel_param->outfile);
	free_infile:
		kfree(kernel_param->infile);
	out:
		return rc;
}

void submit_work_func( struct work_struct *work ) {
	int rc = 0;
	my_work_t *in_work = (my_work_t *)work;

	switch(in_work->type) {
	case ENCRYPT:
		rc = encrypt();
		break;
	case DECRYPT:
		rc = decrypt();
		break;
	case COMPRESS:
		rc = compress();
		break;
	default:
		printk("Do something \n");
	}

	kfree((void *)work);
	return;
}

static struct workqueue_struct *job_wq = NULL;

asmlinkage long submitjob(void *arg)
{
	long rc = 0;
	submit_job *job;
	jcipher *jcipher_work;
	my_work_t *in_work;

	rc = validate_user_args((submit_job *) arg);

	if (rc) {
		goto k_sys_args_fail;
	}

	job = kzalloc(sizeof(submit_job), GFP_KERNEL);
	if (!job) {
		rc = -ENOMEM;
		goto k_sys_args_fail;
	}

	rc = copy_from_user(&job->type, &((submit_job *)arg)->type, sizeof(int));
	if (rc) {
		goto free_job;
	}

	switch(job->type) {
	case ENCRYPT:
	case DECRYPT:
		rc = validate_user_jcipher_args((jcipher *)((submit_job *)arg)->work);
		jcipher_work = kzalloc(sizeof(jcipher), GFP_KERNEL);
		if (!jcipher_work) {
			rc = -ENOMEM;
			goto free_job;
		}
		rc = copy_jcipher_data_to_kernel((jcipher *)((submit_job *)arg)->work,
			jcipher_work);
		if(rc)
			goto free_jcipher;
		job->work = jcipher_work;
		break;
	default:
		pr_err("error\n");
		return -1;
	}

	printk("job->type = %d\n", job->type);
	printk("job->work->infile = %s\n", ((jcipher *)job->work)->infile);
	printk("job->work->outfile = %s\n", ((jcipher *)job->work)->outfile);
	printk("job->work->cipher = %s\n", ((jcipher *)job->work)->cipher);
	printk("job->work->keybuf = %s\n", ((jcipher *)job->work)->keybuf);
	printk("job->work->keylen = %d\n", ((jcipher *)job->work)->keylen);
	printk("job->work->flag = %d\n", ((jcipher *)job->work)->flag);

	in_work =  (my_work_t *)kzalloc(sizeof(my_work_t), GFP_KERNEL);
	if (in_work) {
		INIT_WORK((struct work_struct *)in_work, submit_work_func);
		in_work->type = job->type;
		queue_work(job_wq, (struct work_struct *)in_work);
	}

	free_jcipher:
		kfree(jcipher_work);
	free_job:
		kfree(job);
	k_sys_args_fail:
		return rc;
}

static int __init init_sys_submitjob(void)
{
	printk("installed new sys_submitjob module\n");
	if (sysptr == NULL)
		sysptr = submitjob;
	if (!job_wq)
		job_wq = create_workqueue("jobs_queue");
	return 0;
}
static void  __exit exit_sys_submitjob(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	if (job_wq)
		destroy_workqueue(job_wq);
	printk("removed sys_submitjob module\n");
}
module_init(init_sys_submitjob);
module_exit(exit_sys_submitjob);
MODULE_LICENSE("GPL");
