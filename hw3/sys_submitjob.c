#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include "jobs.h"

#define NETLINK_USER 31

asmlinkage extern long (*sysptr)(void *arg);
static struct workqueue_struct *work_queue = NULL;
atomic_t queue_size;
atomic_t unique_id;
static LIST_HEAD(head);
struct sock *nl_sk = NULL;

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

long validate_user_xcrypt_args(xcrypt *user_param) {
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

	if(!(user_param->flag == 1 || user_param->flag == 2)) {
		pr_err("user parameters are not valid!\n");
		return -EINVAL;
	}

	if(!(strlen_user(user_param->infile) <= MAX_FILE_NAME_LENGTH ||
		strlen_user(user_param->outfile) <= MAX_FILE_NAME_LENGTH)) {
		return -ENAMETOOLONG;
	}

	return 0;
}

long copy_xcrypt_data_to_kernel(xcrypt *user_param, xcrypt *kernel_param)
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

// static void nl_recv_msg(struct sk_buff *skb)
// {
// 
    // struct nlmsghdr *header;
    // int pid;
    // struct sk_buff *skb_out;
    // int msg_size;
    // char *msg = "Hello from kernel";
    // int res;

    // printk(KERN_INFO "Entering: %s\n", __FUNCTION__);

    // msg_size = strlen(msg);

    // header = (struct nlmsghdr *)skb->data;
    // printk(KERN_INFO "Netlink received msg payload: %s\n",
    // 	(char *)nlmsg_data(header));
    // pid = header->nlmsg_pid; /*pid of sending process */

    // skb_out = nlmsg_new(msg_size, 0);
    // if (!skb_out) {
    //     printk(KERN_ERR "Failed to allocate new skb\n");
    //     return;
    // }

    // header = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    // NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
    // strncpy(nlmsg_data(header), msg, msg_size);

    // res = nlmsg_unicast(nl_sk, skb_out, pid);
    // if (res < 0)
    //     printk(KERN_INFO "Error while sending bak to user\n");
// }

static void nl_send_msg(int pid, char *msg)
{
    struct nlmsghdr *header;
    struct sk_buff *skb_out;
    int msg_size;
    int rc = 0;

    msg_size = strlen(msg);
    // msg_size = sizeof(int);

    skb_out = nlmsg_new(msg_size, 0);
    if (!skb_out) {
        printk(KERN_ERR "Failed to allocate new skb\n");
        return;
    }

    header = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
    strncpy(nlmsg_data(header), msg, msg_size);

    rc = nlmsg_unicast(nl_sk, skb_out, pid);
    if (rc < 0)
        printk(KERN_INFO "Error while sending bak to user\n");
}

void submit_work_func(struct work_struct *work) {
	int rc = 0;
	qwork *in_work = (qwork *)work;
	struct list_head *pos, *q;
	job_list *node = NULL;

	switch(in_work->type) {
	case ENCRYPT:
	case DECRYPT:
		rc = do_xcrypt((xcrypt *)in_work->task);
		kfree(((xcrypt *)in_work->task)->infile);
		kfree(((xcrypt *)in_work->task)->outfile);
		kfree(((xcrypt *)in_work->task)->keybuf);
		kfree(((xcrypt *)in_work->task)->cipher);
		kfree((xcrypt *)in_work->task);
		break;
	case COMPRESS:
		rc = compress();
		break;
	case DECOMPRESS:
		rc = decompress();
		break;
	case CHECKSUM:
		rc = checksum();
		break;
	case CONCAT:
		rc = concat();
		break;
	default:
		printk("Do something \n");
	}
	atomic_dec(&queue_size);

	list_for_each_safe(pos, q, &head) {
		node = list_entry(pos, job_list, list);
		if(node->id == in_work->id) {
			printk("deleting id = %d\n", node->id);
			list_del(pos);
			kfree(node);
		}
	}

	nl_send_msg(in_work->pid, "hello world");

	printk("node list.\n");
	list_for_each_safe(pos, q, &head) {
		node = list_entry(pos, job_list, list);
		printk("node->id = %d\n", node->id);
		printk("node->type = %d\n", node->type);
	}

	printk("picked = %d\n", atomic_read(&queue_size));
	kfree((void *)work);
	return;
}

asmlinkage long submitjob(void *arg)
{
	long rc = 0;
	submit_job *job;
	xcrypt *xcrypt_work = NULL;
	qwork *in_work;
	job_list *node = NULL;

	if(atomic_read(&queue_size) == 5) {
		printk("workqueue is full!\n");
		goto out;
	}

	rc = validate_user_args((submit_job *) arg);
	if (rc) {
		goto out;
	}

	job = kzalloc(sizeof(submit_job), GFP_KERNEL);
	if (!job) {
		rc = -ENOMEM;
		goto out;
	}
	rc = copy_from_user(&job->type, &((submit_job *)arg)->type, sizeof(int));
	if (rc) {
		goto free_job;
	}
	rc = copy_from_user(&job->pid, &((submit_job *)arg)->pid, sizeof(int));
	if (rc) {
		goto free_job;
	}

	switch(job->type) {
	case ENCRYPT:
	case DECRYPT:
		rc = validate_user_xcrypt_args((xcrypt *)((submit_job *)arg)->work);
		xcrypt_work = kzalloc(sizeof(xcrypt), GFP_KERNEL);
		if (!xcrypt_work) {
			rc = -ENOMEM;
			goto free_job;
		}
		rc = copy_xcrypt_data_to_kernel((xcrypt *)((submit_job *)arg)->work,
			xcrypt_work);
		if(rc)
			goto free_xcrypt;
		job->work = xcrypt_work;
		break;
	case COMPRESS:
	case DECOMPRESS:
	case CHECKSUM:
	case CONCAT:
		job->work = NULL;
		printk("IMPLEMENT ME!\n");
		break;
	default:
		pr_err("error\n");
		return -1;
	}

	printk("job->type = %d\n", job->type);
	printk("job->work->infile = %s\n", ((xcrypt *)job->work)->infile);
	printk("job->work->outfile = %s\n", ((xcrypt *)job->work)->outfile);
	printk("job->work->cipher = %s\n", ((xcrypt *)job->work)->cipher);
	printk("job->work->keybuf = %s\n", ((xcrypt *)job->work)->keybuf);
	printk("job->work->keylen = %d\n", ((xcrypt *)job->work)->keylen);
	printk("job->work->flag = %d\n", ((xcrypt *)job->work)->flag);

	node = (job_list *)kzalloc(sizeof(job_list), GFP_KERNEL);
	if(!node) {
		rc = -ENOMEM;
		goto free_xcrypt;
	}

	in_work =  (qwork *)kzalloc(sizeof(qwork), GFP_KERNEL);
	if (in_work) {
		INIT_WORK((struct work_struct *)in_work, submit_work_func);
		atomic_inc(&unique_id);
		in_work->id = atomic_read(&unique_id);
		in_work->type = job->type;
		in_work->task = job->work;
		in_work->pid = job->pid;
		node->id = in_work->id;
		node->type = in_work->type;
		node->queued_job = (struct work_struct *)in_work;
		atomic_inc(&queue_size);
		printk("posted = %d\n", atomic_read(&queue_size));
		queue_work(work_queue, (struct work_struct *)in_work);
		INIT_LIST_HEAD(&node->list);
		list_add_tail(&node->list, &head);
	} else {
		rc = -ENOMEM;
		goto free_job_on_queue;
	}

	goto out;
	free_job_on_queue:
		kfree(node);
	free_xcrypt:
		kfree(xcrypt_work);
	free_job:
		kfree(job);
	out:
		return rc;
}

static int __init init_sys_submitjob(void)
{
	struct netlink_kernel_cfg cfg = {
    	.input = NULL,
	};
	nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
    if (!nl_sk) {
        printk(KERN_ALERT "Error creating socket.\n");
        return -ESOCKTNOSUPPORT;
    }

	printk("installed new sys_submitjob module\n");
	if (sysptr == NULL)
		sysptr = submitjob;
	if (!work_queue)
		work_queue = alloc_workqueue("jobs_queue", 0, 5);
	atomic_set(&queue_size, 0);
	atomic_set(&unique_id, 0);

	return 0;
}
static void  __exit exit_sys_submitjob(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	if (work_queue) {
		flush_workqueue(work_queue);
		destroy_workqueue(work_queue);
	}
	atomic_set(&queue_size, 0);
	atomic_set(&unique_id, 0);
	netlink_kernel_release(nl_sk);
	printk("removed sys_submitjob module\n");
}
module_init(init_sys_submitjob);
module_exit(exit_sys_submitjob);
MODULE_LICENSE("GPL");
