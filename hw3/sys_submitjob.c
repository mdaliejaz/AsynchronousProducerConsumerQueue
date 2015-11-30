#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/delay.h>
#include <linux/skbuff.h>
#include "jobs.h"

#define NETLINK_USER 31

DEFINE_SPINLOCK(list_lock);

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
	if (user_param->type == LIST_JOB) {
		goto out;
	}

	if (user_param->work == NULL || IS_ERR(user_param->work) ||
		unlikely(!access_ok(VERIFY_READ, user_param->work,
			sizeof(user_param->work)))) {
		pr_err("user parameters are not valid!\n");
		return -EINVAL;
	}
	out:
		return 0;
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
	int rc = 0, i;
	char *checksum_result = NULL;
	qwork *in_work = (qwork *)work;
	struct list_head *pos, *q;
	job_list *node = NULL;

	msleep(20000);
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
	case DEFLATE:
		rc = do_xpress((xpress *)in_work->task);
		kfree(((xpress *)in_work->task)->infile);
		kfree(((xpress *)in_work->task)->outfile);
		kfree(((xpress *)in_work->task)->algo);
		kfree((xpress *)in_work->task);
		break;
	case CHECKSUM:
		checksum_result = (char *)kzalloc(sizeof(MD5_DIGEST_LENGTH) + 1,
			GFP_KERNEL);
		if (!checksum_result) {
			rc = -ENOMEM;
			goto free_checksum_data;
		}
		rc = do_checksum((checksum *)in_work->task, checksum_result);
		printk("checksum_result = %s\n", checksum_result);
		free_checksum_data:
			kfree((checksum *)in_work->task);
			kfree(checksum_result);
		break;
	case CONCAT:
		rc = do_concat((concat *)in_work->task);
		kfree(((concat *)in_work->task)->outfile);
		for(i = 0; i < ((concat *)in_work->task)->infile_count; i++) {
			kfree(((concat *)in_work->task)->infiles[i]);
		}
		kfree(((concat *)in_work->task)->infiles);
		kfree((concat *)in_work->task);
		break;
	default:
		printk("Do something \n");
	}
	atomic_dec(&queue_size);

	spin_lock(&list_lock);
	list_for_each_safe(pos, q, &head) {
		node = list_entry(pos, job_list, list);
		if(node->id == in_work->id) {
			printk("deleting id = %d\n", node->id);
			list_del(pos);
			kfree(node);
		}
	}
	spin_unlock(&list_lock);

	nl_send_msg(in_work->pid, "hello world");

	printk("picked = %d\n", atomic_read(&queue_size));
	kfree(work);
	return;
}

asmlinkage long submitjob(void *arg)
{
	long rc = 0, i;
	char return_job_list[100] = {0}, job_detail[5];
	submit_job *job;
	xcrypt *xcrypt_work = NULL;
	xpress *xpress_work = NULL;
	checksum *checksum_work = NULL;
	concat *concat_work = NULL;
	qwork *in_work;
	struct list_head *pos, *q;
	job_list *node = NULL;

	if(atomic_read(&queue_size) == 20) {
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

		printk("job->type = %d\n", job->type);
		printk("job->work->infile = %s\n", ((xcrypt *)job->work)->infile);
		printk("job->work->outfile = %s\n", ((xcrypt *)job->work)->outfile);
		printk("job->work->cipher = %s\n", ((xcrypt *)job->work)->cipher);
		printk("job->work->keybuf = %s\n", ((xcrypt *)job->work)->keybuf);
		printk("job->work->keylen = %d\n", ((xcrypt *)job->work)->keylen);
		printk("job->work->flag = %d\n", ((xcrypt *)job->work)->flag);
		break;
	case COMPRESS:
	case DEFLATE:
		rc = validate_user_xpress_args((xpress *)((submit_job *)arg)->work);
		xpress_work = (xpress *)kzalloc(sizeof(xpress), GFP_KERNEL);
		if (!xpress_work) {
			rc = -ENOMEM;
			goto free_job;
		}
		rc = copy_xpress_data_to_kernel((xpress *)((submit_job *)arg)->work,
			xpress_work);
		if(rc)
			goto free_xpress;
		job->work = xpress_work;

		printk("job->type = %d\n", job->type);
		printk("job->pid = %d\n", job->pid);
		printk("job->work->infile = %s\n", ((xpress *)job->work)->infile);
		printk("job->work->outfile = %s\n", ((xpress *)job->work)->outfile);
		printk("job->work->algo = %s\n", ((xpress *)job->work)->algo);
		printk("job->work->flag = %d\n", ((xpress *)job->work)->flag);
		break;
	case CHECKSUM:
		rc = validate_user_checksum_args((checksum *)((submit_job *)arg)->work);
		checksum_work = (checksum *)kzalloc(sizeof(checksum), GFP_KERNEL);
		if (!checksum_work) {
			rc = -ENOMEM;
			goto free_job;
		}
		rc = copy_checksum_data_to_kernel((checksum *)((submit_job *)arg)->work,
			checksum_work);
		if(rc)
			goto free_checksum;
		job->work = checksum_work;

		printk("job->type = %d\n", job->type);
		printk("job->pid = %d\n", job->pid);
		printk("job->work = %s\n", ((checksum *)job->work)->infile);
		break;
	case CONCAT:
		rc = validate_user_concat_args((concat *)((submit_job *)arg)->work);
		concat_work = (concat *)kzalloc(sizeof(concat), GFP_KERNEL);
		if (!concat_work) {
			rc = -ENOMEM;
			goto free_job;
		}
		for(i = 0; i < ((concat *)((submit_job *)arg)->work)->infile_count; i++) {
			// printk("fine\n");
			printk("job->infiles[i] = %s\n", (((concat *)((submit_job *)arg)->work)->infiles[i]));
		}
		rc = copy_concat_data_to_kernel((concat *)((submit_job *)arg)->work,
			concat_work);
		if(rc)
			goto free_concat;
		if(!concat_work)
			printk("work is NULL\n");
		job->work = concat_work;

		printk("job->type = %d\n", job->type);
		printk("job->pid = %d\n", job->pid);
		printk("job->outfile = %s\n", ((concat *)job->work)->outfile);
		printk("job->infile_count = %d\n", ((concat *)job->work)->infile_count);
		break;
	case LIST_JOB:
		strcat(return_job_list, "Job ID\tJob Type\tJob PID\n");
		spin_lock(&list_lock);
		list_for_each_safe(pos, q, &head) {
			node = list_entry(pos, job_list, list);
			sprintf(job_detail, "%d\t%d\t%d\n", node->id, node->type, node->pid);
			strcat(return_job_list, job_detail);
		}
		spin_unlock(&list_lock);
		rc = copy_to_user((char *)((submit_job *)arg)->work, return_job_list, strlen(return_job_list));
		goto free_job;
		break;
	case REMOVE_JOB:
		printk("(int *)((submit_job *)arg)->work = %d\n", *(int *)((submit_job *)arg)->work);
		spin_lock(&list_lock);
		list_for_each_safe(pos, q, &head) {
			node = list_entry(pos, job_list, list);
			if(*(int *)((submit_job *)arg)->work == node->id) {
				printk("deleting id = %d\n", node->id);
				rc = cancel_work_sync(node->queued_job);
				if(rc) {
					in_work = (qwork *)node->queued_job;
					switch(in_work->type) {
					case ENCRYPT:
					case DECRYPT:
						kfree(((xcrypt *)in_work->task)->infile);
						kfree(((xcrypt *)in_work->task)->outfile);
						kfree(((xcrypt *)in_work->task)->keybuf);
						kfree(((xcrypt *)in_work->task)->cipher);
						kfree((xcrypt *)in_work->task);
						break;
					case COMPRESS:
					case DEFLATE:
						kfree(((xpress *)in_work->task)->infile);
						kfree(((xpress *)in_work->task)->outfile);
						kfree(((xpress *)in_work->task)->algo);
						kfree((xpress *)in_work->task);
						break;
					case CHECKSUM:
						kfree((checksum *)in_work->task);
						break;
					case CONCAT:
						kfree(((concat *)in_work->task)->outfile);
						for(i = 0; i < ((concat *)in_work->task)->infile_count; i++) {
							kfree(((concat *)in_work->task)->infiles[i]);
						}
						kfree(((concat *)in_work->task)->infiles);
						kfree((concat *)in_work->task);
						break;
					}

					printk("removed from queue.\n");
					list_del(pos);
					printk("list_del.\n");
					kfree(node);
					printk("free node\n");
					rc = 0;
				} else {
					printk("Could not delete!\n");
				}
			}
		}
		spin_unlock(&list_lock);
		printk("free job\n");
		goto free_job;
		break;
	default:
		pr_err("error\n");
		return -1;
	}

	node = (job_list *)kzalloc(sizeof(job_list), GFP_KERNEL);
	if(!node) {
		rc = -ENOMEM;
		goto free_job_on_queue;
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
		node->pid = in_work->pid;
		node->queued_job = (struct work_struct *)in_work;
		atomic_inc(&queue_size);
		queue_work(work_queue, (struct work_struct *)in_work);

		spin_lock(&list_lock);
		INIT_LIST_HEAD(&node->list);
		list_add_tail(&node->list, &head);
		spin_unlock(&list_lock);
	} else {
		rc = -ENOMEM;
		goto free_job_on_queue;
	}

	goto out;

	free_job_on_queue:
		if(node)
			kfree(node);
	free_xcrypt:
		if(xcrypt_work)
			kfree(xcrypt_work);
	free_xpress:
		if(xpress_work);
			kfree(xpress_work);
	free_checksum:
		if(checksum_work)
			kfree(checksum_work);
	free_concat:
		if(concat_work)
			kfree(concat_work);
	free_job:
		if(job)
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
		work_queue = alloc_workqueue("jobs_queue", 0, 1);
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
