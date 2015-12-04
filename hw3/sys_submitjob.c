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

DEFINE_SPINLOCK(list_lock);

asmlinkage extern long (*sysptr)(void *arg);
static struct workqueue_struct *work_queue = NULL;
static struct workqueue_struct *priority_work_queue = NULL;

atomic_t queue_size;
atomic_t priority_queue_size;

atomic_t unique_id;

static LIST_HEAD(head);
struct sock *nl_sk = NULL;

long validate_user_args(submit_job *user_param) {
	if (user_param == NULL || IS_ERR(user_param) ||
		unlikely(!access_ok(VERIFY_READ, user_param, sizeof(user_param)))) {
		pr_err("User Parameters are Not Valid!\n");
		return -EFAULT;
	}

	// if (user_param->type == LIST_JOB) {
	// 	if (user_param->work == NULL || IS_ERR(user_param->work)) {
	// 		pr_err("user parameters are not valid!\n");
	// 		return -EINVAL;
	// 	}
	// 	goto out;
	// }

	if (user_param->work == NULL || IS_ERR(user_param->work) ||
		unlikely(!access_ok(VERIFY_READ, user_param->work,
			sizeof(user_param->work)))) {
		pr_err("User Parameters are Not Valid!\n");
		return -EINVAL;
	}
// out:
	return 0;
}

static void nl_send_msg(int pid, nl_msg *msg)
{
    struct nlmsghdr *header;
    struct sk_buff *skb_out;
    int msg_size;
    int rc = 0;

    msg_size = sizeof(nl_msg);

    skb_out = nlmsg_new(msg_size, 0);
    if (!skb_out) {
        printk(KERN_ERR "Failed to allocate new skb\n");
        return;
    }

    header = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
    memcpy(nlmsg_data(header), msg, msg_size);

    rc = nlmsg_unicast(nl_sk, skb_out, pid);
    if (rc < 0)
        printk(KERN_INFO "Error while sending bak to user\n");
}

void submit_work_func(struct work_struct *work) {
	int rc = 0, i, wait = 0, pid;
	char checksum_result[40] = {0}, msg[100] = {0}, post_msg[500] = {0};
	qwork *in_work = (qwork *)work;
	struct list_head *pos, *q;
	job_list *node = NULL;
	nl_msg message;

	switch(in_work->type) {
	case ENCRYPT:
	case DECRYPT:
		rc = do_xcrypt((xcrypt *)in_work->task);
		if(rc)
			sprintf(msg, "En/Decryption of %s Failed!\n",
				((xcrypt *)in_work->task)->infile);
		else
			sprintf(msg, "En/Decryption of %s went successful!\n",
				((xcrypt *)in_work->task)->infile);
		if(((xcrypt *)in_work->task)->infile)
			kfree(((xcrypt *)in_work->task)->infile);
		if(((xcrypt *)in_work->task)->outfile)
			kfree(((xcrypt *)in_work->task)->outfile);
		if(((xcrypt *)in_work->task)->keybuf)
			kfree(((xcrypt *)in_work->task)->keybuf);
		if(((xcrypt *)in_work->task)->cipher)
			kfree(((xcrypt *)in_work->task)->cipher);
		if((xcrypt *)in_work->task)
			kfree((xcrypt *)in_work->task);
		break;
	case COMPRESS:
	case DECOMPRESS:
		rc = do_xpress((xpress *)in_work->task);
		if(rc)
			sprintf(msg, "De/Compression of %s Failed!\n",
				((xpress *)in_work->task)->infile);
		else
			sprintf(msg, "De/Compression of %s went successful!\n",
				((xpress *)in_work->task)->infile);
		if(((xpress *)in_work->task)->infile)
			kfree(((xpress *)in_work->task)->infile);
		if(((xpress *)in_work->task)->outfile)
			kfree(((xpress *)in_work->task)->outfile);
		if(((xpress *)in_work->task)->algo)
			kfree(((xpress *)in_work->task)->algo);
		if((xpress *)in_work->task)
			kfree((xpress *)in_work->task);
		break;
	case CHECKSUM:
		rc = do_checksum((checksum *)in_work->task, checksum_result);
		if(rc)
			sprintf(msg, "Checksum computation of %s Failed!\n",
				((checksum *)in_work->task)->infile);
		else
			sprintf(msg, "Checksum for %s computed: %s.\n",
				((checksum *)in_work->task)->infile, checksum_result);
		if(((checksum *)in_work->task)->infile)
			kfree(((checksum *)in_work->task)->infile);
		if((checksum *)in_work->task != NULL)
			kfree((checksum *)in_work->task);
		break;
	case CONCAT:
		rc = do_concat((concat *)in_work->task);
		if(rc)
			sprintf(msg, "Concatenation of %d files Failed!\n",
				((concat *)in_work->task)->infile_count);
		else
			sprintf(msg, "Concatenated %d files successfully!\n",
				((concat *)in_work->task)->infile_count);
		if(((concat *)in_work->task)->outfile != NULL)
			kfree(((concat *)in_work->task)->outfile);
		for(i = 0; i < ((concat *)in_work->task)->infile_count; i++) {
			if(((concat *)in_work->task)->infiles[i] != NULL)
				kfree(((concat *)in_work->task)->infiles[i]);
		}
		if(((concat *)in_work->task)->infiles != NULL)
			kfree(((concat *)in_work->task)->infiles);
		if((concat *)in_work->task != NULL)
			kfree((concat *)in_work->task);
		break;
	default:
		printk("Unrecognised Option!\n");
	}

	if(in_work->priority)
		atomic_dec(&priority_queue_size);
	else
		atomic_dec(&queue_size);

	spin_lock(&list_lock);
	list_for_each_safe(pos, q, &head) {
		node = list_entry(pos, job_list, list);
		if(node->id == in_work->id) {
			pid = node->pid;
			wait = node->wait;
			sprintf(post_msg, "Job %d(PID = %d): %s", node->id, node->pid, msg);
			list_del(pos);
			kfree(node);
		}
	}
	spin_unlock(&list_lock);

	sprintf(message.msg, "%s", post_msg);
	message.err = rc;
	if(wait == 1)
		nl_send_msg(in_work->pid, &message);
	pr_info("%s", post_msg);

	if(in_work && in_work->is_cancelling == 0)
		kfree(work);
	return;
}

asmlinkage long submitjob(void *arg)
{
	long rc = 0;
	int job_id, i, job_found = 0;
	char return_job_list[200] = {0}, job_detail[20];
	submit_job *job;
	xcrypt *xcrypt_work = NULL;
	xpress *xpress_work = NULL;
	checksum *checksum_work = NULL;
	concat *concat_work = NULL;
	qwork *in_work = NULL;
	struct list_head *pos, *q;
	job_list *node = NULL;
	nl_msg message;

	rc = validate_user_args((submit_job *) arg);
	if (rc) {
		pr_err("Invalid User args!\n");
		goto out;
	}

	job = kzalloc(sizeof(submit_job), GFP_KERNEL);
	if (!job) {
		pr_err("Failed to allocate memory for job.\n");
		rc = -ENOMEM;
		goto out;
	}
	rc = copy_from_user(&job->type, &((submit_job *)arg)->type, sizeof(int));
	if (rc) {
		pr_err("Copying of Job Type Failed.\n");
		goto free_job;
	}
	rc = copy_from_user(&job->pid, &((submit_job *)arg)->pid, sizeof(int));
	if (rc) {
		pr_err("Copying of Job PID Failed.\n");
		goto free_job;
	}
	rc = copy_from_user(&job->priority, &((submit_job *)arg)->priority, sizeof(int));
	if (rc) {
		pr_err("Copying of Job Priority Failed.\n");
		goto free_job;
	}

	rc = copy_from_user(&job->wait, &((submit_job *)arg)->wait, sizeof(int));
	if (rc) {
		pr_err("Copying of Job Priority Failed.\n");
		goto free_job;
	}

	if(job->priority == 1) {
		if(atomic_read(&priority_queue_size) == 20) {
			pr_info("Priority Workqueue is Full!\n");
			goto free_job;
		}
	} else if(job->priority == 0) {
		if(atomic_read(&queue_size) == 20) {
			pr_info("Workqueue is Full!\n");
			goto free_job;
		}
	} else {
		pr_err("Unrecognised Job Priority.\n");
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

		// printk("job->type = %d\n", job->type);
		// printk("job->work->infile = %s\n", ((xcrypt *)job->work)->infile);
		// printk("job->work->outfile = %s\n", ((xcrypt *)job->work)->outfile);
		// printk("job->work->cipher = %s\n", ((xcrypt *)job->work)->cipher);
		// printk("job->work->keybuf = %s\n", ((xcrypt *)job->work)->keybuf);
		// printk("job->work->keylen = %d\n", ((xcrypt *)job->work)->keylen);
		// printk("job->work->flag = %d\n", ((xcrypt *)job->work)->flag);
		break;
	case COMPRESS:
	case DECOMPRESS:
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

		// printk("job->type = %d\n", job->type);
		// printk("job->pid = %d\n", job->pid);
		// printk("job->work->infile = %s\n", ((xpress *)job->work)->infile);
		// printk("job->work->outfile = %s\n", ((xpress *)job->work)->outfile);
		// printk("job->work->algo = %s\n", ((xpress *)job->work)->algo);
		// printk("job->work->flag = %d\n", ((xpress *)job->work)->flag);
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

		// printk("job->type = %d\n", job->type);
		// printk("job->pid = %d\n", job->pid);
		// printk("job->work = %s\n", ((checksum *)job->work)->infile);
		break;
	case CONCAT:
		rc = validate_user_concat_args((concat *)((submit_job *)arg)->work);
		concat_work = (concat *)kzalloc(sizeof(concat), GFP_KERNEL);
		if (!concat_work) {
			rc = -ENOMEM;
			goto free_job;
		}
		// for(i = 0; i < ((concat *)((submit_job *)arg)->work)->infile_count;
		// 	i++) {
		// 	printk("job->infiles[i] = %s\n",
		// 		(((concat *)((submit_job *)arg)->work)->infiles[i]));
		// }
		rc = copy_concat_data_to_kernel((concat *)((submit_job *)arg)->work,
			concat_work);
		if(rc)
			goto free_concat;

		job->work = concat_work;

		// printk("job->type = %d\n", job->type);
		// printk("job->pid = %d\n", job->pid);
		// printk("job->outfile = %s\n", ((concat *)job->work)->outfile);
		// printk("job->infile_count = %d\n", ((concat *)job->work)->infile_count);
		break;
	case LIST_JOB:
		strcat(return_job_list, "Job ID\tJob Type\tJob PID\tJob Priority\n");
		spin_lock(&list_lock);
		list_for_each_safe(pos, q, &head) {
			node = list_entry(pos, job_list, list);
			sprintf(job_detail, "%d\t%d\t%d\t%d\n", node->id, node->type,
				node->pid, node->priority);
			strcat(return_job_list, job_detail);
		}
		spin_unlock(&list_lock);
		rc = copy_to_user((char *)((submit_job *)arg)->work, return_job_list,
			strlen(return_job_list));
		if (rc) {
			pr_err("Copying of Job List to User Failed.\n");
		}
		goto free_job;
		break;
	case REMOVE_JOB:
		// printk("(int *)((submit_job *)arg)->work = %d\n",
		// 	*(int *)((submit_job *)arg)->work);
		rc = copy_from_user(&job_id, (int *)((submit_job *)arg)->work,
			sizeof(int));
		if (rc) {
			pr_err("Copying of Job ID from User Failed.\n");
			goto free_job;
		}
		spin_lock(&list_lock);
		list_for_each_safe(pos, q, &head) {
			node = list_entry(pos, job_list, list);
			if(job_id == node->id) {
				job_found = 1;
				((qwork *)node->queued_job)->is_cancelling = 1;
				rc = cancel_work_sync(node->queued_job);
				if(rc) {
					if(node->priority)
						atomic_dec(&priority_queue_size);
					else
						atomic_dec(&queue_size);
					pr_info("Successfully Deleted Job %d.\n", job_id);
					sprintf(message.msg, "%s",
						"This Job got deleted by some other process!\n");
					message.err = -1;
					if(node->wait == 1)
						nl_send_msg(node->pid, &message);
					if(node != NULL)
						in_work = (qwork *)node->queued_job;
					switch(in_work->type) {
					case ENCRYPT:
					case DECRYPT:
						if((xcrypt *)in_work->task != NULL) {
							if(((xcrypt *)in_work->task)->infile != NULL)
								kfree(((xcrypt *)in_work->task)->infile);
							if(((xcrypt *)in_work->task)->outfile != NULL)
								kfree(((xcrypt *)in_work->task)->outfile);
							if(((xcrypt *)in_work->task)->keybuf != NULL)
								kfree(((xcrypt *)in_work->task)->keybuf);
							if(((xcrypt *)in_work->task)->cipher != NULL)
								kfree(((xcrypt *)in_work->task)->cipher);
							// Check again to avoid race condition
							if((xcrypt *)in_work->task != NULL)
								kfree((xcrypt *)in_work->task);
						}
						break;
					case COMPRESS:
					case DECOMPRESS:
						if((xpress *)in_work->task != NULL) {
							if(((xpress *)in_work->task)->infile != NULL)
								kfree(((xpress *)in_work->task)->infile);
							if(((xpress *)in_work->task)->outfile != NULL)
								kfree(((xpress *)in_work->task)->outfile);
							if(((xpress *)in_work->task)->algo != NULL)
								kfree(((xpress *)in_work->task)->algo);
							// Check again to avoid race condition
							if((xpress *)in_work->task != NULL)
								kfree((xpress *)in_work->task);
						}
						break;
					case CHECKSUM:
						if((checksum *)in_work->task != NULL) {
							if(((checksum *)in_work->task)->infile != NULL)
								kfree(((checksum *)in_work->task)->infile);
							if(((checksum *)in_work->task)->algo != NULL)
								kfree(((checksum *)in_work->task)->algo);
							// Check again to avoid race condition
							if((checksum *)in_work->task != NULL)
								kfree((checksum *)in_work->task);
						}
						break;
					case CONCAT:
						if((concat *)in_work->task) {
							if(((concat *)in_work->task)->outfile != NULL)
								kfree(((concat *)in_work->task)->outfile);
							for(i = 0; i <
								((concat *)in_work->task)->infile_count; i++) {
								if((((concat *)in_work->task)->infiles[i]) != NULL)
									kfree(((concat *)in_work->task)->infiles[i]);
							}
							if(((concat *)in_work->task)->infiles != NULL)
								kfree(((concat *)in_work->task)->infiles);
							// Check again to avoid race condition
							if((concat *)in_work->task != NULL)
								kfree((concat *)in_work->task);
						}
						break;
					default:
						pr_err("Unrecognised Option.\n");
					}

					if(node->queued_job != NULL)
						kfree(node->queued_job);

					list_del(pos);
					if (node)
						kfree(node);
					rc = 0;
				} else {
					pr_err("Failed to Delete Job %d. Job might have already "
						"been scheduled\n", job_id);
					rc = -1;
				}
			}
		}
		if(!job_found) {
			pr_err("Failed to Delete Job %d. Could not find it in any queue. "
						"The Job might have already been scheduled\n", job_id);
			rc = -22;
		}
		spin_unlock(&list_lock);
		goto free_job;
		break;
	case SWAP_JOB_PRIORITY:
		rc = copy_from_user(&job_id, (int *)((submit_job *)arg)->work,
			sizeof(int));
		if (rc) {
			pr_err("Copying of Job ID from User Failed.\n");
			goto free_job;
		}
		spin_lock(&list_lock);
		list_for_each_safe(pos, q, &head) {
			node = list_entry(pos, job_list, list);
			if(job_id == node->id) {
				job_found = 1;
				((qwork *)node->queued_job)->is_cancelling = 1;
				rc = cancel_work_sync(node->queued_job);
				if(rc) {
					if(node->priority)
						atomic_dec(&priority_queue_size);
					else
						atomic_dec(&queue_size);
					pr_info("Successfully Deleted Job %d.\n", job_id);
					if(node != NULL) {
						if(node->priority) {
							node->priority = 0;
							((qwork *)node->queued_job)->priority = 0;
							((qwork *)node->queued_job)->is_cancelling = 0;
							rc = queue_work(work_queue,
								(struct work_struct *)node->queued_job);
							pr_info("Putting Job %d on high priority queue.\n",
								node->pid);
							if(rc) {
								atomic_inc(&queue_size);
								rc = 0;
							} else {
								rc = -1;
							}
						} else {
							node->priority = 1;
							((qwork *)node->queued_job)->priority = 1;
							((qwork *)node->queued_job)->is_cancelling = 0;
							rc = queue_work(priority_work_queue,
								(struct work_struct *)node->queued_job);
							pr_info("Putting Job %d on normal priority queue.\n",
								node->pid);
							if(rc) {
								atomic_inc(&priority_queue_size);
								rc = 0;
							} else {
								rc = -1;
							}
						}
					}
					rc = 0;
				} else {
					pr_err("Could Not Swap Priority for Job with ID = %d.\n",
						job_id);
					rc = -1;
				}
			}
		}
		if(!job_found)
			rc = -22;
		spin_unlock(&list_lock);
		pr_debug("free job\n");
		goto free_job;
		break;
	default:
		pr_err("Invalid Option!\n");
		return -1;
	}

	node = (job_list *)kzalloc(sizeof(job_list), GFP_KERNEL);
	if(!node) {
		rc = -ENOMEM;
		goto free_concat;
	}

	in_work =  (qwork *)kzalloc(sizeof(qwork), GFP_KERNEL);	// Need to free this somewhere. check
	if (in_work) {
		INIT_WORK((struct work_struct *)in_work, submit_work_func);
		atomic_inc(&unique_id);
		in_work->id = atomic_read(&unique_id);
		in_work->type = job->type;
		in_work->task = job->work;
		in_work->pid = job->pid;
		in_work->priority = job->priority;
		in_work->is_cancelling = 0;
		node->id = in_work->id;
		node->type = in_work->type;
		node->pid = in_work->pid;
		node->wait = job->wait;
		node->priority = in_work->priority;
		node->queued_job = (struct work_struct *)in_work;
		if(job->priority) {
			rc = queue_work(priority_work_queue, (struct work_struct *)in_work);
			pr_info("Putting Job %d on high priority queue.\n", job->pid);
			if (rc) {
				atomic_inc(&priority_queue_size);
				rc = 0;
			} else {
				rc = -EINVAL;
				goto free_in_work;
			}
		} else {
			rc = queue_work(work_queue, (struct work_struct *)in_work);
			pr_info("Putting Job %d on normal priority queue.\n", job->pid);
			if(rc) {
				atomic_inc(&queue_size);
				rc = 0;
			} else {
				rc = -EINVAL;
				goto free_in_work;
			}
		}

		spin_lock(&list_lock);
		INIT_LIST_HEAD(&node->list);
		list_add_tail(&node->list, &head);
		spin_unlock(&list_lock);
	} else {
		rc = -ENOMEM;
		goto free_job_on_queue;
	}

	goto out;
free_in_work:
	if(in_work != NULL)
		kfree(in_work);
free_job_on_queue:
	if(node != NULL)
		kfree(node);
free_concat:
	if(concat_work != NULL)
		kfree(concat_work);
free_checksum:
	if(checksum_work != NULL)
		kfree(checksum_work);
free_xpress:
	if(xpress_work != NULL);
		kfree(xpress_work);
free_xcrypt:
	if(xcrypt_work != NULL)
		kfree(xcrypt_work);
free_job:
	if(job != NULL)
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

	if (sysptr == NULL)
		sysptr = submitjob;
	if (work_queue == NULL) {
		work_queue = alloc_workqueue("jobs_queue", 0, 5);
	}
	if (priority_work_queue == NULL) {
		priority_work_queue = alloc_workqueue("priority_jobs_queue", WQ_HIGHPRI, 5);
	}

	atomic_set(&queue_size, 0);
	atomic_set(&priority_queue_size, 0);
	atomic_set(&unique_id, 0);

	printk("installed new sys_submitjob module\n");

	return 0;
}
static void  __exit exit_sys_submitjob(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	if (work_queue != NULL) {
		flush_workqueue(work_queue);
		destroy_workqueue(work_queue);
		work_queue = NULL;
	}
	if (priority_work_queue != NULL) {
		flush_workqueue(priority_work_queue);
		destroy_workqueue(priority_work_queue);
		priority_work_queue = NULL;
	}

	atomic_set(&queue_size, 0);
	atomic_set(&priority_queue_size, 0);
	atomic_set(&unique_id, 0);
	netlink_kernel_release(nl_sk);

	printk("removed sys_submitjob module\n");
}
module_init(init_sys_submitjob);
module_exit(exit_sys_submitjob);
MODULE_LICENSE("GPL");
