#include <linux/linkage.h>
#include <linux/moduleloader.h>

asmlinkage extern long (*sysptr)(void *arg);

asmlinkage long submitjob(void *arg)
{
	/* dummy syscall: returns 0 for non null, -EINVAL for NULL */
	printk("submitjob received arg %p\n", arg);
	if (arg == NULL)
		return -EINVAL;
	else
		return 0;
}

static int __init init_sys_submitjob(void)
{
	printk("installed new sys_submitjob module\n");
	if (sysptr == NULL)
		sysptr = submitjob;
	return 0;
}
static void  __exit exit_sys_submitjob(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	printk("removed sys_submitjob module\n");
}
module_init(init_sys_submitjob);
module_exit(exit_sys_submitjob);
MODULE_LICENSE("GPL");
