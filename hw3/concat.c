#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/delay.h>
#include "jobs.h"

int concat() {
	msleep(600);
	printk("IMPLEMENT concatenation.\n");
	return 0;
}
