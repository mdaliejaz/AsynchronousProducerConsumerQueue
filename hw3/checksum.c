#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/delay.h>
#include "jobs.h"

int checksum() {
	msleep(600);
	printk("IMPLEMENT checksum.\n");
	return 0;
}
