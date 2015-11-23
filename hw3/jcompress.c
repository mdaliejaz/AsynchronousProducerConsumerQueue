#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/delay.h>
#include "jobs.h"

int compress() {
	msleep(600);
	printk("IMPLEMENT compression.\n");
	return 0;
}

int decompress() {
	msleep(600);
	printk("IMPLEMENT decompression.\n");
	return 0;
}
