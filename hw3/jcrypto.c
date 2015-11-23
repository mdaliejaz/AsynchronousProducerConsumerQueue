#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/delay.h>
#include "jobs.h"

int encrypt() {
	msleep(600);
	printk("IMPLEMENT encryption.\n");
	return 0;
}

int decrypt() {
	msleep(600);
	printk("IMPLEMENT decryption.\n");
	return 0;
}
