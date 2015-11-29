#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/fs.h>
#include "submitjob.h"

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
