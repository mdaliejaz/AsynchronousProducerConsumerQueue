#include "submitjob.h"

#define MD5_DIGEST_LENGTH 32

int do_xcrypt(xcrypt *);
int validate_user_xcrypt_args(xcrypt *);
int copy_xcrypt_data_to_kernel(xcrypt *, xcrypt *);

int do_xpress(xpress *);
int validate_user_xpress_args(xpress *);
int copy_xpress_data_to_kernel(xpress *, xpress *);

int do_checksum(checksum *, char *);
int validate_user_checksum_args(checksum *);
int copy_checksum_data_to_kernel(checksum *, checksum *);

int do_concat(concat *);
int validate_user_concat_args(concat *);
int copy_concat_data_to_kernel(concat *, concat *);

int validate_file(struct file *, int);

typedef struct queue_work {
	struct work_struct worker;
	int type;
	int id;
	int pid;
	int priority;
	int is_cancelling;
	void *task;
} qwork;

typedef struct queue_job_list {
	int id;
	int type;
	int pid;
	int priority;
	int wait;
	struct work_struct *queued_job;
	struct list_head list;
} job_list;
