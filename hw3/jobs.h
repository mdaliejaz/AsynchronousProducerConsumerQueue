#include "submitjob.h"

#define MD5_DIGEST_LENGTH 32

int do_xcrypt(xcrypt *);
int do_xpress(xpress *);
int do_checksum(checksum *, char *);
int concat(void);
int validate_file(struct file *, int);

typedef struct queue_work {
	struct work_struct worker;
	int type;
	int id;
	int pid;
	void *task;
} qwork;

typedef struct queue_job_list {
	int id;
	int type;
	struct work_struct *queued_job;
	struct list_head list;
} job_list;
