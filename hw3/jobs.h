#include "submitjob.h"

int do_xcrypt(xcrypt *);
int compress(void);
int decompress(void);
int checksum(void);
int concat(void);

typedef struct queue_work {
	struct work_struct worker;
	int type;
	int id;
	void *task;
} qwork;

typedef struct queue_job_list {
	int id;
	int type;
	struct work_struct *queued_job;
	struct list_head list;
} job_list;
