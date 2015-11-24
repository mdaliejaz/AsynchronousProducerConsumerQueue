#include "submitjob.h"

int jcrypt(jcipher *);
int compress(void);
int decompress(void);

typedef struct queue_work {
	struct work_struct worker;
	int type;
	int id;
	void *task;
} qwork;

typedef struct queue_job_list {
	int job_id;
	int job_type;
	struct work_struct *queued_job;
	struct list_head list;
} job_list;
