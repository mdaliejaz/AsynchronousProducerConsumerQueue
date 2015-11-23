#include "submitjob.h"

int jcrypt(jcipher *);
int compress(void);
int decompress(void);

typedef struct {
	struct work_struct worker;
	int type;
	void *task;
} qwork;
