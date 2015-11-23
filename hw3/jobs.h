#include "submitjob.h"

int encrypt(void);
int decrypt(void);
int compress(void);
int decompress(void);

typedef struct {
	struct work_struct worker;
	int type;
} my_work_t;
