obj-m += sys_submitjob.o

INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

all: post_job submitjob

post_job: post_job.c
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi post_job.c -o post_job

submitjob:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f post_job
