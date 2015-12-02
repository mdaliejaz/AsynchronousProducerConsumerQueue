obj-m += mod_submitjob.o
mod_submitjob-y := sys_submitjob.o xcrypt.o xpress.o checksum.o concat.o shared.o

INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

all: post_job netlink submitjob

netlink:
	gcc -c -Wall -Werror netlink.c -o netlink.o

post_job: post_job.c netlink.o
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi post_job.c netlink.o -o post_job -lcrypto -pthread

submitjob:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f post_job
