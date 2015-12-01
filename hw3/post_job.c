#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <openssl/md5.h>
#include <string.h>
#include "submitjob.h"

#ifndef __NR_submitjob
#error submitjob system call not defined
#endif

int main(int argc, char *argv[])
{
	int rc = 0, pid, i, j, priority = 0;
	submit_job job;
	char opt, *algo, *password, *res, *job_list, *junk;
	char out_realpath[PATH_MAX + 1], in_realpath[PATH_MAX + 1];
	int passlen = 0, job_id;
	int type = 0, t_found = 0, a_found = 0, p_found = 0, i_found = 0;
	unsigned char pass_hash[MD5_DIGEST_LENGTH];
	xcrypt xcrypt_work;
	xpress xpress_work;
	checksum checksum_work;
	concat concat_work;

	opt = getopt(argc, argv, "t:a:p:i:Ph");
	while (opt != -1) {
		switch (opt) {
		case 't':
			if (t_found) {
				fprintf(stderr, "Type of command can be specified only "
						"once\n");
			}
			t_found = 1;
			if(!strcmp(optarg,"ENCRYPT")) {
				type = ENCRYPT;
			}
			else if(!strcmp(optarg,"DECRYPT")) {
				type = DECRYPT;
			}
			else {
				type = *optarg - '0';
			}
			break;
		case 'a':
			if (a_found) {
				fprintf(stderr, "Algorithm to be used can be specified only "
				        "once!\n");
			}
			a_found = 1;
			algo = optarg;
			break;
		case 'p':
			if (p_found) {
				fprintf(stderr, "Passphrase can be specified only once!\n");
			}
			p_found = 1;

			password = optarg + '\0';
			passlen = strlen(password);
			if (passlen < 6) {
				fprintf(stderr, "The password must be at least 6 characters "
				        "long. The entered password is only %d characters.\n"
				        "For details use -h flag.", passlen);
				return -1;
			}
			MD5((unsigned char*) password, passlen, pass_hash);
			pass_hash[passlen] = '\0';
			break;
		case 'i':
			if (i_found) {
				fprintf(stderr, "You can remove/swap priority of "
					"only one job at a time!\n");
			}
			i_found = 1;

			job_id = strtol(optarg, &junk, 10);
			printf("ID = %d\n", job_id);
			break;
		case 'P':
			priority = 1;
			printf("Priority job = %d\n", type);
			break;
		case 'h':
			printf("./post_job: UNIMPLEMENTED.\n");
			return 0;
		default:
			printf("./post_job: Try './post_job -h' for more information.\n");
			return -1;
		}
		opt = getopt(argc, argv, "t:a:p:i:Ph");
	}

	// add type check validation
	if (type == ENCRYPT || type == DECRYPT) {
		if (p_found == 0){
			fprintf(stderr, "Password is a must for encryption/decryption.\n"
							"Try './post_job -h' for more information.\n");
			return -1;
		}

		if (optind + 2 != argc) {
			fprintf(stderr, "%d = Insufficient number of arguments.\n",
				optind);
			return -1;
		}

		res = realpath(argv[optind], in_realpath);
		if (res) {
			xcrypt_work.infile =  in_realpath + '\0';
		}
		else {
			perror("realpath");
			return -1;
		}

		res = realpath(argv[optind + 1], out_realpath);
		// No error check as the file might not exist
		xcrypt_work.outfile =  out_realpath + '\0';

		xcrypt_work.cipher = algo + '\0';
		xcrypt_work.keybuf = pass_hash + '\0';
		xcrypt_work.keylen = MD5_DIGEST_LENGTH;
		xcrypt_work.flag = type;

		job.type = type;
		job.work = &xcrypt_work;

		if(strlen(xcrypt_work.infile) > MAX_FILE_NAME_LENGTH ||
			strlen(xcrypt_work.outfile) > MAX_FILE_NAME_LENGTH) {
			fprintf(stderr, "The maximum size of filename allowed is 255 "
				"characters One of your file name exceeds the allowed "
				"limit.\n");
			return -1;
		}
		// printf("0. Type = %d\n", job.type);
		// printf("0. algo = %s\n", ((xcrypt *)job.work)->cipher);
		// printf("0. keybuf = %s\n", ((xcrypt *)job.work)->keybuf);
		// printf("0. infile = %s\n", ((xcrypt *)job.work)->infile);
		// printf("0. outfile = %s\n", ((xcrypt *)job.work)->outfile);
		// printf("0. keylen = %d\n", ((xcrypt *)job.work)->keylen);
		// printf("0. flags = %d\n", ((xcrypt *)job.work)->flag);
	} else if (type == COMPRESS || type == DEFLATE) {
		if (optind + 2 != argc) {
			fprintf(stderr, "%d = Insufficient number of arguments.\n",
				optind);
			return -1;
		}

		res = realpath(argv[optind], in_realpath);
		if (res) {
			xpress_work.infile =  in_realpath + '\0';
		}
		else {
			perror("realpath");
			return -1;
		}

		res = realpath(argv[optind + 1], out_realpath);
		// No error check as the file might not exist
		xpress_work.outfile =  out_realpath + '\0';

		xpress_work.algo = algo + '\0';
		xpress_work.flag = type;

		job.type = type;
		printf("type = %d\n", type);
		job.work = &xpress_work;

		if(strlen(xpress_work.infile) > MAX_FILE_NAME_LENGTH ||
			strlen(xpress_work.outfile) > MAX_FILE_NAME_LENGTH) {
			fprintf(stderr, "The maximum size of filename allowed is 255 "
				"characters One of your file name exceeds the allowed "
				"limit.\n");
			return -1;
		}
		printf("0. Type = %d\n", job.type);
		printf("0. algo = %s\n", ((xpress *)job.work)->algo);
		printf("0. infile = %s\n", ((xpress *)job.work)->infile);
		printf("0. outfile = %s\n", ((xpress *)job.work)->outfile);
		printf("0. flags = %d\n", ((xpress *)job.work)->flag);
	} else if (type == CHECKSUM) {
		if (optind + 1 != argc) {
			fprintf(stderr, "%d = Insufficient number of arguments.\n",
				optind);
			return -1;
		}

		res = realpath(argv[optind], in_realpath);
		if (res) {
			checksum_work.infile =  in_realpath + '\0';
		}
		else {
			perror("realpath");
			return -1;
		}
		job.type = type;
		job.work = &checksum_work;

		if(strlen(checksum_work.infile) > MAX_FILE_NAME_LENGTH) {
			fprintf(stderr, "The maximum size of filename allowed is 255 "
				"characters One of your file name exceeds the allowed "
				"limit.\n");
			return -1;
		}
		printf("0. Type = %d\n", job.type);
		printf("0. infile = %s\n", ((xpress *)job.work)->infile);
	} else if (type == CONCAT) {
		if (!(optind + 2 <= argc)) {
			fprintf(stderr, "%d = Insufficient number of arguments.\n",
				optind);
			return -1;
		}

		concat_work.infile_count = argc - optind - 1;

		res = realpath(argv[optind], out_realpath);
		concat_work.outfile =  out_realpath + '\0';

		concat_work.infiles = malloc(sizeof(char *) * concat_work.infile_count);

		for(i = optind + 1, j = 0; i < argc; i++, j++) {
			res = realpath(argv[i], in_realpath);
			if (res) {
				concat_work.infiles[j] = (char *)malloc(strlen(in_realpath) + 1);
				strcpy(concat_work.infiles[j], in_realpath);
				concat_work.infiles[j][strlen(in_realpath)] = '\0';
			}
			else {
				perror("realpath of one of the input file");
				return -1;
			}
			printf("infile[%d] = %s\n", j, concat_work.infiles[j]);

			if(strlen(concat_work.infiles[j]) > MAX_FILE_NAME_LENGTH) {
				fprintf(stderr, "The maximum size of filename allowed is 255 "
					"characters One of your file name exceeds the allowed "
					"limit.\n");
				return -1;
			}
		}

		job.type = type;
		job.work = &concat_work;

		printf("0. Type = %d\n", job.type);
		printf("0. outfile = %s\n", ((concat *)job.work)->outfile);
		printf("0. infile count = %d\n", ((concat *)job.work)->infile_count);
		for(i = 0; i < concat_work.infile_count; i++) {
			printf("0. infile[%d] = %s\n", i, ((concat *)job.work)->infiles[i]);
		}
	} else if (type == LIST_JOB) {
		job.type = type;
		job_list = (char *)malloc(sizeof(int) * 100);
		job.work = job_list;
	} else if (type == REMOVE_JOB) {
		if (!i_found) {
			fprintf(stderr, "You must specify the Job ID of the process to be deleted.\n");
			goto out;
		}
		job.type = type;
		job.work = &job_id;
		printf("removing ID = %d\n", job_id);
	} else if (type == SWAP_JOB_PRIORITY) {
		if (!i_found) {
			fprintf(stderr, "You must specify the Job ID of the process to be deleted.\n");
			goto out;
		}
		job.type = type;
		job.work = &job_id;
		printf("swap priority ID = %d\n", job_id);
	}

	job.priority = priority;
	pid = getpid();
	job.pid = pid;
	// rc = nl_bind(pid);
	if(rc) {
		goto out;
	}

	printf("pid = %d\n", pid);

	printf("type = %d\n", job.type);

	rc = syscall(__NR_submitjob, (void *) &job);
	if (rc == 0)
		printf("syscall returned %d\n", rc);
	else
		printf("syscall returned %d (errno=%d)\n", rc, errno);

	// receive_from_kernel(pid);

	if(type == CONCAT) {
		for(i = 0; i < concat_work.infile_count; i++) {
			if(!concat_work.infiles[i])
				free(concat_work.infiles[i]);
		}
		if(concat_work.infiles)
			free(concat_work.infiles);
	}

	if(type == LIST_JOB) {
		printf("List of Jobs in queue:\n%s", job_list);
		free(job_list);
	}

	out:
	exit(rc);
}
