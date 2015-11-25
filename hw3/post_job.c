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


// int validate_and_copy_params(submit_job *job, int argc, char **argv)
// {
// 	char opt, *algo, *password;
// 	int passlen = 0;
// 	int i = 0;
// 	int type = 0, t_found = 0, a_found = 0, p_found = 0;
// 	unsigned char pass_hash[MD5_DIGEST_LENGTH];
// 	xcrypt xcrypt_work;

// 	opt = getopt(argc, argv, "t:a:p:h");
// 	while (opt != -1) {
// 		switch (opt) {
// 		case 't':
// 			if (t_found) {
// 				fprintf(stderr, "Type of command can be specified only "
// 				        "once\n");
// 			}
// 			t_found = 1;
// 			type = *optarg - '0';
// 			break;
// 		case 'a':
// 			if (a_found) {
// 				fprintf(stderr, "Algorithm to be used can be specified only "
// 				        "once\n");
// 			}
// 			a_found = 1;
// 			algo = optarg;
// 			break;
// 		case 'p':
// 			if (p_found) {
// 				fprintf(stderr, "Passphrase can be specified only once\n");
// 			}
// 			p_found = 1;

// 			password = optarg + '\0';
// 			passlen = strlen(password);
// 			if (passlen < 6) {
// 				fprintf(stderr, "The password must be at least 6 characters "
// 				        "long. The entered password is only %d characters.\n"
// 				        "For details use -h flag.", passlen);
// 				return -1;
// 			}
// 			// optarg[MD5_DIGEST_LENGTH] = '\0';
// 			MD5((unsigned char*) password, passlen, pass_hash);
// 			// pass_hash[MD5_DIGEST_LENGTH] = '\0';
// 				/*
// 				 * MD5 returns integer representation of the hash.
// 				 * We need to turn it into a hex representation so that it can 
// 				 * be passed around.
// 				 */
// 				// printf("converting\n");
// 				// printf("strlen(pass_hash) = %d\n", sizeof(pass_hash));
// 				// printf("strlen(keybuf) = %d\n", sizeof(&xcrypt_work->keybuf));
// 				for(i = 0; i < 16; i++) {
// 					sprintf(&xcrypt_work.keybuf[i*2], "%02x", (unsigned int)pass_hash[i]);
// 				}
// 				// printf("converted\n");
// 				xcrypt_work.keybuf[32] = '\0'; // Terminating with a null.
// 				// printf("Terminated\n");
// 				// xcrypt_work->keylen = strlen(xcrypt_work->keybuf);
// 				// printf("keylen\n");
// 			break;
// 		case 'h':
// 			printf("./post_job: UNIMPLEMENTED.\n");
// 			return 0;
// 		default:
// 			printf("./post_job: Try './post_job -h' for more information.\n");
// 			return -1;
// 		}
// 		opt = getopt(argc, argv, "t:a:p:h");
// 	}

// 	if (type == 1 || type ==2) {
// 		if (type == 1 && p_found == 0){
// 			fprintf(stderr, "Password is a must for encryption/decryption.\n"
// 							"Try './post_job -h' for more information.\n");
// 			return -1;
// 		}

// 		if (optind + 2 != argc) {
// 			fprintf(stderr, "%d = Insufficient number of arguments.\n", optind);
// 			fprintf(stderr, "%s\t%s\t%s\t%s\n", argv[optind], argv[optind + 1], argv[optind+2], argv[optind+3]);
// 			return -1;
// 		}

// 		xcrypt_work.infile = argv[optind] + '\0';
// 		xcrypt_work.outfile = argv[optind + 1] + '\0';
// 		// printf("pass = %s\n", pass_hash);
// 		// xcrypt_work->keybuf = pass_hash;
// 		// xcrypt_work->cipher_type = malloc(sizeof(unsigned char *));
// 		xcrypt_work.cipher = algo + '\0';
// 		xcrypt_work.keylen = 32;
// 		xcrypt_work.flags = type - 1;

// 		job->type = type;
// 		job->work = &xcrypt_work;

// 		// printf("%s\n", (char *)xcrypt_work.cipher_type);
// 		// printf("%p\n", &xcrypt_work);
// 		// printf("%p\n", &xcrypt_work.cipher_type);
// 		// printf("%p\n", &job->work);

// 		if(strlen(xcrypt_work.infile) > MAX_FILE_NAME_LENGTH ||
// 			strlen(xcrypt_work.outfile) > MAX_FILE_NAME_LENGTH) {
// 			fprintf(stderr, "The maximum size of filename allowed is 255 "
// 				"characters One of your file name exceeds the allowed "
// 				"limit.\n");
// 			return -1;
// 		}
// 	}

// 	return 0;
// }


// int main(int argc, char *argv[])
// {
// 	int rc;

// 	submit_job job;
// 	// xcrypt work;
// 	rc = validate_and_copy_params(&job, argc, argv);
// 	void *dummy = (void *) argv[1];

// 	// printf("0. algo = %s\n", work.cipher);
// 	// printf("0. pass = %s\n", work.keybuf);
// 	// printf("0. in = %s\n", work.infile);
// 	// printf("0. out = %s\n", work.outfile);
// 	// printf("0. keylen = %d\n", work.keylen);
// 	// printf("0. flags = %d\n", work.flags);

// 	printf("0. Type = %d\n", job.type);
// 	// printf("0. algo = %s\n", (char *) ((xcrypt *)job.work)->cipher);
// 	// printf("0. keybuf = %s\n", (char *) ((xcrypt *)job.work)->keybuf);
// 	// printf("0. infile = %s\n", (char *) ((xcrypt *)job.work)->infile);
// 	// printf("0. outfile = %s\n", (char *) ((xcrypt *)job.work)->outfile);
// 	// printf("0. keylen = %d\n", ((xcrypt *)job.work)->keylen);
// 	// printf("0. flags = %d\n", ((xcrypt *)job.work)->flags);

// 	printf("0. algo = %s\n", job.work->cipher);
// 	printf("0. keybuf = %s\n", job.work->keybuf);
// 	printf("0. infile = %s\n", job.work->infile);
// 	printf("0. outfile = %s\n", job.work->outfile);
// 	printf("0. keylen = %d\n", job.work->keylen);
// 	printf("0. flags = %d\n", job.work->flags);


// 	rc = syscall(__NR_submitjob, dummy);
// 	if (rc == 0)
// 		printf("syscall returned %d\n", rc);
// 	else
// 		printf("syscall returned %d (errno=%d)\n", rc, errno);

// 	exit(rc);
// }




int main(int argc, char *argv[])
{
	int rc = 0, pid;
	submit_job job;
	char opt, *algo, *password, *res;
	char out_realpath[PATH_MAX + 1], in_realpath[PATH_MAX + 1];
	int passlen = 0;
	int type = 0, t_found = 0, a_found = 0, p_found = 0;
	unsigned char pass_hash[MD5_DIGEST_LENGTH];
	xcrypt xcrypt_work;

	opt = getopt(argc, argv, "t:a:p:h");
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
				        "once\n");
			}
			a_found = 1;
			algo = optarg;
			break;
		case 'p':
			if (p_found) {
				fprintf(stderr, "Passphrase can be specified only once\n");
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
		case 'h':
			printf("./post_job: UNIMPLEMENTED.\n");
			return 0;
		default:
			printf("./post_job: Try './post_job -h' for more information.\n");
			return -1;
		}
		opt = getopt(argc, argv, "t:a:p:h");
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
	}

	// printf("0. Type = %d\n", job.type);
	// printf("0. algo = %s\n", ((xcrypt *)job.work)->cipher);
	// printf("0. keybuf = %s\n", ((xcrypt *)job.work)->keybuf);
	// printf("0. infile = %s\n", ((xcrypt *)job.work)->infile);
	// printf("0. outfile = %s\n", ((xcrypt *)job.work)->outfile);
	// printf("0. keylen = %d\n", ((xcrypt *)job.work)->keylen);
	// printf("0. flags = %d\n", ((xcrypt *)job.work)->flags);

	pid = getpid();
	job.pid = pid;
	rc = nl_bind(pid);
	if(rc) {
		goto out;
	}

	printf("pid = %d\n", pid);

	rc = syscall(__NR_submitjob, (void *) &job);
	if (rc == 0)
		printf("syscall returned %d\n", rc);
	else
		printf("syscall returned %d (errno=%d)\n", rc, errno);

	receive_from_kernel(pid);

	out:
	exit(rc);
}
