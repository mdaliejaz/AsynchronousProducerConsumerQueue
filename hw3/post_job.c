#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <openssl/md5.h>
#include <pthread.h>
#include <string.h>
#include "submitjob.h"

#ifndef __NR_submitjob
#error submitjob system call not defined
#endif

/*
 * This function prints the help for this driver program.
 */
void print_help_on_stdout() {
	fprintf(stdout, "POST_JOB(1)\t\t\tUser Commands\t\t\tPOST_JOB(1)\n\n");

	fprintf(stdout, "NAME\n\tpost_job - posts jobs for asyncronous "
		"processing.\n\n");

	fprintf(stdout, "SYNOPSIS\n\t./post_jobs <job_option> [input_options] "
		"[inputFile ...] [outputFile].\n\n");

	fprintf(stdout, "DESCRIPTION\n\tPosts Jobs asyncronously to the kernel "
		"for processing. Currently Encryption, Decryption, Compression, "
		"Decompression, Checksum computation, Concatenation of multiple "
		"files, Listing of Jobs on queue, Removing a job from queue and "
		"Swapping of Job priority is supported.\n\tThe user can choose "
		"to not wait for the job response and look at it later in dmesg.\n");
	fprintf(stdout, "\tThe submitjob() system call is defined in the kernel "
		"module sys_submitjob.c.\n");

	fprintf(stdout, "\n\tThe Job options are as follows:\n");
	fprintf(stdout, "\t-e\tencrypt the given file\n");
	fprintf(stdout, "\t-d\tdecrypt the given encrypted file\n");
	fprintf(stdout, "\t-s\tshorten or compress the given file\n");
	fprintf(stdout, "\t-r\trestore or decompress the given compressed file\n");
	fprintf(stdout, "\t-c\tcompute checksum of the given file\n");
	fprintf(stdout, "\t-m\tmerge or concatenate the given input files\n");
	fprintf(stdout, "\t-l\tlist the queued jobs waiting to be processed\n");
	fprintf(stdout, "\t-u\tundo or remove a previously put job\n");
	fprintf(stdout, "\t-t\ttweak or swap priority of previously put job\n");

	fprintf(stdout, "\n\tInput options are as follows:\n");
	fprintf(stdout, "\t-a\talgorithm to be used for encryption, decryption,\n"
		"\t\tcompression, decompression and checksum computation\n");
	fprintf(stdout, "\t-p\tpassword to be used for encryption, decryption\n"
		"\t\tPassword should be at least 6 characters long\n");
	fprintf(stdout, "\t-i\tID of the Job to be deleted or whose priority "
		"needs to be changed.\n");
	fprintf(stdout, "\t-w\tdo not wait for the job response\n");
	fprintf(stdout, "\t-P\tpriority to be used as high for the given job\n"
		"\t\tdefault priority is 'no priority' for all the jobs except "
		"checksum computation whose priority is always high\n");
	fprintf(stdout, "\t-h\tdisplay this help and exit\n\n");
	
	fprintf(stdout, "EXAMPLES\n\t./post_job -e -p password -a aes infile "
		"outfile\n");
	fprintf(stdout, "\t\tEncrypts the given input File 'infile' "
		"using the password 'password' and AES algorithm. "
		"The output is an encrypted file named 'outfile'.\n");
	fprintf(stdout, "\t./post_job -d -p password -a des infile outfile\n");
	fprintf(stdout, "\t\tDecrypts the given input File 'infile' "
		"using the password 'password' and DES algorithm. "
		"The output is a decrypted file named 'outfile'.\n");
	fprintf(stdout, "\t./post_job -s -a deflate infile outfile\n");
	fprintf(stdout, "\t\tCompress the given input File 'infile' "
		"using the 'deflate' algorithm. The output is a compressed file "
		"named 'outFile'.\n");
	fprintf(stdout, "\t./post_job -r -a lzo infile outfile\n");
	fprintf(stdout, "\t\tDecompress the given input File 'infile' "
		"using the 'lzo' algorithm. The output is a decompressed file "
		"named 'outFile'.\n");
	fprintf(stdout, "\t./post_job -c -a md5 infile\n");
	fprintf(stdout, "\t\tComputes Checksum of the given input File 'infile' "
		"using the 'md5' algorithm.\n");
	fprintf(stdout, "\t./post_job -m inFile1 infile2 infile3 outfile\n");
	fprintf(stdout, "\t\tConcatenates the given input Files 'infile1' "
		"'infile2' and 'infile3' to gives a new concatenated file "
		"'outfile'.\n");
	fprintf(stdout, "\t./post_job -l\n");
	fprintf(stdout, "\t\tLists the current jobs on queue.\n");
	fprintf(stdout, "\t./post_job -u -i 3\n");
	fprintf(stdout, "\t\tRemoved the job with job ID 3 from the "
		"workqueue.\n");
	fprintf(stdout, "\t./post_job -t -i 3\n");
	fprintf(stdout, "\t\tSwap the priority from high to low or low to high "
		"for the job with job ID 3.\n\n");

	fprintf(stdout, "AUTHOR\n\tWritten by Muhammad Ali Ejaz under the "
		"guidance of Professor Erez Zadok.\n\n");

	fprintf(stdout, "REPORTING BUGS\n\tReport bugs to "
		"<mejaz@cs.stonybrook.edu>.\n\n");

	fprintf(stdout, "COPYRIGHT\n\tCopyright (c) 2015 Muhammad Ali Ejaz.\n"
		"\tThis  is free software. You may redistribute copies of it and/or "
		"modify it under the terms of the GNU General Public License "
		"<http://www.gnu.org/licenses/gpl.html>.\n\tThere is NO WARRANTY, "
		"to the extent permitted by law.\n\n");

	fprintf(stdout, "CSE-506\t\t\tDecember 2015\t\t\tPOST_JOB(1)\n\n");
}

int main(int argc, char *argv[])
{
	int rc = 0, pid, i, j, priority = 0, wait = 1;
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
	pthread_t rcv_msg_thread;

	opt = getopt(argc, argv, "edsrcmluta:p:i:wPh");
	while (opt != -1) {
		switch (opt) {
		case 'e':
			if (t_found) {
				fprintf(stderr, "Type of command can be specified only "
						"once\n");
			}
			t_found = 1;
			type = ENCRYPT;
			break;
		case 'd':
			if (t_found) {
				fprintf(stderr, "Type of command can be specified only "
						"once\n");
			}
			t_found = 1;
			type = DECRYPT;
			break;
		case 's':
			if (t_found) {
				fprintf(stderr, "Type of command can be specified only "
						"once\n");
			}
			t_found = 1;
			type = COMPRESS;
			break;
		case 'r':
			if (t_found) {
				fprintf(stderr, "Type of command can be specified only "
						"once\n");
			}
			t_found = 1;
			type = DECOMPRESS;
			break;
		case 'c':
			if (t_found) {
				fprintf(stderr, "Type of command can be specified only "
						"once\n");
			}
			t_found = 1;
			type = CHECKSUM;
			break;
		case 'm':
			if (t_found) {
				fprintf(stderr, "Type of command can be specified only "
						"once\n");
			}
			t_found = 1;
			type = CONCAT;
			break;
		case 'l':
			if (t_found) {
				fprintf(stderr, "Type of command can be specified only "
						"once\n");
			}
			t_found = 1;
			type = LIST_JOB;
			break;
		case 'u':
			if (t_found) {
				fprintf(stderr, "Type of command can be specified only "
						"once\n");
			}
			t_found = 1;
			type = REMOVE_JOB;
			break;
		case 't':
			if (t_found) {
				fprintf(stderr, "Type of command can be specified only "
						"once\n");
			}
			t_found = 1;
			type = SWAP_JOB_PRIORITY;
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
			break;
		case 'w':
			wait = 0;
			break;
		case 'P':
			priority = 1;
			break;
		case 'h':
			print_help_on_stdout();
			return 0;
		default:
			printf("./post_job: Try './post_job -h' for more information.\n");
			return -1;
		}
		opt = getopt(argc, argv, "edsrcmluta:p:i:wPh");
	}

	// add type check validation
	if (type == ENCRYPT || type == DECRYPT) {
		if (p_found == 0){
			fprintf(stderr, "Password is a must for encryption/decryption.\n"
							"Try './post_job -h' for more information.\n");
			return -1;
		}

		if (a_found == 0){
			algo = "aes";
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
		// No error check as the output file might not exist
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
	} else if (type == COMPRESS || type == DECOMPRESS) {
		if (a_found == 0){
			algo = "deflate";
		}

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
		// No error check as the output file might not exist
		xpress_work.outfile =  out_realpath + '\0';

		xpress_work.algo = algo + '\0';
		xpress_work.flag = type;

		job.type = type;
		job.work = &xpress_work;

		if(strlen(xpress_work.infile) > MAX_FILE_NAME_LENGTH ||
			strlen(xpress_work.outfile) > MAX_FILE_NAME_LENGTH) {
			fprintf(stderr, "The maximum size of filename allowed is 255 "
				"characters One of your file name exceeds the allowed "
				"limit.\n");
			return -1;
		}
		// printf("0. Type = %d\n", job.type);
		// printf("0. algo = %s\n", ((xpress *)job.work)->algo);
		// printf("0. infile = %s\n", ((xpress *)job.work)->infile);
		// printf("0. outfile = %s\n", ((xpress *)job.work)->outfile);
		// printf("0. flags = %d\n", ((xpress *)job.work)->flag);
	} else if (type == CHECKSUM) {
		if (a_found == 0){
			algo = "md5";
		}
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
		checksum_work.algo = algo + '\0';

		job.type = type;
		job.work = &checksum_work;

		if(strlen(checksum_work.infile) > MAX_FILE_NAME_LENGTH) {
			fprintf(stderr, "The maximum size of filename allowed is 255 "
				"characters One of your file name exceeds the allowed "
				"limit.\n");
			return -1;
		}
		// printf("0. Type = %d\n", job.type);
		// printf("0. infile = %s\n", ((xpress *)job.work)->infile);
	} else if (type == CONCAT) {
		if (!(optind + 2 <= argc)) {
			fprintf(stderr, "%d = Insufficient number of arguments.\n",
				optind);
			return -1;
		}

		concat_work.infile_count = argc - optind - 1;

		concat_work.infiles = malloc(sizeof(char *) * concat_work.infile_count);
		for(i = optind, j = 0; i < argc - 1; i++, j++) {
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
			// printf("infile[%d] = %s\n", j, concat_work.infiles[j]);

			if(strlen(concat_work.infiles[j]) > MAX_FILE_NAME_LENGTH) {
				fprintf(stderr, "The maximum size of filename allowed is 255 "
					"characters One of your file name exceeds the allowed "
					"limit.\n");
				return -1;
			}
		}
		res = realpath(argv[argc - 1], out_realpath);
		concat_work.outfile =  out_realpath + '\0';

		job.type = type;
		job.work = &concat_work;

		// printf("0. Type = %d\n", job.type);
		// printf("0. outfile = %s\n", ((concat *)job.work)->outfile);
		// printf("0. infile count = %d\n", ((concat *)job.work)->infile_count);
		// for(i = 0; i < concat_work.infile_count; i++) {
		// 	printf("0. infile[%d] = %s\n", i, ((concat *)job.work)->infiles[i]);
		// }
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
		// printf("removing ID = %d\n", job_id);
	} else if (type == SWAP_JOB_PRIORITY) {
		if (!i_found) {
			fprintf(stderr, "You must specify the Job ID of the process to be deleted.\n");
			goto out;
		}
		job.type = type;
		job.work = &job_id;
	} else {
		fprintf(stderr, "You must specify a valid job type!\n");
		goto out;
	}

	job.priority = priority;
	pid = getpid();
	job.pid = pid;
	job.wait = wait;

	if(wait)
		rc = nl_bind(pid);
	if(rc) {
		fprintf(stderr, "Netlink binding Failed!\n");
		goto out;
	}

	rc = syscall(__NR_submitjob, (void *) &job);
	if (rc == 0) {
		if(wait == 1) {
			/* create a second thread which listens for kernel msg */
			if(pthread_create(&rcv_msg_thread, NULL, receive_from_kernel,
				&pid)) {
				fprintf(stderr, "Error creating thread for Kernel "
					"response.\n");
				rc = -1;
				wait = 0;
			} else {
				fprintf(stdout, "Created a thread which will wait for "
					"kernel Job response!\n");
			}
		} else if (type != LIST_JOB && type != REMOVE_JOB &&
			type != SWAP_JOB_PRIORITY) {
			fprintf(stdout, "Job PID: %d.\n"
				"Once finished, proper message will be put in dmesg!\n", pid);
		}
	}
	else {
		fprintf(stderr, "syscall returned %d (errno=%d)\n", rc, errno);
		perror("Syscall failed");
		wait = 0;
	}

	if(type == CONCAT) {
		for(i = 0; i < concat_work.infile_count; i++) {
			if(!concat_work.infiles[i])
				free(concat_work.infiles[i]);
		}
		if(concat_work.infiles)
			free(concat_work.infiles);
	}

	// Some other tasks can run here
	// while the other thread waits for kernel msg!
	// The following sleep for instance is to demonstrate such behaviour
	if(!rc && wait) {
		sleep(1);
		fprintf(stdout, "Main Thread: (Test) Running task possible in main "
			"thread while the spawned thread waits for kernel msg!\n");
	}

	if(!rc && type == LIST_JOB) {
		fprintf(stdout, "List of Jobs in queue:\n%s", job_list);
		free(job_list);
	}

	if(!rc && type == REMOVE_JOB) {
		if(errno == 22)
			fprintf(stderr, "Could not find Job %d! "
				"The Job might have already been scheduled.\n",job_id);
		else if(rc)
			fprintf(stderr, "Removal of Job %d Failed! "
				"The Job might have already been scheduled.\n",job_id);
		else
			fprintf(stdout, "Removal of Job %d was Successful!\n", job_id);
	}

	if(!rc && type == SWAP_JOB_PRIORITY) {
		if(rc == -22)
			fprintf(stderr, "Could not find Job %d! "
				"The Job might have already been scheduled.\n",job_id);
		else if(rc)
			fprintf(stderr, "Swapping Priority of Job %d Failed! "
				"The Job might have already been scheduled.\n", job_id);
		else
			fprintf(stdout, "Swapping Priority of Job %d was Successful!\n", job_id);
	}

	if(!rc && wait) {
		fprintf(stdout, "Main thread execution over! "
			"Going to join the threads back.\n");
		if(pthread_join(rcv_msg_thread, NULL)) {
			fprintf(stderr, "Error joining thread\n");
			return 2;
		}
	}

out:
	exit(rc);
}
