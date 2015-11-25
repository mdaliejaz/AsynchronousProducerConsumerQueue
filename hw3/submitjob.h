#define ENCRYPT 1
#define DECRYPT 2
#define COMPRESS 3
#define DECOMPRESS 4
#define CHECKSUM 5
#define CONCAT 6

#define MAX_FILE_NAME_LENGTH 255
#define AES_BLOCK_SIZE 16

//struct to submit jobs on queue
typedef struct submit_job {
	int type;
	void *work;
} submit_job;

//struct for encryption/decryption
typedef struct encrypt_decrypt_struct {
	char *infile;				// input filename
	char *outfile;				// outputp filename
	char *cipher;				// cipher type to be used
	unsigned char *keybuf;		// encryption/decryption passphrase
	int keylen;					// length of the passphrase
	int flag;					// encryption or decryption: encryption = 1
} xcrypt;
