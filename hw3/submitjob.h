#define ENCRYPT 1
#define DECRYPT 2
#define COMPRESS 3
#define CHECKSUM 4
#define CONCAT 5

#define MAX_FILE_NAME_LENGTH 255

//struct to submit jobs on queue
typedef struct submit_job {
	int type;
	void *work;
}submit_job;

//struct for encryption/decryption
typedef struct encrypt_decrypt_struct {
	char *infile;				// input filename
	char *outfile;				// outputp filename
	char *cipher;			// cipher type to be used
	unsigned char *keybuf;		// encryption/decryption passphrase
	int keylen;				// length of the passphrase
	int flags;					// encryption or decryption: encryption = 1
} jcipher;
