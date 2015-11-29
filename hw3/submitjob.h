#define ENCRYPT 1
#define DECRYPT 2
#define COMPRESS 3
#define DEFLATE 4
#define CHECKSUM 5
#define CONCAT 6

#define MAX_FILE_NAME_LENGTH 255
#define AES_BLOCK_SIZE 16

//struct to submit jobs on queue
typedef struct submit_job {
	int pid;
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

//struct for compression/decompression
typedef struct compress_decompress_struct {
	char *infile;				// input filename
	char *outfile;				// outputp filename
	char *algo;					// compression/decompression algorithm used
	int flag;					// encryption or decryption: encryption = 1
} xpress;

//struct for checksum
typedef struct checksum_struct {
	char *infile;				// input filename
} checksum;

//struct for file concatenation
typedef struct concat_struct {
	char *outfile;
	char **infiles;
	int infile_count;
	// int oflags;
	// mode_t mode;
	// unsigned int flags;

} concat;

int nl_bind(int);
void receive_from_kernel(int);
