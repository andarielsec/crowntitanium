#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <math.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <dirent.h>
#include <signal.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/buffer.h>
#include <openssl/x509v3.h>
#include <openssl/opensslconf.h>
#include <openssl/ecdsa.h>
#include <sys/random.h>

int cl_encrypt_file_aes_gcm(const char * infile, const char * outfile, const void * key, const void * iv,unsigned char * tag);
int cl_decrypt_file_aes_gcm(const char * infile, const char * outfile, const void * key, const void * iv,unsigned char * tag);
int cl_encrypt_file_camellia_ofb(const char * infile, const char * outfile, const void * key, const void * iv);
int cl_decrypt_file_camellia_ofb(const char * infile, const char * outfile, const void * key, const void * iv);
int cl_encrypt_file_chacha20(const char * infile, const char * outfile, const void * key, const void * iv);
int cl_decrypt_file_chacha20(const char * infile, const char * outfile, const void * key, const void * iv);
int cl_sha2_256(unsigned char * source, int sourcelen,unsigned char * destination);
int cl_sha2_512(unsigned char * source, int sourcelen,unsigned char * destination);
int cl_sha3_256(unsigned char * source, int sourcelen,unsigned char * destination);
int cl_sha3_512(unsigned char * source, int sourcelen,unsigned char * destination);
int cl_crypto_random_data(char * rd);
int cl_encrypt_file(const char * infile, const char * outfile, char *key);
int cl_decrypt_file(const char * infile, const char * outfile, char *key);
void cl_hexdump(char *desc, void *addr, int len);
