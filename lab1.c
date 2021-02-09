#include <time.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#define NUMTRIALS 1000000



unsigned int secret[16] = {
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f};
unsigned char* toEncrypt = (char*)(&secret);
unsigned char* encrypted;


void exportDataToFile(int data[]){
	
}
void findMean(int data[]){
	int sum = 0;
	for (int i = 0; i<NUMTRIALS; i++){
		sum+= data[i];
	}
	int mean = sum/NUMTRIALS;
	printf("Average time: %d", mean); 
}
int timeAES(){
	int times[NUMTRIALS];
	for (int i = 0; i<NUMTRIALS; i++){
		int start = clock();
		//AES_encrypt();
		int end = clock();
		times[i] = start - end;		
	}
}
char publicKey[] = "-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAroyB+A4W/acwRq9gthl0\n"
"jb81nPHQ/s9lZNq0AEUnkWnOK+Rae+JoupsSeUehKYJQJkFYjnBc2aV8gSqxtY+b\n"
"r/XcIRSgk9ULUdELaak1WaYfjVEhyUgiQSXBa/QVsnSLMe4Hn6Mdx9J31y3/TLNp\n"
"AaB3Q37e9nfi3xT8K05govYbgV+j9z0zqJeJhS0D7aRzCc+MYDGlVuLpA0UDtjmA\n"
"KM0xD4e0U845qeUMqq7CdXt5mIiqFr7BL28F7zD9b5tqr407UEhsTESnkP9jfFJM\n"
"+t9+EKVUGmNTJMQPimRFot0ZGaTz4J4Jcnl3y0UhwwNqSVpnrOhAkzV+MhHmNOoc\n"
"wwIDAQAB\n"
                   "-----END PUBLIC KEY-----\n";
RSA *createRSA(unsigned char *key, int public){
	RSA *rsa = NULL;
  	BIO *keybio;
  	keybio = BIO_new_mem_buf(key, -1);
  	if (keybio == NULL){
		printf("Failed to create key BIO");
    		return 0;
  	}
  	if (public) rsa = PEM_read_bio_RSA_PUBKEY(
					keybio, 
					&rsa, 
					NULL, 
					NULL);
  	else rsa = PEM_read_bio_RSAPrivateKey(
					keybio, 
					&rsa, 
					NULL, 
					NULL);
  	if (rsa == NULL)printf("Failed to create RSA");
  	return rsa;
}

int timeRSA(){
	int times[NUMTRIALS];
	RSA *rsa = createRSA(publicKey, 1);
	int padding = RSA_PKCS1_PADDING;
	for (int i = 0; i<NUMTRIALS; i++){
		int start = clock();
		RSA_public_encrypt(
				16,
				toEncrypt,
				encrypted, 
				rsa,
				padding);
		int end = clock();
		times[i] = start - end;
	}
	findMean(times);
}
int main(int argc, char*argv[])
{
	timeRSA();
}
