#include "timer.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
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
char arr[16] = {'a','b','c','d','e','f','g','h','i','a','a','a','a','a','a','a'};
char en[8192];
unsigned char* toEncrypt = arr;
unsigned char* encrypted = en;


void exportDataToFile(int data[]){
	
}
void findMean(int data[]){
	int sum = 0;
	for (int i = 0; i<NUMTRIALS; i++){
		sum+= data[i];
	}
	int mean = sum/NUMTRIALS;
	printf("Average time: %d \n", mean); 
}
FILE *fp;
void writeToFile(int data[], char fName[]){
	fp = fopen(fName, "w");
	for (int i = 0; i < NUMTRIALS; i++){
		fprintf(fp, "%d \n", data[i]);
	}
	fclose(fp);
}
int timeAES(){
	int times[NUMTRIALS];
	int size = 8192;
  	char buf[size];
	unsigned char key[16];
	AES_KEY *expanded;
	expanded = (AES_KEY *)malloc(sizeof(AES_KEY));
	AES_set_encrypt_key(key, 128, expanded);
	printf("Running AES encryption \n");
	for (int i = 0; i<NUMTRIALS; i++){
		int start = timer_start();
		AES_encrypt(arr, buf, expanded);
		int end = timer_stop();
		times[i] = end - start;
	}
	findMean(times);
	writeToFile(times, "aes.txt");
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
	printf("Running RSA encryption \n");
	for (int i = 0; i<NUMTRIALS; i++){
		int start = timer_start();
		RSA_public_encrypt(
				16,
				toEncrypt,
				encrypted, 
				rsa,
				padding);
		int end = timer_stop();
		times[i] = end-start;
	}
	findMean(times);
	writeToFile(times, "rsa.txt");
}
int main(int argc, char*argv[])
{
	timeRSA();
	timeAES();
}
