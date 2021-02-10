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

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
 
#include <arpa/inet.h>  
#include <string.h>
#define PORT 12000

struct sockaddr_in server;

int main(int argc , char *argv[]){
	int valread;
	int socket_desc;
	socket_desc = socket(AF_INET,SOCK_STREAM,0);
	if (socket_desc == -1){
		printf("Could not create socket");
		return -1;
	}
	char *hello = "Hello from client";
	char buffer[1024] = {0};
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_family = AF_INET;
	server.sin_port = htons(PORT);
	   
    	if(inet_pton(AF_INET, 
			"127.0.0.1", 
			&server.sin_addr)<=0){
        	printf("\nInvalid address\n"); 
        	return -1; 
    	} 
   
    	if (connect(socket_desc,
			(struct sockaddr*)&server, 
			sizeof(server)) < 0) { 
        	printf("\nConnection Failed \n"); 
        	return -1; 
    	} 
    	send(socket_desc,hello,strlen(hello),0 ); 
    	printf("Hello message sent\n"); 
    	valread = read(socket_desc,buffer,1024); 
    	printf("%s\n",buffer );   
	return 0;

}
