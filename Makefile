CC=gcc
OPENSSL=../../openssl
INCLUDE=$(OPENSSL)/include/
CFLAGS=-c -I$(INCLUDE) 

all: server lab1

lab1: lab1.c
	$(CC) lab1.c -I$(INCLUDE) -L$(OPENSSL) -g -o lab1 $(OPENSSL)/libcrypto.a -ldl -lpthread

server: server.c
	$(CC) server.c -I$(INCLUDE) -L$(OPENSSL) -o server $(OPENSSL)/libcrypto.a -ldl -lpthread

clean:
	rm -rf server lab1
