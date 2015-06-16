all : sample
all : server
COM = gcc
cbc-encrypt: aes_core.o cbc-encrypt.o
	$(COM) -o cbc-encrypt cbc-encrypt.o aes_core.o; rm cbc-encrypt.o

cbc-encrypt.o:
	$(COM) -c cbc-encrypt.c

aes_core.o:
	$(COM)  -c aes_core.c

sample: sample.o oracle.o
	$(COM)  -g -o sample oracle.o sample.o; rm sample.o

sample.o: sample.c
	$(COM)  -g -c sample.c

oracle.o: oracle.c oracle.h
	$(COM)  -g -c oracle.c

server : server.o cbc-decrypt.o aes_core.o
	$(COM) -o server server.o cbc-decrypt.o  aes_core.o

server.o: server.c 
	$(COM) -c server.c

cbc-decrypt.o: cbc-decrypt.c cbc-decrypt.h aes.h
	$(COM) -c cbc-decrypt.c

clean:
	rm -rf *.o sample
