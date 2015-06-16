cbc-encrypt: aes_core.o cbc-encrypt.o
	gcc -o cbc-encrypt cbc-encrypt.o aes_core.o; rm cbc-encrypt.o

cbc-encrypt.o:
	gcc -c cbc-encrypt.c

aes_core.o:
	gcc -c aes_core.c

sample: sample.o oracle.o
	gcc -g -o sample oracle.o sample.o; rm sample.o

sample.o: sample.c
	gcc -g -c sample.c

oracle.o: oracle.c oracle.h
	gcc -g -c oracle.c

clean:
	rm -rf *.o sample
