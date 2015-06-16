CFLAGS=-lcrypto -Wdeprecated-declarations

all: server
debug: CFLAGS +=-D_DEBUG
debug: server
server: server.o
	gcc $(CFLAGS) server.o -o server
server.o:
	gcc $(CFLAGS) -c server.c -o server.o 
clean:
	rm server
	rm server.o
