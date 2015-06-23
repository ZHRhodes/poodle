#include "Poracle.h"

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>

#define NOFLAGS 0
#define BLOCK_LENGTH 16

/*
int Oracle_Send(unsigned char* ctext, int num_blocks, int &sockfd);
int Oracle_Connect(int &sockfd);
int Oracle_Disconnect(int &sockfd);

void modifyCipherText(unsigned char* buff, int index);
void decrypt_block(unsigned char* buff, int failed_decrypt_byte, int &sockfd);
int findDecryptBreak(unsigned char * buff, int &sockfd);
void changeByteRange(unsigned char* buff, int offset, int length, unsigned char xor_value);

*/

int main(int argc, char* argv[]) {
  	unsigned char ctext[48]; // allocate space for 48 bytes, i.e., 3 blocks
  	unsigned char plaintext_char;
  	int i, tmp, ret, k;
  	FILE *fpIn;
  	int failed_on_byte;
  	int target_padding_value;
  	int padding_value;

  	if (argc != 2) {
    	printf("Usage: sample <filename>\n");
    	return -1;
  	}

  	fpIn = fopen(argv[1], "r");

  	for(i=0; i<48; i++) {
    	fscanf(fpIn, "%02x", &tmp);
    	ctext[i] = tmp;
  	}

  	fclose(fpIn);

  	Oracle_Connect();

  	failed_on_byte = findDecryptBreak(ctext);
  	printf("Failed to decrypt on %d\n", failed_on_byte);
  	Oracle_Disconnect();

  	decrypt_block(ctext, 16);
  	decrypt_block(ctext + 16, failed_on_byte - 16);

	return 0;
}

int Oracle_Connect() {
	struct sockaddr_in servaddr, cliaddr;
  	int rc;
  

  	sockfd = socket(AF_INET, SOCK_STREAM, 0);

  	bzero(&servaddr, sizeof(servaddr));
  	servaddr.sin_family = AF_INET;
  	servaddr.sin_addr.s_addr=inet_addr("198.101.141.164");//54.165.60.84//10.46.118.128
  	servaddr.sin_port=htons(443);

  	if(!connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr))) {
    	printf("Connected to server successfully.\n");
    	return 0;
  	} else {
    	perror("Failed to connect to oracle");
    	return -1;
  	}
}

int Oracle_Disconnect() {
	
  	if(!close(sockfd)) {
    	printf("Connection closed successfully.\n");
    	return 0;
  	} else {
    	perror("[WARNING]: You haven't connected to the server yet");
    	return -1;
  	}
}

// Packet Structure: < num_blocks(1) || ciphertext(16*num_blocks) || null-terminator(1) >
int Oracle_Send(unsigned char* ctext, int num_blocks) {
	 
  	int ctext_len = num_blocks * BLOCK_LENGTH;
  	unsigned char message[(ctext_len)+2];
  	char recvbit[2];

  	message[0] = num_blocks;
  	memcpy((message+1), ctext, ctext_len);
  	message[ctext_len+1] = '\0';
        printf("sending...\n");
  	if(!send(sockfd, message, ctext_len+2, NOFLAGS)) {
    	perror("[WARNING]: You haven't connected to the server yet");
    	return -1;
  	}
        printf("receiving...\n");
  	if(!recv(sockfd, recvbit, 2, NOFLAGS)) {
    	perror("[ERROR]: Recv failed");
        printf("%d %d\n", recvbit[0], errno);
    	return -1;
  	}
  	recvbit[1] = '\0';
        printf("%d: recvbit\n", recvbit[0]);
  	return atoi(recvbit);
}

void changeByteRange(unsigned char* buff, int offset, int length, unsigned char xor_value) {
    int i;
   	for (i = 0; i < length; i++) {
       	buff[i + offset] = buff[i + offset] ^ xor_value;
   	}
}

int findDecryptBreak(unsigned char * buff) {
  	unsigned char buff_cpy[48];
  	int ret, byte_index;

  	byte_index = 16;

  	while (true) {

    	printf("Trying decrypt on index: %d\n", byte_index);
    	memcpy(buff_cpy, buff, 48);
    	modifyCipherText(buff_cpy, byte_index);

    	ret = Oracle_Send(buff_cpy, 3); // the first argument is an unsigned char array ctet;
                               // the second argument indicates how many blocks ctext has
    	if (ret < 1) {
      		printf("Failed decrypt after modifying byte position: %d\n", byte_index);
      		break;
    	}
    	byte_index++;
  	}
  	return byte_index;
}

void decrypt_block(unsigned char* buff, int failed_decrypt_byte) {
  	unsigned char plaintext[17];
  	unsigned char buff_modified[32];
  	int i, k, ret;
  	int padding_value;
  	int target_padding_value;
  	struct timespec sleep_interval;
  	sleep_interval.tv_sec = 0;
  	sleep_interval.tv_nsec = 250000000;

        printf("In decrypt_block now...\n");

  	memset(plaintext, 0, sizeof(plaintext));
  	memcpy(buff_modified, buff, 32);

  	for (k = failed_decrypt_byte; k > 0; k--) {

    	padding_value = 16 - k;
    	target_padding_value = padding_value + 1;

    	printf("Updating padding to %d\n", target_padding_value);
    	changeByteRange(buff_modified, k, padding_value, target_padding_value ^ padding_value);

    	Oracle_Connect();
    	printf("Starting to find i value which will successfully decrypt\n");
    	for (i = 0; i < 256; i++) {
      		printf(".");
      		fflush(stdout);
                printf("flushed...\n");
      		buff_modified[k - 1] = i;
                printf("Sending oracle...\n");
      		ret = Oracle_Send(buff_modified, 2); // the first argument is an unsigned char array ctext;
                printf("sent modified buffer...\n");
      		if (ret == 1) {
        		printf("Successfully decrypted with i = 0x%02X\n", i);
        		break;
      		}
                printf("now sleeping...\n");
      		nanosleep(&sleep_interval, NULL);
                printf("finished sleeping...\n");
    	}
    	printf("\n");
    	if (i == 256) {
      		printf("Did not find value which decrypted the cyphertext\n");
      		Oracle_Disconnect();
      		exit(1);
    	}
    	plaintext[k - 1] = i ^ target_padding_value ^ buff[k - 1];

    	printf("Found plaintext value of: %c\n", plaintext[k - 1]);
  	}
  	Oracle_Disconnect();

  	printf("final plaintext for block: %s\n", plaintext);
}

void modifyCipherText(unsigned char* buff, int index) {
    buff[index]++;
}
