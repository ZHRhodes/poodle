#include "Poracle2.h"

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


int main(int argc, char* argv[]) {
  	
	FILE *open;
	char ctext[48];
	char tmp;
	char ptext[16];


	open = fopen(argv[1], "r");

	for(i=0; i<48; i++) {
    	fscanf(fpIn, "%02x", &tmp);
    	ctext[i] = tmp;
  	}

  	fclose(open);

  	decrypt_block(ctext, ptext);


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

void decrypt_block(unsigned char* ct, unsigned char* pt) {

	int padding, targetpadding, k, i ret;	
	char modifiedCT[32];
	int guessPT;



	memset(pt, 0, sizeof(pt));
  	memcpy(modifiedCT, ct, 32);

	for (k = 15; k >= 0; --k) {

		padding = 16 - k;
		targetpadding = padding;

		Oracle_Connect();

		for (guessPT = 0; guessPT < 256; ++guessPT) {

			for(i = 15; i >=k; --i) {

				if (pt[i]) {
					modifiedCT[i] = ct[i] ^ (char) guessPT ^ (char) targetpadding;
				} else {
					modifiedCT[i] = ct[i] ^ pt[i] ^ (char) targetpadding;
				}

			}

			ret = Oracle_Send(modifiedCT, 2); // the first argument is an unsigned char array ctext;
                printf("sent modified buffer...\n");
      		if (ret == 1) {
        		printf("Successfully decrypted with i = %c\n", i);
        		pt[k] = (char) guessPT;
        		break;
      		}
                printf("now sleeping...\n");
      			nanosleep(&sleep_interval, NULL);
                printf("finished sleeping...\n");
    	
	    	printf("\n");
	    	if (guessPT == 256) {
	      		printf("Did not find value which decrypted the cyphertext\n");
	      		Oracle_Disconnect();
	      		exit(1);
	    	}


		}
		Oracle_Disconnect()


	}


}