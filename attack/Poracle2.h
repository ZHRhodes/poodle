#ifndef POR2_H
#define POR2_H

int sockfd;

int Oracle_Send(unsigned char* ctext, int num_blocks);
int Oracle_Connect();
int Oracle_Disconnect();

void decrypt_block(unsigned char* ct, unsigned char *pt);
#endif
