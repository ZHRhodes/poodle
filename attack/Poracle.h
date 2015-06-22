#ifndef POR_H
#define POR_H

int sockfd;

int Oracle_Send(unsigned char* ctext, int num_blocks);
int Oracle_Connect();
int Oracle_Disconnect();

void modifyCipherText(unsigned char* buff, int index);
void decrypt_block(unsigned char* buff, int failed_decrypt_byte);
int findDecryptBreak(unsigned char * buff);
void changeByteRange(unsigned char* buff, int offset, int length, unsigned char xor_value);

#endif
