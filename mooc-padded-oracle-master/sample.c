#include "oracle.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

void modifyCipherText(unsigned char* buff, int index) {
    buff[index]++;
}

void changeByteRange(unsigned char* buff, int offset, int length, unsigned char xor_value) {
    int i;
    for (i = 0; i < length; i++) {
        buff[i + offset] = buff[i + offset] ^ xor_value;
    }
}

int findDecryptBreak(unsigned char * buff ) {
  unsigned char buff_cpy[48];
  int ret, byte_index;

  byte_index = 16;

  while (true) {

    printf("Trying decrypt on index: %d\n", byte_index);
    memcpy(buff_cpy, buff, 48);
    modifyCipherText(buff_cpy, byte_index);

    ret = Oracle_Send(buff_cpy, 3); // the first argument is an unsigned char array ctext;
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
      buff_modified[k - 1] = i;
      ret = Oracle_Send(buff_modified, 2); // the first argument is an unsigned char array ctext;
      if (ret == 1) {
        printf("Successfully decrypted with i = 0x%02X\n", i);
        break;
      }
      nanosleep(&sleep_interval, NULL);
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

// Read a ciphertext from a file, send it to the server, and get back a result.
// If you run this using the challenge ciphertext (which was generated correctly),
// you should get back a 1. If you modify bytes of the challenge ciphertext, you
// may get a different result...

// Note that this code assumes a 3-block ciphertext.

int main(int argc, char *argv[]) {
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
}
