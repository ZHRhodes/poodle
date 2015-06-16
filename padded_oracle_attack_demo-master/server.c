#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <err.h>
#include <openssl/evp.h>
#include <string.h>

#define AES_BLOCK_SIZE 256

#define EVP_INIT_FAIL -1
#define EVP_DEC_UPDATE -2
#define EVP_DEC_FINAL -3
// 404, 400 (Bad Reauest), 200
static char byteMap[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
static int byteMapLen = sizeof(byteMap);

char not_found_res[] = "HTTP/1.1 404\r\n";
char bad_request_res[] = "HTTP/1.1 400\r\n";
char response[] = "HTTP/1.1 200 OK\r\n"
"Content-Type: text/html; charset=UTF-8\r\n\r\n"
"<doctype !html><html><head><title>Sup</title>"
"</head>"
"<body><h1>sup</h1></body></html>\r\n";

int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx,
	     EVP_CIPHER_CTX *d_ctx, unsigned char*iv){
  int nrounds = 5;
  unsigned char key[32];
  int x = 0;
  int i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
  
  if(i != 32){
    printf("Key size is %d bits - it should be 256 bits", i);
    return -1;    
  }
  #ifdef _DEBUG
  for(; x<32; x++)
    printf("Key: %x iv: %x \n", key[x], iv[x]);
  
  for(x=0; x<8; x++)
    printf("salt: %x\n", salt[x]);
  #endif

  EVP_CIPHER_CTX_init(e_ctx);
  EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
  EVP_CIPHER_CTX_init(d_ctx);
  EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

  return 0;
}
  
unsigned char*aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *pt, int *len){
  int c_len = *len + AES_BLOCK_SIZE - 1;
  int f_len = 0;
  unsigned char *ciphertext = (unsigned char *)malloc(c_len);
 
  /* allows reusing of 'e' for multiple encryption cycles */
  if(!EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL)){
    #ifdef _DEBUG
    printf("ERROR in EVP_EncryptInit_ex \n");
    #endif
    return NULL;
  }
 
  /* update ciphertext, c_len is filled with the length of ciphertext generated,
   *len is the size of plaintext in bytes */
  if(!EVP_EncryptUpdate(e, ciphertext, &c_len, pt, *len)){
    #ifdef _DEBUG
    printf("ERROR in EVP_EncryptUpdate \n");
    #endif
    return NULL;
  }
 
  /* update ciphertext with the final remaining bytes */
  if(!EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len)){
    #ifdef _DEBUG
    printf("ERROR in EVP_EncryptFinal_ex \n");
    #endif
    return NULL;
  }
 
  *len = c_len + f_len;
  return ciphertext;
}
/*
*/
unsigned char*aes_decrypt(EVP_CIPHER_CTX*e, unsigned char *ct, int *len){
  /* plaintext will always be equal to or lesser than length of ciphertext*/
  int p_len = *len, f_len = 0;
  unsigned char *pt = (unsigned char *)malloc(p_len);
 
  if(!EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL)){
    #ifdef _DEBUG
    printf("ERROR in EVP_DecryptInit_ex \n");
    #endif
    return EVP_INIT_FAIL;
  }
 
  if(!EVP_DecryptUpdate(e, pt, &p_len, ct, *len)){
    #ifdef _DEBUG
    printf("ERROR in EVP_DecryptUpdate\n");
    #endif
    return EVP_DEC_UPDATE;
  }
 
  if(!EVP_DecryptFinal_ex(e, pt+p_len, &f_len)){
    #ifdef _DEBUG
    printf("ERROR in EVP_DecryptFinal_ex\n");
    #endif
    return EVP_DEC_FINAL;
  }
 
  *len = p_len + f_len;
  return pt;
}
static uint8_t nibbleFromChar(char c){
  if(c >= '0' && c <= '9') return c - '0';
  if(c >= 'a' && c <= 'f') return c - 'a' + 10;
  if(c >= 'A' && c <= 'F') return c - 'A' + 10;
  return 255;
}

/* Utility function to convert nibbles (4 bit values) into a hex character representation */
static char
nibbleToChar(uint8_t nibble)
{
  if(nibble < byteMapLen) return byteMap[nibble];
  return '*';
}
char *bt_hex(uint8_t *bytes, size_t buflen){
  char *retval;
  int i;
  
  retval = malloc(buflen*2 + 1);
  for(i=0; i<buflen; i++) {
    retval[i*2] = nibbleToChar(bytes[i] >> 4);
    retval[i*2+1] = nibbleToChar(bytes[i] & 0x0f);
  }

  retval[i] = '\0';
  return retval;
}
char *hex_bt(char *inhex){
  char *retval;
  char *p;
  int len, i;
  
  len = strlen(inhex) / 2;
  retval = malloc(len+1);
  for(i=0, p = (char *) inhex; i<len; i++) {
    retval[i] = (nibbleFromChar(*p) << 4) | nibbleFromChar(*(p+1));
    p += 2;
  }
  retval[len] = 0;
  return retval;
}

int main(void){
  int one = 1, client_fd;
  struct sockaddr_in srv_addr, cli_addr;
  socklen_t sin_len = sizeof(cli_addr);
  char*revc_buffer = (char*) malloc(sizeof(char)*10000);
  int recv_len = 0;
  int sock = socket(AF_INET, SOCK_STREAM, 0);

  // Define plaintext
  unsigned char* pt = "sander is cool";

  // Strings needed to parse http verb
  unsigned char* p_substring_begin;
  unsigned char* p_substring_end;

  // http argument should be stored in attr
  unsigned char* attr;

  // enc data
  unsigned char*key_data = "MgXtf937pFYaUFUePF68TuXppNQe9hmP";
  unsigned char salt[] = {1,2,3,4,5,6,7,8,9,2,3,1,2,2,2,4,9,3};

  // Define the iv used on the stack in the main function.
  unsigned char iv[32];

  // define CTX openssl structures for enc and dec
  EVP_CIPHER_CTX en;
  EVP_CIPHER_CTX dec;
  
  if(aes_init(key_data, strlen(key_data), salt, &en, &dec, &iv[0])){
    printf("could not init aes cihper");
    fflush(stdout);
    return -1;
  }

  int strlen_pt = strlen(pt)+1;

  char*ct = aes_encrypt(&en, (unsigned char*)pt, &strlen_pt);
  char*ct_hex = bt_hex(ct, strlen(ct)*2);

  #ifdef _DEBUG
  printf("%s\n", ct);
  #endif
  printf("%s\n", bt_hex(iv,32));
  printf("%s\n",ct_hex);
  fflush(stdout);

  if (sock < 0)
    err(1, "can't open socket");
 
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));
 
  int port = 8081;
  srv_addr.sin_family = AF_INET;
  srv_addr.sin_addr.s_addr = INADDR_ANY;
  srv_addr.sin_port = htons(port);
 
  if (bind(sock, (struct sockaddr *) &srv_addr, sizeof(srv_addr)) == -1) {
    close(sock);
    err(1, "Can't bind");
  }
 
  listen(sock, 5);
  while (1) {
    client_fd = accept(sock, (struct sockaddr *) &cli_addr, &sin_len);
    if (client_fd == -1) {
      perror("Can't accept");
      continue;
    }
    
    recv_len = recvfrom(client_fd, revc_buffer, 100, 0,(struct sockaddr*)&cli_addr, &sin_len);

    revc_buffer[recv_len] = 0;
    p_substring_begin = (unsigned char*)strstr((const char*)revc_buffer, (const char*)"enc=");

    if(p_substring_begin){
      p_substring_end = (unsigned char*)strstr((const char*)p_substring_begin, (const char*)" ");
      
      int n_bytes = p_substring_end - p_substring_begin;
      // -4 because the "enc=" string and +1 for the '\0' symbol
      attr = (unsigned char*) malloc(sizeof(char)*(n_bytes-4)+1);
      strncpy((char*)attr, (const char*)(p_substring_begin + 4), n_bytes-4);
      attr[n_bytes-4] = '\0';
      
      char*rct_hex = hex_bt(attr);

      #ifdef _DEBUG
      printf("%s\n", rct_hex);
      #endif

      int rct_len = strlen(rct_hex);

      #ifdef _DEBUG
      printf("%d\n", rct_len);
      #endif
      
      char* plaintext = (char *)aes_decrypt(&dec, rct_hex, &rct_len);
      if(plaintext == EVP_DEC_FINAL){
	#ifdef _DEBUG
	printf("EVP_DEC_FINAL");
	#endif
	write(client_fd, bad_request_res, sizeof(bad_request_res) - 1); /*-1:'\0'*/
      }else if(!strcmp(plaintext,pt)){
	#ifdef _DEBUG
	printf("strcmp match");
	printf("%s\n", plaintext);
	#endif
	write(client_fd, response, sizeof(response) - 1); /*-1:'\0'*/
      }else{
	#ifdef _DEBUG
	printf("strcmp not match");
	printf("%s\n", plaintext);
	#endif
	write(client_fd, not_found_res, sizeof(not_found_res) - 1); /*-1:'\0'*/
      }
      
      fflush(stdout);
    }else{
      write(client_fd, response, sizeof(response)-1);
    }
    close(client_fd);
  }
  free(revc_buffer);
}
 
