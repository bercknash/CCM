/* Authors: Berck Nash, Elijah Ricca
   Class: Applied Cryptography, Spring 2012
   file: main.c

*/

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdint.h>
#include "ccm.h"

#define PRINT_USAGE {                                                   \
          printf("ccm usage:\n");					\
          printf("%s --adata|-a ASSOCIATED_DATA_FILE\n",argv[0]);	\
          printf("--key|-k KEY_FILE\n");				\
          printf("--payload|-p PAYLOAD_FILE\n");			\
	  printf("--t_len|-t MAC_LENGTH\n");				\
     }                                                                  \

int main(int argc,char *argv[]){

     FILE *adata_file, *key_file, *payload_file, *nonce_file;
     char *adata_filename = NULL;
     char *key_filename = NULL;
     char *payload_filename = NULL;
     char *nonce_filename = NULL;
     int opt, option_index;
     int t_len = 8;

     ccm_t input;
     uint64_t key_len;

     /* parse command line options */
     static struct option long_options[] = {
	  {"adata",		required_argument,	0, 'a'},
	  {"payload",		required_argument,	0, 'p'},
	  {"key",		required_argument,	0, 'k'},
	  {"nonce",		required_argument,	0, 'n'},
	  {"t_len",		required_argument,	0, 't'},
          {"help",              no_argument,            0, 'h'},

     };

     while ((opt = getopt_long (argc, argv, "a:p:k:n:t:h?",
                                long_options, &option_index)) != -1 ) {
          switch (opt) {
          case 'a':
               adata_filename = optarg;
               break;
          case 'p':
               payload_filename = optarg;
               break;
          case 'k':
               key_filename = optarg;
               break;
	  case 'n':
               nonce_filename = optarg;
               break;
	  case 't':
	       t_len = strtol(optarg, NULL, 10);
	       break;
          case 'h': //intentional fall-through
          case '?':
               PRINT_USAGE;
               exit(0);
          }
     }

     /* check t_len size */
     if (t_len != 4 && t_len != 6 && t_len != 8 && t_len != 10 && t_len != 12 && t_len != 14 && t_len != 16)
	  fatal("MAC Length must be either 4,6,8,10,12,14, or 16 bytes long.");
     if (t_len < 8)
	  error("Warning: Mac Length less than 64 bits used.  This is not recommended.");
     input.t_len = t_len;

     /* load associated data */
     adata_file = fopen(adata_filename, "rb");
     if (!adata_file)
	  fatal("Error opening associated data file for reading.");

     /* calculate length of adata */
     fseek(adata_file, 0L, SEEK_END);
     input.a_len = ftell(adata_file);
     rewind(adata_file);
     
     /* read associated data from file */
     input.adata = malloc(input.a_len);
     if (!input.adata)
	  fatal("Error allocating memory for associated data.");
     fread(input.adata, input.a_len, 1, adata_file);
     fclose(adata_file);


     /* load key */
     key_file = fopen(key_filename, "rb");
     if (!key_file)
	  fatal("Error opening key file for reading.");

     /* calculate length of key */
     fseek(key_file, 0L, SEEK_END);
     key_len = ftell(key_file);
     rewind(key_file);

     /* check key length for 128 bits */
     if (key_len != 16)
	  fatal("Key is not 128 bits long.");

     /* read key data from file */
     input.key = malloc(32);
     if (!input.key)
	  fatal("Error allocating memory for key data.");
     fread(input.key, key_len, 1, key_file);
     fclose(key_file);


     /* load payload data */
     payload_file = fopen(payload_filename, "rb");
     if (!payload_file)
	  fatal("Error opening payload data file for reading.");

     /* calculate length of payload */
     fseek(payload_file, 0L, SEEK_END);
     input.p_len = ftell(payload_file);
     rewind(payload_file);
     
     /* read associated payload from file */
     input.payload = malloc(input.p_len);
     if (!input.payload)
	  fatal("Error allocating memory for payload data.");
     fread(input.payload, input.p_len, 1, payload_file);
     fclose(payload_file);

     /* load nonce */
     nonce_file = fopen(nonce_filename, "rb");
     if (!nonce_file)
	  fatal("Error opening nonce data file for reading.");

     /* calculate length of nonce */
     fseek(nonce_file, 0L, SEEK_END);
     input.n_len = ftell(nonce_file);
     rewind(nonce_file);
     
     /* read nonce data from file */
     input.nonce = malloc(input.n_len);
     if (!input.nonce)
	  fatal("Error allocating memory for nonce data.");
     fread(input.nonce, input.n_len, 1, nonce_file);
     fclose(nonce_file);

     printf("size of associated data: %lu bytes\n", input.a_len);
     printf("size of key: %lu bytes\n", key_len);
     printf("size of payload: %lu bytes\n", input.p_len);
     printf("size of nonce: %lu bytes\n", input.n_len);

     unsigned char *ciphertext;
     int c_len;
     ciphertext = ccm_encrypt(&c_len, &input);

     /* copy associated data, key, nonce, and ciphertext to struct for decryption */
     ccm_decrypt_t output;
     output.key = input.key;
     output.adata = input.adata;
     output.nonce = input.nonce;
     output.a_len = input.a_len;
     output.n_len = input.n_len;
     output.t_len = t_len;
     output.ciphertext = ciphertext;
     output.c_len = c_len;

     unsigned char *output_payload;
     int output_p_len = 0;
     int i;
     printf("\n");
	  printf("C:\t");
	  for (i=0; i < c_len; i++) {
	       printf("%02x", ciphertext[i]);
	       if (!((i+1) % 4))
		    printf(" ");
	  }
	  printf("\n");
	  
	  output_payload = ccm_decrypt (&output_p_len, &output);

     if (output_payload != NULL)
	  printf("Decryption verified!\n");
     else
	  printf("Decryption failed.\n");
     return 0;
}
