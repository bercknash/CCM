/* Authors: Berck Nash, Elijah Ricca
   Class: Applied Cryptography, Spring 2012
   file: ccm.c

   CCM
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/aes.h>
#include "ccm.h"

int ccm_encrypt(ccm_t *input)
{
     unsigned char *key = input -> key;
     unsigned char *payload = input -> payload;
     unsigned long a_len = input -> a_len;
     unsigned long p_len = input -> p_len;
     int t_len = input -> t_len;
     int extrabytes, i;
     unsigned char **blocks, **ctr;
     AES_KEY aes_key;

     /* determine number of blocks to allocate */
     if (a_len) {
	  if (a_len < 65280) 
	       extrabytes=2;
	  else if ( a_len < 0x100000000 ) 
	       extrabytes=6;
	  else 
	       extrabytes=10;
     }
     int num_ctr = 1 +  ((p_len + 15) / 16);
     int num_blocks = ((a_len + extrabytes + 15) / 16) + num_ctr;

     /* allocate input blocks */
     blocks = calloc(num_blocks, sizeof(char*));
     if (!blocks)
	  fatal("Error allocating memory for input blocks.");
     for (i=0; i < num_blocks; i++) {
	  blocks[i] = calloc(16, sizeof(char));
	  if (!blocks[i])
	       fatal("Error allocating memory for input blocks.");
     }

     /* allocate counter blocks */
     ctr = calloc(num_ctr, sizeof(char*));
     if (!ctr)
	  fatal("Error allocating memory for input blocks.");
     for (i=0; i < num_ctr; i++) {
	  ctr[i] = calloc(16, sizeof(char));
	  if (!ctr[i])
	       fatal("Error allocating memory for input blocks.");
     }


     /* Format Blocks */
     format(input, blocks, num_blocks, ctr, num_ctr);

     if (AES_set_encrypt_key(key, 128, &aes_key))
	  fatal("Error initializing AES key.");

/* --calculate tag-- */
     unsigned char *y0, *y1, *ybuff, *ytemp;
     y0 = calloc(16, sizeof(char));
     y1 = calloc(16, sizeof(char));
     ybuff = calloc(16, sizeof(char));
     if (!y0 || !y1 || !ybuff)
	  fatal("Error allocating memory for Y buffer.");

     AES_encrypt(blocks[0], y0, &aes_key);

     /* XOR each block with the previous encrypted input block, and encrypt
	This is done in two 64-bit segments for efficiency */
     for (i=1; i<num_blocks; i++) {
	  *((uint64_t *) ybuff) = *((uint64_t*) blocks[i]) ^ *((uint64_t*) y0);
	  *((uint64_t *) (ybuff+8)) = *((uint64_t*) (blocks[i]+8)) ^ *((uint64_t*) (y0+8));
	  AES_encrypt(ybuff, y1, &aes_key);

	  /* swap buffers for next round, don't lose references */
	  ytemp = y0;
	  y0 = y1;
	  y1 = ytemp;
     }

/* copy t_len most significant bits of last round to tag */
     unsigned char *tag;
     tag = calloc(t_len, sizeof(char));
     memcpy(tag, y0, t_len);

     free(y0);
     free(y1);
     free(ybuff);

/* --calculate S blocks -- */
     unsigned char s[num_ctr][16];
     for (i=0; i < num_ctr; i++)
	  AES_encrypt(ctr[i], s[i], &aes_key);

/* --calculate ciphertext-- */
     unsigned char c[p_len+t_len];
     for (i=0; i < p_len; i++) 
	  c[i] = payload[i] ^ s[1][i];

     for (i=0; i< t_len; i++)
	  *(c+p_len+i) = *(tag+i) ^ *(s[0]+i);

/* debug prints */
     printf("\n");
     for (i=0; i < num_blocks; i++) {
	  printf("B%d:\t", i);
	  print_block(blocks[i]);
     }
     printf("\n");
     for (i=0; i < num_ctr; i++) {
	  printf("C%d:\t", i);
	  print_block(ctr[i]);
     }
     printf("\n");
     printf("T:\t");
     for (i=0; i < t_len; i++) {
	  printf("%02x", tag[i]);
	  if (!((i+1) % 4))
	       printf(" ");
     }
     printf("\n");
     printf("\n");
     for (i=0; i < num_ctr; i++) {
	  printf("S%d:\t", i);
	  print_block(s[i]);
     }
     printf("\n");
     printf("C:\t");
     for (i=0; i < t_len+p_len; i++) {
	  printf("%02x", c[i]);
	  if (!((i+1) % 4))
	       printf(" ");
     }
     printf("\n");
     return 0;
}

void print_block(unsigned char *block)
{
     int i;
     for (i=0; i<16; i++) {
	  printf("%02x", block[i]);
	  if (!((i+1) % 4))
	       printf(" ");
     }
     printf("\n");
}
     
void format(ccm_t *input, unsigned char **blocks, int num_blocks, unsigned char **ctr, int num_ctr)
{
     unsigned char *adata = input -> adata;
     unsigned char *payload = input -> payload;
     unsigned char *nonce = input -> nonce;
     unsigned long a_len = input -> a_len;
     unsigned long n_len = input -> n_len;
     unsigned long p_len = input -> p_len;
     int t_len = input -> t_len;
     unsigned char flags = 0;
     int cur_block = 1;
     uint64_t a_len_be, p_len_be, p_len_temp; //temp storage for big endian
     int nextbyte;
     int i;

     /* set a bit of flag (1 if there's any a_data, 0 otherwise)*/
     if (a_len)
	  flags = 0b1 << 6;

     /* set 3 t-bits of flag */
     unsigned int t = (t_len-2)/2;
     flags = flags | (t << 3);

     /* set 3 q-bits of flag */
     unsigned int q = 15 - n_len;
     flags = flags | (q-1);

     /* check that we have enough bits to store payload length */
     uint64_t q_temp = p_len;
     int q_min = 0;
     while (q_temp >>= 1)
	  q_min++;
     q_min /= 8;
     printf("\nqmin: %d",q_min);
     if ( q < q_min)
	  fatal("Nonce is too long for payload size.");
     
     blocks[0][0] = flags;


     memcpy(&blocks[0][1], nonce, n_len); //copy nonce to block

     /* copy payload length to big endian order */
     p_len_temp = p_len << ((8-q)*8);
     p_len_be = htobe64(p_len_temp);

     memcpy(&blocks[0][1]+n_len, (&p_len_be), q); //copy payload length to block

/* ---copy associated data to input blocks--- 
   There are 3 possible formats depending on the length of the data. */
     if (a_len) {
	  if (a_len < 65280) {
	       uint16_t short_a_len_be = htobe16((uint16_t) a_len);
	       memcpy(&blocks[1][0], &short_a_len_be, 2);
	       nextbyte = 2;
	  }
	  else if ( a_len < 0x100000000 ) {
	       uint32_t short_a_len_be = htobe32((uint32_t) a_len);
	       blocks[1][0] = 0xff;
	       blocks[1][1] = 0xfe;
       	       memcpy(&blocks[1][2], &short_a_len_be, 4);
	       nextbyte = 6;
	  }
	  else {
	       a_len_be = htobe64(a_len);
	       blocks[1][0] = 0xff;
	       blocks[1][1] = 0xff;
       	       memcpy(&blocks[1][2], &a_len_be, 8);
	       nextbyte = 10;
	  }

	  int a_rem = a_len; //associated data remaining
	  if (a_rem <= (16-nextbyte)) { //only one row left
	       memcpy(&blocks[1][nextbyte], adata, a_rem);
	       nextbyte += a_rem;
	  }
	  else //more than one row left
	  {
	       memcpy(&blocks[cur_block++][nextbyte], adata, 16-nextbyte); //fill row
	       a_rem -= 16-nextbyte;
	       nextbyte = 0;
	       while (a_rem >= 16) {
		    memcpy(&blocks[cur_block++][0], adata+a_len-a_rem, 16);
		    a_rem -= 16;
	       }
	       memcpy(&blocks[cur_block][0], adata+a_len-a_rem, a_rem);
	       nextbyte = a_rem;
	  }
	  
	  /* zero-pad */
	  memset(&blocks[cur_block++][nextbyte], 0, 16-nextbyte);
     }

/* --copy payload data to input blocks-- */
     int p_rem = p_len;
     /* first copy full blocks */
     i = 0;

     while (p_rem >= 16) {
	  memcpy(blocks[cur_block++], &payload[16*i++], 16);
	  p_rem -= 16;
     }


     if (p_rem) {
	  printf("p_rem: %d\n", p_rem);
	  /* copy remaining partial block */
	  memcpy(blocks[cur_block], &payload[16*i], p_rem);
	  /* zero-pad */
	  memset(&blocks[cur_block++][p_rem], 0, 16-p_rem);
     }
     
     
/* -- format counter blocks -- */
/* reset flags for counter blocks */
     flags = flags & 0b00000111;

     uint64_t long_i; //temporary long buffer for i
     for (i=0; i < num_ctr; i++) {
	  ctr[i][0] = flags;
	  memcpy(&ctr[i][1], nonce, n_len); //copy nonce to ctr
	  long_i = i;
	  long_i = long_i << ((8-q)*8);
	  long_i = htobe64(long_i); // convert long i to big endian
	  memcpy(&ctr[i][1]+n_len, &long_i, q);  //copy i to ctr block
     }

   
     printf("\nNum Bocks: %d\n", num_blocks);
}
