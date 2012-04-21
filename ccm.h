typedef struct {
     unsigned char *key, *adata, *payload, *nonce;
     unsigned long a_len, n_len, p_len;
     int t_len;
} ccm_t;

int ccm_encrypt(unsigned char*, int*, ccm_t*);
void print_block(unsigned char*);
void format(ccm_t*, unsigned char **, int, unsigned char **, int);

/* error handling */
void error(char*); //prints an error messages to stderr, continues
void fatal(char*); //prints an error message to stderr, exits
