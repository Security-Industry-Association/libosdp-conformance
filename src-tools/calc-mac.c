#if 0






void
  calculate_s_enc
  (uint8_t *s_enc,
  char *rnd_a,
  uint8_t *iv,
void
  decrypt_cryptogram
    (uint8_t *cgram,
    uint8_t *cleartext,
    uint8_t *iv,
    uint8_t *key);
void
  dump_buffer
    (char *buffer,
    int length);



{ /* main for osdp-sc-calc */

  uint8_t clear_client_cryptogram [OSDP_KEY_SIZE];
  uint8_t clear_server_cryptogram [OSDP_KEY_SIZE];
  uint8_t iv [OSDP_KEY_SIZE];
  uint8_t payload_chlng [1024];
  int payload_chlng_lth;
  uint8_t payload_client_cryptogram [1024];
  int payload_client_cryptogram_lth;
  uint8_t payload_server_cryptogram [1024];
  int payload_server_cryptogram_lth;
  char rnd_a [OSDP_KEY_SIZE/2];
  int rnd_a_lth;
  uint8_t s_enc [OSDP_KEY_SIZE];
  uint8_t secure_channel_base_key [OSDP_KEY_SIZE] = 
    {0x30, 0x31, 0x32, 0x33,
     0x34, 0x35, 0x36, 0x37,
     0x38, 0x39, 0x3A, 0x3B,
     0x3C, 0x3D, 0x3E, 0x3F};
  int status;


  status = ST_OK;
  memset(iv, 0, sizeof(iv));
  memset(payload_chlng, 0, sizeof(payload_chlng));
  payload_chlng_lth = OSDP_KEY_SIZE;
  memset(payload_client_cryptogram, 0, sizeof(payload_client_cryptogram));
  payload_client_cryptogram_lth = OSDP_KEY_SIZE;
  memset(payload_server_cryptogram, 0, sizeof(payload_server_cryptogram));
  payload_server_cryptogram_lth = OSDP_KEY_SIZE;
  memset(rnd_a, 0, sizeof(rnd_a));
  rnd_a_lth = 0;
  if (argc > 1)
  {
    bytes_from_string(argv [1], (char *)payload_chlng, &payload_chlng_lth);
  };
  if (payload_chlng_lth EQUALS 8)
  {
    rnd_a_lth = 8;
    memcpy(rnd_a, payload_chlng, rnd_a_lth);
  }
  else
  {
    printf("ERROR: osdp_CHLNG payload wrong size (%d.)\n", payload_chlng_lth);
    status = -1;
  };
  if (argc > 2)
    bytes_from_string(argv [2], (char *)payload_client_cryptogram, &payload_client_cryptogram_lth);
  if (payload_client_cryptogram_lth != OSDP_KEY_SIZE)
  {
    printf("ERROR: osdp_CCRYPT payload wrong size (%d.)\n", payload_client_cryptogram_lth);
    status = -1;
  };
  if (argc > 3)
    bytes_from_string(argv [3], (char *)payload_server_cryptogram, &payload_server_cryptogram_lth);

  printf
("              SCBK: ");
    dump_buffer((char *)secure_channel_base_key, sizeof(secure_channel_base_key));
  printf
("osdp_CHLNG payload: ");
  dump_buffer((char *)payload_chlng, payload_chlng_lth); 
  printf
(" Client Cryptogram: ");
  dump_buffer((char *)payload_client_cryptogram, 16); 
  printf
(" Server Cryptogram: ");
  dump_buffer((char *)payload_server_cryptogram, 16); 

  if (status EQUALS ST_OK)
  {
    printf
("             RND.A: ");  dump_buffer(rnd_a, rnd_a_lth);

    calculate_s_enc(s_enc, rnd_a, iv, secure_channel_base_key);
    printf
("          S-ENC IV: "); dump_buffer((char *)iv, sizeof(iv));
    printf
("             S-ENC: "); dump_buffer((char *)s_enc, sizeof(s_enc));

  decrypt_cryptogram(payload_client_cryptogram, clear_client_cryptogram,
    iv, s_enc);
    printf
(" Cli Cgram (clear): ");
      dump_buffer((char *)clear_client_cryptogram, OSDP_KEY_SIZE);

  if (0 EQUALS memcmp(clear_client_cryptogram, rnd_a, sizeof(rnd_a)))
    printf ("***CLIENT CRYPTOGRAM IS GOOD***\n");

  };
  decrypt_cryptogram(payload_server_cryptogram, clear_server_cryptogram,
    iv, s_enc);
  printf
(" Svr Cgram (clear): ");
  dump_buffer((char *)clear_server_cryptogram, OSDP_KEY_SIZE);
  if (0 EQUALS memcmp(clear_server_cryptogram+8, rnd_a, sizeof(rnd_a)))
    printf ("***SERVER CRYPTOGRAM IS GOOD***\n");
  return(status);

} /* main for osdp-sc-calc */


void
  calculate_s_enc
  (uint8_t *s_enc,
  char *rnd_a,
  uint8_t *iv,
  uint8_t *key)

{ /* calculate_s_enc */



  memset(s_enc, 0, OSDP_KEY_SIZE);
  s_enc [0] = 1;
  s_enc [1] = 0x82;
  memcpy(s_enc+2, rnd_a, 6);
  printf
("     S-ENC (clear): ");
  dump_buffer((char *)s_enc, OSDP_KEY_SIZE);

} /* calculate_s_enc */


void
  decrypt_cryptogram
    (uint8_t *cgram,
    uint8_t *cleartext,
    uint8_t *iv,
    uint8_t *key)

{ /* decrypt_cryptogram */

  struct AES_ctx aes_context_ccrypt;


  AES_init_ctx(&aes_context_ccrypt, key);
  AES_ctx_set_iv(&aes_context_ccrypt, iv);
  memcpy(cleartext, cgram, OSDP_KEY_SIZE);
  AES_CBC_decrypt_buffer(&aes_context_ccrypt, cleartext, OSDP_KEY_SIZE);

} /* decrypt_cryptogram */


void
  dump_buffer
    (char *buffer,
    int length)

{ /* dump_buffer */

  int i;
  int line_length_bytes;


  line_length_bytes = 32;
  for (i=0; i<length; i++)
  {
    printf("%02x", buffer [i]);
    if (7 EQUALS (i % 7))
      printf("-");
    else
    {
      if (3 EQUALS (i % 4))
        printf(" ");
    };
    if ((length % line_length_bytes) EQUALS (line_length_bytes-1))
      printf("\n");
  };
  if ((length % line_length_bytes) != (line_length_bytes-1))
    printf("\n");

} /* dump_buffer */

#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <aes.h>

#define EQUALS ==
#define ST_OK (0)
#define OSDP_KEY_SIZE (128/8)
char *default_key = "0102030405060708090a0b0c0d0e0f10"; 
void bytes_from_string(char *string, uint8_t *bytes, int *bytes_length);

int
  main
    (int argc,
    char *argv [])

{

  struct AES_ctx aes_context_scbk;
  uint8_t ciphertext [OSDP_KEY_SIZE];
  int i;
  uint8_t iv [OSDP_KEY_SIZE];
  uint8_t key [OSDP_KEY_SIZE];
  char iv_hex [1024];
  int iv_length_octets;
  char key_hex [1024];
  int key_length_octets;
  uint8_t plaintext [OSDP_KEY_SIZE];
  char plaintext_hex [1024];
  int plaintext_length_octets;


  strcpy(key_hex, default_key);
  if (argc > 1)
  {
    strcpy(key_hex, argv [1]);
    if (argc > 2)
    {
      strcpy(iv_hex, argv [2]);
      if (argc > 3)
      {
        strcpy(plaintext_hex, argv [3]);
      };
    };
  };
  fprintf(stderr, "      Key: %s\n", key_hex);
  fprintf(stderr, "       IV: %s\n", iv_hex);
  fprintf(stderr, "Plaintext: %s\n", plaintext_hex);

  key_length_octets = OSDP_KEY_SIZE;
  bytes_from_string(key_hex, key, &key_length_octets);
  iv_length_octets = OSDP_KEY_SIZE;
  bytes_from_string(iv_hex, iv, &iv_length_octets);
  plaintext_length_octets = strlen(plaintext_hex)/2;
  bytes_from_string(plaintext_hex, plaintext, &plaintext_length_octets);
  memcpy(ciphertext, plaintext, OSDP_KEY_SIZE);

  AES_init_ctx(&aes_context_scbk, key);
  AES_ctx_set_iv(&aes_context_scbk, iv);
  AES_CBC_encrypt_buffer(&aes_context_scbk, ciphertext, OSDP_KEY_SIZE);
  for (i=0; i<OSDP_KEY_SIZE; i++)
    fprintf(stderr, "%02X", ciphertext [i]);
  fprintf(stderr, "\n");

  return(0);
}


/*
  bytes_from_string - forgivingly decode hex bytes

  skips a leading FF
  skips blanks
*/

void
  bytes_from_string
    (char *string,
    uint8_t *bytes,
    int *bytes_length)

{ /* bytes_from_string */

  int byte;
  int done;
  int len;
  uint8_t *pdest;
  char *psource;
  char ptemp [4*1024];
  int status;


  status = 0;
  done = 0;
  if (*bytes_length < 1)
    status = -1;
  if (!string)
    status = -2;

  // remove blanks and pluses (blanks manifest as '+' through http)
  if (status EQUALS ST_OK)
  {
    char *p;
    int i;

    p = string;
    i = 0;
    memset(ptemp, 0, sizeof(ptemp));
    while (!done)
    {
      if (*p EQUALS 0)
        done = 1;
      else
      {
        if ((*p != ' ') && (*p != '+'))
        {
          ptemp [i] = *p;
          i++;
        };
      };
      p++;
    };
    psource = ptemp;
  };

  done = 0;
  if (!done)
  {
    len = strlen(psource);
    if (0 != (len % 2))
      done = 1;
  };
  if (!done)
  {
    // if it starts with 0xff, eat that
    if (tolower(*psource) EQUALS 'f')
      psource = psource + 2;

    pdest = bytes;
    *bytes_length = 0;
    while (!done && (len > 0))
    {
      char octet [3];
      octet [2] = 0;
      memcpy(octet, psource, 2);
      sscanf(octet, "%x", &byte);
      *pdest = 0xff & byte;
      (*bytes_length) ++;
      pdest++;
      len--; len--; psource++; psource++;
    };
  };

} /* bytes_from_string */


