/*
  osdp-sc-calc - calculate secure channel values using SCBK-D

  Usage:

    osdp-sc-calc chlng client-cryptogram server-cryptogram

  Where:
    chlng is the osdp_CHLNG payload
    ccrypt is the osdp_CCRYPT client cryptogram

Example shell script:
#!/bin/bash

CHLNG_PAYLOAD="45 46 35 30 32 45 37 37"
CLIENT_CRYPTOGRAM="b0 90 44 a2 fb 7f f3 34 83 73 35 db da 5c 9a 4a"
SERVER_CRYPTOGRAM="7a fc 6c d5 40 24 42 b0 11 e3 2c a5 2b f8 0b c8"

./osdp-sc-calc "${CHLNG_PAYLOAD}" "${CLIENT_CRYPTOGRAM}" "${SERVER_CRYPTOGRAM}"

  (C)Copyright 2015-2024 Smithee Solutions LLC

  Support provided by the Security Industry Association
  http://www.securityindustry.org

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/


#include <string.h>
#include <stdio.h>

#include <aes.h>


#define OSDP_KEY_SIZE (128/8)
#define EQUALS ==
#define ST_OK (0)


void
  bytes_from_string
    (char *string,
    char *bytes,
    int *bytes_length);
void
  calculate_s_enc
  (uint8_t *s_enc,
  char *rnd_a,
  uint8_t *iv,
  uint8_t *key);
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


int
  main
    (int argc,
    char *argv [])

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

  struct AES_ctx aes_context_scbk;


  memset(s_enc, 0, OSDP_KEY_SIZE);
  s_enc [0] = 1;
  s_enc [1] = 0x82;
  memcpy(s_enc+2, rnd_a, 6);
  printf
("     S-ENC (clear): ");
  dump_buffer((char *)s_enc, OSDP_KEY_SIZE);
  AES_init_ctx(&aes_context_scbk, key);
  AES_ctx_set_iv(&aes_context_scbk, iv);
  AES_CBC_encrypt_buffer(&aes_context_scbk, s_enc, OSDP_KEY_SIZE);

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

