// repair: /* osdp_create_client_cryptogram */
// repair: /* osdp_create_keys */
/*
  oosdp-secure - open osdp secure channel routines

  (C)Copyright 2017-2019 Smithee Solutions LLC
  (C)Copyright 2014-2017 Smithee,Spelvin,Agnew & Plinge, Inc.

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


#include <stdio.h>
#include <memory.h>
#include <unistd.h>


#include <aes.h>


#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>
void osdp_sc_pad (unsigned char *block, int current_length);

extern OSDP_INTEROP_ASSESSMENT osdp_conformance;
extern OSDP_PARAMETERS p_card;
char tlogmsg [1024];
void osdp_pad_message
  (unsigned char *outblock, unsigned char *inblock, unsigned int inlength);


/*
  osdp_calculate_secure_channel_mac
    - calculates MAC for outbound
*/

int
  osdp_calculate_secure_channel_mac
    (OSDP_CONTEXT *ctx,
    unsigned char *msg_to_send,
    int msg_lth,
    unsigned char * mac)

{ /* osdp_calculate_secure_channel_mac */

  struct AES_ctx aes_context_mac1;
  struct AES_ctx aes_context_mac2;
  int current_lth;
  unsigned char hashbuffer [OSDP_BUF_MAX];
  unsigned char last_iv [OSDP_KEY_OCTETS];
  int last_part1_block_offset;
  unsigned char padded_block [OSDP_KEY_OCTETS];
  int part1_block_length;
  int status;


  status = ST_OK;
  if (ctx->verbosity > 3)
    dump_buffer_log(ctx, "whole msg for msg-auth:", msg_to_send, msg_lth);
  memset(hashbuffer, 0, sizeof(hashbuffer));
  memset(padded_block, 0, sizeof(padded_block));
  part1_block_length = 0;
  last_part1_block_offset = 0;
  current_lth = msg_lth;

  if (ctx->verbosity > 3)
    fprintf(ctx->log,
      "calculating MAC for message of length %d.\n", msg_lth);

  if (msg_lth > OSDP_BUF_MAX)
    status = ST_OSDP_EXCEEDS_SC_MAX;

  if (status EQUALS ST_OK)
  {
    memcpy(last_iv, ctx->last_calculated_in_mac, sizeof(last_iv));
    if (ctx->verbosity > 3)
    {
      dump_buffer_log(ctx, "S-MAC1 at osdp_calculate_secure_channel_mac:",
        ctx->s_mac1, OSDP_KEY_OCTETS);
      dump_buffer_log(ctx, "last calc in MAC (iv for msg-auth calc first block):",
        last_iv, OSDP_KEY_OCTETS);
    };

    // if it's longer than one block calculate the partial MAC using MAC1
    if (msg_lth > OSDP_KEY_OCTETS)
    {
      part1_block_length = (msg_lth/OSDP_KEY_OCTETS)*OSDP_KEY_OCTETS;
      last_part1_block_offset = part1_block_length - OSDP_KEY_OCTETS;
      memcpy(hashbuffer, msg_to_send, part1_block_length);
      if (ctx->verbosity > 3)
      {
        dump_buffer_log(ctx, (char *)"msg-auth part 1 input:",
          hashbuffer, part1_block_length);
      };
      AES_init_ctx (&aes_context_mac1, ctx->s_mac1);
      AES_ctx_set_iv (&aes_context_mac1, last_iv);
      AES_CBC_encrypt_buffer(&aes_context_mac1, hashbuffer, part1_block_length);
      current_lth = current_lth - part1_block_length;
      memcpy(last_iv, hashbuffer+last_part1_block_offset, OSDP_KEY_OCTETS);
    };

    // use MAC2 ("for the last block")

    memcpy(padded_block, msg_to_send+part1_block_length,
      msg_lth-part1_block_length);
    osdp_sc_pad(padded_block, current_lth);
    if (ctx->verbosity > 3)
    {
      dump_buffer_log(ctx, (char *)"IV for last block in mac",
        last_iv, sizeof(last_iv));
      dump_buffer_log(ctx, (char *)"padded mac block",
        padded_block, OSDP_KEY_OCTETS);
    };
    memcpy (hashbuffer, padded_block, OSDP_KEY_OCTETS);

    // IV is last received MAC or last block of part1

    AES_init_ctx (&aes_context_mac2, ctx->s_mac2);
    AES_ctx_set_iv (&aes_context_mac2, last_iv);
    memcpy (hashbuffer, padded_block, OSDP_KEY_OCTETS);
    AES_CBC_encrypt_buffer(&aes_context_mac2, hashbuffer, OSDP_KEY_OCTETS);
    if (ctx->verbosity > 3)
      dump_buffer_log(ctx, "last block encrypted for MAC:", hashbuffer, OSDP_KEY_OCTETS);

    // this MAC is saved as the last sent MAC

    memcpy(ctx->last_calculated_out_mac, hashbuffer, sizeof(ctx->last_calculated_out_mac));

    mac [0] = hashbuffer [0];
    mac [1] = hashbuffer [1];
    mac [2] = hashbuffer [2];
    mac [3] = hashbuffer [3];
  }; // ok msg_lth

#if 0
  if (msg_lth <= OSDP_KEY_OCTETS)
  {
    unsigned char hashbuffer [OSDP_KEY_OCTETS];

    osdp_pad_message(padded_block, msg_to_send, msg_lth);
    if (ctx->verbosity > 3)
    {
      //dump_buffer_log(ctx, "mac2", ctx->s_mac2, sizeof(ctx->s_mac2));
      //dump_buffer_log(ctx, "padded mac block", padded_block, OSDP_KEY_OCTETS);
    };
    AES_init_ctx (&aes_context_mac2, ctx->s_mac2);
    AES_ctx_set_iv (&aes_context_mac2, ctx->last_calculated_in_mac);
    memcpy (hashbuffer, padded_block, sizeof(hashbuffer));
    AES_CBC_encrypt_buffer(&aes_context_mac2, hashbuffer, sizeof(hashbuffer));

    // update the out-mac for next time
    memcpy(ctx->last_calculated_out_mac, hashbuffer,
      sizeof(ctx->last_calculated_out_mac));

    if (ctx->verbosity > 3)
      dump_buffer_log(ctx, "encrypted mac block", hashbuffer, OSDP_KEY_OCTETS);
    mac [0] = hashbuffer [0];
    mac [1] = hashbuffer [1];
    mac [2] = hashbuffer [2];
    mac [3] = hashbuffer [3];
  };
#endif
  return (status);

} /* osdp_calculate_secure_channel_mac */


int
  osdp_build_secure_message
    (OSDP_CONTEXT *ctx,
    unsigned char *buf,
    int *updated_length,
    unsigned char command,
    int dest_addr,
    int sequence,
    int data_length,
    unsigned char *data,
    int sec_block_type,
    int sec_block_length,
    unsigned char *sec_blk)

{ /* osdp_build_secure_mesage */

  int check_size;
  unsigned char * cmd_ptr;
  unsigned char *crc_check;
  unsigned char enc_buf [OSDP_BUF_MAX];
  int encrypt_payload;
  int new_length;
  unsigned char * next_data;
  OSDP_HDR *p;
  int padded_length;
  int padding;
  unsigned short int parsed_crc;
  unsigned char sc_mac[4];
  unsigned char *sp;
  int status;
  int whole_msg_lth;


  status = ST_OK;
  if (m_check EQUALS OSDP_CHECKSUM)
    check_size = 1;
  else
    check_size = 2;
  new_length = *updated_length;

  p = (OSDP_HDR *)buf;
  p->som = C_SOM;
  new_length ++;

  // addr
  p->addr = dest_addr;
  if (ctx->role EQUALS OSDP_ROLE_PD)
    p->addr = p->addr | 0x80;
  new_length ++;

  /*
    length goes in before CRC calc.
    length is 5 (fields to CTRL) + [if no sec] 1 for CMND + data
  */
  whole_msg_lth = 5;
  whole_msg_lth = whole_msg_lth + 1; //CMND
  whole_msg_lth = whole_msg_lth + data_length;
  whole_msg_lth = whole_msg_lth + sec_block_length +2; //contents+hdr

  // if it gets a MAC suffix add in the length of that.

  encrypt_payload = 0;
  if ((sec_block_type EQUALS OSDP_SEC_SCS_17) ||
    (sec_block_type EQUALS OSDP_SEC_SCS_18))
    encrypt_payload = 1;
  if ((sec_block_type EQUALS OSDP_SEC_SCS_15) ||
    (sec_block_type EQUALS OSDP_SEC_SCS_16) ||
    (sec_block_type EQUALS OSDP_SEC_SCS_17) ||
    (sec_block_type EQUALS OSDP_SEC_SCS_18))
    whole_msg_lth = whole_msg_lth + 4;
  whole_msg_lth = whole_msg_lth + check_size; // including CRC

  p->len_lsb = 0x00ff & whole_msg_lth;
  new_length ++;
  p->len_msb = (0xff00 & whole_msg_lth) >> 8;
  new_length ++;

  // control
  p->ctrl = 0;
  p->ctrl = p->ctrl | (0x3 & sequence);

  // set CRC depending on current value of global parameter
  if (m_check EQUALS OSDP_CRC)
    p->ctrl = p->ctrl | 0x04;

  new_length ++;

  // secure is bit 3 (mask 0x08)
  p->ctrl = p->ctrl | 0x08;
  cmd_ptr = buf + 4; // assume security block is 2 bytes len=1 and type

  // fill in secure data.  first is length (lth,type,payload)

  sp = buf+5;
  *sp = sec_block_length+2;
  sp++;
  *sp = sec_block_type;
  sp++;
  if (sec_block_length > 0)
    memcpy (sp, sec_blk, sec_block_length);
  sp = sp + sec_block_length;
  cmd_ptr = sp;
  new_length = new_length + 2+ sec_block_length; // account for lth/typ
  
  *cmd_ptr = command;
  new_length++;
  next_data = 1+cmd_ptr;

  padding = 0; // in case there's none
  if (data_length > 0)
  {
    int i;
    unsigned char *sptr;
    sptr = cmd_ptr + 1;

    if (encrypt_payload)
    {
      padded_length = sizeof(enc_buf);
      status = osdp_encrypt_payload(ctx, data, data_length, enc_buf, &padded_length, &padding);
    }
    else
    {
      memcpy(enc_buf, data, data_length);
      padded_length = data_length;
    };

    for (i=0; i<padded_length; i++)
    {
      *(sptr+i) = *(i+enc_buf);
      new_length ++;
      next_data ++; // where crc goes (after data)
    };
  };
  if (ctx->verbosity > 9)
    dump_buffer_log(ctx, "Secure Before MAC append", buf, new_length);

  // update message length to add crypto padding, add before MAC calculation

  whole_msg_lth = whole_msg_lth + padding;
  p->len_lsb = 0x00ff & whole_msg_lth;
  p->len_msb = (0xff00 & whole_msg_lth) >> 8;

  // append 4-byte partial MAC for SCS_15-18
  if ((sec_block_type EQUALS OSDP_SEC_SCS_15) ||
    (sec_block_type EQUALS OSDP_SEC_SCS_16) ||
    (sec_block_type EQUALS OSDP_SEC_SCS_17) ||
    (sec_block_type EQUALS OSDP_SEC_SCS_18))
  {
    if (ctx->verbosity > 3)
      dump_buffer_log(ctx, "buffer for mac calc:", buf, new_length);
    status = osdp_calculate_secure_channel_mac(ctx, buf, new_length, sc_mac);
    if (status EQUALS 0)
    {
      memcpy(next_data, sc_mac, 4);
      next_data = next_data + 4;
      new_length = new_length + 4;
    };
  };
  if (ctx->verbosity > 9)
    dump_buffer_log(ctx, "Secure After MAC append", buf, new_length);

  // crc
  if (m_check EQUALS OSDP_CRC)
  {
    crc_check = next_data;
    parsed_crc = fCrcBlk (buf, new_length);

    // low order byte first
    *(crc_check+1) = (0xff00 & parsed_crc) >> 8;
    *(crc_check) = (0x00ff & parsed_crc);
    new_length ++;
    new_length ++;
  }
  else
  {
    unsigned char
      cksum;
    unsigned char *
      pchecksum;

    pchecksum = next_data;
    cksum = checksum (buf, new_length);
    *pchecksum = cksum;
    new_length ++;
  };

  *updated_length = new_length;
  if (ctx->verbosity > 3)
    dump_buffer_log(ctx, "buffer after build-secure:", (unsigned char *)p, *updated_length);
  return (status);

} /* osdp_build_message */

int
  osdp_decrypt_payload
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* osdp_decrypt_payload */

  struct AES_ctx aes_context_decrypt;
  unsigned char *cptr;
  int cur_actual;
  unsigned char decrypt_iv [OSDP_KEY_OCTETS];
  int done;
  int i;
  int pad_blocksize;
  int status;


  status = ST_OK;
  memcpy(decrypt_iv, ctx->last_calculated_out_mac, OSDP_KEY_OCTETS);
  if (ctx->verbosity > 3)
    dump_buffer_log(ctx, "pre-invert payload iv:", decrypt_iv, OSDP_KEY_OCTETS);
  for(i=0; i<OSDP_KEY_OCTETS; i++)
    decrypt_iv [i] = ~decrypt_iv [i];
  if (ctx->verbosity > 3)
    fprintf(ctx->log,
"osdp_decrypt_payload: sec blk typ %02x payload is %d. bytes\n", msg->security_block_type,
      msg->data_length);
  if (msg->security_block_type > OSDP_SEC_SCS_16)
  {
    if (ctx->verbosity > 3)
    {
      dump_buffer_log(ctx, "payload to decrypt:", msg->data_payload, msg->data_length);
      dump_buffer_log(ctx, "payload key:", ctx->s_enc, OSDP_KEY_OCTETS);
      dump_buffer_log(ctx, "payload iv:", decrypt_iv, OSDP_KEY_OCTETS);
    };
    AES_init_ctx(&aes_context_decrypt, ctx->s_enc);
    AES_ctx_set_iv(&aes_context_decrypt, decrypt_iv);
    AES_CBC_decrypt_buffer(&aes_context_decrypt, msg->data_payload, msg->data_length);
    if (ctx->verbosity > 3)
      dump_buffer_log(ctx, "payload decrypted:", msg->data_payload, msg->data_length);

    pad_blocksize = 0;
    cptr = msg->data_payload + msg->data_length - 1;
    cur_actual = msg->data_length;
    done = 0;
    while (!done)
    {
      if (*cptr != 0)
      {
        if (*cptr != 0x80)
        {
          done = 1;
          status = ST_OSDP_SC_DECRYPT_LTH_1;
        };
      };
      if (*cptr EQUALS 0)
      {
        cptr--;
        cur_actual--;
        pad_blocksize++;
        if (pad_blocksize > (OSDP_KEY_OCTETS-1))
        {
          status = ST_OSDP_SC_DECRYPT_LTH_2;
          done = 1;
        };
      };
      if (*cptr EQUALS 0x80)
      {
        cur_actual--;
        done = 1;
      };
    };
    if (status EQUALS ST_OK)
    {
      msg->data_length = cur_actual;
      msg->payload_decrypted = 1;
    };
  };
  if (ctx->verbosity > 3)
    dump_buffer_log(ctx, "decrypted payload:", msg->data_payload, msg->data_length);

  return(status);

} /* osdp_decrypt_payload */



void
  osdp_pad_message
    (unsigned char *outblock,
    unsigned char *inblock,
    unsigned int inlength)

{ /* osdp_pad_message */

  int padlength;


  padlength = 0;
  if (inlength < OSDP_KEY_OCTETS)
  {
    padlength = OSDP_KEY_OCTETS - inlength;
  };
  if (inlength <= OSDP_KEY_OCTETS)  // stop crazy input
  {
    memcpy(outblock, inblock, inlength);
    if (padlength > 0)
    {
      outblock [padlength] = 0x80;
      if (padlength > 1)
      {
        memset(outblock+inlength+1, 0, padlength-1);
      };
    };
  };

} /* osdp_pad_message */


void
  osdp_create_client_cryptogram
    (OSDP_CONTEXT *ctx,
    OSDP_SC_CCRYPT *ccrypt_response)

{ /* osdp_create_client_cryptogram */

  struct AES_ctx aes_context_s_enc;
  unsigned char iv [16];
  unsigned char message [16];


  memset (iv, 0, sizeof (iv));
  memcpy (message, ctx->rnd_a, 8);
  memcpy (message+8, ctx->rnd_b, 8);

  AES_init_ctx(&aes_context_s_enc, ctx->s_enc);
  AES_ctx_set_iv(&aes_context_s_enc, iv);
  memcpy(ccrypt_response->cryptogram, message, sizeof (ccrypt_response->cryptogram));
  AES_CBC_encrypt_buffer(&aes_context_s_enc, ccrypt_response->cryptogram, sizeof (message));
  return;

} /* osdp_create_client_cryptogram */


void
  osdp_create_keys
    (OSDP_CONTEXT *ctx)

{ /* osdp_create_keys */

  struct AES_ctx aes_context_scbk;
  unsigned char cleartext [OSDP_KEY_OCTETS];
  unsigned char iv [OSDP_KEY_OCTETS];


  fflush (ctx->log);
  memset (iv, 0, sizeof (iv));

  // S-ENC
  memset (ctx->s_enc, 0, sizeof (ctx->s_enc));
  memset (cleartext, 0, sizeof (cleartext));
  cleartext [0] = 1;
  cleartext [1] = 0x82;
  memcpy (cleartext+2, ctx->rnd_a, 6);

  (void) oosdp_log_key (ctx,
"current_scbk calculating s_enc: ", ctx->current_scbk);
  (void) oosdp_log_key (ctx,
"   cleartext calculating s_enc: ", cleartext);

  AES_init_ctx (&aes_context_scbk, ctx->current_scbk);
  AES_ctx_set_iv (&aes_context_scbk, iv);
  memcpy (ctx->s_enc, cleartext, sizeof (ctx->s_enc));
  AES_CBC_encrypt_buffer (&aes_context_scbk, ctx->s_enc, sizeof (ctx->s_enc));
  //AES_CBC_encrypt_buffer (ctx->s_enc, cleartext, OSDP_KEY_OCTETS, ctx->current_scbk, iv);

  (void) oosdp_log_key (ctx,
"     s_enc in osdp_create_keys: ", ctx->s_enc);

  // S-MAC-1
  memset (ctx->s_mac1, 0, sizeof (ctx->s_mac1));
  cleartext [0] = 1;
  cleartext [1] = 1;
  memcpy (cleartext+2, ctx->rnd_a, 6);
  (void) oosdp_log_key (ctx,
"   cleartext calculating s_mac1: ", cleartext);
  memcpy (ctx->s_mac1, cleartext, sizeof (ctx->s_mac1));
  AES_ctx_set_iv (&aes_context_scbk, iv);
  AES_CBC_encrypt_buffer (&aes_context_scbk, ctx->s_mac1, sizeof (ctx->s_mac1));
  //AES_CBC_encrypt_buffer (ctx->s_mac1, cleartext, OSDP_KEY_OCTETS, ctx->current_scbk, iv);
  (void) oosdp_log_key (ctx,
"     s_mac1 in osdp_create_keys: ", ctx->s_mac1);

  // S-MAC-2
  memset (ctx->s_mac2, 0, sizeof (ctx->s_mac2));
  cleartext [0] = 1;
  cleartext [1] = 2;
  memcpy (cleartext+2, ctx->rnd_a, 6);
  (void) oosdp_log_key (ctx,
"   cleartext calculating s_mac2: ", cleartext);
  memcpy (ctx->s_mac2, cleartext, sizeof (ctx->s_mac2));
  AES_ctx_set_iv (&aes_context_scbk, iv);
  AES_CBC_encrypt_buffer (&aes_context_scbk, ctx->s_mac2, sizeof (ctx->s_mac1));
  (void) oosdp_log_key (ctx,
"     s_mac2 in osdp_create_keys: ", ctx->s_mac2);

  return;

} /* osdp_create_keys */


int
  osdp_encrypt_payload
    (OSDP_CONTEXT *ctx,
    unsigned char *data,
    int data_length,
    unsigned char *enc_buf,
    int *padded_length,
    int *padding)

{ /* osdp_encrypt_payload */

  struct AES_ctx aes_context_encrypt;
  unsigned char encrypt_iv [OSDP_KEY_OCTETS];
  int i;
  int status;


  status = ST_OK;
  if (*padded_length <= data_length)
    status = ST_OSDP_SC_ENCRYPT_LTH_1;
  if (status EQUALS ST_OK)
  {
    if (data_length < 1)
      status = ST_OSDP_SC_ENCRYPT_LTH_2;
    if (status EQUALS ST_OK)
      if (*padded_length < data_length)
        status = ST_OSDP_SC_ENCRYPT_LTH_3;
  };
  if (status EQUALS ST_OK)
  {
    // zeroize the whole cyphertext buffer, then copy in the plaintext.

    memset(enc_buf, 0, *padded_length);
    memcpy(enc_buf, data, data_length);
    *padded_length = data_length; // 'cause we just encrypt it without padding;

    // if it's an even number of blocks just encrypt it.

    if (0 != (data_length % (2^OSDP_KEY_OCTETS)))
    {
      // needs padding.  calc padding, add the padding marker.  buffer was zeroes already.

      *padded_length =
        ((data_length+(OSDP_KEY_OCTETS-1))/OSDP_KEY_OCTETS)*OSDP_KEY_OCTETS;
      enc_buf [data_length] = 0x80;
      *padding = *padded_length - data_length;
    };
  };
// DEBUG
dump_buffer_log(ctx, "payload cleartext with padding:",
  enc_buf, *padded_length);
  // do encryption.  key is s-enc; iv is inverse of last rec mac
  memcpy(encrypt_iv, ctx->last_calculated_in_mac, OSDP_KEY_OCTETS);
  for(i=0; i<OSDP_KEY_OCTETS; i++)
    encrypt_iv [i] = ~encrypt_iv [i];
// DEBUG
dump_buffer_log(ctx, "iv(inverted):", encrypt_iv, OSDP_KEY_OCTETS);
dump_buffer_log(ctx, "s_enc:", ctx->s_enc, OSDP_KEY_OCTETS);
  AES_init_ctx (&aes_context_encrypt, ctx->s_enc);
  AES_ctx_set_iv (&aes_context_encrypt, encrypt_iv);
  AES_CBC_encrypt_buffer(&aes_context_encrypt, enc_buf, *padded_length);
// DEBUG
dump_buffer_log(ctx, "payload ciphertext:",
  enc_buf, *padded_length);

  return(status);

} /* osdp_encrypt_payload */


/*
  get a key.  if default key was requested, use it.
  if non-default key was requested but it hasn't been loaded return an error.

  uses secure_channel_use [OO_SCU_KEYED]
*/

int
   osdp_get_key_slot
     (OSDP_CONTEXT *ctx,
     OSDP_MSG *msg,
     int *returned_key_slot)

{ /* osdp_get_key_slot */

  int key_slot;
  OSDP_SECURE_MESSAGE *s_msg;
  int status;


  status = ST_OK;
  key_slot = OSDP_KEY_SCBK; // meaning our key
  s_msg = (OSDP_SECURE_MESSAGE *)(msg->ptr);
  if (s_msg->sec_blk_data EQUALS OSDP_KEY_SCBK_D)
  {
    key_slot = OSDP_KEY_SCBK_D;
  }
  else
  {
    if (s_msg->sec_blk_data EQUALS OSDP_KEY_SCBK)
    {
      key_slot = OSDP_KEY_SCBK;
      if (ctx->secure_channel_use [OO_SCU_KEYED] != OO_SECPOL_KEYLOADED)
        status = ST_OSDP_NO_KEY_LOADED;
    }
    else
    {
      status = ST_OSDP_BAD_KEY_SELECT;
    };
  };

  *returned_key_slot = key_slot;
  return (status);

} /* osdp_get_key_slot */


void
  osdp_reset_secure_channel
    (OSDP_CONTEXT *ctx)

{ /* osdp_reset_secure_channel */

  // secure channel processing is being reset.  set things
  // back to the beginning.

  // refresh rnd.a
  memcpy (ctx->rnd_a, "12345678", 8);

  // refresh rnd.b
  memcpy (ctx->rnd_b, "abcdefgh", 8);

  memset(ctx->rmac_i, 0, sizeof(ctx->rmac_i));
  memset (ctx->last_calculated_in_mac, 0, sizeof (ctx->last_calculated_in_mac));
  memset (ctx->last_calculated_out_mac, 0, sizeof (ctx->last_calculated_out_mac));
  ctx->secure_channel_use [OO_SCU_ENAB] = OO_SCS_USE_DISABLED;
  if (ctx->enable_secure_channel > 0)
    ctx->secure_channel_use [OO_SCU_ENAB] = OO_SCS_USE_ENABLED;
  fprintf (ctx->log, "  Resetting Secure Channel\n");

} /* osdp_reset_secure_channel */

/*
  oo_hash_check
    - calculate MAC for inbound
*/

int
  oo_hash_check
    (OSDP_CONTEXT *ctx,
    unsigned char *message,
    int security_block_type,
    unsigned char *hash,
    int message_length)

{ /* oo_hash_check */

  struct AES_ctx aes_context_mac1;
  struct AES_ctx aes_context_mac2;
  unsigned char current_iv [OSDP_KEY_OCTETS];
  int current_length;
  unsigned char *current_pointer;
  int first_blocks_length;
  unsigned char hashbuffer [OSDP_KEY_OCTETS];
  unsigned char last_block [OSDP_KEY_OCTETS];
  int last_block_length;
  unsigned char *message_pointer;
  unsigned char first_blocks_temp [OSDP_BUF_MAX];
  int status;


  status = ST_OK;
  if (security_block_type > OSDP_SEC_SCS_14)
  {
    status = ST_OSDP_SC_BAD_HASH;
    message_pointer = message;
    current_length = message_length - 4; // less hash on wire
    current_pointer = message;
    last_block_length = current_length;
    memcpy(current_iv, ctx->last_calculated_out_mac, OSDP_KEY_OCTETS);
    if (current_length > OSDP_KEY_OCTETS)
    {
      first_blocks_length = (current_length/OSDP_KEY_OCTETS)*OSDP_KEY_OCTETS;
      last_block_length = current_length - (current_length/OSDP_KEY_OCTETS)*OSDP_KEY_OCTETS;
      if (last_block_length EQUALS 0)
      {
        first_blocks_length = first_blocks_length - OSDP_KEY_OCTETS;
        last_block_length = OSDP_KEY_OCTETS;
      };
      memcpy(current_iv, ctx->last_calculated_out_mac, OSDP_KEY_OCTETS);
dump_buffer_log(ctx, "s_mac1:", ctx->s_mac1, OSDP_KEY_OCTETS);
dump_buffer_log(ctx, "iv:", current_iv, OSDP_KEY_OCTETS);

      AES_init_ctx(&aes_context_mac1, ctx->s_mac1);
      AES_ctx_set_iv(&aes_context_mac1, current_iv);
      memcpy(first_blocks_temp, current_pointer, first_blocks_length);
dump_buffer_log(ctx, "first blocks from wire:", first_blocks_temp, first_blocks_length);
      AES_CBC_encrypt_buffer(&aes_context_mac1, first_blocks_temp, first_blocks_length);
      memcpy(current_iv, first_blocks_temp + (first_blocks_length - OSDP_KEY_OCTETS), OSDP_KEY_OCTETS);

      current_pointer = message_pointer + first_blocks_length;

// DEBUG
dump_buffer_log(ctx, "IV after mac1:", current_iv, OSDP_KEY_OCTETS);
    };

    // process the last block
    memset(last_block, 0, sizeof(last_block));
    memcpy(last_block, current_pointer, last_block_length);
    if (last_block_length != OSDP_KEY_OCTETS)
    {
      osdp_sc_pad(last_block, last_block_length);
    };
    AES_init_ctx (&aes_context_mac2, ctx->s_mac2);
    AES_ctx_set_iv (&aes_context_mac2, current_iv);
    memcpy (hashbuffer, last_block, sizeof(last_block));
    AES_CBC_encrypt_buffer(&aes_context_mac2, hashbuffer, sizeof(hashbuffer));
    memcpy(ctx->last_calculated_in_mac,
      hashbuffer, sizeof(ctx->last_calculated_in_mac));
    if (ctx->verbosity > 9)
      dump_buffer_log(ctx, "calc hash", hashbuffer, sizeof(hashbuffer));

    // the hash we calculated (hashbuffer) should match the hash extracted
    // from the message (hash)

    if (0 EQUALS memcmp(hash, hashbuffer, 4))
    {
      status = ST_OK;
      ctx->hash_ok ++;
    };
  };
  fflush(ctx->log);
  return(status);

} /* oo_hash_check */


void osdp_sc_pad
  (unsigned char *block,
  int current_length)

{ /* osdp_sc_pad */

  unsigned char *next_octet;
  int pad_count;

  pad_count = 0;
  next_octet = block;
  if (current_length != OSDP_KEY_OCTETS)
  {
    pad_count = OSDP_KEY_OCTETS - current_length - 1;
    next_octet = block + current_length;
    *next_octet = 0x80;
    memset(next_octet+1, 0, pad_count);
  };

} /* osdp_sc_pad */


// return a string to dump containing the security block.
// does not include a trailing newline.

char *osdp_sec_block_dump
  (unsigned char *sec_block)

{ /* osdp_sec_block_dump */

  int dump_details;
  int i;
  static char sec_block_dump [1024];
  unsigned char sec_block_length;
  unsigned char sec_block_type;
  char tmsg [1024];


  dump_details = 1; // unless we print something pretty dump it
  sec_block_dump [0] = 0;
  sec_block_type = *(sec_block+1);
  sec_block_length = *sec_block;
  switch (sec_block_type)
  {
    case OSDP_SEC_SCS_11:
      if (sec_block [2] EQUALS OSDP_KEY_SCBK_D)
        sprintf(sec_block_dump, "SCS_11 (Begin Sequence) Key: Default");
      else
      {
        if (sec_block [2] EQUALS OSDP_KEY_SCBK)
          sprintf(sec_block_dump, "SCS_11 (Begin Sequence) Key: SCBK");
        else
          sprintf(sec_block_dump, "SCS_11 (Begin Sequence) Key: UNKNOWN (0x%x)",
            sec_block [2]);
      };
      if (sec_block_length > 3)
      {
        sprintf(tmsg, " Note: Sec Block too long (%d.)", sec_block_length);
        strcat(sec_block_dump, tmsg);
      };
      dump_details = 0;
      break;
    case OSDP_SEC_SCS_12:
      if (sec_block [2] EQUALS OSDP_KEY_SCBK_D)
        sprintf(sec_block_dump, "SCS_12 Key: Default");
      else
      {
        if (sec_block [2] EQUALS OSDP_KEY_SCBK)
          sprintf(sec_block_dump, "SCS_12 Key: SCBK");
        else
          sprintf(sec_block_dump, "SCS_12 Key: UNKNOWN (0x%x)",
            sec_block [2]);
      };
      if (sec_block_length > 3)
      {
        sprintf(tmsg, " Note: Sec Block too long (%d.)", sec_block_length);
        strcat(sec_block_dump, tmsg);
      };
      dump_details = 0;
      break;
    default:
      sprintf(sec_block_dump, "Sec Blk %02x", sec_block_type);
      break;
  };
  if (dump_details && (sec_block_length > 2))
  {
    strcat(sec_block_dump, " Details:");
    for (i=2; i<sec_block_length; i++)
    {
      sprintf(tlogmsg, " %02x", *(2+sec_block));
      strcat(sec_block_dump, tlogmsg);
    }
  };

  return (sec_block_dump);

} /* osdp_sec_block_dump */


int
  osdp_setup_scbk
    (OSDP_CONTEXT
      *ctx,
    OSDP_MSG
      *msg)

{ /* osdp_setup_scbk */

  OSDP_SECURE_MESSAGE *secure_message;
  int status;


  status= ST_OK;
  if (msg != NULL)
  {
    secure_message = (OSDP_SECURE_MESSAGE *)(msg->ptr);
    ctx->current_key_slot = secure_message->sec_blk_data;
    if (secure_message->sec_blk_data EQUALS OSDP_KEY_SCBK_D)
    {
      memcpy (ctx->current_scbk, OSDP_SCBK_DEFAULT, sizeof (ctx->current_scbk));
      ctx->secure_channel_use [OO_SCU_KEYED] = OO_SECPOL_KEYLOADED;
    }
    if (secure_message->sec_blk_data EQUALS OSDP_KEY_SCBK)
      if (ctx->secure_channel_use [OO_SCU_KEYED] != OO_SECPOL_KEYLOADED)
        status = ST_OSDP_NO_SCBK;
  }
  else
  {
    if (ctx->enable_secure_channel EQUALS 2)
    {
      memcpy (ctx->current_scbk, OSDP_SCBK_DEFAULT, sizeof (ctx->current_scbk));
      ctx->secure_channel_use [OO_SCU_KEYED] = OO_SECPOL_KEYLOADED;
    }
    if (ctx->enable_secure_channel EQUALS 1)
      if (ctx->secure_channel_use [OO_SCU_KEYED] != OO_SECPOL_KEYLOADED)
        status = ST_OSDP_NO_SCBK;
  };
  return (status);

} /* osdp_setup_scbk */


/*
  send_secure_message - send an OSDP secure channel message

  assumes command is a valid value.
*/

int
  send_secure_message
    (OSDP_CONTEXT *ctx,
    int command,
    int dest_addr,
    int *current_length,
    int data_length,
    unsigned char *data,
    int sec_block_type,
    int sec_block_length,
    unsigned char *sec_blk)

{ /* send_secure_message */

  unsigned char buf [2];
  int old_state;
  int status;
  unsigned char test_blk [1024];
  int true_dest;


  status = ST_OK;
  fflush (ctx->log);
  true_dest = dest_addr;
  *current_length = 0;

  // so we remember our state
  old_state = 128 + sec_block_type;
  if (ctx->secure_channel_use [OO_SCU_ENAB] != OO_SCS_OPERATIONAL)
    ctx->secure_channel_use [OO_SCU_ENAB] = old_state;

  status = osdp_build_secure_message
    (ctx,
    test_blk, // message itself
    current_length, // returned message length in bytes
    command,
    true_dest,
    next_sequence (ctx),
    data_length, // data length to use
    data,
    sec_block_type, sec_block_length, sec_blk); // security values
  if (status EQUALS ST_OK)
  {
    OSDP_MSG m;
//    int parse_role;
    OSDP_HDR returned_hdr;
    int status_monitor;

    memset (&m, 0, sizeof (m));
    m.ptr = test_blk; // marshalled outbound message
    m.lth = *current_length;

    // parse the message for display.  role to parse is the OTHER guy
//    parse_role = OSDP_ROLE_CP; if (ctx->role EQUALS OSDP_ROLE_CP) parse_role = OSDP_ROLE_PD;
    status_monitor = osdp_parse_message (ctx, OSDP_ROLE_MONITOR, //parse_role,
      &m, &returned_hdr);
    if (ctx->verbosity > 8)
      if (status_monitor != ST_OK)
      {
        sprintf (tlogmsg,"parse_message for monitoring returned %d.\n",
          status_monitor);
        status = oosdp_log (ctx, OSDP_LOG_STRING_CP, 1, tlogmsg);
      };
    (void)monitor_osdp_message (ctx, &m);
  };
  if (status EQUALS ST_OK)
  {
    buf [0] = 0xff;
    // send start-of-message marker (0xff)
    send_osdp_data (ctx, &(buf[0]), 1);

    if (sec_block_type EQUALS OSDP_SEC_SCS_11)
      ctx->secure_channel_use [0] = 128 + OSDP_SEC_SCS_11;

    send_osdp_data (ctx, test_blk, *current_length);
  };
  return (status);

} /* send_secure_message */

