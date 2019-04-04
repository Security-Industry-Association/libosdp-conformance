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


int
  action_osdp_CHLNG
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_CHLNG */

  OSDP_SC_CCRYPT ccrypt_response;
  int current_length;
  int nak;
  unsigned char osdp_nak_response_data [2];
  int status;


  status = ST_OK;
  nak = 0;

  // make sure this PD was enabled for secure channel (see enable-secure-channel command)

fprintf(stderr, "enab? %d\n", ctx->secure_channel_use[OO_SCU_ENAB]);
  if (OO_SCS_USE_ENABLED != ctx->secure_channel_use[OO_SCU_ENAB])
    nak = 1;
  if (nak)
  {
    current_length = 0;
    osdp_nak_response_data [0] = OO_NAK_UNK_CMD;
    osdp_nak_response_data [1] = 0xff;
    status = send_message (ctx,
      OSDP_NAK, p_card.addr, &current_length,
      sizeof(osdp_nak_response_data), osdp_nak_response_data);
    ctx->sent_naks ++;
    osdp_conformance.rep_nak.test_status = OCONFORM_EXERCISED;
    if (ctx->verbosity > 2)
    {
      fprintf (ctx->log, "NAK: osdp_CHLNG but Secure Channel disabled\n");
    };
  };
  if (!nak)
  {
    unsigned char sec_blk [1];

    osdp_reset_secure_channel (ctx);
    memcpy (ctx->rnd_a, msg->data_payload, sizeof (ctx->rnd_a));
    status = osdp_setup_scbk (ctx, msg);
    if (status != ST_OK)
    {
      nak = 1;
      osdp_reset_secure_channel (ctx);
      current_length = 0;
      osdp_nak_response_data [0] = OO_NAK_UNK_CMD;
      osdp_nak_response_data [1] = 0xFE;
      status = send_message (ctx,
        OSDP_NAK, p_card.addr, &current_length,
        sizeof(osdp_nak_response_data), osdp_nak_response_data);
      ctx->sent_naks ++;
      osdp_conformance.rep_nak.test_status = OCONFORM_EXERCISED;
      if (ctx->verbosity > 2)
      {
        fprintf (ctx->log, "NAK: SCBK not initialized");
      };
    };
    if (!nak && (status EQUALS ST_OK))
    {
      osdp_create_keys (ctx);

      // build up an SCS_12 response

      if (ctx->enable_secure_channel EQUALS 2)
        sec_blk [0] = OSDP_KEY_SCBK_D;
      else
        sec_blk [0] = OSDP_KEY_SCBK;

      // client ID
#if SAMPLE
            memset (ccrypt_response.client_id, 0,
              sizeof (ccrypt_response.client_id));
            ccrypt_response.client_id [0] = 1;
#else
      memcpy (ccrypt_response.client_id,
        ctx->vendor_code, 3);
      ccrypt_response.client_id [3] = ctx->model;
      ccrypt_response.client_id [4] = ctx->version;
      memcpy (ccrypt_response.client_id+5,
        ctx->serial_number, 3);
#endif

      // RND.B
      memcpy ((char *)(ctx->rnd_b), "abcdefgh", 8);
      memcpy ((char *)(ccrypt_response.rnd_b), (char *)(ctx->rnd_b), sizeof (ccrypt_response.rnd_b));
printf ("fixme: RND.B\n");

      osdp_create_client_cryptogram (ctx, &ccrypt_response);

      current_length = 0;
 
      status = send_secure_message (ctx,
        OSDP_CCRYPT, p_card.addr, &current_length, 
        sizeof (ccrypt_response), (unsigned char *)&ccrypt_response,
        OSDP_SEC_SCS_12, sizeof (sec_blk), sec_blk);
    };
  };
  return (status);

} /* action_osdp_CHLNG */


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

  struct AES_ctx aes_context_mac2;
  unsigned char padded_block [OSDP_KEY_OCTETS];
  int status;


  status = ST_OK;

  // if it's short use MAC2 ("for the last block")

  if (msg_lth <= OSDP_KEY_OCTETS)
  {
    unsigned char hashbuffer [OSDP_KEY_OCTETS];

    osdp_pad_message(padded_block, msg_to_send, msg_lth);
    if (ctx->verbosity > 3)
    {
      dump_buffer_log(ctx, "mac2", ctx->s_mac2, sizeof(ctx->s_mac2));
      dump_buffer_log(ctx, "rmac_i", ctx->rmac_i, sizeof(ctx->rmac_i));
      dump_buffer_log(ctx, "padded mac block", padded_block, OSDP_KEY_OCTETS);
    };
    AES_init_ctx (&aes_context_mac2, ctx->s_mac2);
    AES_ctx_set_iv (&aes_context_mac2, ctx->rmac_i);
    memcpy (hashbuffer, padded_block, sizeof(hashbuffer));
    AES_CBC_encrypt_buffer(&aes_context_mac2, hashbuffer, sizeof(hashbuffer));

    // update the out-mac for next time
    memcpy(ctx->last_calculated_out_mac, hashbuffer, sizeof(ctx->last_calculated_in_mac));

    if (ctx->verbosity > 3)
      dump_buffer_log(ctx, "encrypted mac block", hashbuffer, OSDP_KEY_OCTETS);
    mac [0] = hashbuffer [0];
    mac [1] = hashbuffer [1];
    mac [2] = hashbuffer [2];
    mac [3] = hashbuffer [3];
  };
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
  int new_length;
  unsigned char * next_data;
  OSDP_HDR *p;
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
  cmd_ptr = buf + 5; // STUB pretend security block is 3 bytes len len 1 payload

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

  if (data_length > 0)
  {
    int i;
    unsigned char *sptr;
    sptr = cmd_ptr + 1;
    for (i=0; i<data_length; i++)
    {
      *(sptr+i) = *(i+data);
      new_length ++;
      next_data ++; // where crc goes (after data)
    };
  };
  if (ctx->verbosity > 8)
    dump_buffer_log(ctx, "Secure Before MAC append", buf, new_length);

  // append 4-byte partial MAC for SCS_15-18
  if ((sec_block_type EQUALS OSDP_SEC_SCS_15) ||
    (sec_block_type EQUALS OSDP_SEC_SCS_16) ||
    (sec_block_type EQUALS OSDP_SEC_SCS_17) ||
    (sec_block_type EQUALS OSDP_SEC_SCS_18))
  {
    status = osdp_calculate_secure_channel_mac(ctx, buf, new_length, sc_mac);
    if (status EQUALS 0)
    {
      memcpy(next_data, sc_mac, 4);
      next_data = next_data + 4;
      new_length = new_length + 4;
    };
  };
  if (ctx->verbosity > 8)
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
  return (status);

} /* osdp_build_message */


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

#if 0
  struct AES_ctx aes_context_s_enc;
#endif
  unsigned char iv [16];
  unsigned char message [16];


  memset (iv, 0, sizeof (iv));
  memcpy (message, ctx->rnd_a, 8);
  memcpy (message+8, ctx->rnd_b, 8);
if (ctx->verbosity > 8)
{
  int i;
  fprintf (stderr, "s_enc in osdp_create_client_cryptogram: ");
  for (i=0; i<OSDP_KEY_OCTETS; i++)
    fprintf (stderr, "%02x", ctx->s_enc [i]);
  fprintf (stderr, "\n");
};
#if 0
  AES_init_ctx (&aes_context_s_enc, ctx->s_enc);
  AES_ctx_set_iv (&aes_context_s_enc, iv);
  memcpy (ccrypt_response->cryptogram, message, sizeof (ccrypt_response->cryptogram));
  AES_CBC_encrypt_buffer (ccrypt_response->cryptogram, message, sizeof (message), ctx->s_enc, iv);
#endif
  
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

  memset (ctx->last_calculated_in_mac, 0, sizeof (ctx->last_calculated_in_mac));
  memset (ctx->last_calculated_out_mac, 0, sizeof (ctx->last_calculated_out_mac));
  ctx->secure_channel_use [OO_SCU_ENAB] = OO_SCS_USE_DISABLED;
  if (ctx->enable_secure_channel > 0)
    ctx->secure_channel_use [OO_SCU_ENAB] = OO_SCS_USE_ENABLED;
  fprintf (ctx->log, "Resetting Secure Channel\n");

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

  struct AES_ctx aes_context_mac2;
  int current_length;
  unsigned char hashbuffer [OSDP_KEY_OCTETS];
  unsigned char last_block [OSDP_KEY_OCTETS];
  unsigned char *message_pointer;
  int status;


  status = ST_OK;
  if (security_block_type > OSDP_SEC_SCS_14)
  {
    if (ctx->verbosity > 3)
    {
      fprintf(ctx->log, "...hash check: checking %02x%02x%02x%02x\n",
        hash[0], hash[1], hash[2], hash[3]);
    };
    message_pointer = message;
    current_length = message_length - 4; // less hash on wire
    if (current_length > OSDP_KEY_OCTETS)
    {
      fprintf(ctx->log, "... first several blocks...\n");
    };

    // process the last block
    memset(last_block, 0, sizeof(last_block));
    memcpy(last_block, message_pointer, current_length);
    if (current_length != OSDP_KEY_OCTETS)
    {
      osdp_sc_pad(last_block, current_length);
    };
if (ctx->verbosity > 3)
{
  dump_buffer_log(ctx, "hashable message", last_block, sizeof(last_block));
  dump_buffer_log(ctx, "s_mac2", ctx->s_mac2, sizeof(ctx->s_mac2));
  dump_buffer_log(ctx, "rmac_i", ctx->rmac_i, sizeof(ctx->rmac_i));
};
    AES_init_ctx (&aes_context_mac2, ctx->s_mac2);
    AES_ctx_set_iv (&aes_context_mac2, ctx->last_calculated_in_mac);
    memcpy (hashbuffer, last_block, sizeof(last_block));
    AES_CBC_encrypt_buffer(&aes_context_mac2, hashbuffer, sizeof(hashbuffer));
    memcpy(ctx->last_calculated_in_mac, hashbuffer, sizeof(ctx->last_calculated_in_mac));
    dump_buffer_log(ctx, "calc hash", hashbuffer, sizeof(hashbuffer));

    if (0 EQUALS memcmp(last_block, hash, 4))
      fprintf(stderr, "HASH MATCHES\n");
  };
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
  OSDP_MSG m;
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
    buf [0] = 0xff;
    // send start-of-message marker (0xff)
    send_osdp_data (ctx, &(buf[0]), 1);

    if (sec_block_type EQUALS OSDP_SEC_SCS_11)
      ctx->secure_channel_use [0] = 128 + OSDP_SEC_SCS_11;

    send_osdp_data (ctx, test_blk, *current_length);

    m.direction = ctx->role;
    m.msg_cmd = command;
    m.ptr = test_blk; // marshalled outbound message
    m.lth = *current_length;
    m.data_payload = data;
    (void)monitor_osdp_message(ctx, &m);
  };
  return (status);

} /* send_secure_message */

