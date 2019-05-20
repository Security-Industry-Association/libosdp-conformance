/*
  oosdp_secure_actions - open osdp secure channel action routines

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


#include <aes.h>


#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>


extern OSDP_PARAMETERS p_card;
char tlogmsg [1024];


int
  action_osdp_CCRYPT
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_CCRYPT */

  struct AES_ctx aes_context_s_enc;
  OSDP_SC_CCRYPT *ccrypt_payload;
  unsigned char *client_cryptogram;
  int current_length;
  unsigned char iv [16];
  unsigned char message [16];
  unsigned char sec_blk [1];
  OSDP_SECURE_MESSAGE *secure_message;
  unsigned char server_cryptogram [16];
  int status;

  status = ST_OK;

// DEBUG
#if 0
  // display it first.
  (void)oosdp_make_message (OOSDP_MSG_CCRYPT, tlogmsg, msg);
  fprintf(ctx->log, "%s\n", tlogmsg); fflush(ctx->log);
#endif

  memset (iv, 0, sizeof (iv));

  // check for proper state AND secure channel enabled.

  if ((ctx->secure_channel_use [OO_SCU_ENAB] EQUALS 128+OSDP_SEC_SCS_11) &&
    (ctx->enable_secure_channel > 0))
  {
    secure_message = (OSDP_SECURE_MESSAGE *)(msg->ptr);
    if (ctx->enable_secure_channel EQUALS 2)
      if (secure_message->sec_blk_data != OSDP_KEY_SCBK_D)
        status = ST_OSDP_UNKNOWN_KEY;

    if (ctx->enable_secure_channel EQUALS 1)
      if (secure_message->sec_blk_data != OSDP_KEY_SCBK)
        status = ST_OSDP_UNKNOWN_KEY;

    if (status EQUALS ST_OK)
    {
      ccrypt_payload = (OSDP_SC_CCRYPT *)(msg->data_payload);
      client_cryptogram = ccrypt_payload-> cryptogram;
      // decrypt the client cryptogram (validate header, RND.A, collect RND.B)
if (ctx->verbosity > 8)
{
  int i;
  fprintf (stderr, "s_enc: ");
  for (i=0; i<OSDP_KEY_OCTETS; i++)
    fprintf (stderr, "%02x", ctx->s_enc [i]);
  fprintf (stderr, "\n");
};
      AES_init_ctx (&aes_context_s_enc, ctx->s_enc);
      AES_ctx_set_iv (&aes_context_s_enc, iv);
      memcpy (message, client_cryptogram, sizeof (message));
      AES_CBC_decrypt_buffer (&aes_context_s_enc, message, sizeof (message));
//      AES_CBC_decrypt_buffer (message, client_cryptogram, sizeof (message), ctx->s_enc, iv);

      if (0 != memcmp (message, ctx->rnd_a, sizeof (ctx->rnd_a)))
        status = ST_OSDP_CHLNG_DECRYPT;
    };
    if (status EQUALS ST_OK)
    {
      // client crytogram looks ok, save RND.B

      memcpy (ctx->rnd_b, message + sizeof (ctx->rnd_a), sizeof (ctx->rnd_b));

      memcpy (message, ctx->rnd_b, sizeof (ctx->rnd_b));
      memcpy (message+sizeof (ctx->rnd_b), ctx->rnd_a, sizeof (ctx->rnd_a));
      AES_ctx_set_iv (&aes_context_s_enc, iv);
      memcpy (server_cryptogram, message, sizeof (server_cryptogram));
      AES_CBC_encrypt_buffer (&aes_context_s_enc, server_cryptogram, sizeof (server_cryptogram));
//      AES_CBC_encrypt_buffer (server_cryptogram, message, sizeof (server_cryptogram), ctx->s_enc, iv);

      if (ctx->enable_secure_channel EQUALS 1)
        sec_blk [0] = OSDP_KEY_SCBK;
      if (ctx->enable_secure_channel EQUALS 2)
        sec_blk [0] = OSDP_KEY_SCBK_D;

      status = send_secure_message (ctx,
        OSDP_SCRYPT, p_card.addr, &current_length, 
        sizeof (server_cryptogram), server_cryptogram,
        OSDP_SEC_SCS_13, sizeof (sec_blk), sec_blk);
    };
  }
  else
    status = ST_OSDP_SC_WRONG_STATE;

  // if there was an error reset the secure channel and let the world continue
  if (status != ST_OK)
  {
    fprintf(ctx->log, "Error processing CCRYPT.  Secure Channel reset.\n");
    status = ST_OK;
    osdp_reset_secure_channel (ctx);
  };
  return (status);

} /* action_osdp_CCRYPT */


int
  action_osdp_RMAC_I
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_RMAC_I */

  unsigned char iv [16];
  int status;


  status = ST_OK;
  memset (iv, 0, sizeof (iv));

  // check for proper state

  if (ctx->secure_channel_use [OO_SCU_ENAB] EQUALS 128+OSDP_SEC_SCS_13)
  {
    memcpy (ctx->rmac_i, msg->data_payload, msg->data_length);
    memcpy(ctx->rmac_i, msg->data_payload, sizeof(ctx->rmac_i));
    memcpy(ctx->last_calculated_out_mac, ctx->rmac_i, sizeof(ctx->last_calculated_out_mac));
    memcpy(ctx->last_calculated_in_mac, ctx->rmac_i, sizeof(ctx->last_calculated_in_mac));
    ctx->secure_channel_use [OO_SCU_ENAB] = OO_SCS_OPERATIONAL;
    fprintf (ctx->log, "*** SECURE CHANNEL OPERATIONAL***\n");
  }
  else
  {
    status = ST_OSDP_SC_WRONG_STATE;
    osdp_reset_secure_channel (ctx);
  };
  return (status);

} /* action_osdp_RMAC_I */


int
  action_osdp_SCRYPT
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_SCRYPT */

  struct AES_ctx aes_context_s_enc;
  struct AES_ctx aes_context_mac1;
  struct AES_ctx aes_context_mac2;
  int current_key_slot;
  int current_length;
  unsigned char iv [16];
  unsigned char message1 [16];
  unsigned char message2 [16];
  unsigned char message3 [16];
  unsigned char sec_blk [1];
  unsigned char server_cryptogram [16]; // size of RND.B plus RND.A
  int status;


  status = ST_OK;
  memset (iv, 0, sizeof (iv));

  // check for proper state

  if (ctx->secure_channel_use [OO_SCU_ENAB] EQUALS 128+OSDP_SEC_SCS_12)
  {
    status = osdp_get_key_slot (ctx, msg, &current_key_slot);
    if (status EQUALS ST_OK)
    {
      memcpy(server_cryptogram, msg->data_payload, sizeof(message1));

      AES_init_ctx (&aes_context_s_enc, ctx->s_enc);
      AES_ctx_set_iv (&aes_context_s_enc, iv);
      AES_CBC_decrypt_buffer (&aes_context_s_enc,
        server_cryptogram, sizeof (server_cryptogram));
      if (ctx->verbosity > 3)
      {
        dump_buffer_log(ctx,
"SrvCgram:",
          msg->data_payload, OSDP_KEY_OCTETS);
        dump_buffer_log(ctx,
"   s-enc:", ctx->s_enc, OSDP_KEY_OCTETS);
        dump_buffer_log(ctx,
"      iv:", iv, OSDP_KEY_OCTETS);
        dump_buffer_log(ctx,
" Decrypt:",
          server_cryptogram, OSDP_KEY_OCTETS);
      };
      if ((0 != memcmp (server_cryptogram, ctx->rnd_b, sizeof (ctx->rnd_b))) ||
        (0 != memcmp (server_cryptogram+sizeof (ctx->rnd_b),
          ctx->rnd_a, sizeof (ctx->rnd_a))))
        status = ST_OSDP_SCRYPT_DECRYPT;
    };
    if (status EQUALS ST_OK)
    {
      sec_blk [0] = 1; // means server cryptogram was good

      memcpy (message1, msg->data_payload, sizeof (server_cryptogram));
      AES_init_ctx (&aes_context_mac1, ctx->s_mac1);
      AES_init_ctx (&aes_context_mac2, ctx->s_mac2);

      memcpy (message2, message1, sizeof (message2));
      AES_ctx_set_iv (&aes_context_mac1, iv);
      AES_CBC_encrypt_buffer (&aes_context_mac1, message2, sizeof (message2));

      memcpy (message3, message2, sizeof (message3));
      AES_ctx_set_iv (&aes_context_mac2, iv);
      AES_CBC_encrypt_buffer (&aes_context_mac2, message3, sizeof (message3));

      memcpy(ctx->rmac_i, message3, sizeof(ctx->rmac_i));
      memcpy(ctx->last_calculated_in_mac, ctx->rmac_i, sizeof(ctx->last_calculated_in_mac));
      memcpy(ctx->last_calculated_out_mac, ctx->rmac_i, sizeof(ctx->last_calculated_out_mac));

      // mark enabled state as operational since we're done initializing

      ctx->secure_channel_use [OO_SCU_ENAB] = OO_SCS_OPERATIONAL;
      current_length = 0;
      status = send_secure_message (ctx,
        OSDP_RMAC_I, p_card.addr, &current_length, 
        sizeof (message3), message3,
        OSDP_SEC_SCS_14, sizeof (sec_blk), sec_blk);
    };
  }
  else
  {
    status = ST_OSDP_SC_WRONG_STATE;
    osdp_reset_secure_channel (ctx);
  };
  return (status);

} /* action_osdp_SCRYPT */

