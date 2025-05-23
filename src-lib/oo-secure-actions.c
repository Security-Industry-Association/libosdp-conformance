/*
  oosdp_secure_actions - open osdp secure channel action routines

  (C)Copyright 2017-2025 Smithee Solutions LLC

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
extern OSDP_INTEROP_ASSESSMENT osdp_conformance;


extern OSDP_PARAMETERS p_card;


int
  action_osdp_CCRYPT
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_CCRYPT */

  struct AES_ctx aes_context_s_enc;
  OSDP_SC_CCRYPT *ccrypt_payload;
  unsigned char *client_cryptogram;
  char cmd [3072];
  int current_length;
  unsigned char iv [16];
  char logging_args [1024];
  unsigned char message [16];
  unsigned char sec_blk [1];
  OSDP_SECURE_MESSAGE *secure_message;
  unsigned char server_cryptogram [16];
  int status;
  int test_results;


  status = ST_OK;
  test_results = OCONFORM_FAIL;
  if (ctx->verbosity > 3)
    fprintf(ctx->log, "\nProcessing received osdp_CCRYPT\n");
  memset (iv, 0, sizeof (iv));

  // check for proper state AND secure channel enabled.

  if ((ctx->secure_channel_use [OO_SCU_ENAB] EQUALS 128+OSDP_SEC_SCS_11) &&
    (ctx->enable_secure_channel > 0))
  {
    secure_message = (OSDP_SECURE_MESSAGE *)(msg->ptr);
    if (ctx->enable_secure_channel EQUALS 2)
      if (secure_message->sec_blk_data != OSDP_KEY_SCBK_D)
        status = ST_OSDP_UNK_KEY_PAIR;

    if (ctx->enable_secure_channel EQUALS 1)
      if (secure_message->sec_blk_data != OSDP_KEY_SCBK)
        status = ST_OSDP_UNK_KEY_DEFAULT;

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

      if (0 != memcmp (message, ctx->rnd_a, sizeof (ctx->rnd_a)))
      {
        status = ST_OSDP_CHLNG_DECRYPT;
      }
      else
      {
        if (ctx->verbosity > 3)
          fprintf(ctx->log, "Client Cryptogram was valid (RND.A matched.)\n");
      };
    };
    if (status EQUALS ST_OK)
    {
      dump_buffer_log(ctx, "Decrypted Client Cryptogram:",
        message, sizeof(message));

      // client crytogram looks ok, save RND.B

      memcpy (ctx->rnd_b, message + sizeof (ctx->rnd_a), sizeof (ctx->rnd_b));
      if (ctx->verbosity > 3)
        dump_buffer_log(ctx, "Saving RND.B:", ctx->rnd_b, sizeof(ctx->rnd_b));

      // if it was a sane CCRYPT log it

      memset(logging_args, 0, sizeof (logging_args));
      sprintf(logging_args, "%02X%02X%02X%02X%02X%02X",
        ctx->rnd_b [0], ctx->rnd_b [1], ctx->rnd_b [2], ctx->rnd_b [3], ctx->rnd_b [4], ctx->rnd_b [5]);
      sprintf(cmd, "%s/run/ACU-actions/osdp_CCRYPT %s", ctx->service_root, logging_args); system(cmd);

      memcpy (message, ctx->rnd_b, sizeof (ctx->rnd_b));
      memcpy (message+sizeof (ctx->rnd_b), ctx->rnd_a, sizeof (ctx->rnd_a));
      if (ctx->verbosity > 3)
        dump_buffer_log(ctx, "Plaintext of server cryptogram:",
          message, sizeof(server_cryptogram));

      AES_ctx_set_iv (&aes_context_s_enc, iv);
      memcpy (server_cryptogram, message, sizeof (server_cryptogram));
      AES_CBC_encrypt_buffer(&aes_context_s_enc,
        server_cryptogram, sizeof (server_cryptogram));

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

  if (status EQUALS ST_OK)
    test_results = OCONFORM_EXERCISED;
  // if there was an error reset the secure channel and let the world continue
  if (status != ST_OK)
  {
    fprintf(ctx->log, "Error processing CCRYPT (status %d.)  Secure Channel reset.\n", status);
    status = ST_OK;
    osdp_reset_secure_channel (ctx);
  };
  (void)osdp_test_set_status(OOC_SYMBOL_cmd_chlng, test_results);
  (void)osdp_test_set_status(OOC_SYMBOL_resp_ccrypt, test_results);
  return (status);

} /* action_osdp_CCRYPT */


int
  action_osdp_CHLNG
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_CHLNG */

  OSDP_SC_CCRYPT ccrypt_response;
  char cmd [3072];
  int current_length;
  char details [1024];
  int nak;
  unsigned char osdp_nak_response_data [2];
  OSDP_SECURE_MESSAGE *s_msg;
  int status;


  status = ST_OK;
  s_msg = (OSDP_SECURE_MESSAGE *)(msg->ptr);
  nak = 0;

  // ditch the current secure channel session.
  if (OO_SCS_OPERATIONAL EQUALS ctx->secure_channel_use[OO_SCU_ENAB])
    osdp_reset_secure_channel(ctx);

  // if in mid-setup (i.e. just got osdp_CHLNG again) reset to permit challenge
  if ((OSDP_SEC_SCS_12 +  OO_SCS_STATE_FLAG) EQUALS
       ctx->secure_channel_use[OO_SCU_ENAB])
  {
    if (ctx->verbosity > 3)
      fprintf(ctx->log, "Secure Channel reset in mid-dialog.\n");
    osdp_reset_secure_channel(ctx);
  };

  // make sure this PD was enabled for secure channel (see enable-secure-channel command)

  if (OO_SCS_USE_ENABLED != ctx->secure_channel_use[OO_SCU_ENAB])
  {
    if (ctx->secure_channel_use [OO_SCU_ENAB] & 0x80)
      fprintf(ctx->log, "=== secure channel last SCS was %02X, not available to start set-up.\n", 0x7F & (ctx->secure_channel_use [OO_SCU_ENAB]));
    fprintf(ctx->log, "=== secure channel state %X\n",
      ctx->secure_channel_use[OO_SCU_ENAB]);
    nak = 1;
  };
  if (nak)
  {
    /*
      secure channel is not enabled on this PD.  Therefore osdp_CHLNG is not a valid command.
      NAK it with the code specified in Annex D (SCS_11 gets NAK 5) 
    */
    current_length = 0;
    osdp_nak_response_data [0] = OO_NAK_UNSUP_SECBLK;
    osdp_nak_response_data [1] = 0xff;
    status = send_message (ctx,
      OSDP_NAK, p_card.addr, &current_length,
      sizeof(osdp_nak_response_data), osdp_nak_response_data);
    ctx->sent_naks ++;
    osdp_test_set_status(OOC_SYMBOL_rep_nak, OCONFORM_EXERCISED);
    if (ctx->verbosity > 2)
    {
      fprintf (ctx->log, "NAK(5): osdp_CHLNG but Secure Channel disabled\n");
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
      fprintf(ctx->log, "SCBK Set-up error %d.\n", status);
      nak = 1;
      osdp_reset_secure_channel (ctx);

      // NAK, "encryption required" (close...), no details (length=1)

      osdp_nak_response_data [0] = OO_NAK_ENC_REQ;
      current_length = 0;
      status = send_message (ctx,
        OSDP_NAK, p_card.addr, &current_length,
        1, osdp_nak_response_data);
      ctx->sent_naks ++;
      osdp_test_set_status(OOC_SYMBOL_rep_nak, OCONFORM_EXERCISED);
      if (ctx->verbosity > 2)
      {
        fprintf (ctx->log, "NAK: SCBK not initialized\n");
      };
    };
    if (!nak && (status EQUALS ST_OK))
    {
      osdp_create_keys (ctx);

      // build up an SCS_12 response
      // mimic the sec_blk value in the CHLNG

      if (s_msg->sec_blk_data EQUALS OSDP_KEY_SCBK_D)
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
      memcpy ((char *)(ccrypt_response.rnd_b), (char *)(ctx->rnd_b), sizeof (ccrypt_response.rnd_b));
//printf ("fixme: RND.B\n");

      osdp_create_client_cryptogram (ctx, &ccrypt_response);

      current_length = 0;
 
      sprintf(details, "RND.A=%02x%02x%02x%02x%02x%02x%02x%02x",
         ctx->rnd_a [0], ctx->rnd_a [1], ctx->rnd_a [2], ctx->rnd_a [3], ctx->rnd_a [4], ctx->rnd_a [5], ctx->rnd_a [6], ctx->rnd_a [7]);

      sprintf(cmd, "%s/run/ACU-actions/osdp_CHLNG", ctx->service_root); system(cmd);

      status = send_secure_message (ctx,
        OSDP_CCRYPT, p_card.addr, &current_length, 
        sizeof (ccrypt_response), (unsigned char *)&ccrypt_response,
        OSDP_SEC_SCS_12, sizeof (sec_blk), sec_blk);

      (void)osdp_test_set_status_ex(OOC_SYMBOL_cmd_chlng, OCONFORM_EXERCISED, details);
      (void)osdp_test_set_status(OOC_SYMBOL_resp_ccrypt, OCONFORM_EXERCISED);
    };
  };
  return (status);

} /* action_osdp_CHLNG */


int
  action_osdp_KEYSET
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_KEYSET */

  int current_length;
  unsigned char *keyset_payload;
  int new_key_length;
  int status;


  status = ST_OK;
  keyset_payload = (unsigned char *)(msg->data_payload);
  // new key type is ignored

  new_key_length = keyset_payload [1];
  if (new_key_length != OSDP_KEY_OCTETS)
  {
    fprintf(ctx->log,
      "Bad key length (%d.) sent, using %d instead.\n",
      new_key_length, OSDP_KEY_OCTETS);
  };

  memcpy(ctx->current_scbk, keyset_payload+2, OSDP_KEY_OCTETS);
  fprintf(ctx->log, "NEW KEY SET\n");
  (void)oo_save_parameters(ctx, OSDP_SAVED_PARAMETERS,
    (unsigned char *)(keyset_payload+2)); // key material starts at +2 of the payload

  // all the time even if in 'quiet' (verbosity 0) mode
  {
    int i;
    fprintf(stderr, "SCBK set via osdp_KEYSET: ");
    for (i=0; i<OSDP_KEY_OCTETS; i++)
      fprintf(stderr, "%02X", keyset_payload[2+i]);
    fprintf(stderr, "\n");
  }

  current_length = 0;
  status = send_message_ex
    (ctx, OSDP_ACK, p_card.addr, &current_length, 0, NULL,
    OSDP_SEC_SCS_16, 0, NULL);

  osdp_test_set_status(OOC_SYMBOL_cmd_keyset, OCONFORM_EXERCISED);
fprintf(ctx->log, "DEBUG: action_osdp_KEYSET bottom\n");
  return (status);

} /* action_osdp_KEYSET */


int
  action_osdp_RMAC_I
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_RMAC_I */

  int acceptable;
  OSDP_HDR *header;
  unsigned char iv [16];
  OSDP_SCS_HEADER *scs_header;
  int status;
  int test_results;


  status = ST_OK;
  header = (OSDP_HDR *)(msg->ptr);
  scs_header = (OSDP_SCS_HEADER *)&(header->cmd_s);
  acceptable = 0;
  test_results = OCONFORM_FAIL;
  memset (iv, 0, sizeof (iv));

  // check for proper state

  if (ctx->secure_channel_use [OO_SCU_ENAB] != 128+OSDP_SEC_SCS_13)
    status = ST_OSDP_SC_WRONG_STATE;
  if (status EQUALS ST_OK)
  {
    // if we're here, scs_blk_type is 0x14
    // bounds check.  length has to be 3. data is either (bad) or (good).  varies by OSDP version.
    if (scs_header->sec_blk_len != 3)
      status = ST_OSDP_SC_BAD_HEADER;
    if (ctx->pd_cap.osdp_version EQUALS OSDP_PROTOCOL_VERSION_IEC)
      if (scs_header->sec_blk_data EQUALS 0)
        acceptable = 1;
    if (ctx->pd_cap.osdp_version EQUALS OSDP_PROTOCOL_VERSION_SIA22)
      if (scs_header->sec_blk_data EQUALS 0xff)
        acceptable = 1;
    if (ctx->pd_cap.osdp_version EQUALS 0)
    {
      fprintf(ctx->log, "****WARNING****  Pre-IEC Variant detected.  Issue osdp_CAP or check implementation.\n");
      (void)osdp_test_set_status(OOC_SYMBOL_resp_rmac_i, OCONFORM_FAIL);
      acceptable = 1;
    };
    if (!acceptable)
    {
       // must be an out of range protocol variant.  issue error, fail, and proceed.

      fprintf(ctx->log, "    RMAC_I Status check: unknown protocol variant (%02X)\n", scs_header->sec_blk_data);
    };
    if (status EQUALS ST_OK)
    {
      acceptable = 1;
    };
  };
  if (ctx->verbosity >2)
  {
    fprintf(ctx->log, "    SCS Hdr %02X Lth %d. Octet1 %2X\n",
      scs_header->sec_blk_type , scs_header->sec_blk_len, scs_header->sec_blk_data);
  };

  if (acceptable)
  {
    memcpy (ctx->rmac_i, msg->data_payload, msg->data_length);
    memcpy(ctx->rmac_i, msg->data_payload, sizeof(ctx->rmac_i));
    memcpy(ctx->last_calculated_out_mac, ctx->rmac_i, sizeof(ctx->last_calculated_out_mac));
    memcpy(ctx->last_calculated_in_mac, ctx->rmac_i, sizeof(ctx->last_calculated_in_mac));
    ctx->secure_channel_use [OO_SCU_ENAB] = OO_SCS_OPERATIONAL;
    fprintf (ctx->log, "*** SECURE CHANNEL OPERATIONAL***\n");
    (void)osdp_test_set_status(OOC_SYMBOL_cmd_scrypt, OCONFORM_EXERCISED);
    (void)osdp_test_set_status(OOC_SYMBOL_resp_rmac_i, OCONFORM_EXERCISED);
    // if we're set up not on the default key it's on the paired key
    if (memcmp(ctx->current_scbk, ctx->current_default_scbk, sizeof(ctx->current_scbk)) != 0)
      (void)osdp_test_set_status(OOC_SYMBOL_scs_paired, OCONFORM_EXERCISED);
    test_results = OCONFORM_EXERCISED; // for RMAC

    if (ctx->post_command_action EQUALS OO_POSTCOMMAND_SINGLESTEP)
    {
      fprintf(ctx->log, "===> PAUSE at osdp_RMAC_I reception <===\n"); fflush(ctx->log);
      ctx->enable_poll = OO_POLL_NEVER;
    };
  }
  else
  {
    (void)osdp_test_set_status(OOC_SYMBOL_resp_rmac_i, test_results);
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

      if (ctx->conformance_fail_next_rmac_i)
      {
        sec_blk [0] = 0xff; // FAIL
        ctx->conformance_fail_next_rmac_i = 0;
        if (ctx->verbosity > 2)
          fprintf(ctx->log, "Conformance test: RMAC_I responding with error.\n");
      };

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

      osdp_test_set_status(OOC_SYMBOL_cmd_scrypt, OCONFORM_EXERCISED);
      osdp_test_set_status(OOC_SYMBOL_resp_rmac_i, OCONFORM_EXERCISED);
    };
  }
  else
  {
    status = ST_OSDP_SC_WRONG_STATE;
    osdp_reset_secure_channel (ctx);
  };
  //fprintf(stderr, "DEBUG: bottom of SCRYPT last_ %d\n", ctx->last_was_processed);
  return (status);

} /* action_osdp_SCRYPT */

