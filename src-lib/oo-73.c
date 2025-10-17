/*
  oo-73 - PD emulator for extended packet mode (PIV) credential processing.

  (C)Copyright 2020-2025 Smithee Solutions LLC

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


#include <open-osdp.h>
#include <osdp_conformance.h>
extern OSDP_PARAMETERS p_card;
extern char multipart_message_buffer_1 [64*1024];


int
  action_osdp_CRAUTH
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_CRAUTH */

  OSDP_MULTI_HDR_IEC *crauth_header;
  char *crauth_payload;
  int current_length;
  int current_security;
  int inbound_fragment_length;
  int inbound_offset;
  int inbound_total_length;
  OSDP_MULTI_HDR_IEC *resp_hdr;
  int response_length;
  unsigned char response_payload [2048];
  int rlth;
  int status;


  status = ST_OK;

  // whatever else we think, the PD saw the CRAUTH

  osdp_test_set_status(OOC_SYMBOL_cmd_crauth, OCONFORM_EXERCISED);

  crauth_header = (OSDP_MULTI_HDR_IEC *)(msg->data_payload);
  crauth_payload = (char *)&(crauth_header->algo_payload);

  fprintf(ctx->log,
"  CRAUTH hdr: tlsb %02x tmsb %02x offlsb %02x offmsb %02x lenlsb %02x lenmsb %02x\n",
    crauth_header->total_lsb, crauth_header-> total_msb, crauth_header-> offset_lsb,
    crauth_header-> offset_msb, crauth_header-> data_len_lsb, crauth_header-> data_len_msb);
  fprintf(ctx->log, "CRAUTH Algo/Key %02x Payload %02x%02x%02x...\n",
    crauth_header->algo_payload,
    *(crauth_payload), *(1+crauth_payload), *(2+crauth_payload));

  inbound_offset = crauth_header->offset_msb*256 + crauth_header->offset_lsb;
  inbound_fragment_length = crauth_header->data_len_msb*256 + crauth_header->data_len_lsb;
  inbound_total_length = crauth_header->total_msb*256 + crauth_header->total_lsb;
  if (inbound_offset EQUALS 0)
  {
    fprintf(ctx->log, "  CRAUTH: new request (offset zero)\n");
  };
  if (ctx->next_in < inbound_total_length)
  {
    memcpy(ctx->mmsgbuf+ctx->next_in, &(crauth_header->algo_payload), inbound_fragment_length);
    ctx->next_in = ctx->next_in + inbound_fragment_length;
    fprintf(ctx->log, "  CRAUTH: accumulating input, now %d. of %d.\n",
      ctx->next_in, ctx->total_inbound_multipart);
  };
  if (ctx->next_in < inbound_total_length)
    status = send_message_ex (ctx, OSDP_ACK, p_card.addr, &current_length, 0, NULL, OSDP_SEC_SCS_16, 0, NULL);
  else
  {
// zzz else process it.
// OLD CODE
  memset(response_payload, 0, sizeof(response_payload));
  resp_hdr = (OSDP_MULTI_HDR_IEC *)&(response_payload [0]);
rlth=256;
  resp_hdr->total_lsb = (rlth & 0xff);
  resp_hdr->total_msb = (rlth/256);
  // offset is already 0
  resp_hdr->data_len_lsb = (rlth & 0xff);
  resp_hdr->data_len_msb = (rlth/256);
  response_length = rlth + sizeof(resp_hdr);

  current_length = 0;
  current_security = OSDP_SEC_SCS_18;
  status = send_message_ex(ctx, OSDP_CRAUTHR, ctx->pd_address, &current_length,
    response_length, response_payload, current_security, 0, NULL);
  };

  return(status);

} /* action_osdp_CRAUTH */


int
  action_osdp_CRAUTHR
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_CRAUTHR */

  OSDP_MULTI_HDR_IEC *crauthr_header;
  char *crauthr_payload;
  char details [4*2048]; // ...
  int i;
  FILE *pf;
  int response_length;
  char response_payload [2048]; // assumed to be larger than the whole response...
  int status;


  crauthr_header = (OSDP_MULTI_HDR_IEC *)(msg->data_payload);
  crauthr_payload = (char *)&(crauthr_header->algo_payload);

  fprintf(ctx->log,
"  CRAUTHR received: tlsb %02x tmsb %02x offlsb %02x offmsb %02x lenlsb %02x lenmsb %02x\n",
    crauthr_header->total_lsb, crauthr_header-> total_msb, crauthr_header-> offset_lsb,
    crauthr_header-> offset_msb, crauthr_header-> data_len_lsb, crauthr_header-> data_len_msb);
fprintf(ctx->log, "  crauthr payload %02x%02x%02x...\n",
    *(crauthr_payload), *(crauthr_payload+1), *(crauthr_payload+2));

  response_length = (crauthr_header->total_msb * 256) + crauthr_header->total_lsb;
  details [0] = 0;
  status = ST_OK; // assume for now the header has been validated.
  if (response_length > OSDP_OFFICIAL_MSG_MAX)
    status = ST_OSDP_CRAUTHR_HEADER;

  if (status EQUALS ST_OK)
  {
    // save binary format payload.  per convention it goes in /opt/osdp-conformance/results/osdp_CRAUTHR_payload.bin

    pf = fopen("/opt/osdp-conformance/results/osdp_CRAUTHR_payload.bin", "w");
    if (pf != NULL)
    {
      (void) fwrite(crauthr_payload, sizeof(crauthr_payload[0]), response_length, pf);
      fclose(pf);
    };
    memset(response_payload, 0, sizeof(response_payload));
    for (i=0; i<response_length; i++)
    {
      sprintf(response_payload+(2*i), "%02x", (unsigned)*(crauthr_payload+i));
    };
    sprintf(details, "\"crauthr-response\":\"%s\",", response_payload);
    osdp_test_set_status_ex(OOC_SYMBOL_resp_crauthr, OCONFORM_EXERCISED, details);
    osdp_test_set_status_ex(OOC_SYMBOL_cmd_crauth, OCONFORM_EXERCISED, "");
  }
  else
  {
    osdp_test_set_status_ex(OOC_SYMBOL_resp_crauthr, OCONFORM_FAIL, details);
  };

  return(status);

} /* action_osdp_CRAUTHR */


int
  action_osdp_GENAUTHR
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_GENAUTHR */

  OSDP_MULTI_HDR_IEC *genauthr_header;
  char *genauthr_payload;
  char details [4*2048]; // ...
  int i;
  int response_length;
  char response_payload [2048]; // assumed to be larger than the whole response...
  int status;


  genauthr_header = (OSDP_MULTI_HDR_IEC *)(msg->data_payload);
  genauthr_payload = (char *)&(genauthr_header->algo_payload);

  fprintf(ctx->log,
"  GENAUTHR received: tlsb %02x tmsb %02x offlsb %02x offmsb %02x lenlsb %02x lenmsb %02x\n",
    genauthr_header->total_lsb, genauthr_header-> total_msb, genauthr_header-> offset_lsb,
    genauthr_header-> offset_msb, genauthr_header-> data_len_lsb, genauthr_header-> data_len_msb);
fprintf(ctx->log, "  genauthr payload %02x%02x%02x...\n",
    *(genauthr_payload), *(genauthr_payload+1), *(genauthr_payload+2));

  response_length = (genauthr_header->total_msb * 256) + genauthr_header->total_lsb;
  details [0] = 0;
  status = ST_OK; // assume for now the header has been validated.
  if (response_length > OSDP_OFFICIAL_MSG_MAX)
    status = ST_OSDP_CRAUTHR_HEADER;

  if (status EQUALS ST_OK)
  {
    memset(response_payload, 0, sizeof(response_payload));
    for (i=0; i<response_length; i++)
    {
      sprintf(response_payload+(2*i), "%02x", (unsigned)*(genauthr_payload+i));
    };
    sprintf(details, "\"genauthr-response\":\"%s\",", response_payload);
    osdp_test_set_status_ex(OOC_SYMBOL_resp_genauthr, OCONFORM_EXERCISED, details);
  }
  else
  {
    osdp_test_set_status_ex(OOC_SYMBOL_resp_genauthr, OCONFORM_FAIL, details);
  };

  return(status);

} /* action_osdp_GENAUTHR */


int
  action_osdp_PIVDATA
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)
{ return(-1); }


int
  action_osdp_PIVDATAR
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)
{ /* action_osdp_PIVDATAR */

  char details [4*2048]; // ...
  int status;


  status = ST_OK;
  dump_buffer_log(ctx, "action_osdp_PIVDATAR ", msg->data_payload, msg->data_length);
  sprintf(details, "\"payload-length\":\"%d\",\"payload-first-3\":\"%02x%02x%02x\",",
    msg->data_length, (msg->data_payload)[0], (msg->data_payload)[1], (msg->data_payload)[2]);
  osdp_test_set_status_ex(OOC_SYMBOL_resp_pivdatar, OCONFORM_EXERCISED, details);
  return(status);

} /* action_osdp_PIVDATAR */


/*
  oo_build_genauth - fabricates a genauth/crauth payload

  arguments:
    current context
    buffer to build out osdp command payload.  
    ptr to buffer length (max on input, updated on return.
    details buffer
    details length
*/

int
  oo_build_genauth
    (OSDP_CONTEXT *ctx,
    unsigned char *challenge_payload_buffer,
    int *payload_length,
    unsigned char *details,
    int details_length)

{ /* oo_build_genauth */

  OSDP_MULTI_HDR_IEC *challenge_hdr;
  int max_in_secure;
  int sdu_data_length;
  int status;


  status = ST_OK;

  // save away the message

  memcpy(multipart_message_buffer_1, details, details_length);
  ctx->total_outbound_multipart = details_length;

  // calculate SDU for the first message.
  // subtract standard header
  // subtract CRC
  // subtract SCS header and MAC if in secure channel

  sdu_data_length = 128; // default max size;

  sdu_data_length = sdu_data_length - (1+1+2+1+2); // less SOM, Addr, Len1, Len2, CTL, CRC

  /*
    if we are in secure channel the max SDU size must be small enough that 2 AES-128 cipherblocks
    fit in the payload.
  */
  if (ctx->secure_channel_use [OO_SCU_ENAB] EQUALS OO_SCS_OPERATIONAL)
  {
    sdu_data_length = sdu_data_length - (2+4);

    max_in_secure = sdu_data_length + sizeof(OSDP_MULTI_HDR_IEC) - 1;
    max_in_secure = (max_in_secure / OSDP_KEY_OCTETS) * OSDP_KEY_OCTETS;
    sdu_data_length = max_in_secure - (sizeof(OSDP_MULTI_HDR_IEC) - 1);
    ctx->current_sdu_length = sdu_data_length;
  };

  if (ctx->verbosity > 3)
  {
    fprintf(ctx->log, "SDU 0x%X details_length %d. official max %d.\n",
      sdu_data_length, details_length, OSDP_OFFICIAL_MSG_MAX);
  };
  if (details_length > OSDP_OFFICIAL_MSG_MAX)
    status = ST_OSDP_UNSUPPORTED_AUTH_PAYLOAD;
  if (status EQUALS ST_OK)
  {
    challenge_hdr = (OSDP_MULTI_HDR_IEC *)challenge_payload_buffer;
    challenge_hdr->total_lsb = details_length & 0xff;
    challenge_hdr->total_msb = (details_length & 0xff00) >> 8;
    challenge_hdr->offset_lsb = 0;
    challenge_hdr->offset_msb = 0;

    // only send a chunk at this time (if it all fits this matches the total)
    challenge_hdr->data_len_lsb = 0xFF & sdu_data_length;
    challenge_hdr->data_len_msb = (0xFF00 & sdu_data_length) >> 8;

    // copy in the first chunk.

    *payload_length = sizeof(*challenge_hdr) - 1 + sdu_data_length;
    memcpy(&(challenge_hdr->algo_payload), multipart_message_buffer_1, sdu_data_length);

    ctx->next_out = sdu_data_length;
  };
  return(status);

} /* oo_build_genauth */


/*

  this sends the next fragment.  it pulls it out of multipart_message_buffer_1

*/

int oo_send_next_genauth_fragment
  (OSDP_CONTEXT *ctx)

{ /* oo_send_next_genauth_fragment */

  OSDP_MULTI_HDR_IEC *challenge_hdr;
  int current_length;
  unsigned char request_payload [2048];
  int status;
  int total_size;


  status = ST_OK;
  memset(request_payload, 0, sizeof(request_payload));

  // calculate how much is left.  adjust the current_sdu_length if we are near the end.
  if ((ctx->next_out + ctx->current_sdu_length) > ctx->total_outbound_multipart)
    ctx->current_sdu_length = ctx->total_outbound_multipart - ctx->next_out;

  challenge_hdr = (OSDP_MULTI_HDR_IEC *)request_payload;
  challenge_hdr->total_lsb = ctx->total_outbound_multipart & 0xff;
  challenge_hdr->total_msb = (ctx->total_outbound_multipart & 0xff00) >> 8;
  challenge_hdr->offset_lsb = ctx->next_out & 0xff;
  challenge_hdr->offset_msb = (ctx->next_out & 0xff00) >> 8;
  challenge_hdr->data_len_lsb = 0xFF & ctx->current_sdu_length;
  challenge_hdr->data_len_msb = (0xFF00 & ctx->current_sdu_length) >> 8;

  // copy in the next chunk

  memcpy(&(challenge_hdr->algo_payload), multipart_message_buffer_1+ctx->next_out, ctx->current_sdu_length);
  ctx->next_out = ctx->next_out + ctx->current_sdu_length;

  // send it.

  total_size = sizeof(OSDP_MULTI_HDR_IEC) - 1 + ctx->current_sdu_length;
  current_length = 0;
  status = send_message_ex(ctx, OSDP_CRAUTH, p_card.addr,
    &current_length, total_size, (unsigned char *)challenge_hdr, OSDP_SEC_SCS_17, 0, NULL);
  return(status);

} /* oo_send_next_genauth_fragment */

