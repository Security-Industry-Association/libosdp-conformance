/*
  oo-73 - PD emulator for extended packet mode (PIV) credential processing.

  (C)Copyright 2020-2022 Smithee Solutions LLC
*/


#include <string.h>


#include <open-osdp.h>
#include <osdp_conformance.h>


int
  action_osdp_CRAUTH
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_CRAUTH */

  OSDP_MULTI_HDR_IEC *crauth_header;
  char *crauth_payload;
  int current_length;
  int current_security;
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
fprintf(stderr, "DEBUG: CRAUTHR sent\n");

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


fprintf(ctx->log, "DEBUG: osdp_CRAUTHR stub.\n");
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


fprintf(ctx->log, "DEBUG: osdp_GENAUTHR stub.\n");
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
  fprintf(ctx->log, "DEBUG: osdp_PIVDATAR stub.\n");
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
  int status;


  status = ST_OK;
  if (details_length > OSDP_OFFICIAL_MSG_MAX)
    status = ST_OSDP_UNSUPPORTED_AUTH_PAYLOAD;
  if (status EQUALS ST_OK)
  {
    challenge_hdr = (OSDP_MULTI_HDR_IEC *)challenge_payload_buffer;
    challenge_hdr->total_lsb = details_length & 0xff;
    challenge_hdr->total_msb = (details_length & 0xff00) >> 8;
    challenge_hdr->offset_lsb = 0;
    challenge_hdr->offset_msb = 0;
    challenge_hdr->data_len_lsb = challenge_hdr->total_lsb;
    challenge_hdr->data_len_msb = challenge_hdr->total_msb;
    if (*payload_length > (sizeof(*challenge_hdr)-1+details_length))
    {
      *payload_length = sizeof(*challenge_hdr) - 1 + details_length;
      memcpy(&(challenge_hdr->algo_payload), details, details_length);
      dump_buffer_log(ctx, "oo_build_genauth: ", challenge_payload_buffer, *payload_length);
    }
    else
      status = ST_OSDP_PAYLOAD_TOO_SHORT;
  };
  return(status);

} /* oo_build_genauth */

