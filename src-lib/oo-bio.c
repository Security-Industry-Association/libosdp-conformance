/*
  oo-bio - biometrics routines

  (C)Copyright 2017-2022 Smithee Solutions LLC

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
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>


#include <jansson.h>


#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>


int
  action_osdp_BIOMATCH
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_BIOMATCH */

  int current_length;
  char logmsg [1024];
  unsigned char osdp_bio_match_response_data [100];
  unsigned char osdp_nak_response_data [2];
  int response_length;
  int status;


  status = ST_OSDP_UNKNOWN_BIO_ACTION;

  if (ctx->verbosity > 2)
  {
    sprintf (logmsg, "BIOMATCHR rdr=%02X type=%02X format=%02X quality=%02X\n",
      *(msg->data_payload + 0), *(msg->data_payload + 1),
      *(msg->data_payload + 2), *(msg->data_payload + 3));
    fprintf (ctx->log, "%s", logmsg);
    logmsg[0]=0;
  };

  // assuming of course it's sane
  osdp_test_set_status(OOC_SYMBOL_cmd_biomatch, OCONFORM_EXERCISED);

  if (ctx->pd_cap.enable_biometrics EQUALS 0)
  {
    status = ST_OK;

    // if disabled do this

    // we don't actually DO a biometrics read at this time, so NAK it.

    current_length = 0;
    osdp_nak_response_data [0] = OO_NAK_UNK_CMD;
    osdp_nak_response_data [1] = 0xff;
    status = send_message_ex(ctx, OSDP_NAK, ctx->pd_address, &current_length, 1, osdp_nak_response_data, OSDP_SEC_SCS_18, 0, NULL);
    ctx->sent_naks ++;
    osdp_test_set_status(OOC_SYMBOL_rep_nak, OCONFORM_EXERCISED);
    if (ctx->verbosity > 2)
    {
      fprintf (ctx->log, "BIO not enable, responding with NAK\n");
    };
  };

  // if enabled for biometrics send the reply.

  if (ctx->pd_cap.enable_biometrics EQUALS 1)
  {
    status = ST_OK;

    // if there's a template json read it

    memset(osdp_bio_match_response_data, 0, sizeof(osdp_bio_match_response_data));
    response_length = 16; // bogus value
    // response is all zeroes for now.

    current_length = 0;
    status = send_message_ex(ctx, OSDP_BIOMATCHR, ctx->pd_address, &current_length, response_length, osdp_bio_match_response_data, OSDP_SEC_SCS_18, 0, NULL);

    osdp_test_set_status(OOC_SYMBOL_resp_biomatchr, OCONFORM_EXERCISED);
  };

  return(status);

} /* action_osdp_BIOMATCH */


int
  action_osdp_BIOMATCHR
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)
{
  char command [1024];


  // assuming of course it's sane
  osdp_test_set_status(OOC_SYMBOL_resp_biomatchr, OCONFORM_EXERCISED);

  sprintf(command, "/opt/osdp-conformance/run/ACU-actions/osdp_BIOMATCHR %02X %02x %02x %02X",
    ctx->pd_address, msg->data_payload [0], msg->data_payload [1], msg->data_payload [2]);
  system(command);
  return(ST_OK);
}


int
  action_osdp_BIOREAD
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_BIOREAD */

  int current_length;
  char logmsg [1024];
  char command [1024];
  unsigned char osdp_bio_read_response_data [100];
  unsigned char osdp_nak_response_data [2];
  int response_length;
  int status;


  status = ST_OSDP_UNKNOWN_BIO_ACTION;

  if (ctx->verbosity > 2)
  {
    sprintf (logmsg, "BIOREAD rdr=%02x type=%02x format=%02x quality=%02x\n",
      *(msg->data_payload + 0), *(msg->data_payload + 1),
      *(msg->data_payload + 2), *(msg->data_payload + 3));
    fprintf (ctx->log, "%s", logmsg);
    logmsg[0]=0;
  };

  // assuming of course it's sane
  osdp_test_set_status(OOC_SYMBOL_cmd_bioread, OCONFORM_EXERCISED);

  if (ctx->pd_cap.enable_biometrics EQUALS 0)
  {
    status = ST_OK;

    // if disabled do this

    // we don't actually DO a biometrics read at this time, so NAK it.

    current_length = 0;
    osdp_nak_response_data [0] = OO_NAK_UNK_CMD;
    osdp_nak_response_data [1] = 0xff;
    status = send_message_ex(ctx, OSDP_NAK, ctx->pd_address, &current_length, 1, osdp_nak_response_data, OSDP_SEC_SCS_18, 0, NULL);
    ctx->sent_naks ++;
    osdp_test_set_status(OOC_SYMBOL_rep_nak, OCONFORM_EXERCISED);
    if (ctx->verbosity > 2)
    {
      fprintf (ctx->log, "BIO not enable, responding with NAK\n");
    };
  };

  // if enabled for bioread send the replay.

  if (ctx->pd_cap.enable_biometrics EQUALS 1)
  {
    status = ST_OK;

    // if there's a template json read it

    memset(osdp_bio_read_response_data, 0, sizeof(osdp_bio_read_response_data));
    osdp_bio_read_response_data [0] = 0; // reader
    osdp_bio_read_response_data [1] = 0; // status good
    osdp_bio_read_response_data [2] = 0; // type
    osdp_bio_read_response_data [3] = 0xff; // quality
    osdp_bio_read_response_data [4] = 8; // lth lsb
    osdp_bio_read_response_data [5] = 0; // lth msb
    response_length = 6 + 8;

    // response is all zeroes for now.

    current_length = 0;
    status = send_message_ex(ctx, OSDP_BIOREADR, ctx->pd_address, &current_length, response_length, osdp_bio_read_response_data, OSDP_SEC_SCS_18, 0, NULL);

    osdp_test_set_status(OOC_SYMBOL_resp_bioreadr, OCONFORM_EXERCISED);

    sprintf(command, "/opt/osdp-conformance/run/ACU-actions/osdp_BIOREAD %02X %02x %02x %02X",
      ctx->pd_address, msg->data_payload [0], msg->data_payload [1], msg->data_payload [2]);
    system(command);
  };

  return(status);

} /* action_osdp_BIOREAD */


int
  action_osdp_BIOREADR
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_BIOREADR */

  char command [4000];
  FILE *credsf;
  int i;
  char octet [3];
  int template_length;
  char template_string [3000];


  // assuming of course it's sane
  osdp_test_set_status(OOC_SYMBOL_resp_bioreadr, OCONFORM_EXERCISED);

  template_length = msg->data_length - 6;
  template_string [0] = 0;
  for (i=0; i < template_length; i++)
  {
    sprintf(octet, "%02x", msg->data_payload [6+i]);
    strcat(template_string, octet);
  };
  credsf = fopen("/opt/osdp-conformance/run/ACU/osdp-saved-credentials.json", "w");
  if (credsf != NULL)
  {
    // in the response type and quality are at 2 and 3.  format is not specified, say it's 0

    fprintf(credsf, "{\"bio-template\":\"%s\", \"bio-format\":\"%02X\", \"bio-quality\":\"%02X\", \"bio-type\":\"%02X\"}\n",
      template_string,
      0, msg->data_payload [3], msg->data_payload [2]);
    fclose(credsf);
  };
  sprintf(command, "/opt/osdp-conformance/run/ACU-actions/osdp_BIOREADR %02X %02X %02X %02X %02X %s",
    ctx->pd_address, msg->data_payload [0], msg->data_payload [1], msg->data_payload [2], msg->data_payload [3], template_string);
  system(command);
  return(ST_OK);

} /* action_osdp_BIOREADR */


/*
  send_bio_match_template - send an osdp_BIOMATCH command to a PD

  details contains the payload structure in table 26 except
  the template is the hex string (so needs conversion)
*/
int
  send_bio_match_template
    (OSDP_CONTEXT *ctx,
    unsigned char *details,
    int details_length)

{ /* send_bio_match_template */

  int current_length;
  unsigned short int returned_lth;
  int send_length;
  int status;
  unsigned char template_buffer [2000];



  status = osdp_string_to_buffer(ctx, (char *)(details+4), template_buffer+6, &returned_lth);
  memcpy((char *)template_buffer, (char *)details, 4);
  template_buffer [4] = returned_lth & 0xff;
  template_buffer [5] = returned_lth >> 8;
  send_length = 6 + returned_lth;

  current_length = 0;
  if (ctx->verbosity > 2)
    fprintf (ctx->log, "biomatch sent t=%02X f=%02X q=%02X l=%d.\n",
      template_buffer [1], template_buffer [2], template_buffer [3], (template_buffer [5] * 256) + template_buffer [4]);
  status = send_message_ex(ctx, OSDP_BIOMATCH, ctx->pd_address,
     &current_length, send_length, template_buffer, OSDP_SEC_SCS_17, 0, NULL);
fprintf(stderr, "DEBUG: just sent BIOMATCH\n");
  return (status);

} /* send_bio_match_template */


/*
  send_bio_read_template - send an osdp_BIOREAD command to a PD
*/
int
  send_bio_read_template
    (OSDP_CONTEXT
      *ctx)

{ /* send_bio_read_template */

  int current_length;
  unsigned char param [4];
  int status;


  param [0] = 0; // reader 0
  param [1] = 0; // default bio type
  param [2] = 2; // ANSI/INCITS 378 Fingerprint template "49"
  param [3] = 0xFF; // quality

  current_length = 0;
  if (ctx->verbosity > 2)
    fprintf (ctx->log, "bioread sent\n");
  status = send_message_ex(ctx, OSDP_BIOREAD, ctx->pd_address,
     &current_length, sizeof(param), param, OSDP_SEC_SCS_17, 0, NULL);
  return (status);

} /* send_bio_read_template */

