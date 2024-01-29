/*
  oo-mgmt-actions - action routines for (some) mgmt functions

  (C)Copyright 2022-2023 Smithee Solutions LLC

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
extern OSDP_INTEROP_ASSESSMENT osdp_conformance;


int
  action_osdp_MFGREP
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_MFGREP */

  char cmd [2*1024];
  int count;
  int i;
  OSDP_MFGREP_RESPONSE *mfg;
  unsigned char mfg_command;
  OSDP_HDR *oh;
  char payload [1024];
  int status;
  char tmp1 [1024];


  status = ST_OK;
  oh = (OSDP_HDR *)(msg->ptr);
  count = oh->len_lsb + (oh->len_msb << 8);
  count = count - 6; // assumes no SCS header
  if (ctx->secure_channel_use [OO_SCU_ENAB] EQUALS OO_SCS_OPERATIONAL)
    count = count - 2; // for SCS 18
  count = count - msg->check_size;

  count = count - 4; // 3 for OUI, 1 for command
        
  mfg = (OSDP_MFGREP_RESPONSE *)(msg->data_payload);
  mfg_command = *(&(mfg->data));

  payload [0] = 0;
  for (i=0; i<count; i++)
  {
    sprintf(tmp1, "%02x", *(&(mfg->data)+1+i));
    strcat(payload, tmp1);
  };
  sprintf(cmd, "\"{\\\"1\\\":\\\"%02X\\\",\\\"2\\\":\\\"%02X%02X%02X\\\",\\\"3\\\":\\\"%02X\\\",\\\"4\\\":\\\"%s\\\"}\"",
    ctx->pd_address,
    mfg->vendor_code [0], mfg->vendor_code [1], mfg->vendor_code [2], mfg_command, payload);
  {
    FILE *f;
    f = fopen("/opt/osdp-conformance/run/ACU/osdp-mfg-response.json", "w");
    if (f != NULL)\
    {
      fprintf(f, "%s\n", cmd);
      fclose(f);
    };
  };

  status = oosdp_callout(ctx, "osdp_MFGREP", cmd);

  if (status EQUALS ST_OK)
    status = osdp_test_set_status_ex(OOC_SYMBOL_resp_mfgrep, OCONFORM_EXERCISED, "");

  return(status);

} /* action_osdp_MFGREP */


int
  action_osdp_NAK
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_OSDP_NAK */

  char cmd [3*1024];
  int count;
  OSDP_HDR *oh;
  char nak_code;
  char nak_data;
  int status;


  status = ST_OK;
  oh = (OSDP_HDR *)(msg->ptr);
      ctx->sent_naks ++;
      ctx->last_nak_error = *(0+msg->data_payload);

      if (ctx->verbosity > 2)
      {
        count = oh->len_lsb + (oh->len_msb << 8);
        count = count - 6 - 2; // less header less CRC

        nak_code = *(msg->data_payload);
        nak_data = 0;
        if (count > 1)
        {
          nak_data = *(1+msg->data_payload);
          sprintf (tlogmsg, "osdp_NAK: Error Code %02x Data %02x",
            nak_code, *(1+msg->data_payload));
        }
        else
        {
          sprintf (tlogmsg, "osdp_NAK: Error Code %02x", nak_code);
        };

        sprintf(cmd,
          "/opt/osdp-conformance/run/ACU-actions/osdp_NAK %x %x",
          nak_code, nak_data);
        system(cmd);

        fprintf (ctx->log, "%s\n", tlogmsg);
// { *(0+msg->data_payload) is nak code 070-03-(3+that) is test zzz };
        switch(*(0+msg->data_payload))
        {
//7 3 3 is nak 0
//not yet displayed: OO_NAK_COMMAND_LENGTH OO_NAK_BIO_TYPE_UNSUPPORTED OO_NAK_BIO_FMT_UNSUPPORTED OO_NAK_CMD_UNABLE
        case OO_NAK_CHECK_CRC:
          fprintf(ctx->log, "  NAK: (1)Bad CRC/Checksum\n");
          break;
        case OO_NAK_UNK_CMD:
          fprintf(ctx->log, "  NAK: (3)Command not implemented by PD\n");
          break;
        case OO_NAK_SEQUENCE:
          fprintf(ctx->log, "  NAK: (4)Unexpected sequence number\n");
          ctx->seq_bad ++;
            // hopefully not double counted, works in monitor mode
          ctx->next_sequence = 0; // reset sequence due to NAK
          break;
        case OO_NAK_UNSUP_SECBLK:
          fprintf(ctx->log, "  NAK: (5)Security block not accepted.\n");
          break;
        case OO_NAK_ENC_REQ:
          // drop out of secure channel and in fact reset the sequence number

          fprintf(ctx->log, "  NAK: (%d)Encryption required.\n", nak_code);
          osdp_reset_secure_channel(ctx);
          ctx->next_sequence = 0; 
          break;

        };
      };
      osdp_test_set_status(OOC_SYMBOL_rep_nak, OCONFORM_EXERCISED);
      if (nak_code EQUALS 3) 
        osdp_test_set_status(OOC_SYMBOL_resp_nak_3, OCONFORM_EXERCISED);
      if (nak_code EQUALS 5) 
        osdp_test_set_status(OOC_SYMBOL_resp_nak_5, OCONFORM_EXERCISED);

      // collateral effects of a NAK...

      // if the PD NAK'd during secure channel set-up then reset out of secure channel

      if (ctx->secure_channel_use [OO_SCU_ENAB] & 0x80)
      {
        osdp_reset_secure_channel (ctx);
      }
      else
      {
        // if the PD said it does BIO and it NAK'd a BIOREAD fail the test.

        if (ctx->last_command_sent EQUALS OSDP_BIOREAD)
        {
          if (ctx->configured_biometrics)
            osdp_test_set_status(OOC_SYMBOL_cmd_bioread, OCONFORM_FAIL);
        };

        // if the PD NAK'd a BIOMATCH fail the test.

        if (ctx->last_command_sent EQUALS OSDP_BIOMATCH)
        {
          if (ctx->configured_biometrics)
            osdp_test_set_status(OOC_SYMBOL_cmd_biomatch, OCONFORM_FAIL);
        };

        // if the PD NAK'd an ID fail the test.

        if (ctx->last_command_sent EQUALS OSDP_ID)
        {
          osdp_test_set_status(OOC_SYMBOL_cmd_id, OCONFORM_FAIL);
        };

        // if the PD NAK'd an ACURXSIZE fail the test.  If you didn't want the failure signal you'd use the sequencer to skip the test.
        if (ctx->last_command_sent EQUALS OSDP_ACURXSIZE)
        {
          osdp_test_set_status(OOC_SYMBOL_cmd_acurxsize, OCONFORM_FAIL);
        };

        // if the PD NAK'd a TEXT fail the test.  If you didn't want the failure signal you'd use the sequencer to skip the test.
        if ((unsigned int)(ctx->last_command_sent) EQUALS (unsigned int)OSDP_TEXT)
        {
          osdp_test_set_status(OOC_SYMBOL_cmd_text, OCONFORM_FAIL);
        };

        // if the PD NAK'd a KEEPACTIVE fail the test.  If you didn't want the failure signal you'd use the sequencer to skip the test.
        if ((unsigned int)(ctx->last_command_sent) EQUALS (unsigned int)OSDP_KEEPACTIVE)
        {
          osdp_test_set_status(OOC_SYMBOL_cmd_keepactive, OCONFORM_FAIL);
        };

// assumes test_details is still valid.
// assumes it was a perm on command
#define LP_ON (12)
        if (ctx->test_details [LP_ON] EQUALS OSDP_LEDCOLOR_BLUE)
          osdp_test_set_status(OOC_SYMBOL_cmd_led_blue, OCONFORM_FAIL);
        if (ctx->test_details [LP_ON] EQUALS OSDP_LEDCOLOR_CYAN)
          osdp_test_set_status(OOC_SYMBOL_cmd_led_cyan, OCONFORM_FAIL);
        if (ctx->test_details [LP_ON] EQUALS OSDP_LEDCOLOR_MAGENTA)
          osdp_test_set_status(OOC_SYMBOL_cmd_led_magenta, OCONFORM_FAIL);
        if (ctx->test_details [LP_ON] EQUALS OSDP_LEDCOLOR_WHITE)
          osdp_test_set_status(OOC_SYMBOL_cmd_led_white, OCONFORM_FAIL);

        // if the PD NAK'd an OSTAT that is a fail.  The initiator of the OSTAT is responsible for only
        // using it if output support declared.

        if (ctx->last_command_sent EQUALS OSDP_OSTAT)
        {
          osdp_test_set_status(OOC_SYMBOL_cmd_ostat, OCONFORM_FAIL);
        };

        // if the PD NAK'd an RSTAT that is ok because RSTAT/RSTATR are effectively deprecated

        if (ctx->last_command_sent EQUALS OSDP_RSTAT)
        {
          osdp_test_set_status(OOC_SYMBOL_cmd_rstat, OCONFORM_EXERCISED);
        };

      // if the PD NAK'd an ISTAT fail the test.
      if (ctx->last_command_sent EQUALS OSDP_ISTAT)
      {
        osdp_conformance.cmd_istat.test_status = OCONFORM_FAIL;
        SET_FAIL ((ctx), "3-6-1");
      };

      // if the PD NAK'd a KEYSET fail the test.
      if (ctx->last_command_sent EQUALS OSDP_KEYSET)
      {
        osdp_test_set_status(OOC_SYMBOL_cmd_keyset, OCONFORM_FAIL);
      };

      // if the PD NAK'd an LSTAT fail the test.
      if (ctx->last_command_sent EQUALS OSDP_LSTAT)
      {
        osdp_test_set_status(OOC_SYMBOL_cmd_lstat, OCONFORM_FAIL);
      };
      // if the PD NAK'd a CAP fail the test.
      if (ctx->last_command_sent EQUALS OSDP_CAP)
      {
        osdp_test_set_status(OOC_SYMBOL_cmd_cap, OCONFORM_FAIL);
      };

      };

      ctx->last_was_processed = 1; // if we got a NAK that processes the cmd

  return(status);

} /* action_osdp_NAK */


int
  action_osdp_RSTAT
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_RSTAT */

  int current_length;
  unsigned char osdp_rstat_response_data [1];
  int status;


  status = ST_OK;
  osdp_test_set_status(OOC_SYMBOL_cmd_rstat, OCONFORM_EXERCISED);
  osdp_test_set_status(OOC_SYMBOL_resp_rstatr, OCONFORM_EXERCISED);
  osdp_rstat_response_data [ 0] = 1; //hard code to "not connected"
  current_length = 0;
//  status = send_message (ctx, OSDP_RSTATR, p_card.addr, &current_length, sizeof (osdp_rstat_response_data), osdp_rstat_response_data);
  status = send_message_ex(ctx, OSDP_RSTATR, p_card.addr, &current_length, sizeof (osdp_rstat_response_data), osdp_rstat_response_data, OSDP_SEC_SCS_18, 0, NULL);
  if (ctx->verbosity > 2)
  {
    sprintf (tlogmsg, "Responding with OSDP_RSTATR");
    fprintf (ctx->log, "%s\n", tlogmsg); tlogmsg[0]=0;
  };

  return (status);

} /* action_osdp_RSTAT */

