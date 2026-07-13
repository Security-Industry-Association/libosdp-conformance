/*
  oo-actions - open osdp action routines

  (C)Copyright 2017-2026 Smithee Solutions LLC

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
#include <stdlib.h>
#include <unistd.h>


#include <aes.h>


#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>


int
  action_osdp_BUSY
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_BUSY */

  char cmd [2*8192];
  int status;


  status = ST_OK;
  fprintf(ctx->log, "BUSY received\n");

  sprintf(cmd, "\"{\\\"1\\\":\\\"%02X\\\"}\"",
    ctx->pd_address);
  status = oosdp_callout(ctx, "osdp_BUSY", cmd);

  osdp_test_set_status(OOC_SYMBOL_resp_busy, OCONFORM_EXERCISED);
  return(status);

} /* action_osdp_BUSY */


int
  action_osdp_MFGERRR
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_MFGERRR */

  char cmd [2*8192];
  int count;
  FILE *f;
  int i;
  OSDP_HDR *oh;
  char payload [8192];
  int status;
  char tmp1 [8192];


  status = ST_OK;
  fprintf(ctx->log, "MFGERRR received\n");

  // calculate length of payload

  oh = (OSDP_HDR *)(msg->ptr);
  count = oh->len_lsb + (oh->len_msb << 8);
  count = count - 6; // assumes no SCS header
  if (ctx->secure_channel_use [OO_SCU_ENAB] EQUALS OO_SCS_OPERATIONAL)
    count = count - 2; // for SCS 18
  count = count - msg->check_size;

  // the callout creates osdp-mfg-error.json.  It includes the (current known) OUI
  // for convienience, that was not in the message.
  // arg 1 is the PD address
  // arg 2 is the OUI
  // arg 3 the hex string version of the payload
  // infer arg 3's length from strlen(arg 3)/2

  payload [0] = 0;
  for (i=0; i<count; i++)
  {
    sprintf(tmp1, "%02x", msg->data_payload [i]);
    strcat(payload, tmp1);
  };
  sprintf(cmd, "\"{\\\"1\\\":\\\"%02X\\\",\\\"2\\\":\\\"%02X%02X%02X\\\",\\\"3\\\":\\\"%s\\\"}\"",
    ctx->pd_address,
    ctx->vendor_code [0], ctx->vendor_code [1], ctx->vendor_code [2], payload);
  {
    f = fopen("/opt/osdp-conformance/run/ACU/osdp-mfg-error.json", "w");
    if (f != NULL)\
    {
      fprintf(f, "%s\n", cmd);
      fclose(f);
    };
  };
  status = oosdp_callout(ctx, "osdp_MFGERRR", cmd);

  osdp_test_set_status(OOC_SYMBOL_resp_mfgerrr, OCONFORM_EXERCISED);
  return(status);

} /* action_osdp_MFGERRR */


int
  action_osdp_PDCAP
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_PDCAP */

  char aux [4096];
  FILE *capf;
  char cmd [2048];
  OSDP_PDCAP_ENTRY *entry;
  int i;
  int max_multipart;
  int num_entries;
  unsigned char *ptr;
  char results_filename [3072];
  int status;
  char temp_string [1024];


  status = ST_OK;
  strcpy(aux, "\"capabilities\":[");
  if (ctx->verbosity > 3)
  {
    fprintf(ctx->log,
"action_osdp_PDCAP: message data length is %d.\n", msg->data_length);
    fflush(ctx->log);
  };
  num_entries = msg->data_length / 3;
  ptr = msg->data_payload;
  entry = (OSDP_PDCAP_ENTRY *)ptr;
  for (i=0; i<num_entries; i++)
  {
    aux [0] = 0; // null the aux string just in case it gets through
    if (ctx->verbosity > 1)
    {
      // create results json files

      sprintf(results_filename, "%s/results/070-05-%02d-results.json", ctx->service_root, 1+entry->function_code);
      capf = fopen(results_filename, "w");
      fprintf(capf, "{\"test\":\"070-05-%02d\",\"test-status\":\"1\",\"pdcap-function\":\"%d\",\"pdcap-compliance\":\"%d\",\"pdcap-number\":\"%d\"}\n",
        entry->function_code+1, entry->function_code, entry->compliance, entry->number_of);
      fclose(capf);

      sprintf(temp_string, "{\"function\":\"%02x\",\"compliance\":\"%02x\",\"number-of\":\"%02x\"},",
        entry->function_code, entry->compliance, entry->number_of);
      if (ctx->verbosity > 3)
      {
        fprintf(ctx->log, "f %02x c %02x n %02x old len %d.\n",
          entry->function_code, entry->compliance, entry->number_of, (int)strlen(aux));
        fflush(ctx->log);
      };
      strcat(aux, temp_string);
    };

    switch (entry->function_code)
    {
    case OSDP_CAP_AUDIBLE_OUT:
      if (ctx->verbosity > 1)
        fprintf(ctx->log, "PD: Annunciator present. ");

      // here in the ACU record the PD says it has a buzzer
      ctx->configured_sounder = 1; // only one per spec

      switch(entry->compliance)
      {
      case 1:
        {
          if (ctx->verbosity > 1)
            fprintf(ctx->log, "On/Off only.\n");
        };
        break;
      case 2:
        {
          if (ctx->verbosity > 1)
            fprintf(ctx->log, "Timed and On/Off.\n");
        };
        break;
      default:
        {
          if (ctx->verbosity > 1)
            fprintf(ctx->log, "Not defined (%02x %02x)\n",
              entry->compliance, entry->number_of);
        };
        break;
      };
      break;
    case OSDP_CAP_BIOMETRICS:
      ctx->configured_biometrics = 1;
      break;
    case OSDP_CAP_CARD_FORMAT:
      switch(entry->compliance)
      {
      case 1:
        {
          if (ctx->verbosity > 1)
            fprintf(ctx->log, "Card format: Binary.\n");
        };
        break;
      case 2:
        {
          if (ctx->verbosity > 1)
            fprintf(ctx->log, "Card format: BCD.\n");
        };
        break;
      case 3:
        {
          if (ctx->verbosity > 1)
            fprintf(ctx->log, "Card format: Binary or BCD.\n");
        };
        break;
      default:
        {
          if (ctx->verbosity > 1)
            fprintf(ctx->log, "Card format: not defined (%02x %02x)\n",
              entry->compliance, entry->number_of);
        };
        break;
      };
      break;
    case OSDP_CAP_CHECK_CRC:
      if ((entry->compliance EQUALS 0) && (m_check EQUALS OSDP_CRC))
      {
      if (ctx->verbosity > 1)
        fprintf(ctx->log,
"WARNING: Device does not support CRC but CRC configured.\n");
      };
      break;
    case OSDP_CAP_CONTACT_STATUS:
      if (ctx->verbosity > 1)
      fprintf(ctx->log, "Capability not processed in this ACU: Contact Status (%d)\n",
        entry->function_code);
      break;
    case OSDP_CAP_LED_CONTROL:
      if (ctx->verbosity > 9)
        fprintf(ctx->log, "Capability not processed in this ACU: LED Control (%d)\n",
          entry->function_code);
      break;
    case OSDP_CAP_MAX_MULTIPART:
      max_multipart = entry->compliance;
      max_multipart = max_multipart + (256*entry->number_of);
      if (ctx->verbosity > 1)
      fprintf(ctx->log, "PD: largest combined message %d.(0x%x)\n",
        max_multipart, max_multipart);
      break;
    case OSDP_CAP_OUTPUT_CONTROL:
      if (ctx->verbosity > 1)
      fprintf(ctx->log, "Capability not processed in this ACU: Output Control (%d)\n",
        entry->function_code);
      break;
    case OSDP_CAP_READERS:
      if (ctx->verbosity > 1)
      fprintf(ctx->log, "PD: %d. Attached readers (%x)\n", entry->number_of, entry->compliance);
      break;
    case OSDP_CAP_REC_MAX:
      ctx->pd_cap.rec_max = entry->compliance + 256*entry->number_of;
      break;
    case OSDP_CAP_SECURE:
      if (entry->compliance EQUALS 0)
      {
        if (ctx->enable_secure_channel > 0)
      if (ctx->verbosity > 1)
          fprintf(ctx->log, "Secure Channel not supported by PD, disabling (was enabled.)\n");
        ctx->enable_secure_channel = 0;
      };
      break;
    case OSDP_CAP_SMART_CARD:
      if (entry->compliance & 1)
      {
        ctx->pd_cap.smart_card_transparent = 1;
      if (ctx->verbosity > 1)
        fprintf(ctx->log, "PD Supports Transparent Mode\n");
      };
      if (entry->compliance & 2)
      {
        ctx->pd_cap.smart_card_extended_packet_mode = 1;
      if (ctx->verbosity > 1)
        fprintf(ctx->log, "PD Supports Extended Packet Mode\n");
      };
      break;
    case OSDP_CAP_SPE:
      if (ctx->verbosity > 1)
      fprintf(ctx->log, "Capability not processed in this ACU: Secure PIN Entry\n");
      break;
    case OSDP_CAP_TEXT_OUT:
      if (ctx->verbosity > 1)
      fprintf(ctx->log, "Capability not processed in this ACU: Text Output (%d)\n",
        entry->function_code);
      break;
    case OSDP_CAP_TIME_KEEPING:
      if (ctx->verbosity > 1)
      fprintf(ctx->log, "Capability not processed in this ACU: Time Keeping (%d)\n",
        entry->function_code);
      break;
    case OSDP_CAP_VERSION:
      ctx->pd_cap.osdp_version = entry->compliance;
      if (ctx->verbosity > 1)
        fprintf(ctx->log, "PD supports OSDP version %d\n", entry->compliance);
      break;
    default:
      // have to accept this to keep running status = ST_OSDP_UNKNOWN_CAPABILITY;
      if (ctx->verbosity > 1)
        fprintf(ctx->log, "unknown capability: 0x%02x\n", entry->function_code);
      status = ST_OK;
      break;
    };
    entry ++;
  };
      if (ctx->verbosity > 1)
  fprintf(ctx->log, "PD Capabilities response processing complete.\n\n");
  if (ctx->last_command_sent EQUALS OSDP_CAP)
    osdp_test_set_status(OOC_SYMBOL_cmd_cap, OCONFORM_EXERCISED);
  strcat(aux, "{\"function\":\"0\",\"compliance\":\"0\",\"number-of\":\"0\"}],");

  /*
    ACTION SCRIPT ARGS: 1=number of entries
  */
  sprintf(cmd, "%s/run/ACU-actions/osdp_PDCAP %d", ctx->service_root,
    num_entries);
  if (ctx->verbosity > 1)
    system(cmd);

  osdp_test_set_status_ex(OOC_SYMBOL_rep_device_capas, OCONFORM_EXERCISED, aux);
  return(status);

} /* action_osdp_PDCAP */


int
  action_osdp_TEXT
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_TEXT */

  int current_length;
  int status;
  int text_length;
  char tlogmsg  [1024];


  status = ST_OK;
  osdp_test_set_status(OOC_SYMBOL_cmd_text, OCONFORM_EXERCISED);

  memset (ctx->text, 0, sizeof (ctx->text));
  text_length = (unsigned char) *(msg->data_payload+5);
  strncpy (ctx->text, (char *)(msg->data_payload+6), text_length);

  if (ctx->verbosity > 2)
  {
    fprintf (ctx->log, "Text:");
    fprintf (ctx->log,
      " Rdr %x tc %x tsec %x Row %x Col %x Lth %x\n",
      *(msg->data_payload + 0), *(msg->data_payload + 1), *(msg->data_payload + 2),
      *(msg->data_payload + 3), *(msg->data_payload + 4), *(msg->data_payload + 5));
  };

  memset (tlogmsg, 0, sizeof (tlogmsg));
  strncpy (tlogmsg, (char *)(msg->data_payload+6), text_length);
  if (ctx->verbosity > 2)
    fprintf (ctx->log, "Text: %s\n", tlogmsg);

  // we always ack the TEXT command regardless of param errors

  current_length = 0;
  status = send_message_ex (ctx, OSDP_ACK, ctx->pd_address, &current_length, 0, NULL, OSDP_SEC_SCS_16, 0, NULL);
  ctx->pd_acks ++;
  if (ctx->verbosity > 2)
    fprintf (ctx->log, "Responding with OSDP_ACK\n");

  return (status);

} /* action_osdp_TEXT */

