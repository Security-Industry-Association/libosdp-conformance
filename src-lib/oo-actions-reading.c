/*
  oo-actions - open osdp action routines

  (C)Copyright 2017-2024 Smithee Solutions LLC

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


#ifdef NOT_USED
#include <stdio.h>
#include <stdlib.h>


#include <aes.h>


#include <osdp-tls.h>


extern OSDP_INTEROP_ASSESSMENT osdp_conformance;


// used for responses to osdp_POLL

int pending_response_length;
unsigned char pending_response_data [1500];
unsigned char pending_response;
#endif
#include <memory.h>
#include <unistd.h>
#include <open-osdp.h>
#include <osdp_conformance.h>
extern OSDP_PARAMETERS p_card;


int action_osdp_KEYPAD
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_RAW */

        char command [1024];
  int i;
        int kblimit;
  char root [256];
  int status;
        char temp [8];
        char tstring [1024];

  status = ST_OK;
  if (strlen(ctx->service_root) > 256)
    status = -1;
  if (status EQUALS ST_OK)
  {
        tstring[0] = 0;
        kblimit = sizeof(temp);
  strcpy(root, ctx->service_root);
  sprintf(command, "SERVICE_ROOT=%s %s/actions/osdp_KEYPAD %d %d %02X ", 
    root, root,
    *(0+msg->data_payload), *(1+msg->data_payload), *(2+msg->data_payload));

        sprintf (tlogmsg, "Reader: %d. Digits: %d. First Digit: ",
          *(0+msg->data_payload), *(1+msg->data_payload));
        if (msg->data_payload [1] <= sizeof(temp))
          kblimit = msg->data_payload [1];
        
        for (i=0; i<kblimit; i++)
        {
          sprintf(tstring, "%02X", msg->data_payload [2+i]);
          strcat(tlogmsg, tstring);
          strcat(command, tstring);

          memcpy (temp, ctx->last_keyboard_data, 7);
          memcpy (ctx->last_keyboard_data+1, temp, 7);
          ctx->last_keyboard_data [0] = msg->data_payload [2+i];
        };
        fprintf (ctx->log, "PD Keypad Buffer: %s\n", tlogmsg);
        system(command);
        osdp_test_set_status(OOC_SYMBOL_resp_keypad, OCONFORM_EXERCISED);
  };
  return (status);

} /* action_osdp_KEYPAD */


int
  action_osdp_RAW
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_RAW */

  int bits;
  char cmd [16384]; // bigger than hex_details
  OSDP_COMMAND command_for_later;
  char details [1024];
  int display;
  char hex_details [4096];
  char hstr [1024]; // hex string of raw card data payload
  char json_blob [1024];
  unsigned char *raw_data;
  int status;


  status = ST_OK;
  display = 0; // assume encrypted and can't see it.
  details [0] = 0;

  if (ctx->role EQUALS OSDP_ROLE_CP) // check this, should not need to check this here.
  {
    (void)oosdp_make_message (OOSDP_MSG_RAW, tlogmsg, msg);
    fprintf(ctx->log, "%s\n", tlogmsg); fflush(ctx->log); tlogmsg [0] = 0;

    raw_data = msg->data_payload + 4;
    dump_buffer_log(ctx, "osdp_RAW data", msg->data_payload, msg->data_length);
    if (msg->security_block_length > 0)
    {
      fprintf(ctx->log, "  RAW card data contents encrypted.\n");
    };
    if (msg->payload_decrypted)
    {
      fprintf(ctx->log, "  Contents was decrypted.\n");
      display = 1;
    };
    if (msg->security_block_length EQUALS 0)
      display = 1;
    if (display)
    {
      char raw_fmt [1024];
      /*
        this processes an osdp_RAW.  byte 0=rdr, b1=fmt, 2-3 are length (2=lsb)
      */

      strcpy(raw_fmt, "unspecified");
      if (*(msg->data_payload+1) EQUALS 1)
        strcpy(raw_fmt, "P/data/P");
      if (*(msg->data_payload+1) > 1)
        sprintf(raw_fmt, "unknown(%d)", *(msg->data_payload+1));

      fprintf(ctx->log, "Raw data: Format %s (Reader %d) ", raw_fmt, *(msg->data_payload+0));
      bits = *(msg->data_payload+2) + ((*(msg->data_payload+3))<<8);
      ctx->last_raw_read_bits = bits;

      fprintf(ctx->log, "%d. bits: ", bits);
      {
        int i;
        int octets;
        char tstr [32];

        octets = (bits+7)/8;
        if (octets > sizeof (ctx->last_raw_read_data))
          octets = sizeof (ctx->last_raw_read_data);

        hstr[0] = 0;
        for (i=0; i<octets; i++)
        {
          sprintf (tstr, "%02x", *(raw_data+i));
          strcat (hstr, tstr);
        };
        fprintf(ctx->log, "%s\n", hstr);

        memcpy (ctx->last_raw_read_data, raw_data, octets);
      };

      status = oo_write_status (ctx);

      /*
        build up raw details for the results file.
        (yeah I decode it several times.)
      */
      {
        int i;
        char octet [3];

        hex_details [0] = 0;
        strcpy(details, "\"payload\":\"");
        for (i=0; i<msg->data_length; i++)
        {
          sprintf(octet, "%02x", *(msg->data_payload+i));
          strcat(details, octet);
          strcat(hex_details, octet);
        };
        strcat(details, "\",");
      };

      // run the action routine with the bytes,bit count,format, details

      sprintf(json_blob, "{\\\"bits\\\":\\\"%d\\\",\\\"raw\\\":\\\"", bits);
      strcat(json_blob, hstr);
      strcat(json_blob, "\\\"}");
      sprintf(cmd, "SERVICE_ROOT=%s %s/osdp_RAW %s %d %d %s \"%s\"",
        ctx->service_root,
        oo_osdp_root(ctx, OO_DIR_ACTIONS),
        hstr, bits, *(msg->data_payload+1), hex_details, json_blob);
      system(cmd);
    }; // not encrypted

    // I'm the ACU, I got an osdp_RAW, report results and details

    osdp_test_set_status_ex(OOC_SYMBOL_rep_raw, OCONFORM_EXERCISED, details);
  };

  switch(ctx->raw_reaction_command)
  {
  case 0x00:
    // do nothing special
    break;

  default:
    fprintf(ctx->log, "unknown raw_reaction_command %02X\n", ctx->raw_reaction_command);
    ctx->raw_reaction_command = 0;
    break;

  case OSDP_CRAUTH:
    {
      fprintf(ctx->log, "Exercising test 060-25-03");
    };
    break;

  case OSDP_LED:
    // immediately send a LED response (blinking Red perhaps?)
fprintf(stderr, "DEBUG: insert LED red blink here.\n");

    memset(&command_for_later, 0, sizeof(command_for_later));
    command_for_later.command = OSDP_CMDB_LED;
    memcpy(command_for_later.details, ctx->test_details, ctx->test_details_length);
    command_for_later.details_length = ctx->test_details_length;
    ctx->raw_reaction_command = 0;
    status = enqueue_command(ctx, &command_for_later);
    break;

  case OSDP_GENAUTH:
    {
      fprintf(ctx->log, "Exercising test 060-24-03");
    };
    break;
  };

  // if a (react to raw) genauth was requested, enqueue the request

  if (0 EQUALS strcmp (ctx->test_in_progress, "060-24-03"))
  {
    // stick in a poll so the next command is not back to back with the osdp_RAW response

    memset(&command_for_later, 0, sizeof(command_for_later));
    command_for_later.command = OSDP_CMDB_SEND_POLL;
    status = enqueue_command(ctx, &command_for_later);
    memset(&command_for_later, 0, sizeof(command_for_later));
    command_for_later.command = OSDP_CMDB_WITNESS;
    memcpy(command_for_later.details, ctx->test_details, ctx->test_details_length);
    command_for_later.details_length = ctx->test_details_length;
    ctx->test_details_length = 0; // done with it, "clear" the buffer.

    status = enqueue_command(ctx, &command_for_later);

    // say they did this command.  report generator will know this vs. a crauth

    osdp_test_set_status(OOC_SYMBOL_060_24_03, OCONFORM_EXERCISED);
  };

  // if a (react to raw) crauth was requested, enqueue the request

  if (0 EQUALS strcmp (ctx->test_in_progress, "060-25-03"))
  {
fprintf(stderr, "DEBUG: inserted POLL before CRAUTH\n");
    memset(&command_for_later, 0, sizeof(command_for_later));
    command_for_later.command = OSDP_CMDB_SEND_POLL;
    status = enqueue_command(ctx, &command_for_later);
fprintf(stderr, "DEBUG: crauth enqueued\n");
    memset(&command_for_later, 0, sizeof(command_for_later));
    command_for_later.command = OSDP_CMDB_CHALLENGE;
    memcpy(command_for_later.details, ctx->test_details, ctx->test_details_length);
    command_for_later.details_length = ctx->test_details_length;
    ctx->test_details_length = 0; // done with it, "clear" the buffer.

    status = enqueue_command(ctx, &command_for_later);

    // say they did this command.  report generator will know this vs. a crauth

    osdp_test_set_status(OOC_SYMBOL_060_25_03, OCONFORM_EXERCISED);
  };

  // if a genauth-after-raw was requested, do it now.

  if (0 EQUALS strcmp (ctx->test_in_progress, "060-24-02"))
  {
    int current_length;
    unsigned char details [OSDP_OFFICIAL_MSG_MAX];
    int details_length;
    unsigned char payload [OSDP_OFFICIAL_MSG_MAX];
    int payload_length;


    memset(details, 0, sizeof(details));
    details_length = 270; // estimated null payload ... //sizeof(details);
    if (ctx->test_details_length > 0)
    {
      if (ctx->test_details_length < OSDP_OFFICIAL_MSG_MAX)
      {
        memcpy(details, ctx->test_details, ctx->test_details_length);
        details_length = ctx->test_details_length;
        ctx->test_details_length = 0;  // it's been consumed.
      };
    };
    payload_length = sizeof(payload);
    status = oo_build_genauth(ctx, payload, &payload_length, details, details_length);
    if (status EQUALS ST_OK)
    {
      current_length = 0;
      status = send_message_ex
        (ctx, OSDP_GENAUTH, p_card.addr, &current_length, payload_length, payload,
        OSDP_SEC_SCS_17, 0, NULL);
fprintf(stderr, "DEBUG: give GENAUTH a chance...\n"); sleep(5);
    };
  };

  // if a crauth-after-raw was requested, do it now.

  if (0 EQUALS strcmp (ctx->test_in_progress, "060-25-02"))
  {
    int current_length;
    unsigned char details [OSDP_OFFICIAL_MSG_MAX];
    int details_length;
    unsigned char payload [OSDP_OFFICIAL_MSG_MAX];
    int payload_length;

    memset(details, 0, sizeof(details));
    details_length = 270; // estimated null payload ... //sizeof(details);
    if (ctx->test_details_length > 0)
    {
      if (ctx->test_details_length < OSDP_OFFICIAL_MSG_MAX)
      {
        memcpy(details, ctx->test_details, ctx->test_details_length);
        details_length = ctx->test_details_length;
        ctx->test_details_length = 0;  // it's been consumed.
      };
    };

    // build up the payload.  The SDU looks the same for genauth and crauth so
    // we can use the same routine and just send a different command.

    payload_length = sizeof(payload);
    status = oo_build_genauth(ctx, payload, &payload_length, details, details_length);
    if (status EQUALS ST_OK)
    {
      current_length = 0;
      status = send_message_ex
        (ctx, OSDP_CRAUTH, p_card.addr, &current_length, payload_length, payload,
        OSDP_SEC_SCS_17, 0, NULL);
fprintf(stderr, "DEBUG: give CRAUTH a chance...\n"); sleep(5);
    };
  };

  return (status);

} /* action_osdp_RAW */

