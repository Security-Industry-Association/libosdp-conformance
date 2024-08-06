/*
  oo-ui - UI routines for open-osdp

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
extern int pending_response_length;
extern unsigned char pending_response_data [1500];
extern unsigned char pending_response;

char file_transfer_buffer [2048];

unsigned char leftover_command;
unsigned char leftover_data [4*1024];
int leftover_length;
unsigned char leftover_args [1024];


#include <stdio.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>

#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>
#include <iec-xwrite.h>


//extern OSDP_CONTEXT context;
extern OSDP_OUT_CMD current_output_command [];
extern OSDP_BUFFER osdp_buf;
extern OSDP_INTEROP_ASSESSMENT osdp_conformance;
extern OSDP_PARAMETERS p_card;


int
  process_command
  (int command,
  OSDP_CONTEXT *ctx, //context,
  unsigned int details_length,
  int details_param_1,
  char *details)

{ /* process_command */

OSDP_CONTEXT *context; // kludge for old name
  extern unsigned char *creds_buffer_a;
  extern int creds_buffer_a_lth;
  int current_length;
  int processed;
  unsigned char sec_blk [1];
  int status;
  unsigned char value [4];


context=ctx;
  status = ST_CMD_UNKNOWN;
  if (ctx->verbosity > 3)
  {
    fprintf (ctx->log, "process_command: command is %d\n",
      command);
  };
  processed = 0;
  if (command EQUALS OSDP_CMD_NOOP)
  {
    processed = 1;
    status = ST_OK;
  };
  if ((!processed) &&(context->current_menu EQUALS OSDP_MENU_TOP))
  {
    switch (command)
    {
    case OSDP_CMDB_ACURXSIZE:
      {
        int max_size;

        max_size = OSDP_BUF_MAX;
        if (max_size > OSDP_OFFICIAL_MSG_MAX)
          max_size = OSDP_OFFICIAL_MSG_MAX;
        value [0] = 0x00ff & max_size;
        value [1] = (0xff00 & max_size) >> 8;
        current_length = 0;
        status = send_message_ex(context, OSDP_ACURXSIZE, p_card.addr,
          &current_length, 2, value,
          OSDP_SEC_SCS_17, 0, NULL);
      };
      break;

    case OSDP_CMDB_BIOREAD:
      status = send_bio_read_template (ctx, (unsigned char *)details, details_length);
      break;

    case OSDP_CMDB_BIOMATCH:
      status = send_bio_match_template(ctx, (unsigned char *)details, details_length);
      break;

    case OSDP_CMDB_BUSY:
      context->next_response = OSDP_BUSY;
      if (context->verbosity > 2)
        fprintf (stderr, "Declaring BUSY on next response\n");
      status = ST_OK;
      break;

    case OSDP_CMDB_CONFORM_050_06_02:
      status = ST_OK;
      ctx->next_huge = 1;
      if (context->verbosity > 2)
        fprintf (context->log, "Activating oversize response\n");
      break;

    case OSDP_CMDB_CONFORM_060_24_02:
      status = ST_OK;
      strcpy (context->test_in_progress, "060-24-02"); // genauth-after-raw
      context->raw_reaction_command = OSDP_GENAUTH;
      memcpy(context->test_details, details, details_length);
      context->test_details_length = details_length;
      if (context->verbosity > 2)
        fprintf (context->log, "Sending osdp_GENAUTH after next Raw response\n");
      break;

    case OSDP_CMDB_CONFORM_060_24_03:
      status = ST_OK;
      strcpy (context->test_in_progress, "060-24-03"); // crauth enqueue-after-raw
      memcpy(context->test_details, details, details_length);
      context->test_details_length = details_length;
      if (context->verbosity > 2)
        fprintf (context->log, "Enqueuing osdp_GENAUTH after next Raw response\n");
      break;

    case OSDP_CMDB_CONFORM_060_25_02:
      status = ST_OK;
      strcpy (context->test_in_progress, "060-25-02"); // crauth-after-raw
      context->raw_reaction_command = OSDP_CRAUTH;
      memcpy(context->test_details, details, details_length);
      context->test_details_length = details_length;
      if (context->verbosity > 2)
        fprintf (context->log, "Sending osdp_CRAUTH after next Raw response\n");
      break;

    case OSDP_CMDB_CONFORM_060_25_03:
      status = ST_OK;
      strcpy (context->test_in_progress, "060-25-03"); // crauth enqueue-after-raw
      memcpy(context->test_details, details, details_length);
      context->test_details_length = details_length;
      if (context->verbosity > 2)
        fprintf (context->log, "Enqueuing osdp_CRAUTH after next Raw response\n");
      break;

    case OSDP_CMDB_CONFORM_070_17_02:
      if (context->verbosity > 2)
        fprintf(context->log, "Conformance test 070-17-02: next RMAC_I response will report failure.\n");
      context->conformance_fail_next_rmac_i = 1;
      status = ST_OK;
      break;

    case OSDP_CMDB_CONFORM_2_2_1:
      strcpy (context->test_in_progress, "2-2-1");
      status = send_comset (context, OSDP_CONFIGURATION_ADDRESS, p_card.addr, "9600", 0);
      break;

    case OSDP_CMDB_CONFORM_2_2_2:
      strcpy (context->test_in_progress, "2-2-2");
      status = send_comset (context, OSDP_CONFIGURATION_ADDRESS, p_card.addr, "19200", 0);
      break;

    case OSDP_CMDB_CONFORM_2_2_3:
      strcpy (context->test_in_progress, "2-2-3");
      status = send_comset (context, OSDP_CONFIGURATION_ADDRESS, p_card.addr, "38400", 0);
      break;

    case OSDP_CMDB_CONFORM_2_2_4:
      strcpy (context->test_in_progress, "2-2-4");
      status = send_comset (context, OSDP_CONFIGURATION_ADDRESS, p_card.addr, "115200", 0);
      break;

    case OSDP_CMDB_CONFORM_2_6_1:
      {
        OSDP_TEXT_HEADER
          otxt;

        otxt.reader = 0;
        otxt.tc = 2;
        otxt.tsec = 0;
        otxt.row = 1;
        otxt.col = 1;
        otxt.length = strlen (context->text);
        memcpy (otxt.text, context->text, 1024);
        current_length = 0;
        status = send_message_ex(context, OSDP_TEXT, p_card.addr,
          &current_length, 
          sizeof(otxt)-sizeof(otxt.text) + strlen(otxt.text),
          (unsigned char *)&otxt,
          OSDP_SEC_SCS_17, 0, NULL);
        status = ST_OK;
      };
      break;

    case OSDP_CMDB_CONFORM_2_11_3:

      // request ID but do it on the "all stations" PD address.

      {
        unsigned char param [1];

fprintf(context->log, "*** DEPRECATED COMMAND use ident,config-address=1 instead.\n");

        strcpy (context->test_in_progress, "2_11_3");
        param [0] = 0;
        current_length = 0;
        status = send_message_ex (context, OSDP_ID, 0x7F,
          &current_length, sizeof (param), param,
          OSDP_SEC_SCS_17, 0, NULL);
        status = ST_OK;
      };
      break;

    case OSDP_CMDB_CONFORM_2_14_3:
      strcpy (context->test_in_progress, "2_14_3");
      current_length = 0;

      // no security block for an SCS_17

      status = send_secure_message(context, OSDP_POLL, p_card.addr,
        &current_length, 0, NULL, OSDP_SEC_SCS_17, 0, sec_blk);

      if (status EQUALS ST_OK)
        SET_PASS (context, "2-14-3");
      status = ST_OK;
      break;

    case OSDP_CMDB_CONFORM_3_20_1:
      {
        OSDP_MFG_COMMAND omfg;

        strcpy (context->test_in_progress, "3_20_1");
        // send the tester's vendor code
        omfg.vendor_code [0] = context->vendor_code [0];
        omfg.vendor_code [1] = context->vendor_code [1];
        omfg.vendor_code [2] = context->vendor_code [2];
        omfg.mfg_command_id = 1;
        omfg.data = 0xff;
        current_length = 0;
        status = send_message_ex(context, OSDP_MFG, p_card.addr,
          &current_length, sizeof(omfg), (unsigned char *)&omfg,
          OSDP_SEC_SCS_17, 0, NULL);
        if (status EQUALS ST_OK)
          SET_PASS (context, "3-20-1");
        status = ST_OK;
      };
      break;

    case OSDP_CMDB_CHALLENGE:
    case OSDP_CMDB_WITNESS:
      {
        unsigned char challenge_command [OSDP_OFFICIAL_MSG_MAX];
        int challenge_payload_size;
        unsigned char osdp_command;

        status = ST_OK;
        if (ctx->verbosity > 3)
        {
          fprintf(ctx->log, "osdp_GENAUTH processing started.  Challenge size %d.\n", details_length);
        };
        if (ctx->m_check != OSDP_CRC)
          status = ST_OSDP_CRC_REQUIRED;
        if (status EQUALS ST_OK)
        {
          osdp_command = OSDP_GENAUTH;
          challenge_payload_size = sizeof(challenge_command);
          strcpy (context->test_in_progress, "x-challenge");
          memset (&challenge_command, 0, sizeof (challenge_command));

          status = oo_build_genauth(ctx, (unsigned char *)challenge_command, &challenge_payload_size,
            (unsigned char *)details, details_length);
          if (ctx->verbosity > 3)
          {
            fprintf(ctx->log, "  cmd %02X challenge payload size %d. (status from oo_build_genauth %d.)\n",
              osdp_command, challenge_payload_size, status);
          };
          if (command EQUALS OSDP_CMDB_CHALLENGE)
            osdp_command = OSDP_CRAUTH;
        current_length = 0;
        status = send_message_ex(context, osdp_command, p_card.addr,
          &current_length, challenge_payload_size, challenge_command, OSDP_SEC_SCS_17, 0, NULL);

// if it was a witness, sleep a while in case it takes a while for the ACK to get back.
if (command EQUALS OSDP_CMDB_WITNESS)
{
  fprintf(stderr, "DEBUG: sleep after GENAUTH send\n");
  sleep(5);
}
        };
      };
      break;

    /*
      Induce a NAK.  To test an ACU send a garbage command.  To test a PD, NAK the next
      command that comes in the door.
    */
    case OSDP_CMDB_INDUCE_NAK:
      {
        unsigned char nothing;

        if (context ->role EQUALS OSDP_ROLE_ACU)
        {
          strcpy (context->test_in_progress, "induce-NAK");
          current_length = 0;
          status = send_message (context,
            OSDP_UNDEF, p_card.addr, &current_length, 0, &nothing);
        }
        else
        {
          // we're the PD.  nak the next command.
          // 0x030000 for default; 0x010000 for reason specified; 0x020000 for reason+detail specified

          // third byte is 0x03 if using defaults
          // third byte is 0x01 if using just a reason
          // third byte is 0x02 if using reason and detail

          ctx->next_nak = 0x030000;
          if (details [2] EQUALS 1)
            ctx->next_nak = 0x010000 | details [0];
          if (details [2] EQUALS 2)
          {
            int octet;

            octet = details [1];
            octet = octet * 256;
            ctx->next_nak = 0x020000 | details [0];
            ctx->next_nak = ctx->next_nak | octet;
          };
          status = ST_OK;
        };
      };
      break;

    case OSDP_CMDB_INPUT_STATUS:
      context->next_istatr = 1;
      status = ST_OK;
      break;

    case OSDP_CMDB_KEYSET:
      {
        unsigned char key_buffer [2+OSDP_KEY_OCTETS];
        unsigned short int keybuflth;


        keybuflth = sizeof(key_buffer) - 2;
        status = osdp_string_to_buffer(context,
          details, key_buffer+2, &keybuflth);
        key_buffer [0] = 1; // SCBK
        key_buffer [1] = OSDP_KEY_OCTETS;

        keybuflth = sizeof(key_buffer);
        current_length = 0;
if(1)//        if (context->verbosity > 3)
        {
          dump_buffer_log(context, "KEYSET key:", key_buffer, keybuflth);
        };
        status = send_message_ex(context, OSDP_KEYSET, p_card.addr,
          &current_length, keybuflth, key_buffer,
          OSDP_SEC_SCS_17, 0, NULL);
fprintf(stderr, "DEBUG: send keyset status %d cl %d sleep 1\n",
  status, current_length);
sleep(1);

        // load it to prepare for use, and save it.
//        memcpy(context->current_scbk, key_buffer+2, sizeof(context->current_scbk));
        oo_save_parameters(context, OSDP_SAVED_PARAMETERS, key_buffer+2);
      };
      break;

    case OSDP_CMDB_MFG:
      {
        unsigned char data [1024];
        int i;
        int idx;
        OSDP_MFG_ARGS *oargs;
        OSDP_MFG_COMMAND *omfg;
        int out_idx;
        int send_length;
        char tmps [3];

        oargs = (OSDP_MFG_ARGS *)details;
        context->left_to_send_destination = p_card.addr;
        omfg = (OSDP_MFG_COMMAND *)data;
        if (details_param_1 EQUALS OSDP_CONFIGURATION_ADDRESS)
          context->left_to_send_destination = OSDP_CONFIGURATION_ADDRESS;
        tmps[2] = 0;
        memcpy(tmps, oargs->oui+0, 2);
        sscanf(tmps, "%x", &i);
        omfg->vendor_code [0] = i;
        memcpy(tmps, oargs->oui+2, 2);
        sscanf(tmps, "%x", &i);
        omfg->vendor_code [1] = i;
        memcpy(tmps, oargs->oui+4, 2);
        sscanf(tmps, "%x", &i);
        omfg->vendor_code [2] = i;
        omfg->mfg_command_id = oargs->command_ID;
        send_length = sizeof(OSDP_MFG_COMMAND) - 1;
        out_idx = 0;
        for (idx=0; idx<strlen(oargs->c_s_d); idx=idx+2)
        {
          tmps[2] = 0;
          memcpy(tmps, (idx)+(oargs->c_s_d), 2);
          sscanf(tmps, "%x", &i);
          *(&(omfg->data)+out_idx) = i;
          out_idx ++;
          send_length ++;
        };

        if (osdp_awaiting_response(context))
        {
          fprintf(stderr, "busy before OSDP_MFG, skipping send\n");
          fflush(stderr); fflush(context->log);
fprintf(stderr, "287 busy, enqueing %02x d %02x-%02x-%02x L %d.\n",
  OSDP_MFG, data [0], data [1], data [2], send_length);

          leftover_command = OSDP_MFG;
          memcpy(leftover_data, data, send_length);
          leftover_length = send_length;
          context->left_to_send = leftover_length;

          memcpy(leftover_args, oargs, 1024); // kludge copy just the first 1k
        }
        else
        {
          current_length = 0;
          status = send_message_ex(context, OSDP_MFG, context->left_to_send_destination, &current_length, send_length, data,
          OSDP_SEC_SCS_17, 0, NULL);
        };
        status = ST_OK;
      };
      break;

    case OSDP_CMDB_MFGREP:
    {
      unsigned char data [1024];
      int i;
      int idx;
      OSDP_MFG_ARGS *oargs;
      OSDP_MFG_COMMAND *omfg;
      int out_idx;
      int send_length;
      char tmps [3];

      oargs = (OSDP_MFG_ARGS *)details;
      omfg = (OSDP_MFG_COMMAND *)data;
      tmps[2] = 0;
      memcpy(tmps, oargs->oui+0, 2);
      sscanf(tmps, "%x", &i);
      omfg->vendor_code [0] = i;
      memcpy(tmps, oargs->oui+2, 2);
      sscanf(tmps, "%x", &i);
      omfg->vendor_code [1] = i;
      memcpy(tmps, oargs->oui+4, 2);
      sscanf(tmps, "%x", &i);
      omfg->vendor_code [2] = i;
      omfg->mfg_command_id = oargs->command_ID;
      send_length = sizeof(OSDP_MFG_COMMAND) - 1;
      out_idx = 0;
      for (idx=0; idx<strlen(oargs->c_s_d); idx=idx+2)
      {
        tmps[2] = 0;
        memcpy(tmps, (idx)+(oargs->c_s_d), 2);
        sscanf(tmps, "%x", &i);
        *(&(omfg->data)+out_idx) = i;
        out_idx ++;
        send_length ++;
      };

      pending_response_length = send_length;
      memcpy(pending_response_data, data, pending_response_length);
      pending_response = OSDP_MFGREP;

      status = ST_OK;
    };




    break;

    case OSDP_CMDB_ONDEMAND_LSTATR:
      context->next_response = OSDP_LSTATR;
      if (context->verbosity > 2)
        fprintf (stderr, "Declaring LSTATR on next response\n");
      status = ST_OK;
      break;

      break;

    case OSDP_CMDB_PIVDATA:
      {
        unsigned char pivdata_buffer [OSDP_OFFICIAL_MSG_MAX];

        memcpy(pivdata_buffer, details, 6);
        dump_buffer_log(context, "PIVDATA object,element,offset:", pivdata_buffer, 6);
        current_length = 0;
        status = send_message_ex(context, OSDP_PIVDATA, p_card.addr,
          &current_length, 6, pivdata_buffer,
          OSDP_SEC_SCS_17, 0, NULL);
      };
      break;

    case OSDP_CMDB_SEND_EXPLICIT:
      osdp_trace_dump(context, 0);
      if (details_param_1 > 0)
      {
        current_length = 0;
        status = send_message_ex(context, details[0], p_card.addr,
          &current_length, details_length, (unsigned char *)(details+1),
          OSDP_SEC_SCS_17, 0, NULL);
      }
      else
      {
        if (ctx->last_was_processed)
        {
          // really raw

          ctx->last_was_processed = 0;
          status = send_osdp_data (ctx, (unsigned char *)details, details_length);
        }
        else
        {
          OSDP_COMMAND repeated_command;
          memset(&repeated_command, 0, sizeof(repeated_command));
          repeated_command.command = OSDP_CMDB_SEND_EXPLICIT;
          repeated_command.details_param_1 = details_param_1;
          repeated_command.details_length = details_length;
          memcpy(repeated_command.details, details, details_length);
          status = enqueue_command(ctx, &repeated_command);
        };
      };
      break;

    case OSDP_CMDB_STOP:
      fprintf (context->log, "STOP command received.  Terminating now.\n");
      fflush(context->log);
      exit (0);
      break;

    case OSDP_CMDB_TRANSFER:
      status = oo_filetransfer_initiate(context, details);
      break;

    case OSDP_CMDB_XWRITE:
      {
        int payload_length;

        payload_length = *(short int *)(details+1);
        if (context->verbosity > 3)
          fprintf(context->log,
            "Extended Write, action %d. payload is %d. bytes\n",
            details [0], payload_length);

        // details [0] is the action.  1=get-mode

        switch(details[0])
        {
        default:
          // only squawk on commands, don't report bad status.

          fprintf(context->log, "Unknown xwrite action %d.\n", details[0]);
          break;
        case 1: // get-mode
          status = osdp_xwrite_get_mode(context);
          break;
        case 2: // set-mode
          status = osdp_xwrite_set_mode(context, 1); // 1 for mode 1
          break;
        case 3: // scan
          status = osdp_xwrite_mode1
            (context, OSDP_XWR_1_SMART_CARD_SCAN, NULL, 0);
          break;
        case 4: // set-mode-zero set mode to 0
          status = osdp_xwrite_set_mode(context, 0);
          break;
        case 5: // (done) stop smart card reading
          status = osdp_xwrite_mode1
            (context, OSDP_XWR_1_DONE, NULL, 0);
          break;
        case 6: // send APDU to card
          status = osdp_xwrite_mode1
            (context, OSDP_XWR_1_APDU, (unsigned char *)(details+3),
            payload_length);
          break;
        };
      };
      break;

    case OSDP_CMDB_BUZZ:
      {
        unsigned char
          buzzer_control [5];

        if (context->configured_sounder EQUALS 0)
        {
          fprintf(context->log, "PD reports no sounder capability, skipping osdp_BUZ command\n");
        }
        else
        {
        memset (&buzzer_control, 0, sizeof (buzzer_control));
        /*
          assume reader 0.
          assume "standard" tone.
        */
        buzzer_control [0] = 0;
        buzzer_control [1] = 2;  // default tone
        buzzer_control [2] = details [0]; // 15x100 ms on
        buzzer_control [3] = details [1]; // 15x100 ms off
        buzzer_control [4] = details [2];  // repeat 3 times
        if (context->verbosity > 3)
          fprintf (context->log,
"Requesting Buzz: tone %d on %d(x100ms) off %d(x100ms) repeat %d\n",
            buzzer_control [1], buzzer_control [2],
            buzzer_control [3], buzzer_control [4]);
        current_length = 0;
        status = send_message_ex (context, OSDP_BUZ, p_card.addr,
          &current_length, sizeof (buzzer_control), (unsigned char *)&buzzer_control,
          OSDP_SEC_SCS_17, 0, NULL);
        };
      };
      break;

    case OSDP_CMDB_CAPAS:
      {
        unsigned char
          param [1];

        current_length = 0;
        param [0] = 0;
        if (details [0] EQUALS 1)
        {
          status = send_message_ex (context, OSDP_CAP, p_card.addr, &current_length, sizeof (param), param, OSDP_SEC_STAND_DOWN, 0, NULL);
        }
        else
        {
          status = send_message_ex (context, OSDP_CAP, p_card.addr, &current_length, sizeof (param), param, OSDP_SEC_SCS_17, 0, NULL);
        };
        if (context->verbosity > 2)
          fprintf (context->log, "Requesting Capabilities Report\n");
      };
      status = ST_OK;
      break;

    case OSDP_CMDB_COMSET:
      {
        int dest_address;
        int new_speed;


        /*
            details [0] is the new address
            details [1] is 1 if to send in the clear during a secure channel session (else 0)
                           0x81 to send in the clear and on sequence 0
            details [2] is 1 if you are to send as the current address (else send to config address)
            details [4..7] are the new speed


        */
        new_speed = 0;
        dest_address = OSDP_CONFIGURATION_ADDRESS;
        if (details [2])
          dest_address = p_card.addr;
        if (details [1] & 0x80)
          context->next_sequence = 0;
  
        memcpy (&new_speed, details+4, 4);
        sprintf (context->serial_speed, "%d", new_speed);
        context->new_address = details [0];
        osdp_test_set_status(OOC_SYMBOL_cmd_comset, OCONFORM_EXERCISED);
        if (context->verbosity > 2)
          fprintf (ctx->log, "Set Comms: addr to %02x speed to %s.\n",
            context->new_address, context->serial_speed);
        status = send_comset (context, dest_address, context->new_address, context->serial_speed, 0x01 && (details [1]));

        // reset protocol to beginning

        context->next_sequence = 0;
        context->last_response_received = 0;
      };
      status = ST_OK;
      break;

    case OSDP_CMDB_DUMP_STATUS:
      status = oo_write_status (context);

      dump_conformance (context, &osdp_conformance);
      status = ST_OK;
      break;

    // send osdp_ID
    // if details_param_1 is 0x7F then use the config address else use the current configured address.

    case OSDP_CMDB_IDENT:
      {
        int dest_address;
        unsigned char param [1];

        fprintf(ctx->log, "Identify requested\n");

        if (details_param_1 EQUALS 0x7F)
          dest_address = 0x7F;

        current_length = 0;
        /*
          osdp_ID takes one argment, a one byte value of 0 indicating
          "send Standard PD ID Block"
        */
        param [0] = 0;
        current_length = 0;
        if (osdp_awaiting_response(context))
        {
          fprintf(context->log, "Transmitter busy before OSDP_ID, skipping send\n");
          fflush(context->log);
          leftover_command = OSDP_ID;
          context->left_to_send_destination = dest_address;
          memcpy(leftover_data, param, sizeof(param));
          leftover_length = sizeof(param);
          context->left_to_send = leftover_length;
        }
        else
        {
          if (context->verbosity > 3)
          {
            fprintf(context->log, "    osdp_ID, L=%u V=%02x CLEAR=%d\n",
              (unsigned)sizeof(param), param [0], details [0]);
          };
          dest_address = p_card.addr;
          if (details_param_1 EQUALS 0x7F)
            dest_address = 0x7F;

          // if new sequence was requested start at zero again
          if (details [1] EQUALS 1)
            context->next_sequence = 0;

          // if cleartext was requested just send it in the clear
          if (details [0] EQUALS 1)
          {
            status = send_message_ex (context, OSDP_ID, dest_address,
              &current_length, sizeof (param), param,
              OSDP_SEC_STAND_DOWN, 0, NULL);
          }
          else
          {
            status = send_message_ex (context, OSDP_ID, dest_address,
              &current_length, sizeof (param), param,
              OSDP_SEC_SCS_17, 0, NULL);
          };
        };
      };
      status = ST_OK;
      break;

    case OSDP_CMDB_INIT_SECURE:
      {
        unsigned char sec_blk_1 [1];

        if (context->verbosity > 3)
        {
          fprintf(context->log, "Initiating secure channel.\n");
        };
        status = ST_OK;
        current_length = 0;
        context->secure_channel_use [OO_SCU_ENAB] = OO_SCS_USE_ENABLED;

        // if they specified key slot 1 use the specified key otherwise use
        // the default key.
        if (details_param_1 EQUALS 1)
          context->enable_secure_channel = 1;

        // if default enabled use SCBK-D
        // if not default if key pre-loaded use that else error
        if (context->enable_secure_channel EQUALS 0)
        {
          status = ST_OSDP_SECURE_NOT_ENABLED;
          fprintf(context->log, "Secure Channel not enabled.\n");
        };
        if (status EQUALS ST_OK)
        {
          if (context->enable_secure_channel EQUALS 2)
          {
            sec_blk_1 [0] = OSDP_KEY_SCBK_D;
          }
          else
          {
            sec_blk_1 [0] = OSDP_KEY_SCBK;
          };
        };
        if (status EQUALS ST_OK)
        {
          // clear and initialize secure channel details

          osdp_reset_secure_channel (context);
          status = osdp_setup_scbk (context, NULL);
          if (status EQUALS ST_OK)
            osdp_create_keys (context);

          if (status EQUALS ST_OK)
          {
if (ctx->verbosity > 3)
  fprintf(ctx->log, "about to send CHLNG\n");

            status = send_secure_message (context,
              OSDP_CHLNG, p_card.addr, &current_length, 
              sizeof (context->rnd_a), context->rnd_a,
              OSDP_SEC_SCS_11, sizeof (sec_blk_1), sec_blk_1);
          };
        };
      };
      if (context->verbosity > 3)
      {
        fprintf(context->log, "Initiation of secure channel complete (status=%d.)\n",
          status);
      };
      break;

    case OSDP_CMDB_ISTAT:
      {
        current_length = 0;
        /*
          osdp_ISTAT requires no arguments.
        */
        current_length = 0;

        if (osdp_awaiting_response(context))
        {
          fprintf(stderr, "busy before OSDP_ID, skipping send\n");
          fflush(stderr); fflush(context->log);
        }
        else
        {
          status = send_message_ex (context, OSDP_ISTAT, p_card.addr,
            &current_length, 0, NULL,
            OSDP_SEC_SCS_15, 0, NULL);
          if (context->verbosity > 3)
            fprintf (context->log, "Requesting Input Status\n");
        };
      };
      status = ST_OK;
      break;

    case OSDP_CMDB_KEEPACTIVE:
      // details is the time, lsb/msb
      {
        char keepactive_time [2];

        memcpy(keepactive_time, details, 2);
        current_length = 0;
        status = send_message_ex (context, OSDP_KEEPACTIVE, p_card.addr,
            &current_length, 0, NULL, OSDP_SEC_SCS_15, 0, NULL);
      };
      break;

    case OSDP_CMDB_KEYPAD:
      {
        char keypad_message [1+1+9+1]; // built for 9 digits
        int i;

        memset (&keypad_message, 0, sizeof (keypad_message));
        /*
          assume reader 0
        */
        keypad_message [0] = 0;
        strcpy (keypad_message+2, details); // made to be 9 or less by input mechanism
        keypad_message [1] = strlen (keypad_message+2);

        // map the characters
        for (i=0; i<keypad_message [1]; i++)
        {
          if ((keypad_message [2+i] >= '0') && (keypad_message [2+i] <= '9'))
          {
            if (ctx->verbosity > 3)
              fprintf(ctx->log, "PD Sending keypad: char %d is 0x%02X\n", i, (unsigned int)(keypad_message [2+i]));
          }
          else
          {
            if (keypad_message [2+i] EQUALS '#') keypad_message [2+i] = 0x0d;
            else
              if (keypad_message [2+i] EQUALS '*') keypad_message [2+i] = 0x7f;
              else
                keypad_message [2+i] = 0x7f;

            if (ctx->verbosity > 3)
              fprintf(ctx->log, "PD Sending keypad: char %d mapped to 0x%02X\n", i, keypad_message [2+i]);
          }
        };

        pending_response_length = 2 + strlen(details);
        memcpy(pending_response_data, keypad_message, pending_response_length);
        pending_response = OSDP_KEYPAD;

        if (context->verbosity > 3)
          fprintf (stderr, "Sending keypad response %s\n",
            keypad_message+2);
        osdp_test_set_status(OOC_SYMBOL_resp_keypad, OCONFORM_EXERCISED);
        status = ST_OK;
      };
      break;

    case OSDP_CMDB_LED:
      {
        int details_length;
        unsigned char error_details [1024];
        OSDP_RDR_LED_CTL
          led_control_message;

        memcpy (&led_control_message, details, sizeof (led_control_message));

        details_length = sizeof (error_details);
        status = osdp_validate_led_values (&led_control_message,
          error_details, &details_length);
        if (status EQUALS ST_OK)
        {
          if (osdp_awaiting_response(context))
          {
            fprintf(stderr, "busy before OSDP_LED, skipping send\n");
            fflush(stderr); fflush(context->log);

            leftover_command = OSDP_LED;
            leftover_length = sizeof(led_control_message);
            memcpy(leftover_data, &led_control_message, leftover_length);
            context->left_to_send = leftover_length;
          }
          else
          {
            current_length = 0;
            status = send_message_ex (context, OSDP_LED, p_card.addr,
              &current_length, sizeof (led_control_message), (unsigned char *)&led_control_message,
              OSDP_SEC_SCS_17, 0, NULL);
            memcpy(context->test_details, (char *)&led_control_message, sizeof(led_control_message));
            context->test_details_length = sizeof(led_control_message);
          };
        }
        else
        {
          int nak_length;
          unsigned char osdp_nak_response_data [1024];

          current_length = 0;
          osdp_nak_response_data [0] = OO_NAK_CMD_UNABLE;
          osdp_nak_response_data [1] = error_details [0]; // temp error
          osdp_nak_response_data [2] = error_details [1]; // perm error
          nak_length = 3;
          status = send_message (context,
            OSDP_NAK, p_card.addr, &current_length, nak_length,
            osdp_nak_response_data);
          context->sent_naks ++;
        };
      };
      break;

    case OSDP_CMDB_LSTAT:
      {
        current_length = 0;
        /*
          osdp_LSTAT requires no arguments.
        */
        current_length = 0;

        status = send_message_ex (context, OSDP_LSTAT, p_card.addr,
          &current_length, 0, NULL, OSDP_SEC_SCS_15, 0, NULL);
      };
      status = ST_OK;
      break;

    case OSDP_CMDB_OSTAT:
      {
        current_length = 0;
        /*
          osdp_OSTAT requires no arguments.
        */
        current_length = 0;
        status = send_message_ex (context,
          OSDP_OSTAT, p_card.addr, &current_length, 0, NULL, OSDP_SEC_SCS_15, 0, NULL);
        if (context->verbosity > 3)
          fprintf (context->log, "Requesting Output Status\n");
      };
      status = ST_OK;
      break;

    case OSDP_CMDB_OUT:
      {
        int i;
        OSDP_OUT_MSG osdp_out_msg [16];
        int out_lth;

        out_lth = 0;
        current_length = 0;
        if (context->verbosity > 3)
          fprintf(context->log, "OUT command: %d first output number %d.\n", details_param_1,
            current_output_command [0].output_number);
        if (details_param_1 > 0)
        {
          for (i=0; i<details_param_1; i++)
          {
            osdp_out_msg [i].output_number = details [0+4*i];
            osdp_out_msg [i].control_code = details [1+4*i];
            osdp_out_msg [i].timer_lsb = details [2+4*i];
            osdp_out_msg [i].timer_msb = details [3+4*i];
            out_lth = out_lth + sizeof (osdp_out_msg [0]);
          };
        };
// details_param_1 is number of items
// for i 0 to details_param_1 copy 3 bytes into output number, control_code, timer_msb, timer_lsb
// out_lth is details_param_1 times sizeof(OSDP_OUT_MSG);
        if (details_param_1 EQUALS 0)
        {
          osdp_out_msg [0].output_number = current_output_command [0].output_number;
          osdp_out_msg [0].control_code = current_output_command [0].control_code;
          osdp_out_msg [0].timer_lsb = current_output_command [0].timer & 0xff;
          osdp_out_msg [0].timer_msb = (current_output_command [0].timer > 8) & 0xff;
          out_lth = sizeof (osdp_out_msg [0]);
        };
        status = send_message_ex (context,
          OSDP_OUT, p_card.addr, &current_length,
          out_lth, (unsigned char *)osdp_out_msg, OSDP_SEC_SCS_17, 0, NULL);
        status = ST_OK;
      };
      break;

    case OSDP_CMDB_PRESENT_CARD:
      /*
        use card data from loaded config if no details were provided
      */
      if (details_length > 0)
      {
        context->card_data_valid = details_param_1;
        context->creds_a_avail = details_length;
        memcpy(context->credentials_data, details, details_length);
      }
      else
      {
        context->card_data_valid = p_card.bits;
        context->creds_a_avail = creds_buffer_a_lth;
        memcpy(context->credentials_data, creds_buffer_a, context->creds_a_avail);
      };
      if (context->verbosity > 2)
        fprintf (context->log, "Presenting card data (raw: %d, Creds A: %d)\n",
          context->card_data_valid, context->creds_a_avail);
      status = ST_OK;
      break;

    case OSDP_CMDB_RESET_POWER:
      context->power_report = 1;
      status = ST_OK;
      break;

    case OSDP_CMDB_RSTAT:
      status = ST_OK;
      current_length = 0;
      status = send_message_ex (context,
        OSDP_RSTAT, p_card.addr, &current_length, 0, NULL, OSDP_SEC_SCS_15, 0, NULL);
      if (context->verbosity > 2)
        fprintf (context->log, "Requesting (External) Reader (Tamper) Status\n");
      break;

    case OSDP_CMDB_SEND_POLL:
      current_length = 0;
      status = send_message (context,
        OSDP_POLL, p_card.addr, &current_length, 0, NULL);
      if (context->verbosity > 3)
        fprintf (stderr, "On-demand polling\n");
      status = ST_OK;
      break;

    case OSDP_CMDB_TAMPER:
      context->tamper = 1;
      status = ST_OK;
      break;

    case OSDP_CMDB_TEXT:
      {
        OSDP_TEXT_HEADER otxt;

        // "command":"text","reader":"0","text-command":"2","row":1","column":1","text":"this is a test"
        memset(&otxt, 0, sizeof(otxt));
        otxt.reader = details [0];
        otxt.tc = details [1];
        otxt.tsec = details [2];;
        otxt.row = details [3];
        otxt.col = details [4];
        otxt.length = strlen(&(details [5]));
        strcpy(otxt.text, &(details [5]));
        current_length = 0;
        status = send_message_ex(context, OSDP_TEXT, p_card.addr,
          &current_length, 
          sizeof(otxt)-sizeof(otxt.text) + strlen(otxt.text),
          (unsigned char *)&otxt,
          OSDP_SEC_SCS_17, 0, NULL);
      };
      break;

    default:
      status = ST_CMD_UNKNOWN;
      break;
    };
  };
  return (status);

} /* process_command */

