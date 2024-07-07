/*
  oo-util - open osdp utility routines

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


#include <stdio.h>
#include <memory.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>


#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>
#include <iec-xwrite.h>


extern OSDP_CONTEXT context;
extern OSDP_INTEROP_ASSESSMENT osdp_conformance;
extern OSDP_PARAMETERS p_card;
extern OSDP_BUFFER osdp_buf;
extern char trace_in_buffer [];


int
  process_osdp_message
    (OSDP_CONTEXT *context,
     OSDP_MSG *msg)

{ /* process_osdp_message */

  char cmd [3*1024];
  int count;
  int current_length;
  int current_security;
  char details [1024];
  int i;
  char logmsg [1024];
  char nak_code;
  char nak_data;
  int nak_length;
  int new_speed;
  unsigned char osdp_nak_response_data [2];
  OSDP_HDR *oh;
  int oo_osdp_max_packet;
  int status;
  unsigned char this_command;
  char tlog2 [1024];
  char tlogmsg [1024];
  extern unsigned int web_color_lookup [];


  status = ST_MSG_UNKNOWN;
  oo_osdp_max_packet = 768; // less than the 1K in some of the buffer routines
  context->capability_max_packet = oo_osdp_max_packet;
  oh = (OSDP_HDR *)(msg->ptr);
  if (context -> role EQUALS OSDP_ROLE_PD)
  {
    if (context->verbosity > 9)
    {
      fprintf (context->log, "PD: command %02x\n",
        context->role);
    };

    // if it's for me check the squence

    if (oh->addr EQUALS p_card.addr)
    {
      if ((oh->ctrl & 0x03) EQUALS 0)
      {
        if (context->verbosity > 3)
          fprintf (context->log, "  ACU sent sequence 0 - resetting sequence numbers\n");
        context->next_sequence = 0;
        osdp_reset_secure_channel(context);
      };
    };

    // if they asked for a NAK mangle the command so we hit the default case of the switch

    this_command = msg->msg_cmd;
    if (context->next_nak)
    {
      this_command = OSDP_BOGUS;
      // next_nak is reset at the processing of command OSDP_BOGUS
    };
    if (oh->addr EQUALS OSDP_CONFIGURATION_ADDRESS)
    {
      if ((this_command != OSDP_ID) && (this_command != OSDP_CAP) && (this_command != OSDP_COMSET))
      {
        this_command = OSDP_ILLICIT;
      };
    };

    // update count of whole messages
    context->pdus_received ++;
//TODO pdus_received v.s packets_received

//(void)monitor_osdp_message (context, msg);

  if (context -> role EQUALS OSDP_ROLE_MONITOR)
    (void)monitor_osdp_message (context, msg);
  else
  {
    // if it's for me or it's a broadcast command then trace it

    if (!(0x80 & oh->addr)) // it's a command
    {
      if ((oh->addr EQUALS p_card.addr)  || // it's for me
        (oh->addr EQUALS OSDP_CONFIGURATION_ADDRESS)) // it's a configuration command
      {
        (void)monitor_osdp_message (context, msg);
      }
    };
  };

    switch (this_command)
    {
    case OSDP_ACURXSIZE:
      context->max_acu_receive = 
        (*(msg->data_payload + 1) * 256) + *(msg->data_payload + 0);

      sprintf (logmsg, "  ACU Receive Buffer %d. bytes\n",
        context->max_acu_receive);
      fprintf (context->log, "%s", logmsg);
      logmsg[0]=0;
      osdp_test_set_status(OOC_SYMBOL_cmd_acurxsize, OCONFORM_EXERCISED);
      current_length = 0;
      current_security = OSDP_SEC_SCS_16;
      status = send_message_ex(context, OSDP_ACK, p_card.addr,
        &current_length, 0, NULL, current_security, 0, NULL);
      context->pd_acks ++;
      break;

    case OSDP_BIOMATCH:
      status = action_osdp_BIOMATCH(context, msg);
      break;

    case OSDP_BIOREAD:
      status = action_osdp_BIOREAD(context, msg);
      break;

    case OSDP_BUZ:
      if (context->configured_sounder)
      {
        sprintf (logmsg, "BUZZER %02x %02x %02x %02x %02x\n",
          *(msg->data_payload + 0), *(msg->data_payload + 1),
          *(msg->data_payload + 2), *(msg->data_payload + 3),
          *(msg->data_payload + 4));
        if (context->verbosity > 3)
          fprintf (context->log, "%s", logmsg);
        logmsg[0]=0;
      osdp_test_set_status(OOC_SYMBOL_cmd_buz, OCONFORM_EXERCISED);
      current_length = 0;
      current_security = OSDP_SEC_SCS_16;
      status = send_message_ex(context, OSDP_ACK, p_card.addr,
        &current_length, 0, NULL, current_security, 0, NULL);
      context->pd_acks ++;
      }
      else
      {
        unsigned char osdp_nak_response_data [2];

        // buzzer disabled

        status = ST_OK;

        current_length = 0;

        osdp_nak_response_data [0] = OO_NAK_UNK_CMD;
        nak_length = 1;
 
        status = send_message (context,
          OSDP_NAK, p_card.addr, &current_length, nak_length, osdp_nak_response_data);
        context->sent_naks ++;
        osdp_test_set_status(OOC_SYMBOL_rep_nak, OCONFORM_EXERCISED);
        if (context->verbosity > 2)
        {
          fprintf(context->log, "BUZ command rejected as command unknown.\n");
        };
      };
      break;

    case OSDP_CAP:
      {
        unsigned char *response_cap;
        int response_length;
        unsigned char new_capas [32*3];
        int new_length;

        status = ST_OK;
        new_length = sizeof(new_capas);
        status = osdp_get_capabilities(context, new_capas, &new_length);
        response_cap = new_capas;
        response_length = new_length;

        current_length = 0;

        // SPECIAL CASE: if osdp_CAP comes in in cleartext, answer it in cleartext
        current_security = OSDP_SEC_SCS_18;
        if (msg->security_block_length EQUALS 0)
          current_security = OSDP_SEC_STAND_DOWN;

        status = send_message_ex(context,
          OSDP_PDCAP, p_card.addr, &current_length,
            response_length, response_cap,
            current_security, 0, NULL);
        osdp_test_set_status(OOC_SYMBOL_cmd_cap, OCONFORM_EXERCISED);
        osdp_test_set_status(OOC_SYMBOL_rep_device_capas, OCONFORM_EXERCISED);
      };
      break;

    case OSDP_CHLNG:
      status = action_osdp_CHLNG(context, msg);
      break;

    case OSDP_COMSET:
      status = action_osdp_COMSET(context, msg);
      break;

    case OSDP_CRAUTH:
      status = action_osdp_CRAUTH(context, msg);
      break;

    case OSDP_FILETRANSFER:
      status = action_osdp_FILETRANSFER (context, msg);
      break;

    case OSDP_ID:
      {
        unsigned char osdp_pdid_response_data [12];

        osdp_pdid_response_data [ 0] = context->vendor_code [0];
        osdp_pdid_response_data [ 1] = context->vendor_code [1];
        osdp_pdid_response_data [ 2] = context->vendor_code [2];
        osdp_pdid_response_data [ 3] = context->model;;
        osdp_pdid_response_data [ 4] = context->version;
        osdp_pdid_response_data [ 5] = context->serial_number [0];
        osdp_pdid_response_data [ 6] = context->serial_number [1];
        osdp_pdid_response_data [ 7] = context->serial_number [2];
        osdp_pdid_response_data [ 8] = context->serial_number [3];
        osdp_pdid_response_data [ 9] = context->fw_version [0];
        osdp_pdid_response_data [10] = context->fw_version [1];
        osdp_pdid_response_data [11] = context->fw_version [2];
        status = ST_OK;
        current_length = 0;
        current_security = OSDP_SEC_SCS_18;

        // SPECIAL CASE: if osdp_ID comes in in cleartext, answer it in cleartext

        if (msg->security_block_length EQUALS 0)
          current_security = OSDP_SEC_STAND_DOWN;
        status = send_message_ex(context, OSDP_PDID, oo_response_address(context, oh->addr),
          &current_length, sizeof(osdp_pdid_response_data), osdp_pdid_response_data, current_security, 0, NULL);
        osdp_test_set_status(OOC_SYMBOL_cmd_id, OCONFORM_EXERCISED);
        osdp_test_set_status(OOC_SYMBOL_rep_device_ident, OCONFORM_EXERCISED);
        if (context->verbosity > 2)
        {
          sprintf (logmsg, "Responding with OSDP_PDID");
          fprintf (context->log, "%s\n", logmsg);
        };
      }
      sprintf(cmd, "%s/osdp_ID", oo_osdp_root(context, OO_DIR_ACTIONS));
      system(cmd);
    break;

    case OSDP_ISTAT:
      status = ST_OK;
      {
        unsigned char
          osdp_istat_response_data [OOSDP_DEFAULT_INPUTS];

        // hard code to show all inputs in '0' state.

        memset (osdp_istat_response_data, 0, sizeof (osdp_istat_response_data));
        osdp_test_set_status(OOC_SYMBOL_cmd_istat, OCONFORM_EXERCISED);
        osdp_test_set_status(OOC_SYMBOL_resp_istatr, OCONFORM_EXERCISED);
        current_length = 0;

        status = send_message_ex(context, OSDP_ISTATR, p_card.addr,
          &current_length, sizeof(osdp_istat_response_data), osdp_istat_response_data, OSDP_SEC_SCS_18, 0, NULL);
        if (context->verbosity > 2)
        {
          sprintf (logmsg, "Responding with OSDP_ISTAT (hard-coded all zeroes)");
          fprintf (context->log, "%s\n", logmsg);
        };
      };
      break;

    case OSDP_KEEPACTIVE:
      status = action_osdp_KEEPACTIVE (context, msg);
      break;

    case OSDP_KEYSET:
      status = action_osdp_KEYSET (context, msg);
      break;

    case OSDP_LED:
      if (context->configured_led)
      {
        /*
          There are 256 LED's.  They all use the colors in the spec.
          They switch on or off.  They don't blink.
        */
        int count;
        OSDP_RDR_LED_CTL *led_ctl;

        status = ST_OK;
        oh = (OSDP_HDR *)(msg->ptr);
        led_ctl = (OSDP_RDR_LED_CTL *)(msg->data_payload);
        count = oh->len_lsb + (oh->len_msb << 8);
        count = count - 7;
        count = count / sizeof (*led_ctl);
        if (context->verbosity > 3)
        {
          fprintf (context->log, "LED Control cmd count %d\n", count);
          fprintf (context->log, "LED Control Payload:\n");
        };
        for (i=0; i<count; i++)
        {
          fprintf (context->log, "[%02d] Rdr %d LED %d Tcmd %d Pcmd %d",
            i, led_ctl->reader, led_ctl->led, led_ctl->temp_control,
            led_ctl->perm_control);
          fprintf(context->log, " tc %d pc %d\n", led_ctl->temp_control, led_ctl->perm_control);
          if (led_ctl->reader EQUALS 0)
            if (led_ctl->temp_control EQUALS OSDP_LED_TEMP_SET)
            {
//              if (context->verbosity > 0)
              {
                fprintf(context->log, "LED-TEMP: On: C=%d T=%d Off C=%d T=%d timer %02x %02x\n",
                  led_ctl->temp_on_color, led_ctl->temp_on, led_ctl->temp_off_color, led_ctl->temp_off,
                  led_ctl->temp_timer_lsb, led_ctl->temp_timer_msb);
#define MILLISEC_IN_NANOSEC (1000000) 
              };
            };


            if (led_ctl->perm_control EQUALS OSDP_LED_SET)
            {
              if (context->verbosity > 3)
              {
                fprintf(context->log, "LED-PERM: state %d pOnT %d pOffT %d pOnCol %d pOfCol %d\n",
                  context->led [led_ctl->led].state, led_ctl->perm_on_time,
                  led_ctl->perm_off_time, led_ctl->perm_on_color, led_ctl->perm_off_color);
              };

              context->led [led_ctl->led].state = OSDP_LED_ACTIVATED;
              if (led_ctl->perm_on_time > 0)
                context->led [led_ctl->led].web_color = web_color_lookup [led_ctl->perm_on_color];
              else
                context->led [led_ctl->led].web_color = web_color_lookup [led_ctl->perm_off_color];

              // for conformance tests 3-10-1/3-10-2 we specifically look for LED 0 Color 1 (Red) or Color 2 (Green)

              if (led_ctl->perm_on_color EQUALS 1)
                osdp_test_set_status(OOC_SYMBOL_cmd_led_red, OCONFORM_EXERCISED);
              if (led_ctl->perm_on_color EQUALS 2)
                osdp_test_set_status(OOC_SYMBOL_cmd_led_green, OCONFORM_EXERCISED);
              if (led_ctl->perm_on_color EQUALS 3)
                osdp_test_set_status(OOC_SYMBOL_cmd_led_amber, OCONFORM_EXERCISED);
            };
          led_ctl = led_ctl + sizeof(OSDP_RDR_LED_CTL);
        };

        // we always ack the LED command regardless of how many LED's
        // it asks about

        current_length = 0;
        status = send_message_ex (context, OSDP_ACK, p_card.addr, &current_length,
          0, NULL, OSDP_SEC_SCS_16, 0, NULL);
        context->pd_acks ++;
        if (context->verbosity > 9)
          fprintf (stderr, "Responding with OSDP_ACK\n");
      }
      else
      {
        unsigned char osdp_nak_response_data [2];

        // led disabled

        status = ST_OK;

        current_length = 0;

        osdp_nak_response_data [0] = OO_NAK_UNK_CMD;
        nak_length = 1;
 
        status = send_message (context,
          OSDP_NAK, p_card.addr, &current_length, nak_length, osdp_nak_response_data);
        context->sent_naks ++;
        osdp_test_set_status(OOC_SYMBOL_rep_nak, OCONFORM_EXERCISED);
        if (context->verbosity > 2)
        {
          fprintf(context->log, "LED command rejected as command unknown.\n");
        };
      };
      break;

    case OSDP_OSTAT:
      status = action_osdp_OSTAT(context, msg);
      break;

    case OSDP_OUT:
      status = action_osdp_OUT (context, msg);
      break;

    case OSDP_POLL:
      status = action_osdp_POLL (context, msg);
      break;

    case OSDP_LSTAT:
    status = ST_OK;
    {
      unsigned char
        osdp_lstat_response_data [2];

      osdp_test_set_status(OOC_SYMBOL_cmd_lstat, OCONFORM_EXERCISED);
      osdp_test_set_status(OOC_SYMBOL_resp_lstatr, OCONFORM_EXERCISED);
      osdp_lstat_response_data [ 0] = context->tamper;
      osdp_lstat_response_data [ 1] = context->power_report; // report power failure
      current_length = 0;

      status = send_message_ex(context, OSDP_LSTATR, p_card.addr,
        &current_length, 2, osdp_lstat_response_data, OSDP_SEC_SCS_18, 0, NULL);
      if (context->verbosity > 2)
      {
        sprintf (logmsg, "Responding with OSDP_LSTATR (T=%d P=%d)", context->tamper, context->power_report);
        fprintf (context->log, "%s\n", logmsg);
        // clear tamper and power now reported
        context->tamper = 0;
        context->power_report = 0;
      };
    };
    break;

    case OSDP_MFG:
      status = action_osdp_MFG (context, msg);
      break;

    case OSDP_RSTAT:
      status = action_osdp_RSTAT (context, msg);
      break;

    case OSDP_SCRYPT:
      status = action_osdp_SCRYPT (context, msg);
      break;

    case OSDP_TEXT:
      status = action_osdp_TEXT (context, msg);
      break;

    case OSDP_ILLICIT:
      {
        osdp_nak_response_data [0] = 0xe0;
fprintf(context->log, "DEBUG3: NAK: %d.\n", osdp_nak_response_data [0]);
        status = send_message_ex(context, OSDP_NAK, p_card.addr,
          &current_length, 1, osdp_nak_response_data, OSDP_SEC_SCS_18, 0, NULL);
        context->sent_naks ++;
      };
      break;

    case OSDP_BOGUS:
    default:
      status = ST_OK;
      {
        unsigned char osdp_nak_response_data [2];

        current_length = 0;

        osdp_nak_response_data [0] = OO_NAK_UNK_CMD;
        osdp_nak_response_data [1] = 0xff;
        nak_length = 2;
 
        // if it was an induced NAK then call it error code 0xff and detail 0xee
        if (context->next_nak)
        {
          if (0x30000 EQUALS (0xFF0000 & context->next_nak))
          {
            // default NAK response

            osdp_nak_response_data [0] = 0xff;
            osdp_nak_response_data [1] = 0xee;
            nak_length = 2;
          };
          if (0x10000 EQUALS (0xFF0000 & context->next_nak))
          {
            // reason specified
            osdp_nak_response_data [0] = 0xff & context->next_nak;
            nak_length = 1;
          };
          if (0x20000 EQUALS (0xFF0000 & context->next_nak))
          {
            // reason and detail specified
            osdp_nak_response_data [0] = 0xff & context->next_nak;
            osdp_nak_response_data [1] = (0xff00 & context->next_nak) >> 8;
            nak_length = 2;
          };

          context->next_nak = 0;
        };

        status = send_message (context,
          OSDP_NAK, p_card.addr, &current_length, nak_length, osdp_nak_response_data);
        context->sent_naks ++;
        osdp_test_set_status(OOC_SYMBOL_rep_nak, OCONFORM_EXERCISED);
        if (context->verbosity > 2)
        {
          fprintf(context->log, "CMD %02x declared invalid or unknown\n", msg->msg_cmd);
        };
      };
      break;
    };
  } /* role PD */
  if (context->role EQUALS OSDP_ROLE_ACU)
  {
    // if we're here we think it's a whole sane response so we can say the last was processed.
    context->last_was_processed = 1;

    if (msg->msg_cmd EQUALS OSDP_BIOREADR)
      fprintf(stderr, "DEBUG: monitoring bioreadr...\n");

    (void)monitor_osdp_message (context, msg);

    status = osdp_timer_start(context, OSDP_TIMER_RESPONSE);

    context->last_response_received = msg->msg_cmd;
    switch (msg->msg_cmd)
    {
    case OSDP_ACK:
      if (context->verbosity > 3)
        fprintf(stderr, "DEBUG: ack check multi next_out %d total_outbound_multipart %d\n", context->next_out,
  context->total_outbound_multipart);
      status = ST_OK;

      /*
        if we were in the middle of sending a CRAUTH send the next fragment
      */
      if (context->next_out < context->total_outbound_multipart)
      {
        status= oo_send_next_genauth_fragment(context);
      };

      // for the moment receiving an ACK is considered processing.
      // really should be more fine-grained

      context->last_was_processed = 1;

      if (msg->security_block_type >= OSDP_SEC_SCS_11)
      {
        if (context->verbosity > 9)
          fprintf(stderr, "Received SCS %02x on osdp_ACK\n", msg->security_block_type);
      };
      break;

    case OSDP_BIOMATCHR:
      status = action_osdp_BIOMATCHR(context, msg);
      break;

    case OSDP_BIOREADR:
      status = action_osdp_BIOREADR(context, msg);
      break;

    case OSDP_BUSY:
      status = ST_OK;
      fprintf (context->log, "PD Responded BUSY\n");
      break;

    case OSDP_CCRYPT:
      status = action_osdp_CCRYPT (context, msg);
      break;

    case OSDP_CRAUTHR:
      status = action_osdp_CRAUTHR(context, msg);
      break;

    case OSDP_FTSTAT:
      status = action_osdp_FTSTAT(context, msg);
      break;

    case OSDP_GENAUTHR:
      status = action_osdp_GENAUTHR(context, msg);
      break;

    case OSDP_ISTATR:
      status = ST_OK;
      count = oh->len_lsb + (oh->len_msb << 8);
      count = count - 8;
      sprintf(tlogmsg, "\n  Count: %d Data:", count);
      for (i=0; i<count; i++)
      {
        sprintf(tlog2, " %02x", *(i+msg->data_payload));
        strcat(tlogmsg, tlog2);
      };
      fprintf (context->log, "Input Status: %s\n", tlogmsg);
      osdp_test_set_status(OOC_SYMBOL_resp_istatr, OCONFORM_EXERCISED);
      break;

    case OSDP_KEYPAD:
      {
        char command [1024];
        int kblimit;
        char temp [8];
        char tstring [1024];

        status = ST_OK;
        tstring[0] = 0;
        kblimit = sizeof(temp);
        sprintf(command, "/opt/osdp-conformance/run/ACU-actions/osdp_KEYPAD %d %d %02X ", 
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

          memcpy (temp, context->last_keyboard_data, 7);
          memcpy (context->last_keyboard_data+1, temp, 7);
          context->last_keyboard_data [0] = msg->data_payload [2+i];
        };
        fprintf (context->log, "PD Keypad Buffer: %s\n", tlogmsg);
        system(command);
        osdp_test_set_status(OOC_SYMBOL_resp_keypad, OCONFORM_EXERCISED);
      };
      break;

    // action for NAK

    case OSDP_NAK:
      status = ST_OK;
//      context->sent_naks ++;
      context->last_nak_error = *(0+msg->data_payload);

      if (context->verbosity > 2)
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

        fprintf (context->log, "%s\n", tlogmsg);
// { *(0+msg->data_payload) is nak code 070-03-(3+that) is test zzz };
        switch(*(0+msg->data_payload))
        {
//7 3 3 is nak 0
//not yet displayed: OO_NAK_COMMAND_LENGTH OO_NAK_BIO_TYPE_UNSUPPORTED OO_NAK_BIO_FMT_UNSUPPORTED OO_NAK_CMD_UNABLE
        case OO_NAK_CHECK_CRC:
          fprintf(context->log, "  NAK: (1)Bad CRC/Checksum\n");
          break;
        case OO_NAK_UNK_CMD:
          fprintf(context->log, "  NAK: (3)Command not implemented by PD\n");
          break;
        case OO_NAK_SEQUENCE:
          fprintf(context->log, "  NAK: (4)Unexpected sequence number\n");
          context->seq_bad ++;
            // hopefully not double counted, works in monitor mode
          context->next_sequence = 0; // reset sequence due to NAK
          break;
        case OO_NAK_UNSUP_SECBLK:
          fprintf(context->log, "  NAK: (5)Security block not accepted.\n");
          break;
        case OO_NAK_ENC_REQ:
          // drop out of secure channel and in fact reset the sequence number

          fprintf(context->log, "  NAK: (%d)Encryption required.\n", nak_code);
          osdp_reset_secure_channel(context);
          context->next_sequence = 0; 
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

      if (context->secure_channel_use [OO_SCU_ENAB] & 0x80)
      {
        osdp_reset_secure_channel (context);
      }
      else
      {
        // if the PD said it does BIO and it NAK'd a BIOREAD fail the test.

        if (context->last_command_sent EQUALS OSDP_BIOREAD)
        {
          if (context->configured_biometrics)
            osdp_test_set_status(OOC_SYMBOL_cmd_bioread, OCONFORM_FAIL);
        };

        // if the PD NAK'd a BIOMATCH fail the test.

        if (context->last_command_sent EQUALS OSDP_BIOMATCH)
        {
          if (context->configured_biometrics)
            osdp_test_set_status(OOC_SYMBOL_cmd_biomatch, OCONFORM_FAIL);
        };

        // if the PD NAK'd an ID fail the test.

        if (context->last_command_sent EQUALS OSDP_ID)
        {
          osdp_test_set_status(OOC_SYMBOL_cmd_id, OCONFORM_FAIL);
        };

        // if the PD NAK'd an ACURXSIZE fail the test.  If you didn't want the failure signal you'd use the sequencer to skip the test.
        if (context->last_command_sent EQUALS OSDP_ACURXSIZE)
        {
          osdp_test_set_status(OOC_SYMBOL_cmd_acurxsize, OCONFORM_FAIL);
        };

        // if the PD NAK'd a TEXT fail the test.  If you didn't want the failure signal you'd use the sequencer to skip the test.
        if ((unsigned int)(context->last_command_sent) EQUALS (unsigned int)OSDP_TEXT)
        {
          osdp_test_set_status(OOC_SYMBOL_cmd_text, OCONFORM_FAIL);
        };

        // if the PD NAK'd a KEEPACTIVE fail the test.  If you didn't want the failure signal you'd use the sequencer to skip the test.
        if ((unsigned int)(context->last_command_sent) EQUALS (unsigned int)OSDP_KEEPACTIVE)
        {
          osdp_test_set_status(OOC_SYMBOL_cmd_keepactive, OCONFORM_FAIL);
        };

// assumes test_details is still valid.
// assumes it was a perm on command
#define LP_ON (12)

        if (context->test_details [LP_ON] EQUALS OSDP_LEDCOLOR_AMBER)
          osdp_test_set_status(OOC_SYMBOL_cmd_led_amber, OCONFORM_FAIL);
        if (context->test_details [LP_ON] EQUALS OSDP_LEDCOLOR_BLACK)
          osdp_test_set_status(OOC_SYMBOL_cmd_led_black, OCONFORM_FAIL);
        if (context->test_details [LP_ON] EQUALS OSDP_LEDCOLOR_BLUE)
          osdp_test_set_status(OOC_SYMBOL_cmd_led_blue, OCONFORM_FAIL);
        if (context->test_details [LP_ON] EQUALS OSDP_LEDCOLOR_CYAN)
          osdp_test_set_status(OOC_SYMBOL_cmd_led_cyan, OCONFORM_FAIL);
        if (context->test_details [LP_ON] EQUALS OSDP_LEDCOLOR_GREEN)
          osdp_test_set_status(OOC_SYMBOL_cmd_led_green, OCONFORM_FAIL);
        if (context->test_details [LP_ON] EQUALS OSDP_LEDCOLOR_MAGENTA)
          osdp_test_set_status(OOC_SYMBOL_cmd_led_magenta, OCONFORM_FAIL);
        if (context->test_details [LP_ON] EQUALS OSDP_LEDCOLOR_RED)
          osdp_test_set_status(OOC_SYMBOL_cmd_led_red, OCONFORM_FAIL);
        if (context->test_details [LP_ON] EQUALS OSDP_LEDCOLOR_WHITE)
          osdp_test_set_status(OOC_SYMBOL_cmd_led_white, OCONFORM_FAIL);

        // if the PD NAK'd an OSTAT that is a fail.  The initiator of the OSTAT is responsible for only
        // using it if output support declared.

        if (context->last_command_sent EQUALS OSDP_OSTAT)
        {
          osdp_test_set_status(OOC_SYMBOL_cmd_ostat, OCONFORM_FAIL);
        };

        // if the PD NAK'd an RSTAT that is ok because RSTAT/RSTATR are effectively deprecated

        if (context->last_command_sent EQUALS OSDP_RSTAT)
        {
          osdp_test_set_status(OOC_SYMBOL_cmd_rstat, OCONFORM_EXERCISED);
        };

      // if the PD NAK'd an ISTAT fail the test.
      if (context->last_command_sent EQUALS OSDP_ISTAT)
      {
        osdp_conformance.cmd_istat.test_status = OCONFORM_FAIL;
        SET_FAIL ((context), "3-6-1");
      };

      // if the PD NAK'd a KEYSET fail the test.
      if (context->last_command_sent EQUALS OSDP_KEYSET)
      {
        osdp_test_set_status(OOC_SYMBOL_cmd_keyset, OCONFORM_FAIL);
      };

      // if the PD NAK'd an LSTAT fail the test.
      if (context->last_command_sent EQUALS OSDP_LSTAT)
      {
        osdp_test_set_status(OOC_SYMBOL_cmd_lstat, OCONFORM_FAIL);
      };
      // if the PD NAK'd a CAP fail the test.
      if (context->last_command_sent EQUALS OSDP_CAP)
      {
        osdp_test_set_status(OOC_SYMBOL_cmd_cap, OCONFORM_FAIL);
      };

      };

      context->last_was_processed = 1; // if we got a NAK that processes the cmd
      break;

    case OSDP_COM:
      status = ST_OK;
      osdp_test_set_status(OOC_SYMBOL_resp_com, OCONFORM_EXERCISED);
      new_speed = *(1+msg->data_payload);
      new_speed = (new_speed << 8) +*(2+msg->data_payload);
      new_speed = (new_speed << 8) +*(3+msg->data_payload);
      new_speed = (new_speed << 8) +*(4+msg->data_payload);
      switch(new_speed)
      {
      case 38400:
        osdp_test_set_status(OOC_SYMBOL_signalling_38400, OCONFORM_EXERCISED);
        break;
      };
      if (context->verbosity > 2)
      {
        fprintf (context->log, "osdp_COM: Addr %02x Baud (m->l) %02x %02x %02x %02x\n",
          *(0+msg->data_payload), *(1+msg->data_payload), *(2+msg->data_payload),
          *(3+msg->data_payload), *(4+msg->data_payload));
      };
      break;

    case OSDP_LSTATR:
      status = ST_OK;
      fprintf (context->log, "Local Status Report:");
      fprintf (context->log,
        " Tamper %d Power %d\n",
        *(msg->data_payload + 0), *(msg->data_payload + 1));
      osdp_test_set_status(OOC_SYMBOL_resp_lstatr, OCONFORM_EXERCISED);
      if (*(msg->data_payload) > 0)
        osdp_test_set_status(OOC_SYMBOL_resp_lstatr_tamper, OCONFORM_EXERCISED);
      if (*(msg->data_payload + 1) > 0)
        osdp_test_set_status(OOC_SYMBOL_resp_lstatr_power, OCONFORM_EXERCISED);

      /*
        ACTION SCRIPT ARGS: 1=1 if tamper 0 if not, 2=1 if poweron 0 if not
      */
      sprintf(cmd, "%s/run/ACU-actions/osdp_LSTATR %d %d %d", context->service_root,
        *(msg->data_payload + 0), *(msg->data_payload + 1), (oh->addr & 0x7f));
      system(cmd);
      break;

    case OSDP_MFGERRR:
      status = action_osdp_MFGERRR(context, msg);
      break;

    case OSDP_MFGREP:
      status = action_osdp_MFGREP(context, msg);
      break;

    case OSDP_OSTATR:
      osdp_test_set_status(OOC_SYMBOL_resp_ostatr, OCONFORM_EXERCISED);

      // if this is in response to an OSTAT then mark that too.
      if (context->last_command_sent EQUALS OSDP_OSTAT)
        osdp_test_set_status(OOC_SYMBOL_cmd_ostat, OCONFORM_EXERCISED);

      break;

    case OSDP_PDCAP:
      status = action_osdp_PDCAP(context, msg);
      break;

    case OSDP_PDID:
//      status = oosdp_make_message (OOSDP_MSG_PD_IDENT, tlogmsg, msg);
//      if (status == ST_OK)
//        status = oosdp_log (context, OSDP_LOG_NOTIMESTAMP, 1, tlogmsg);

      // consistency check (test 4-3-2)
      // OUI must not be zero

      sprintf(details,
"\"pd-oui\":\"%02x%02x%02x\",\"pd-model\":\"%d\",\"pd-version\":\"%d\",\"pd-serial\":\"%02x%02x%02x%02x\",\"pd-firmware\":\"%d-%d-%d\",",
        msg->data_payload [0], msg->data_payload [1], msg->data_payload [2],
        msg->data_payload [3], msg->data_payload [4],
        msg->data_payload [5], msg->data_payload [6], msg->data_payload [7], msg->data_payload [8],
        msg->data_payload [9], msg->data_payload [10], msg->data_payload [11]);

      osdp_test_set_status(OOC_SYMBOL_cmd_id, OCONFORM_EXERCISED);
      osdp_test_set_status_ex(OOC_SYMBOL_rep_device_ident, OCONFORM_EXERCISED, details);
      if ((msg->data_payload [0] EQUALS 0) &&
        (msg->data_payload [1] EQUALS 0) &&
        (msg->data_payload [2] EQUALS 0))
      {
        fprintf(context->log, "OUI in PDID is invalid (all 0's)\n");
        osdp_test_set_status(OOC_SYMBOL_rep_pdid_check, OCONFORM_FAIL);
      }
      else
      {
        context->vendor_code [0] = *(0+msg->data_payload);
        context->vendor_code [1] = *(1+msg->data_payload);
        context->vendor_code [2] = *(2+msg->data_payload);
        context->model = *(3+msg->data_payload);
        context->version = *(4+msg->data_payload);
        context->serial_number [0] = *(5+msg->data_payload);
        context->serial_number [1] = *(6+msg->data_payload);
        context->serial_number [2] = *(7+msg->data_payload);
        context->serial_number [3] = *(8+msg->data_payload);
        context->fw_version [0] = *(9+msg->data_payload);
        context->fw_version [1] = *(10+msg->data_payload);
        context->fw_version [2] = *(11+msg->data_payload);

        sprintf(cmd, "/opt/osdp-conformance/run/ACU-actions/osdp_PDID OUI %02X%02X%02X M-V %03d-%03d SN %02X%02X%02X%02X FW %03d.%03d.%03d",
          context->vendor_code [0], context->vendor_code [1], context->vendor_code [2],
          context->model, context->version,
          context->serial_number [0], context->serial_number [1],
          context->serial_number [2], context->serial_number [3],
          context->fw_version [0], context->fw_version [1], context->fw_version [2]);
        system(cmd);

        osdp_test_set_status(OOC_SYMBOL_rep_pdid_check, OCONFORM_EXERCISED);
      };

      context->last_was_processed = 1;

      sprintf(details,
"\"pd-oui\":\"%02x%02x%02x\",\"pd-model\":\"%d\",\"pd-version\":\"%d\",\"pd-serial\":\"%02x%02x%02x%02x\",\"pd-firmware\":\"%d-%d-%d\",",
        msg->data_payload [0], msg->data_payload [1], msg->data_payload [2],
        msg->data_payload [3], msg->data_payload [4],
        msg->data_payload [5], msg->data_payload [6], msg->data_payload [7], msg->data_payload [8],
        msg->data_payload [9], msg->data_payload [10], msg->data_payload [11]);

      // if we got a coherent PDID response the current speed must be working, report that.
      if (strcmp("9600", context->serial_speed) EQUALS 0)
        osdp_test_set_status(OOC_SYMBOL_signalling, OCONFORM_EXERCISED);
      if (strcmp("19200", context->serial_speed) EQUALS 0)
        osdp_test_set_status(OOC_SYMBOL_signalling_19200, OCONFORM_EXERCISED);
      if (strcmp("38400", context->serial_speed) EQUALS 0)
        osdp_test_set_status(OOC_SYMBOL_signalling_38400, OCONFORM_EXERCISED);
      if (strcmp("57600", context->serial_speed) EQUALS 0)
        osdp_test_set_status(OOC_SYMBOL_signalling_57600, OCONFORM_EXERCISED);
      if (strcmp("115200", context->serial_speed) EQUALS 0)
        osdp_test_set_status(OOC_SYMBOL_signalling_115200, OCONFORM_EXERCISED);
      if (strcmp("230400", context->serial_speed) EQUALS 0)
        osdp_test_set_status(OOC_SYMBOL_signalling_230400, OCONFORM_EXERCISED);
      break;

    case OSDP_PIVDATA:
      status = action_osdp_PIVDATA(context, msg);
      break;

    case OSDP_PIVDATAR:
      status = action_osdp_PIVDATAR(context, msg);
      break;

    case OSDP_XRD:
      status = action_osdp_XRD(context, msg);
      break;

    default:
      if (context->verbosity > 2)
      {
        fprintf (stderr, "CMD %02x Unknown to ACU\n", msg->msg_cmd);
      };
    break;

    case OSDP_RAW:
      status = action_osdp_RAW (context, msg);
      break;

    case OSDP_RMAC_I:
      status = action_osdp_RMAC_I (context, msg);
      break;

    case OSDP_RSTATR:
      {
        unsigned char reader_0_tamper_status;
        char *tstatus;

        // received osdp_RSTATR.  Assume it's for one attached reader.

        status = ST_OK;
        reader_0_tamper_status = *(msg->data_payload + 0);
        fprintf (context->log, "Reader Tamper Status Report:");
        switch(reader_0_tamper_status)
        {
        case 0: tstatus = "Normal"; break;
        case 1: tstatus = "Not Connected"; break;
        case 2: tstatus = "Tamper"; break;
        };
        fprintf (context->log, " Ext Rdr %d Tamper Status %s\n",
          0, tstatus);
        osdp_test_set_status(OOC_SYMBOL_resp_rstatr, OCONFORM_EXERCISED);
        if (context->last_command_sent EQUALS OSDP_RSTAT)
          osdp_test_set_status(OOC_SYMBOL_cmd_rstat, OCONFORM_EXERCISED);
      };
      break;
    };
  } /* role ACU */

  if (status EQUALS ST_MSG_UNKNOWN)
    osdp_conformance.last_unknown_command = msg->msg_cmd;
  if (status != ST_OK)
  {
    fprintf(context->log, "Error %d. in process_osdp_message, recovering.\n", status);
    status = ST_OK;
  };

  fflush (context->log);
  return (status);

} /* process_osdp_message */

