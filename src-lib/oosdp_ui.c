/*
  oosdp_ui - UI routines for open-osdp

  (C)2014-2016 Smithee Spelvin Agnew & Plinge, Inc.

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
#include <string.h>
#include <time.h>
#include <arpa/inet.h>


#include <gnutls/gnutls.h>


#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>


extern OSDP_CONTEXT
  context;
extern OSDP_OUT_CMD
  current_output_command [];
extern OSDP_BUFFER
  osdp_buf;
extern OSDP_INTEROP_ASSESSMENT
  osdp_conformance;
extern OSDP_PARAMETERS
  p_card;


void
  dump_conformance
    (OSDP_CONTEXT
      *ctx,
    OSDP_INTEROP_ASSESSMENT
      *oconf);


char
  *conformance_status
    (unsigned char
      cstat)

{ /* conformance_status */

  static char
    response [1024];

  switch (cstat)
  {
  case OCONFORM_UNTESTED:
    strcpy (response, "Untested");
    osdp_conformance.untested ++;
    break;
  case OCONFORM_EXERCISED:
    strcpy (response, "Exercised");
    osdp_conformance.pass ++;
    break;
  case OCONFORM_EX_GOOD_ONLY:
    strcpy (response, "Exercised (no edge case tests)");
    osdp_conformance.pass ++;
    break;
  case OCONFORM_FAIL:
    strcpy (response, "Failed)");
    osdp_conformance.fail ++;
    break;
  default:
    sprintf (response, "conformance status unknown(%d)", cstat);
    break;
  };
  return (response);
} /* conformance_status */


void
  dump_conformance
    (OSDP_CONTEXT *ctx,
    OSDP_INTEROP_ASSESSMENT *oconf)

{ /* dump_conformance */
  int
    profile_total2;
  int
    profile_total3;
  int
    profile_total4;


  profile_total2 = 17;
  profile_total3 = 19;
  profile_total4 = 17;

  oconf->pass = 0;
  oconf->fail = 0;
  oconf->untested = 0;

  // fill in results for mmt cases

  if (oconf->conforming_messages >= PARAM_MMT)
  {
    oconf->physical_interface.test_status =
      OCONFORM_EXERCISED;
    oconf->signalling.test_status =
      OCONFORM_EXERCISED;
    oconf->character_encoding.test_status =
      OCONFORM_EXERCISED;
    oconf->channel_access.test_status =
      OCONFORM_EXERCISED;
    oconf->packet_format.test_status =
      OCONFORM_EXERCISED;
    oconf->SOM.test_status =
      OCONFORM_EXERCISED;
    oconf->LEN.test_status =
      OCONFORM_EXERCISED;
    oconf->CTRL.test_status =
      OCONFORM_EXERCISED;
    oconf->CTRL.test_status =
      OCONFORM_EXERCISED;
    oconf->security_block.test_status =
      OCONFORM_EXERCISED;
    oconf->CHKSUM_CRC16.test_status =
      OCONFORM_EXERCISED;
    if (oconf->last_unknown_command EQUALS OSDP_POLL)
      oconf->CMND_REPLY.test_status =
        OCONFORM_EXERCISED;
    else
      oconf->CMND_REPLY.test_status =
        OCONFORM_FAIL;
  };
  fprintf (ctx->log, "Conformance Report:\n");

  fprintf (ctx->log, "2.1  Physical Interface                 %s\n",
    conformance_status (oconf->physical_interface.test_status));
  fprintf (ctx->log, "2.2  Signalling                         %s\n",
    conformance_status (oconf->signalling.test_status));
  fprintf (ctx->log, "2.3  Character Encoding                 %s\n",
    conformance_status (oconf->character_encoding.test_status));
  fprintf (ctx->log, "2.4  Channel Access                     %s\n",
    conformance_status (oconf->channel_access.test_status));
  fprintf (ctx->log, "2.5  Multi-byte Data Encoding           %s\n",
    conformance_status (oconf->multibyte_data_encoding.test_status));
  fprintf (ctx->log, "2.6  Packet Size Limits                 %s\n",
"???"); //    conformance_status (oconf->channel_access.test_status));
  fprintf (ctx->log, "2.7  Timing                             %s\n",
    "Not implemented in open-osdp");
  fprintf (ctx->log, "2.8  Message Synchronization            %s\n",
    "Not implemented in open-osdp");
  fprintf (ctx->log, "2.9  Packet Formats                     %s\n",
    conformance_status (oconf->packet_format.test_status));
  fprintf (ctx->log, "2.10 SOM - Start of Message             %s\n",
    conformance_status (oconf->SOM.test_status));
  fprintf (ctx->log, "2.11 ADDR - Address                     %s\n",
"???"); //    conformance_status (oconf->channel_access.test_status));
  fprintf (ctx->log, "2.12 LEN - Length                       %s\n",
    conformance_status (oconf->LEN.test_status));
  fprintf (ctx->log, "2.13 CTRL - Control                     %s\n",
    conformance_status (oconf->CTRL.test_status));
  fprintf (ctx->log, "2.14 Security Block (hdr process only)  %s\n",
    conformance_status (oconf->security_block.test_status));
  fprintf (ctx->log, "2.15 CMND/REPLY - Command/Reply Code    %s\n",
    conformance_status (oconf->CMND_REPLY.test_status));
  fprintf (ctx->log, "2.16 CHKSUM/CRC16 - Message Check Codes %s\n",
    conformance_status (oconf->CHKSUM_CRC16.test_status));
  fprintf (ctx->log, "2.17 Large Data Messages                %s\n",
"???"); //    conformance_status (oconf->channel_access.test_status));

  fprintf (ctx->log, "3.1  Poll                               %s\n",
    conformance_status (oconf->cmd_poll.test_status));
  fprintf (ctx->log, "3.2  ID Report Request                  %s\n",
    conformance_status (oconf->cmd_id.test_status));
  fprintf (ctx->log, "3.3  Peripheral Device Capabilities Req %s\n",
    conformance_status (oconf->cmd_pdcap.test_status));

  fprintf (ctx->log, "3.9  Output Control Command             %s\n",
    conformance_status (oconf->cmd_out.test_status));
  fprintf (ctx->log, "3.10 Reader LED Control Command         %s\n",
    conformance_status (oconf->cmd_led.test_status));
  fprintf (ctx->log, "3.11 Reader Buzzer Control Command      %s\n",
"???");//    conformance_status (oconf->cmd_led.test_status));
  fprintf (ctx->log, "3.12 Reader Text Output Command         %s\n",
"???");//    conformance_status (oconf->cmd_led.test_status));
  fprintf (ctx->log, "3.13 (Deprecated)\n");
  fprintf (ctx->log, "3.14 Communication Configuration Cmd    %s\n",
"???");//    conformance_status (oconf->cmd_led.test_status));
  fprintf (ctx->log, "3.15 (Deprecated)\n");
  fprintf (ctx->log, "3.16 Set Automatic Rdr Prompt Strings   %s\n",
"???");//    conformance_status (oconf->cmd_led.test_status));
  fprintf (ctx->log, "3.17 Scan and Send Biometric Template   %s\n",
"???");//    conformance_status (oconf->cmd_led.test_status));
  fprintf (ctx->log, "3.18 Scan and Match Biometric Template  %s\n",
"???");//    conformance_status (oconf->cmd_led.test_status));
  fprintf (ctx->log, "3.19 (Deprecated)\n");
  fprintf (ctx->log, "3.20 Manufacturer Specific Command      %s\n",
"???");//    conformance_status (oconf->cmd_led.test_status));
  fprintf (ctx->log, "3.21 Stop Multi Part Message            %s\n",
"???");//    conformance_status (oconf->cmd_led.test_status));
  fprintf (ctx->log, "3.22 Maximum Accetpable Reply Size      %s\n",
"???");//    conformance_status (oconf->cmd_led.test_status));

  fprintf (ctx->log, "4.1  General Ack Nothing to Report      %s\n",
    conformance_status (oconf->rep_ack.test_status));
  fprintf (ctx->log, "4.2  Negative Ack Error Response        %s\n",
    conformance_status (oconf->rep_nak.test_status));
  fprintf (ctx->log, "4.3  Device Identification Report       %s\n",
    conformance_status (oconf->rep_device_ident.test_status));
  fprintf (ctx->log, "4.4  Device Capabilities Report         %s\n",
    conformance_status (oconf->rep_device_capas.test_status));
  fprintf (ctx->log, "4.5  Local Status Report                %s\n",
    conformance_status (oconf->rep_local_stat.test_status));
  fprintf (ctx->log, "4.7  Output Status                      %s\n",
    conformance_status (oconf->rep_output_stat.test_status));
  fprintf (ctx->log, "4.9  Card Data Report, Raw Bit Array    %s\n",
    conformance_status (oconf->rep_raw.test_status));

  fprintf (ctx->log, "4.17 PD Busy Reply                      %s\n",
    conformance_status (oconf->rep_busy.test_status));
#if 0
  //OSDP_CONFORM rep_input_stat;          // 4.6
  OSDP_CONFORM rep_reader_tamper;       // 4.8
  OSDP_CONFORM rep_raw;                 // 4.9
  OSDP_CONFORM rep_formatted;           // 4.10
  OSDP_CONFORM rep_keypad;              // 4.11
  OSDP_CONFORM rep_comm;                // 4.12
  OSDP_CONFORM rep_scan_send;           // 4.13
  OSDP_CONFORM rep_scan_match;          // 4.14
  // 3.x
  OSDP_CONFORM cmd_diag;                // 3.4
  OSDP_CONFORM cmd_lstat;               // 3.5
  OSDP_CONFORM cmd_istat;               // 3.6
  OSDP_CONFORM cmd_ostat;               // 3.7

  OSDP_CONFORM cmd_rstat;               // 3.8
  OSDP_CONFORM cmd_out;                 // 3.9
  OSDP_CONFORM cmd_led;                 // 3.10
  OSDP_CONFORM cmd_buz;                 // 3.11
  OSDP_CONFORM cmd_text;                // 3.12
  OSDP_CONFORM cmd_comset;              // 3.13
  OSDP_CONFORM cmd_prompt;              // 3.16
  OSDP_CONFORM cmd_bioread;             // 3.17
  OSDP_CONFORM cmd_biomatch;            // 3.18
  OSDP_CONFORM cmd_cont;                // 3.19
  OSDP_CONFORM cmd_mfg;                 // 3.20
  // 3.x partial...

#endif
  fprintf (ctx->log,
    "Profile: Basic (Section 2: %d Section 3: %d Section 4: %d)\n",
    profile_total2,  profile_total3, profile_total4);
  fprintf (ctx->log,
    "Passed: %d Failed: %d Untested: %d\n",
    oconf->pass, oconf->fail, oconf->untested);
  fprintf (ctx->log, "---end of report---\n");
fprintf (ctx->log, "mmt %d of %d\n",
  oconf->conforming_messages,
  PARAM_MMT);
}


int
  process_command
  (int
     command,
  OSDP_CONTEXT
     *context,
  char
    *details)

{ /* process_command */

  extern int
    creds_buffer_a_lth;
  int
    current_length;
  int
    processed;
  int
    status;


  status = ST_CMD_UNKNOWN;
  if (context->verbosity > 3)
  {
    fprintf (context->log, "process_command: command is %d\n",
      command);
  };
  processed = 0;
  if (command EQUALS OSDP_CMD_NOOP)
  {
    processed = 1;
    status = ST_OK;
  };
  if ((!processed) && (context->current_menu EQUALS OSDP_MENU_CP_DIAG))
  {
    context->role = OSDP_ROLE_CP;
    switch (command)
    {
    case OSDP_CMD_CP_SEND_POLL:
      current_length = 0;
      status = send_message (context,
        OSDP_POLL, p_card.addr, &current_length, 0, NULL);
      if (context->verbosity > 2)
        fprintf (stderr, "Polling\n");
      break;

    case OSDP_CMD_GET_CREDS_A:
      {
#if 0
        OSDP_MULTI_GETPIV
          mmsg;

        current_length = 0;
        memset (&mmsg, 0, sizeof (mmsg));
        mmsg.oui [0] = 0x08;
        mmsg.oui [0] = 0x00;
        mmsg.oui [0] = 0x1b;
        mmsg.total = htons (16); // container tag plus data tag
        mmsg.offset = 0;
        mmsg.length = htons (16); // container tag plus data tag
        mmsg.cmd = 0;
        mmsg.container_tag [0] = 0x00;
        mmsg.container_tag [1] = 0x00;
        mmsg.container_tag [2] = 0x00;
        mmsg.data_tag [0] = 0x00;
        status = send_message (context,
          OSDP_MFG, p_card.addr, &current_length, sizeof (mmsg), (unsigned char *)&mmsg);
#endif
status = -1;
      };
      break;

    case OSDP_CMD_COMSET:
      {
       unsigned char
         param [5];

        current_length = 0;
        param [0] = p_card.addr; // set to PD 1
        param [1] = 0x00ff & 9600; // hard-code tp 9600 BPS
        param [2] = (0xff00 & 9600) >> 8;
        param [3] = 0;
        param [4] = 0;
        status = send_message (context, OSDP_COMSET, 0x7f,
          &current_length, sizeof (param), param);
        if (context->verbosity > 2)
          fprintf (context->log, "COM Set: PD %d, Speed %d.\n",
            param [0], 9600);
      };
      break;

    case OSDP_CMD_LCL_STAT:
      status = ST_OK;
      current_length = 0;
      status = send_message (context,
        OSDP_LSTAT, p_card.addr, &current_length, 0, NULL);
      if (context->verbosity > 2)
        fprintf (stderr, "Requesting Capabilities Report\n");
      break;

    case OSDP_CMD_RDR_STAT:
      status = ST_OK;
      current_length = 0;
      status = send_message (context,
        OSDP_RSTAT, p_card.addr, &current_length, 0, NULL);
      if (context->verbosity > 2)
        fprintf (stderr, "Requesting (External) Reader (Tamper) Status\n");
      break;


    case OSDP_CMD_EXIT:
      context->current_menu = OSDP_MENU_TOP;
      status = ST_OK;
      break;

    default:
      status = ST_CMD_UNKNOWN;
      break;
    };
    processed = 1;
  };
  if ((!processed) && (context->current_menu EQUALS OSDP_MENU_PD_DIAG))
  {
    context->role = OSDP_ROLE_PD;
    switch (command)
    {
    case OSDP_CMD_PD_POWER:
      context->power_report = 1;
      status = ST_OK;
      break;
    case OSDP_CMD_PD_CARD_PRESENT:
      status = ST_OK;
      /*
        use card data from loaded config
      */
      context->card_data_valid = p_card.bits;
      context->creds_a_avail = creds_buffer_a_lth;
      if (context->verbosity > 2)
        fprintf (context->log, "Presenting card data (raw: %d, Creds A: %d)\n",
          context->card_data_valid, context->creds_a_avail);
      break;
    case OSDP_CMD_EXIT:
      context->current_menu = OSDP_MENU_TOP;
      status = ST_OK;
      break;
    };
    processed = 1;
  };
  if ((!processed) &&(context->current_menu EQUALS OSDP_MENU_TOP))
  {
    switch (command)
    {
    // breech-loaded cases.  by convention these occur at the top of the old menu structure for transitional purposes.

    case OSDP_CMDB_CAPAS:
      {
        unsigned char
          param [1];

        current_length = 0;
        param [0] = 0;
        status = send_message (context,
          OSDP_CAP, p_card.addr, &current_length, sizeof (param), param);
        osdp_conformance.cmd_pdcap.test_status =
          OCONFORM_EXERCISED;
        if (context->verbosity > 2)
          fprintf (stderr, "Requesting Capabilities Report\n");
      };
      status = ST_OK;
      break;
    case OSDP_CMDB_DUMP_STATUS:
#if 1
//0
      fprintf (stderr,
"Role: %d (0=CP,1=PD,2=Mon) Chksum(0)/CRC(1): %d\n",
         context->role, m_check);
      fprintf (stderr,
"  Timeout %02d(%d.) Dump %d Debug %d.\n",
         m_idle_timeout, p_card.poll, m_dump, context->verbosity);
      fprintf (stderr,
" PwrRpt %d Special-1 %d\nCP Polls %d; PD Acks %d NAKs %d CsumErr %d\n",
         context->power_report, context->special_1,
         context->cp_polls, context->pd_acks, context->sent_naks,
         context->checksum_errs);
      if (context->role EQUALS OSDP_ROLE_PD)
      {
        fprintf (stderr, "PD Address 0x%02x ", p_card.addr);
      };
      {
        int count;
        int i;
        count = 0;
        if (osdp_buf.next > 0)
          count = osdp_buf.next;
        fprintf (stderr, "Buffer had %d bytes\n", count);
        for (i=0; i<count; i++)
          fprintf (stderr, " %02x", osdp_buf.buf [i]);
        fprintf (stderr, "\n");
        status = ST_OK;
      };
#endif
      {
        status = write_status (context);

        dump_conformance (context, &osdp_conformance);
        status = ST_OK;
      };
      break;
    case OSDP_CMDB_IDENT:
      {
        unsigned char
          param [1];

        current_length = 0;
        /*
          osdp_ID takes one argment, a one byte value of 0 indicating
          "send Standard PD ID Block"
        */
        param [0] = 0;
        current_length = 0;
        status = send_message (context,
          OSDP_ID, p_card.addr, &current_length, sizeof (param), param);
        osdp_conformance.cmd_id.test_status =
          OCONFORM_EXERCISED;
        if (context->verbosity > 3)
          fprintf (stderr, "Requesting PD Ident\n");
      };
      status = ST_OK;
      break;

    case OSDP_CMDB_INIT_SECURE:
      {
        unsigned char
          sec_blk [1];

        status = ST_OK;
        current_length = 0;
        sec_blk [0] = OSDP_KEY_SCBK_D;
        strncpy ((char *)(context->random_value), "12345678", 8);
        if (context->verbosity > 2)
          fprintf (stderr, "using SCBK-D, hard-coded RND.A to 12345678\n");
        status = send_secure_message (context,
          OSDP_CHLNG, p_card.addr, &current_length, 
          sizeof (context->random_value), context->random_value,
          OSDP_SEC_SCS_11, sizeof (sec_blk), sec_blk);
        if (context->verbosity > 2)
          fprintf (stderr, "Initiating Secure Channel\n");
      };
      break;

    case OSDP_CMDB_LED:
      {
        OSDP_RDR_LED_CTL
          led_control_message;

        memset (&led_control_message, 0, sizeof (led_control_message));
        /*
          assume reader 0
          assume LED 0
          assume permanent (templ control 0)
          assume on time is 3 sec (30x100 ms)
          assume off time is 1 sec (10x100 ms)
          assume on LED color is RED
          assume off LED color is BLACK
        */
        led_control_message.perm_control = OSDP_LED_SET;
        led_control_message.perm_on_time = 30;
        led_control_message.perm_off_time = 10;
        led_control_message.perm_on_color = OSDP_LEDCOLOR_RED;
        led_control_message.perm_off_color = OSDP_LEDCOLOR_BLACK;
        current_length = 0;
        status = send_message (context,
          OSDP_LED, p_card.addr, &current_length, sizeof (led_control_message), (unsigned char *)&led_control_message);
        osdp_conformance.cmd_led.test_status =
          OCONFORM_EXERCISED;
        if (context->verbosity > 3)
          fprintf (stderr, "Requesting LED tmp ctl %02x perm ctl %02x perm color %02x\n",
            0, 0, 0);
      };
      break;
    case OSDP_CMDB_OUT:
      {
        OSDP_OUT_MSG
          osdp_out_msg [16];
        int
          out_lth;

        current_length = 0;
        osdp_out_msg [0].output_number = current_output_command [0].output_number;
        osdp_out_msg [0].control_code = current_output_command [0].control_code;
        osdp_out_msg [0].timer_lsb = current_output_command [0].timer & 0xff;
        osdp_out_msg [0].timer_lsb = (current_output_command [0].timer > 8) & 0xff;
        out_lth = sizeof (osdp_out_msg [0]);
        status = send_message (context,
          OSDP_OUT, p_card.addr, &current_length, out_lth, (unsigned char *)osdp_out_msg);
        status = ST_OK;
      };
      break;
    case OSDP_CMDB_PRESENT_CARD:
      /*
        use card data from loaded config
      */
      context->card_data_valid = p_card.bits;
      context->creds_a_avail = creds_buffer_a_lth;
      if (context->verbosity > 2)
        fprintf (context->log, "Presenting card data (raw: %d, Creds A: %d)\n",
          context->card_data_valid, context->creds_a_avail);
      status = ST_OK;
      break;
    case OSDP_CMDB_RESET_POWER:
      context->power_report = 1;
      status = ST_OK;
      break;
    case OSDP_CMDB_SEND_POLL:
      current_length = 0;
      status = send_message (context,
        OSDP_POLL, p_card.addr, &current_length, 0, NULL);
      if (context->verbosity > 3)
        fprintf (stderr, "On-demand polling\n");
      status = ST_OK;
      break;

    // menu (keyboard-driven) cases

    case OSDP_CMD_CP_DIAG:
      context->current_menu = OSDP_MENU_CP_DIAG;
      status = ST_OK;
      break;
    case OSDP_CMD_PD_DIAG:
      context->current_menu = OSDP_MENU_PD_DIAG;
      status = ST_OK;
      break;
    case OSDP_CMD_DUMP_STATUS:
      fprintf (stderr,
"Role: %d (0=CP,1=PD,2=Mon) Chksum(0)/CRC(1): %d\n",
         context->role, m_check);
      fprintf (stderr,
"  Timeout %02d(%d.) Dump %d Debug %d.\n",
         m_idle_timeout, p_card.poll, m_dump, context->verbosity);
      fprintf (stderr,
" PwrRpt %d Special-1 %d\nCP Polls %d; PD Acks %d NAKs %d CsumErr %d\n",
         context->power_report, context->special_1,
         context->cp_polls, context->pd_acks, context->sent_naks,
         context->checksum_errs);
      if (context->role EQUALS OSDP_ROLE_PD)
      {
        fprintf (stderr, "PD Address 0x%02x ", p_card.addr);
      };
      {
        int count;
        int i;
        count = 0;
        if (osdp_buf.next > 0)
          count = osdp_buf.next;
        fprintf (stderr, "Buffer had %d bytes\n", count);
        for (i=0; i<count; i++)
          fprintf (stderr, " %02x", osdp_buf.buf [i]);
        fprintf (stderr, "\n");
        status = ST_OK;
      };
      dump_conformance (context, &osdp_conformance);
      break;
    case OSDP_CMD_EXIT:
      status = ST_EXIT;
      break;
    case 8:
      context->current_menu = OSDP_MENU_SETUP;
      status = ST_OK;
      break;
    default:
      status = ST_CMD_UNKNOWN;
      break;
    };
  };
  return (status);

} /* process_command */


int
  usage
    (void)

{ /* usage */

  int
    status;

  status = -3;
  printf ("Usage:\n");
  printf ("--checksum - use checksum\n");
  printf ("--cp       - configure as CP\n");
  printf ("--crc      - use CRC\n");
  printf ("--debug    - generate debug messages\n");
  printf ("--device=/dev/ttyUSB0 - specify device\n");
  printf ("--init-command[=command-script] - generate init command for port\n");
  printf ("--no-poll  - refrain from polling every few seconds\n");
  printf ("--pd       - configure as PD\n");
  printf ("--pd-addr=[0-126] - PD addres in decimal range 0-126\n");
  printf ("--?        - this message\n");
  return (status);

} /* usage */

