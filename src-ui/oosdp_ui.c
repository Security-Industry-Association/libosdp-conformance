/*
  oosdp_ui - UI routines for open-osdp

  (C)2017-2021 Smithee Solutions LLC

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
        fprintf (stderr, "Requesting Local Status Report\n");
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
"Role: %d (0=ACU,1=PD,2=Mon) Chksum(0)/CRC(1): %d\n",
         context->role, m_check);
      fprintf (stderr,
"  Timeout %02d(%d.) Dump %d Debug %d.\n",
         m_idle_timeout, p_card.poll, m_dump, context->verbosity);
      fprintf (stderr,
" PwrRpt %d Special-1 %d\nACU Polls %d; PD Acks %d NAKs %d CsumErr %d\n",
         context->power_report, context->special_1,
         context->acu_polls, context->pd_acks, context->sent_naks,
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

    case OSDP_CMDB_LSTAT:
      {
        current_length = 0;
        /*
          osdp_LSTAT requires no arguments.
        */
        current_length = 0;
        status = send_message (context,
          OSDP_LSTAT, p_card.addr, &current_length, 0, NULL);
        osdp_conformance.cmd_lstat.test_status =
          OCONFORM_EXERCISED;
        if (context->verbosity > 3)
          fprintf (stderr, "Requesting Local Status\n");
      };
      status = ST_OK;
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
//        led_control_message.perm_on_color = OSDP_LEDCOLOR_RED;
        led_control_message.perm_on_color = details [0];
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

    case OSDP_CMDB_RSTAT:
      current_length = 0;
      /*
        osdp_RSTAT requires no arguments.
      */
      current_length = 0;
      status = send_message (context,
        OSDP_RSTAT, p_card.addr, &current_length, 0, NULL);
      osdp_conformance.cmd_rstat.test_status =
        OCONFORM_EXERCISED;
      if (context->verbosity > 3)
        fprintf (stderr, "Requesting Remote Status\n");
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
    case OSDP_CMDB_TAMPER:
      context->tamper = 1;
      status = ST_OK;
      break;
    case OSDP_CMDB_TEXT:
      {
        OSDP_TEXT_HEADER
          otxt;

        otxt.reader = 0;
        otxt.tc = 0;
        otxt.tsec = 0;
        otxt.row = 0;
        otxt.col = 0;
        otxt.length = strlen (context->text);
        memcpy (otxt.text, context->text, 1024);
        current_length = 0;
        status = send_message (context,
          OSDP_TEXT, p_card.addr, &current_length,
          sizeof(otxt)-sizeof(otxt.text) + strlen(otxt.text),
          (unsigned char *)&otxt);
      };
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
"Role: %d (0=ACU,1=PD,2=Mon) Chksum(0)/CRC(1): %d\n",
         context->role, m_check);
      fprintf (stderr,
"  Timeout %02d(%d.) Dump %d Debug %d.\n",
         m_idle_timeout, p_card.poll, m_dump, context->verbosity);
      fprintf (stderr,
" PwrRpt %d Special-1 %d\nACU Polls %d; PD Acks %d NAKs %d CsumErr %d\n",
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
  printf ("--cp       - configure as ACU\n");
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

