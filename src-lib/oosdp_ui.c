unsigned char leftover_command;
unsigned char leftover_data [4*1024];
int leftover_length;
/*
  oosdp_ui - UI routines for open-osdp

  (C)Copyright 2017-2019 Smithee Solutions LLC
  (C)Copyright 2014-2017 Smithee Spelvin Agnew & Plinge, Inc.

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
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>

#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>
#include <iec-xwrite.h>


extern OSDP_CONTEXT context;
extern OSDP_OUT_CMD current_output_command [];
extern OSDP_BUFFER osdp_buf;
extern OSDP_INTEROP_ASSESSMENT osdp_conformance;
extern OSDP_PARAMETERS p_card;
char tlogmsg [1024];


int
  process_command
  (int command,
  OSDP_CONTEXT *context,
  unsigned int details_length,
  int details_param_1,
  char *details)

{ /* process_command */

  extern unsigned char *creds_buffer_a;
  extern int creds_buffer_a_lth;
  int current_length;
  int processed;
  unsigned char sec_blk [1];
  int status;
  unsigned char value [4];


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
        osdp_conformance.packet_size_from_acu.test_status =
          OCONFORM_EXERCISED;
        osdp_conformance.cmd_max_rec.test_status =
          OCONFORM_EXERCISED;
      };
      break;

    case OSDP_CMDB_BUSY:
      context->next_response = OSDP_BUSY;
      if (context->verbosity > 2)
        fprintf (stderr, "Declaring BUSY on next response\n");
      status = ST_OK;
      break;

    case OSDP_CMDB_CONFORM_2_2_1:
      strcpy (context->test_in_progress, "2-2-1");
      osdp_conformance.signalling.test_status = OCONFORM_FAIL;
      status = send_comset (context, OSDP_CONFIGURATION_ADDRESS, p_card.addr,
        "9600");
      break;

    case OSDP_CMDB_CONFORM_2_2_2:
      strcpy (context->test_in_progress, "2-2-2");
      osdp_conformance.alt_speed_2.test_status = OCONFORM_FAIL;
//      status = send_comset (context, p_card.addr, "19200");
      status = send_comset (context, OSDP_CONFIGURATION_ADDRESS, p_card.addr,
        "19200");
      break;

    case OSDP_CMDB_CONFORM_2_2_3:
      strcpy (context->test_in_progress, "2-2-3");
      osdp_conformance.alt_speed_3.test_status = OCONFORM_FAIL;
      status = send_comset (context, OSDP_CONFIGURATION_ADDRESS, p_card.addr,
        "38400");
      break;

    case OSDP_CMDB_CONFORM_2_2_4:
      strcpy (context->test_in_progress, "2-2-4");
      osdp_conformance.alt_speed_4.test_status = OCONFORM_FAIL;
      status = send_comset (context, OSDP_CONFIGURATION_ADDRESS, p_card.addr,
        "115200");
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
        osdp_conformance.packet_size_limits.test_status =
          OCONFORM_EXERCISED;
        status = ST_OK;
      };
      break;

    case OSDP_CMDB_CONFORM_2_11_3:
      // request ID but do it on the "all stations" PD address.

      {
        unsigned char param [1];

        strcpy (context->test_in_progress, "2_11_3");
        param [0] = 0;
        current_length = 0;
        status = send_message_ex (context, OSDP_ID, 0x7F,
          &current_length, sizeof (param), param,
          OSDP_SEC_SCS_17, 0, NULL);

        osdp_conformance.address_config.test_status = OCONFORM_EXERCISED;
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
        OSDP_MFG_HEADER
          omfg;

        osdp_conformance.resp_mfg.test_status = OCONFORM_EXERCISED;
        strcpy (context->test_in_progress, "3_20_1");
        // send the tester's vendor code
        omfg.vendor_code [0] = context->MFG_oui [0];
        omfg.vendor_code [1] = context->MFG_oui [1];
        omfg.vendor_code [2] = context->MFG_oui [2];
        omfg.command_id = 1;
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
      {
        unsigned char challenge_command [1024];
//        int offset;
//        int total_size;


//        total_size = 8; // tbd

        strcpy (context->test_in_progress, "x-challenge");
        memset (&challenge_command, 0, sizeof (challenge_command));

 //       offset = 0;
        // multi-part header
#if 0
// KLUDGE: assume it'll all fit in this one message
multipart total lsb is 0x00ff and total_size
multipart total msb os total_size >> 8;
multipart offset lsb is 0
multipart offset msb is 0
multipart fragsize lsb is total_size & 0xff
multipart fragsize msb is total_size >> 8

        memcpy(genauth_command+offset, details, details_length);

        if (context->verbosity > 3)
          fprintf (stderr,
"Requesting GenAuth\n");
        current_length = 0;
        status = send_message (context,
          OSDP_CRAUTH, p_card.addr, &current_length, sizeof (genauth_commanbuzzer_control), (unsigned char *)&buzzer_control);
#endif
      };
      break;

    case OSDP_CMDB_INDUCE_NAK:
      {
        unsigned char nothing;

        strcpy (context->test_in_progress, "4_2_1");
        current_length = 0;
        status = send_message (context,
          OSDP_UNDEF, p_card.addr, &current_length, 0, &nothing);
      };
      break;

    case OSDP_CMDB_KEYSET:
      {
        unsigned char key_buffer [OSDP_KEY_OCTETS];
        unsigned short int keybuflth;

        keybuflth = sizeof(key_buffer);
        status = osdp_string_to_buffer(context,
          details, key_buffer, &keybuflth);
        current_length = 0;
        if (context->verbosity > 3)
        {
          dump_buffer_log(context, "KEYSET key:", key_buffer, keybuflth);
        };
        status = send_message_ex(context, OSDP_KEYSET, p_card.addr,
          &current_length, keybuflth, key_buffer,
          OSDP_SEC_SCS_17, 0, NULL);
        osdp_conformance.cmd_keyset.test_status =
          OCONFORM_EXERCISED;
      };
      break;

    case OSDP_CMDB_MFG:
      {
        unsigned char data [1024];
        int i;
        int idx;
        OSDP_MFG_ARGS *oargs;
        OSDP_MFG_HEADER *omfg;
        int out_idx;
        int send_length;
        char tmps [3];

        oargs = (OSDP_MFG_ARGS *)details;
        omfg = (OSDP_MFG_HEADER *)data;
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
        omfg->command_id = oargs->command_ID;
        send_length = sizeof(OSDP_MFG_HEADER) - 1;
        out_idx = 0;
fprintf(stderr, "string is >%s<\n", oargs->c_s_d);
        for (idx=0; idx<strlen(oargs->c_s_d); idx=idx+2)
        {
          tmps[2] = 0;
          memcpy(tmps, (idx)+(oargs->c_s_d), 2);
          sscanf(tmps, "%x", &i);
          *(&(omfg->data)+out_idx) = i;
          if (context->verbosity > 3)
            fprintf(stderr, "mfg data %d. s %s hex value 0x%x\n",
              out_idx, tmps, i);
          out_idx ++;
          send_length ++;
        };

fprintf(stderr,"w:%d (250)\n", context->last_was_processed);
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
        }
        else
        {
          current_length = 0;
          status = send_message (context,
            OSDP_MFG, p_card.addr, &current_length, send_length, data);
        };
        status = ST_OK;
      };
      break;

    case OSDP_CMDB_STOP:
      fprintf (context->log, "STOP command received.  Terminating now.\n");
      exit (0);
      break;

    case OSDP_CMDB_TRANSFER:
      {
        char data_filename [1024];
        OSDP_HDR_FILETRANSFER *file_transfer;
        FILE *osdp_data_file;
        int size_to_read;
        int status_io;
        int transfer_send_size;
        unsigned char xfer_buffer [MAX_BUF];


        status = ST_OK;

        // find and open file

        strcpy(data_filename, "./osdp_data_file");
        if (strlen (details) > 0)
          strcpy(data_filename, details);
        strcpy(context->xferctx.filename, data_filename);
        osdp_data_file = fopen (data_filename, "r");
        if (osdp_data_file EQUALS NULL)
        {
fprintf(stderr, "local open failed, errno %d\n", errno);
          strcpy(data_filename, "/opt/osdp-conformance/etc/osdp_data_file");
          osdp_data_file = fopen (data_filename, "r");
          if (osdp_data_file EQUALS NULL)
          {
            fprintf(context->log, "SEND: data file not found (checked %s as last resort)\n",
              data_filename);
            status = ST_OSDP_BAD_TRANSFER_FILE;
          }
          else 
            if (context->verbosity > 3)
              fprintf(stderr, "data file is /opt/osdp-conformance/etc/osdp_data_file\n");
        }
        else
        {
          if (context->verbosity > 3)
          {
            fprintf(stderr, "data file is ./osdp_data_file\n");
            fprintf(context->log, "SEND: Data file is %s\n",
              data_filename);
          };
        };

        if (status EQUALS ST_OK)
        {
          struct stat datafile_status;

          context->xferctx.xferf = osdp_data_file;
          stat(data_filename, &datafile_status);
fprintf(stderr, "data file %s size %d.\n", data_filename, (int)datafile_status.st_size);
          context->xferctx.total_length = datafile_status.st_size;
          context->xferctx.current_offset = 0; // should be set already but just in case.

          memset (xfer_buffer, 0, sizeof(xfer_buffer));
          file_transfer = (OSDP_HDR_FILETRANSFER *)xfer_buffer;

          // load data from file starting at msg->FtData

          if (context->pd_cap.rec_max > 0)
            if (context->max_message EQUALS 0)
              context->max_message = context->pd_cap.rec_max;
          if (context->max_message EQUALS 0)
          {
            context->max_message = 128;
            fprintf(stderr, "max message unset, setting it to 128\n");
            context->xferctx.current_send_length = context->max_message;
          };
          size_to_read = context->max_message;
          size_to_read = size_to_read + 1 - sizeof(OSDP_HDR_FILETRANSFER);
fprintf(stderr, "Reading %d. from file to start.\n", size_to_read);
          status_io = fread (&(file_transfer->FtData), sizeof (unsigned char), size_to_read, osdp_data_file);

          // if what's left is less than allowed size, adjust

          if (status_io < size_to_read)
            size_to_read = status_io;

          file_transfer->FtType = OSDP_FILETRANSFER_TYPE_OPAQUE;
          osdp_doubleByte_to_array(size_to_read, file_transfer->FtFragmentSize);
          osdp_quadByte_to_array(context->xferctx.total_length, file_transfer->FtSizeTotal);
          osdp_quadByte_to_array(context->xferctx.current_offset, file_transfer->FtOffset); 

          if (context->verbosity > 3)
            fprintf (stderr, "Initiating File Transfer\n");

          context->xferctx.state = OSDP_XFER_STATE_TRANSFERRING;
          current_length = 0;
          transfer_send_size = size_to_read;
          transfer_send_size = transfer_send_size - 1 + sizeof (*file_transfer);
fprintf(stderr, "xfer size %d.\n", transfer_send_size);
          status = send_message (context,
            OSDP_FILETRANSFER, p_card.addr, &current_length,
            transfer_send_size, (unsigned char *)file_transfer);

          // after the send update the current offset
          context->xferctx.current_offset = context->xferctx.current_offset + size_to_read;
        };
      };
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
          fprintf (stderr,
"Requesting Buzz: tone %d on %d(x100ms) off %d(x100ms) repeat %d\n",
            buzzer_control [1], buzzer_control [2],
            buzzer_control [3], buzzer_control [4]);
        current_length = 0;
        status = send_message_ex (context, OSDP_BUZ, p_card.addr,
          &current_length, sizeof (buzzer_control), (unsigned char *)&buzzer_control,
          OSDP_SEC_SCS_17, 0, NULL);
      };
      break;

    case OSDP_CMDB_CAPAS:
      {
        unsigned char
          param [1];

        current_length = 0;
        param [0] = 0;
        status = send_message_ex (context, OSDP_CAP, p_card.addr,
          &current_length, sizeof (param), param,
          OSDP_SEC_SCS_17, 0, NULL);
        if (context->verbosity > 2)
          fprintf (stderr, "Requesting Capabilities Report\n");
      };
      status = ST_OK;
      break;

    case OSDP_CMDB_COMSET:
      {
        int
          new_speed;


        new_speed = 0;
        memcpy (&new_speed, details+4, 4);
        sprintf (context->serial_speed, "%d", new_speed);
        context->new_address = details [0];
        osdp_conformance.cmd_comset.test_status = OCONFORM_EXERCISED;
        if (context->verbosity > 2)
          fprintf (stderr, "Set Comms: addr to %02x speed to %s.\n",
            context->new_address, context->serial_speed);
        status = send_comset (context, OSDP_CONFIGURATION_ADDRESS,
          context->new_address, context->serial_speed);

        // reset protocol to beginning

        context->next_sequence = 0;
        context->last_response_received = 0;
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
"  Timeout %ld(%d.) Dump %d Debug %d.\n",
         context->timer[0].i_sec, p_card.poll, m_dump, context->verbosity);
      fprintf (stderr,
" PwrRpt %d\nCP Polls %d; PD Acks %d NAKs %d CsumErr %d\n",
         context->power_report,
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
        status = oo_write_status (context);

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
fprintf(stderr,"w:%d\n", context->last_was_processed);
        if (osdp_awaiting_response(context))
        {
          fprintf(stderr, "busy before OSDP_ID, skipping send\n");
          fflush(stderr); fflush(context->log);
          leftover_command = OSDP_ID;
          memcpy(leftover_data, param, sizeof(param));
          leftover_length = sizeof(param);
          context->left_to_send = leftover_length;
        }
        else
        {
          if (context->verbosity > 3)
          {
            fprintf(context->log, "    osdp_ID, L=%ld V=%02x\n",
              sizeof(param), param [0]);
          };
          status = send_message_ex (context, OSDP_ID, p_card.addr,
            &current_length, sizeof (param), param,
            OSDP_SEC_SCS_17, 0, NULL);

          if (context->verbosity > 3)
            fprintf (stderr, "Requesting PD Ident\n");
          osdp_conformance.cmd_id.test_status = OCONFORM_EXERCISED;
        };
      };
      status = ST_OK;
      break;

    case OSDP_CMDB_INIT_SECURE:
      {
        unsigned char sec_blk_1 [1];

        status = ST_OK;
        current_length = 0;
        context->secure_channel_use [OO_SCU_ENAB] = OO_SCS_USE_ENABLED;

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
            status = send_secure_message (context,
              OSDP_CHLNG, p_card.addr, &current_length, 
              sizeof (context->rnd_a), context->rnd_a,
              OSDP_SEC_SCS_11, sizeof (sec_blk_1), sec_blk_1);
          };
        };
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
          status = send_message (context,
            OSDP_ISTAT, p_card.addr, &current_length, 0, NULL);
          if (context->verbosity > 3)
            fprintf (stderr, "Requesting Input Status\n");
          osdp_conformance.cmd_istat.test_status =
            OCONFORM_EXERCISED;
        };
      };
      status = ST_OK;
      break;

    case OSDP_CMDB_KEEPACTIVE:
      // details is the time, as an int; convert to network time (short int)
      {
        short int keepactive_time;

        keepactive_time = *(int *)details;
        keepactive_time = htons(keepactive_time);
        status = ST_OK;
        status = send_message (context,
          OSDP_KEEPACTIVE, p_card.addr, &current_length,
          sizeof (keepactive_time), (unsigned char *)&keepactive_time);
      };
      break;

    case OSDP_CMDB_KEYPAD:
      {
        char
          keypad_message [1+1+9+1]; // built for 9 digits

        memset (&keypad_message, 0, sizeof (keypad_message));
        /*
          assume reader 0
        */
        keypad_message [0] = 0;
        strcpy (keypad_message+2, details); // made to be 9 or less by input mechanism
        keypad_message [1] = strlen (keypad_message+2);
        current_length = 0;
        // buffer size gets -1 'cause there was a null at the end to make the string stuff work.
        status = send_message (context,
          OSDP_KEYPAD, p_card.addr, &current_length, sizeof (keypad_message)-1, (unsigned char *)&keypad_message);
        if (context->verbosity > 3)
          fprintf (stderr, "Sending keypad response %s\n",
            keypad_message+2);
        SET_PASS (context, "4-11-1");
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
        int details_length;
        unsigned char error_details [1024];
        OSDP_RDR_LED_CTL
          led_control_message;

        memcpy (&led_control_message, details, sizeof (led_control_message));
fprintf(stderr,
"Rdr %d. LED %d. TEMP Ctl %02x ON=%02x OFF=%02x ON-COL=%02x OFF-COL=%02x Timer LSB %02x MSB %02x\n",
  led_control_message.reader, led_control_message.led,
  led_control_message.temp_control, 
  led_control_message.temp_on, led_control_message.temp_off,
  led_control_message.temp_on_color, led_control_message.temp_off_color,
  led_control_message.temp_timer_lsb, led_control_message.temp_timer_msb);
fprintf(stderr,
"  PERM Ctl %02x ON-Time=%02x OFF-Time=%02x ON-COL=%02x OFF-COL=%02x\n",
  led_control_message.perm_control, 
  led_control_message.perm_on_time, led_control_message.perm_off_time,
  led_control_message.perm_on_color, led_control_message.perm_off_color);

        details_length = sizeof (error_details);
        status = osdp_validate_led_values (&led_control_message,
          error_details, &details_length);
        if (status EQUALS ST_OK)
        {
          current_length = 0;
          status = send_message_ex (context, OSDP_LED, p_card.addr,
            &current_length, sizeof (led_control_message), (unsigned char *)&led_control_message,
            OSDP_SEC_SCS_17, 0, NULL);
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

    case OSDP_CMDB_OSTAT:
      {
        current_length = 0;
        /*
          osdp_OSTAT requires no arguments.
        */
        current_length = 0;
        status = send_message (context,
          OSDP_OSTAT, p_card.addr, &current_length, 0, NULL);
        if (context->verbosity > 3)
          fprintf (stderr, "Requesting Output Status\n");
      };
      status = ST_OK;
      break;

    case OSDP_CMDB_OUT:
      {
        OSDP_OUT_MSG
          osdp_out_msg [16];
        int
          out_lth;

        current_length = 0;
fprintf(stderr, "DEBUG: at OSDP_CMDB_OUT: output number is %d.\n",
  current_output_command [0].output_number);
        osdp_out_msg [0].output_number =
          current_output_command [0].output_number;
        osdp_out_msg [0].control_code = current_output_command [0].control_code;
        osdp_out_msg [0].timer_lsb = current_output_command [0].timer & 0xff;
        osdp_out_msg [0].timer_msb =
          (current_output_command [0].timer > 8) & 0xff;
        out_lth = sizeof (osdp_out_msg [0]);
        status = send_message (context,
          OSDP_OUT, p_card.addr, &current_length, out_lth,
          (unsigned char *)osdp_out_msg);
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
      status = send_message (context,
        OSDP_RSTAT, p_card.addr, &current_length, 0, NULL);
      if (context->verbosity > 2)
        fprintf (stderr, "Requesting (External) Reader (Tamper) Status\n");
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
      };
      break;

    default:
      status = ST_CMD_UNKNOWN;
      break;
    };
  };
  return (status);

} /* process_command */

