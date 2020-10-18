extern int pending_response_length;
extern unsigned char pending_response_data [1500];
extern unsigned char pending_response;

char file_transfer_buffer [2048];

unsigned char leftover_command;
unsigned char leftover_data [4*1024];
int leftover_length;
/*
  oo-ui - UI routines for open-osdp

  (C)Copyright 2017-2020 Smithee Solutions LLC

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


//extern OSDP_CONTEXT context;
extern OSDP_OUT_CMD current_output_command [];
extern OSDP_BUFFER osdp_buf;
extern OSDP_INTEROP_ASSESSMENT osdp_conformance;
extern OSDP_PARAMETERS p_card;
char tlogmsg [1024];


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
        osdp_conformance.packet_size_from_acu.test_status =
          OCONFORM_EXERCISED;
        osdp_conformance.cmd_max_rec.test_status =
          OCONFORM_EXERCISED;
      };
      break;

    case OSDP_CMDB_BIOREAD:
      status = send_bio_read_template (ctx);
      break;

    case OSDP_CMDB_BIOMATCH:
status = -1;
exit(-1);
      break;

    case OSDP_CMDB_BUSY:
      context->next_response = OSDP_BUSY;
      if (context->verbosity > 2)
        fprintf (stderr, "Declaring BUSY on next response\n");
      status = ST_OK;
      break;

    case OSDP_CMDB_CONFORM_060_24_02:
      status = ST_OK;
      strcpy (context->test_in_progress, "060-24-02"); // genauth-after-raw
      memcpy(context->test_details, details, details_length);
      context->test_details_length = details_length;
      if (context->verbosity > 2)
        fprintf (context->log, "Sending osdp_GENAUTH after next osdp_RAW\n");
      break;

    case OSDP_CMDB_CONFORM_060_25_02:
      status = ST_OK;
      strcpy (context->test_in_progress, "060-25-02"); // crauth-after-raw
      memcpy(context->test_details, details, details_length);
      context->test_details_length = details_length;
      if (context->verbosity > 2)
        fprintf (context->log, "Sending osdp_CRAUTH after next osdp_RAW\n");
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
        osdp_test_set_status(OOC_SYMBOL_cmd_id, OCONFORM_EXERCISED);
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
    case OSDP_CMDB_WITNESS:
      {
        unsigned char challenge_command [OSDP_OFFICIAL_MSG_MAX];
        OSDP_MULTI_HDR_IEC *challenge_hdr;
        int challenge_payload_size;
        int challenge_size;
        unsigned char osdp_command;
        int total_size;

        challenge_size = details_length;
        challenge_payload_size = sizeof(challenge_command);
        strcpy (context->test_in_progress, "x-challenge");
        memset (&challenge_command, 0, sizeof (challenge_command));
        total_size = challenge_size + sizeof(*challenge_hdr) - 1; // hdr has 1 byte of data

        status= oo_build_genauth(ctx, (unsigned char *)challenge_command, &challenge_payload_size, (unsigned char *)details, details_length);

#if 0
        challenge_hdr = (OSDP_MULTI_HDR_IEC *)&(challenge_command [0]);
        challenge_hdr->total_lsb = total_size & 0xff;
        challenge_hdr->total_msb = (total_size & 0xff00) >> 8;
        challenge_hdr->offset_lsb = 0;
        challenge_hdr->offset_msb = 0;
        challenge_hdr->data_len_lsb = challenge_hdr->total_lsb;
        challenge_hdr->data_len_msb = challenge_hdr->total_msb;
        memcpy(&(challenge_hdr->algo_payload), details, details_length);
dump_buffer_log(context, "CRAUTH: ", challenge_command, total_size);
#endif
        details_length = total_size;
        osdp_command = OSDP_CRAUTH;
        if (command EQUALS OSDP_CMDB_CHALLENGE)
          osdp_command = OSDP_GENAUTH;
        current_length = 0;
        status = send_message_ex(context, osdp_command, p_card.addr,
          &current_length, total_size, challenge_command, OSDP_SEC_SCS_17, 0, NULL);
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
        unsigned char key_buffer [2+OSDP_KEY_OCTETS];
        unsigned short int keybuflth;
struct timespec pre_command_sleep;
struct timespec sleep_leftover;


memset(&pre_command_sleep, 0, sizeof(pre_command_sleep));
memset(&sleep_leftover, 0, sizeof(sleep_leftover));
pre_command_sleep.tv_nsec = 175*1000*1000; // 175 milliseconds
//status_posix = 
///nanosleep(&pre_command_sleep, &sleep_leftover);
       
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

        // load it to prepare for use, and save it.
        memcpy(context->current_scbk, key_buffer+2,
          sizeof(context->current_scbk));
        oo_save_parameters(context, OSDP_SAVED_PARAMETERS, NULL);
///nanosleep(&pre_command_sleep, &sleep_leftover);
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

    case OSDP_CMDB_STOP:
      fprintf (context->log, "STOP command received.  Terminating now.\n");
      fflush(context->log);
      exit (0);
      break;

    case OSDP_CMDB_TRANSFER:
      {
        OSDP_HDR_FILETRANSFER *file_transfer;
        int size_to_read;
        int status_io;
        int transfer_send_size;
        static unsigned char xfer_buffer [OSDP_BUF_MAX];


        status = ST_OK;

        // find and open file

        strcpy(context->xferctx.filename, "./osdp_data_file");
        if (strlen (details) > 0)
          strcpy(context->xferctx.filename, details);

        fprintf(context->log, "  File transfer: file %s\n",
          context->xferctx.filename);

        context->xferctx.xferf = fopen (context->xferctx.filename, "r");
        if (context->xferctx.xferf EQUALS NULL)
        {
          fprintf(context->log, "  local open failed, errno %d\n", errno);
          strcpy(context->xferctx.filename, "/opt/osdp-conformance/etc/osdp_data_file");
          context->xferctx.xferf = fopen (context->xferctx.filename, "r");
          if (context->xferctx.xferf EQUALS NULL)
          {
            fprintf(context->log, "SEND: data file not found (checked %s as last resort)\n",
              context->xferctx.filename);
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
            fprintf(context->log, "  File transfer: Data file is %s\n",
              context->xferctx.filename);
          };
        };

        if (status EQUALS ST_OK)
        {
          struct stat datafile_status;

          stat(context->xferctx.filename, &datafile_status);
          fprintf(context->log,
            "  FIle transfer: data file %s size %d.\n",
            context->xferctx.filename, (int)datafile_status.st_size);
          context->xferctx.total_length = datafile_status.st_size;
          context->xferctx.current_offset = 0; // should be set already but just in case.

          memset (xfer_buffer, 0, sizeof(xfer_buffer));
          file_transfer = (OSDP_HDR_FILETRANSFER *)xfer_buffer;

          // load data from file starting at msg->FtData

          if (context->pd_cap.rec_max > 0)
          {
            if (context->max_message EQUALS 0)
            {
              context->max_message = context->pd_cap.rec_max;
              if (context->max_message >800) context->max_message = 800;
            };
          };
          if (context->max_message EQUALS 0)
          {
            context->max_message = 128;
            fprintf(stderr, "max message unset, setting it to 128\n");
            context->xferctx.current_send_length = context->max_message;
          };
          size_to_read = context->max_message;
          size_to_read = size_to_read + 1 - sizeof(OSDP_HDR_FILETRANSFER);
fprintf(stderr, "Reading %d. from file to start.\n", size_to_read);
memset(&(file_transfer->FtData), 0, size_to_read);
          status_io = fread (&(file_transfer->FtData), sizeof (unsigned char), size_to_read, context->xferctx.xferf);

          // if what's left is less than allowed size, adjust

          if (status_io < size_to_read)
            size_to_read = status_io;

          file_transfer->FtType = OSDP_FILETRANSFER_TYPE_OPAQUE;
          context->xferctx.total_sent = size_to_read;
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
          status = send_message_ex(context, OSDP_FILETRANSFER, p_card.addr, &current_length,
            transfer_send_size, (unsigned char *)file_transfer,
          OSDP_SEC_SCS_17, 0, NULL);

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
        osdp_test_set_status(OOC_SYMBOL_cmd_comset, OCONFORM_EXERCISED);
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
"  Dump %d Debug %d.\n",
         m_dump, context->verbosity);
//"  Timeout %ld(%d.) Dump %d Debug %d.\n",
//         context->timer[0].i_sec, p_card.poll, m_dump, context->verbosity);
      fprintf (stderr,
" PwrRpt %d\nACU Polls %d; PD Acks %d NAKs %d CsumErr %d\n",
         context->power_report,
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
            fprintf(context->log, "    osdp_ID, L=%u V=%02x\n",
              (unsigned)sizeof(param), param [0]);
          };
          status = send_message_ex (context, OSDP_ID, p_card.addr,
            &current_length, sizeof (param), param,
            OSDP_SEC_SCS_17, 0, NULL);

          if (context->verbosity > 3)
            fprintf (stderr, "Requesting PD Ident\n");
          osdp_test_set_status(OOC_SYMBOL_cmd_id, OCONFORM_EXERCISED);
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
      // details is the time, lsb/msb
      {
        char keepactive_time [2];

        memcpy(keepactive_time, details, 2);
        status = ST_OK;
        status = send_message (context,
          OSDP_KEEPACTIVE, p_card.addr, &current_length,
          sizeof (keepactive_time), (unsigned char *)&keepactive_time);
      };
      break;

    case OSDP_CMDB_KEYPAD:
      {
        char keypad_message [1+1+9+1]; // built for 9 digits

        memset (&keypad_message, 0, sizeof (keypad_message));
        /*
          assume reader 0
        */
        keypad_message [0] = 0;
        strcpy (keypad_message+2, details); // made to be 9 or less by input mechanism
        keypad_message [1] = strlen (keypad_message+2);

        pending_response_length = 2 + strlen(details);
        memcpy(pending_response_data, keypad_message, pending_response_length);
        pending_response = OSDP_KEYPAD;

        if (context->verbosity > 3)
          fprintf (stderr, "Sending keypad response %s\n",
            keypad_message+2);
        SET_PASS (context, "4-11-1");
      };
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
        status = send_message (context,
          OSDP_LSTAT, p_card.addr, &current_length, 0, NULL);
        osdp_conformance.cmd_lstat.test_status =
          OCONFORM_EXERCISED;
        if (context->verbosity > 3)
          fprintf (stderr, "Requesting Local Status\n");
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

