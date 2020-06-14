int pending_response_length;
unsigned char pending_response_data [1500];
unsigned char pending_response;
/*
  oosdp-actions - open osdp action routines

  (C)Copyright 2017-2020 Smithee Solutions LLC
  (C)Copyright 2014-2017 Smithee,Spelvin,Agnew & Plinge, Inc.

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


#include <aes.h>


#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>


extern OSDP_INTEROP_ASSESSMENT
  osdp_conformance;
extern OSDP_PARAMETERS
  p_card;
char tlogmsg [2*1024];


int
  action_osdp_COMSET
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_COMSET */

  int current_length;
  int i;
  unsigned char osdp_com_response_data [5];
  char logmsg [1024];
  int status;


  memset (osdp_com_response_data, 0, sizeof (osdp_com_response_data));
  i = *(1+msg->data_payload) + (*(2+msg->data_payload) << 8) +
    (*(3+msg->data_payload) << 16) + (*(4+msg->data_payload) << 24);

  sprintf(logmsg, "COMSET Data Payload %02x %02x%02x%02x%02x %d. 0x%x",
    *(0+msg->data_payload), *(1+msg->data_payload),
    *(2+msg->data_payload), *(3+msg->data_payload),
    *(4+msg->data_payload), i, i);
  fprintf(ctx->log, "%s\n", logmsg);

  p_card.addr = *(msg->data_payload); // first byte is new PD addr
  fprintf (ctx->log, "PD Address set to %02x\n", p_card.addr);

  osdp_com_response_data [0] = p_card.addr;
  *(unsigned short int *)(osdp_com_response_data+1) = 9600; // hard-code to 9600 BPS
  status = ST_OK;
  current_length = 0;
        status = send_message_ex (ctx, OSDP_COM, p_card.addr,
          &current_length, sizeof (osdp_com_response_data), osdp_com_response_data,
          OSDP_SEC_SCS_18, 0, NULL);
  if (ctx->verbosity > 2)
  {
          sprintf (logmsg, "Responding with OSDP_COM");
          fprintf (ctx->log, "%s\n", logmsg); logmsg[0]=0;
  };
  if (status EQUALS ST_OK)
  {
    ctx->new_address = p_card.addr;
    sprintf(ctx->serial_speed, "%d", i);

    fprintf(ctx->log, "comset to addr %02x speed %s\n",
      p_card.addr, ctx->serial_speed);
    if (ctx->verbosity > 2)
      fprintf(ctx->log, "OSDP_COMSET received, setting addr to %02x speed to %s.\n",
        p_card.addr, ctx->serial_speed);
    (void)oo_save_parameters(ctx, OSDP_SAVED_PARAMETERS, NULL);
    status = init_serial (ctx, p_card.filename);
  };
  return (status);

} /* action_osdp_COMSET */


int
  action_osdp_FILETRANSFER
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_FILETRANSFER */

  OSDP_HDR_FILETRANSFER *filetransfer_message;
  unsigned short int fragment_size;
  unsigned int offset;
  OSDP_HDR_FTSTAT response;
  int status;
  int status_io;
  unsigned char *transfer_fragment;


  status = ST_OK;
  filetransfer_message = (OSDP_HDR_FILETRANSFER *)(msg->data_payload);
  memset (&response, 0, sizeof(response));

  if (status EQUALS ST_OK)
    status = osdp_filetransfer_validate(ctx, filetransfer_message,
      &fragment_size, &offset);
  (void)oosdp_make_message (OOSDP_MSG_FILETRANSFER, tlogmsg, msg);
  fprintf(ctx->log, "%s\n", tlogmsg); fflush(ctx->log);
// check FtType
// check FtFragmentSize sane

  if (status EQUALS ST_OK)
  {
    transfer_fragment = &(filetransfer_message->FtData);
    if (offset EQUALS 0)
    {
      ctx->xferctx.xferf = fopen("./incoming_data", "w");
      if (ctx->xferctx.xferf EQUALS NULL)
        status = ST_OSDP_BAD_TRANSFER_SAVE;
      if (status != ST_OK)
      {
        // if open of write file failed, send back error and reset

        osdp_doubleByte_to_array(OSDP_FTSTAT_ABORT_TRANSFER,
          response.FtStatusDetail);
        status = osdp_send_ftstat(ctx, &response);
        (void) osdp_wrapup_filetransfer(ctx);
      };
    };
  };
  if (status EQUALS ST_OK)
  {
    status_io = fwrite(transfer_fragment, sizeof(transfer_fragment[0]),
      fragment_size, ctx->xferctx.xferf);
    if (status_io != fragment_size)
    {
      // not same error but need to abort so same status code on the wire

      osdp_doubleByte_to_array(OSDP_FTSTAT_ABORT_TRANSFER,
        response.FtStatusDetail);
      status = osdp_send_ftstat(ctx, &response);
      if (status EQUALS ST_OK)
        osdp_wrapup_filetransfer(ctx);
    }
    else
    {
      // update counters

      ctx->xferctx.current_offset = ctx->xferctx.current_offset + fragment_size;
      if (ctx->xferctx.current_offset EQUALS ctx->xferctx.total_length)
      {
        osdp_doubleByte_to_array(OSDP_FTSTAT_PROCESSED,
          response.FtStatusDetail);
        status = osdp_send_ftstat(ctx, &response);
        osdp_wrapup_filetransfer(ctx);
      }
      else
      {
        osdp_doubleByte_to_array(ctx->max_message, response.FtUpdateMsgMax);
fprintf(stderr, "current_offset : \"%d\n", ctx->xferctx.current_offset);
fprintf(stderr, "total_length : %d\n", ctx->xferctx.total_length);
fprintf(stderr, "current_send_length : %d\n", ctx->xferctx.current_send_length);
fprintf(stderr, "response mmax %02x %02x\n",
  response.FtUpdateMsgMax [0],
  response.FtUpdateMsgMax [1]);
        osdp_doubleByte_to_array(OSDP_FTSTAT_OK, response.FtStatusDetail);
        status = osdp_send_ftstat(ctx, &response);
      };
    };
  };
  if (status != ST_OK)
  {
    // something bad happened.  abort.  But tell the caller we dealt with it.

    osdp_doubleByte_to_array(OSDP_FTSTAT_ABORT_TRANSFER,
      response.FtStatusDetail);
    status = osdp_send_ftstat(ctx, &response);
    if (status EQUALS ST_OK)
      osdp_wrapup_filetransfer(ctx);

    status = ST_OK; // 'cause we recovered.
  };

  // update status json
  if (status EQUALS ST_OK)
    status = oo_write_status (ctx);
  return (status);

} /* action_osdp_FILETRANSFER */


/*
  action_osdp_FTSTAT - processing incoming osdp_FTSTAT message at CP

  this causes the next chunk to be transferred, or terminates the transfer,
  or switches to "finishing" mode if the PD needs more time.
*/
int
  action_osdp_FTSTAT
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_FTSTAT */

  OSDP_HDR_FTSTAT *ftstat_message;
  int status;


  osdp_test_set_status(OOC_SYMBOL_cmd_filetransfer, OCONFORM_EXERCISED);
  osdp_test_set_status(OOC_SYMBOL_resp_ftstat, OCONFORM_EXERCISED);
  ftstat_message = (OSDP_HDR_FTSTAT *)(msg->data_payload);
  status = osdp_ftstat_validate(ctx, ftstat_message);
  (void)oosdp_make_message (OOSDP_MSG_FTSTAT, tlogmsg, msg);
  fprintf(ctx->log, "%s\n", tlogmsg); fflush(ctx->log);
  if (status EQUALS ST_OSDP_FILEXFER_FINISHING)
  {
    // the filetransfer context was already set to "finishing".
    // (and this is ok so reset the status)
    status = ST_OK;
  };
  if (status EQUALS ST_OSDP_FILEXFER_WRAPUP)
  {
    osdp_wrapup_filetransfer(ctx);
    status = ST_OK;
  }
  else
  {
    if (status EQUALS ST_OK)
  {
    // if more send more

fprintf(stderr, "t=%d o=%d\n",
  ctx->xferctx.total_length, ctx->xferctx.current_offset);

    if (ctx->xferctx.total_length > ctx->xferctx.current_offset)
    {
      status = osdp_send_filetransfer(ctx);
    }
    else
    {
      // if we're done and it's not "finishing" then wrap up
      if (ctx->xferctx.state != OSDP_XFER_STATE_FINISHING)
        osdp_wrapup_filetransfer(ctx);
      else
        status = osdp_send_filetransfer(ctx); // will send benign msg
    };
  };
  };
  if (status EQUALS ST_OK)
    status = oo_write_status (ctx);
  return (status);

} /* action_osdp_FTSTAT */


int
  action_osdp_MFG
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_MFG */

  int current_length;
  int i;
  OSDP_MFG_HEADER *mfg;
  OSDP_CONFIG_GUID *mfg_config_guid;
  unsigned char osdp_com_response_data [5];
  int status;
  int unknown;


  status = ST_OK;
  unknown = 1;
  mfg = (OSDP_MFG_HEADER *)(msg->data_payload);
  mfg_config_guid = (OSDP_CONFIG_GUID *)&(mfg->data);

fprintf (stderr, "osdp_MFG action stub\n");
fprintf(stderr, "1:%02x 2:%02x 3:%02x cmd:%02x data:%02x\n",
  mfg->vendor_code [0], mfg->vendor_code [1], mfg->vendor_code [2],
  mfg->command_id, mfg->data);

  if (0 EQUALS memcmp(mfg->vendor_code, OOSDP_MFG_VENDOR_CODE, sizeof(OOSDP_MFG_VENDOR_CODE)))
  {
    switch (mfg->command_id)
    {
    case OOSDP_MFG_CONFIG_GUID:
      if (0 EQUALS memcmp(mfg_config_guid->guid, ctx->my_guid, sizeof(ctx->my_guid)))
      {
        unknown = 0;
        p_card.addr = mfg_config_guid->new_address;
        i = *(1+mfg_config_guid->new_speed) + (*(2+mfg_config_guid->new_speed) << 8) +
          (*(3+mfg_config_guid->new_speed) << 16) + (*(4+mfg_config_guid->new_speed) << 24);

        // respond with osdp_COM, then set the speed. Just like COMSET.
        osdp_com_response_data [0] = p_card.addr;
        *(unsigned short int *)(osdp_com_response_data+1) = i;
        current_length = 0;
        status = send_message (ctx,
          OSDP_COM, p_card.addr, &current_length,
          sizeof (osdp_com_response_data), osdp_com_response_data);

        // set the speed and address
        ctx->new_address = p_card.addr;
        status = init_serial (ctx, p_card.filename);
      };
      break;
    case OOSDP_MFG_PING:
      {
        unsigned char mfg_response [sizeof(struct osdp_mfg_header) + 4];
        OSDP_MFG_HEADER *mh;

        unknown = 0; // we known this guy
        mh = (OSDP_MFG_HEADER *)mfg_response;
        memcpy(mh->vendor_code, OOSDP_MFG_VENDOR_CODE, sizeof(OOSDP_MFG_VENDOR_CODE));
        mh->command_id = OOSDP_MFGR_PING_ACK;
        memcpy(&(mh->data), (char *)&(mfg->data), 4); // arbitrarily copy the 4 detail bytes back at ya
        current_length = 0;
        status = send_message(ctx, OSDP_MFGREP, p_card.addr, &current_length, sizeof(mfg_response), mfg_response);
      };
      break;
    };
  };
  if (unknown)
  {
    // dunno this mfg command, nak it

    int nak_length;
    unsigned char osdp_nak_response_data [1024];

    current_length = 0;
    osdp_nak_response_data [0] = OO_NAK_UNK_CMD;
    memcpy(osdp_nak_response_data, mfg->vendor_code, 3);
    nak_length = 3;
fprintf(ctx->log, "DEBUG: 5 NAK: %d.\n", osdp_nak_response_data [0]);
    status = send_message (ctx, OSDP_NAK, p_card.addr, &current_length, nak_length,
      osdp_nak_response_data); ctx->sent_naks ++;
  };

  return (status);

} /* action_osdp_MFG */


int
  action_osdp_OUT
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_OUT */

  unsigned char buffer [1024];
  int current_length;
  int done;
  OSDP_OUT_MSG *outmsg;
  int status;
  int to_send;


  status = ST_OK;
  osdp_conformance.cmd_out.test_status = OCONFORM_EXERCISED;
fprintf (stderr, "data_length in OSDP_OUT: %d\n",
  msg->data_length);
#if 0
// if too many for me (my MAX) then error and NAK?
// set 'timer' to msb*256+lsb
#define OSDP_OUT_OFF_PERM_TIMEOUT (3)
#define OSDP_OUT_ON_PERM_TIMEOUT  (4)
#define OSDP_OUT_ON_TEMP_TIMEOUT  (5)
#define OSDP_OUT_OFF_TEMP_TIMEOUT (6)
#endif
  done = 0;
  if (status != ST_OK)
    done = 1;
  while (!done)
  {
    outmsg = (OSDP_OUT_MSG *)(msg->data_payload);
    sprintf (tlogmsg, "  Out: Line %02x Ctl %02x LSB %02x MSB %02x",
      outmsg->output_number, outmsg->control_code,
      outmsg->timer_lsb, outmsg->timer_msb);
    fprintf (ctx->log, "%s\n", tlogmsg);
    if ((outmsg->output_number < 0) ||
      (outmsg->output_number > (OSDP_MAX_OUT-1)))
      status = ST_OUT_TOO_MANY;
    if (status EQUALS ST_OK)
    {
      switch (outmsg->control_code)
      {
      case OSDP_OUT_NOP:
        break;
      case OSDP_OUT_OFF_PERM_ABORT:
        ctx->out [outmsg->output_number].current = 0;
        ctx->out [outmsg->output_number].timer = 0;
        break;  
      case OSDP_OUT_ON_PERM_ABORT:
        ctx->out [outmsg->output_number].current = 1;
        ctx->out [outmsg->output_number].timer = 0;
        break;  
      default:
        status = ST_OUT_UNKNOWN;
        break;
      };
    }
    else
      done = 1;

done = 1; // just first one for now.
  };

  // return osdp_OSTATR with now-current output state
  {
    int j;
    unsigned char out_status [OSDP_MAX_OUT];

    for (j=0; j<OSDP_MAX_OUT; j++)
    {
      out_status [j] = ctx->out[j].current;
    };

    to_send = OSDP_MAX_OUT;
    memcpy (buffer, out_status, OSDP_MAX_OUT);
    current_length = 0;
    status = send_message_ex (ctx, OSDP_OSTATR, p_card.addr,
      &current_length, to_send, buffer, OSDP_SEC_SCS_18, 0, NULL);
  };
  status = ST_OK;
  return (status);

} /* action_osdp_OUT */

int
  action_osdp_OSTAT
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_OSTAT */

  unsigned char buffer [1024];
  int current_length;
  int j;
  unsigned char out_status [OSDP_MAX_OUT];
  int status;
  int to_send;


  status = ST_OK;
  osdp_conformance.cmd_ostat.test_status = OCONFORM_EXERCISED;

  for (j=0; j<OSDP_MAX_OUT; j++)
  {
    out_status [j] = ctx->out[j].current;
  };
  to_send = OSDP_MAX_OUT;
  memcpy (buffer, out_status, OSDP_MAX_OUT);
  current_length = 0;
  status = send_message (ctx, OSDP_OSTATR, p_card.addr,
    &current_length, to_send, buffer);
  return (status);

} /* action_osdp_OUT */


int
  action_osdp_PDCAP
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_PDCAP */

  char aux [4096];
  OSDP_PDCAP_ENTRY *entry;
  int i;
  int max_multipart;
  int num_entries;
  unsigned char *ptr;
  int status;
  char temp_string [1024];


  status = ST_OK;
  strcpy(aux, "\"capabilities\":{");
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
    sprintf(temp_string, "{\"function\":\"%02x\",\"compliance\":\"%02x\",\"number-of\":\"%02x\"},",
      entry->function_code, entry->compliance, entry->number_of);
    if (ctx->verbosity > 3)
    {
      fprintf(ctx->log, "f %02x c %02x n %02x old len %d.\n",
        entry->function_code, entry->compliance, entry->number_of, (int)strlen(aux));
      fflush(ctx->log);
    };
    strcat(aux, temp_string);

    switch (entry->function_code)
    {
    case OSDP_CAP_AUDIBLE_OUT:
      fprintf(ctx->log,
"PD: %d. Annunciators, ", entry->number_of);
      switch(entry->compliance)
      {
      case 1:
        fprintf(ctx->log, "On/Off only.\n");
        break;
      case 2:
        fprintf(ctx->log, "Timed and On/Off.\n");
        break;
      default:
        fprintf(ctx->log, "Not defined (%02x %02x)\n",
          entry->compliance, entry->number_of);
        break;
      };
      break;
    case OSDP_CAP_BIOMETRICS:
      fprintf(ctx->log,
"Capability not processed in this ACU: %s\n", osdp_pdcap_function(entry->function_code));
      break;
    case OSDP_CAP_CARD_FORMAT:
      switch(entry->compliance)
      {
      case 1:
        fprintf(ctx->log, "Card format: Binary.\n");
        break;
      case 2:
        fprintf(ctx->log, "Card format: BCD.\n");
        break;
      case 3:
        fprintf(ctx->log, "Card format: Binary or BCD.\n");
        break;
      default:
        fprintf(ctx->log, "Card format: not defined (%02x %02x)\n",
          entry->compliance, entry->number_of);
        break;
      };
      break;
    case OSDP_CAP_CHECK_CRC:
      if ((entry->compliance EQUALS 0) && (m_check EQUALS OSDP_CRC))
      {
        fprintf(ctx->log,
"WARNING: Device does not support CRC but CRC configured.\n");
      };
      break;
    case OSDP_CAP_CONTACT_STATUS:
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
      fprintf(ctx->log, "PD: largest combined message %d.(0x%x)\n",
        max_multipart, max_multipart);
      break;
    case OSDP_CAP_OUTPUT_CONTROL:
      fprintf(ctx->log, "Capability not processed in this ACU: Output Control (%d)\n",
        entry->function_code);
      break;
    case OSDP_CAP_READERS:
      fprintf(ctx->log, "PD: %d. Attached readers (%x)\n", entry->number_of, entry->compliance);
      break;
    case OSDP_CAP_REC_MAX:
      ctx->pd_cap.rec_max = entry->compliance + 256*entry->number_of;
      break;
    case OSDP_CAP_SECURE:
      if (entry->compliance EQUALS 0)
      {
        if (ctx->enable_secure_channel > 0)
          fprintf(ctx->log, "Secure Channel not supported by PD, disabling (was enabled.)\n");
        ctx->enable_secure_channel = 0;
      };
      break;
    case OSDP_CAP_SMART_CARD:
      if (entry->compliance & 1)
      {
        ctx->pd_cap.smart_card_transparent = 1;
        fprintf(ctx->log, "PD Supports Transparent Mode\n");
      };
      if (entry->compliance & 2)
      {
        ctx->pd_cap.smart_card_extended_packet_mode = 1;
        fprintf(ctx->log, "PD Supports Extended Packet Mode\n");
      };
      break;
    case OSDP_CAP_SPE:
      fprintf(ctx->log, "Capability not processed in this ACU: Secure PIN Entry\n");
      break;
    case OSDP_CAP_TEXT_OUT:
      fprintf(ctx->log, "Capability not processed in this ACU: Text Output (%d)\n",
        entry->function_code);
      break;
    case OSDP_CAP_TIME_KEEPING:
      fprintf(ctx->log, "Capability not processed in this ACU: Time Keeping (%d)\n",
        entry->function_code);
      break;
    case OSDP_CAP_VERSION:
      fprintf(ctx->log, "PD supports IEC 60839-11-5 dialect.\n");
      break;
    default:
      status = ST_OSDP_UNKNOWN_CAPABILITY;
      fprintf(ctx->log, "unknown capability: 0x%02x\n", entry->function_code);
      status = ST_OK;
      break;
    };
    entry ++;
  };
  fprintf(ctx->log, "PD Capabilities response processing complete.\n\n");
  if (ctx->last_command_sent EQUALS OSDP_CAP)
    osdp_test_set_status(OOC_SYMBOL_cmd_pdcap, OCONFORM_EXERCISED);
  strcat(aux, "\"#\":\"#\"},\n");
  osdp_test_set_status_ex(OOC_SYMBOL_rep_device_capas, OCONFORM_EXERCISED, aux);

  status = oosdp_make_message (OOSDP_MSG_PD_CAPAS, tlogmsg, msg);
  fprintf (ctx->log, "%s\n", tlogmsg);
  return(status);

} /* action_osdp_PDCAP */


int
  action_osdp_POLL
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_POLL */

  int current_length;
  int done;
  unsigned char osdp_lstat_response_data [2];
  unsigned char osdp_raw_data [4+1024];
  int raw_lth;
  int status;


  status = ST_OK;
  done = 0;

  // i.e. we GOT a poll
  osdp_test_set_status(OOC_SYMBOL_cmd_poll, OCONFORM_EXERCISED);

  /*
    poll response can be many things.  we do one and then return, which
    can cause some turn-the-crank artifacts.  may need multiple polls for
    expected behaviors to happen.
  */
  if (!done)
  {
    if (pending_response_length > 0)
    {
      done = 1;
      current_length = 0;
      status = send_message_ex (ctx,
        pending_response, p_card.addr, &current_length,
        pending_response_length, pending_response_data,
        OSDP_SEC_NOT_SCS, 0, NULL);
      pending_response_length = 0;
    };
  };

  // return BUSY if requested

  if (!done)
  {
    if (ctx->next_response EQUALS OSDP_BUSY)
    {
      ctx->next_response = 0;
      done = 1;
      current_length = 0;
      status = send_message_ex (ctx,
        OSDP_BUSY, p_card.addr, &current_length,
        0, NULL, OSDP_SEC_NOT_SCS, 0, NULL);
      SET_PASS (ctx, "4-16-1");
      if (ctx->verbosity > 2)
      {
        sprintf (tlogmsg, "Responding with osdp_BUSY");
        fprintf (ctx->log, "%s\n", tlogmsg);
      };
    };
  };

  // if there was a power report or tamper return that.

  if ((ctx->power_report EQUALS 1) || (ctx->tamper))
  {
    char details [1024];
    done = 1;

    details [0] = 0;
    if (ctx->tamper)
    {
      strcat(details, "Tamper");
      osdp_conformance.resp_lstatr_tamper.test_status =
        OCONFORM_EXERCISED;
    };
    if (ctx->power_report)
    {
      if (strlen(details) > 0)
        strcat(details, " ");
      strcat(details, "Power");
    };
    osdp_lstat_response_data [ 0] = ctx->tamper;
    osdp_lstat_response_data [ 1] = ctx->power_report;

    // clear tamper and power now reported
    ctx->tamper = 0;
    ctx->power_report = 0;

    current_length = 0;
    status = send_message_ex (ctx,
      OSDP_LSTATR, p_card.addr, &current_length,
      sizeof (osdp_lstat_response_data), osdp_lstat_response_data,
      OSDP_SEC_NOT_SCS, 0, NULL);
    SET_PASS (ctx, "3-1-3");
    SET_PASS (ctx, "4-5-1");
    SET_PASS (ctx, "4-5-3");
    if (ctx->verbosity > 2)
    {
      sprintf (tlogmsg, "Responding with OSDP_LSTATR (%s)", details);
      fprintf (ctx->log, "%s\n", tlogmsg);
    };
  }

  // if there's card data to return, do that.

  if (!done)
  {
    /*
      the presence of card data to return is indicated because either the
      "raw" buffer or the "big" buffer is marked as non-empty when you get here.
    */
    if (ctx->card_data_valid > 0)
    {
      done = 1;
      // send data if it's there (value is number of bits)

      // osdp_RAW is reader, format, countHigh, countLow, data

      osdp_raw_data [ 0] = 0; // one reader, reader 0
      osdp_raw_data [ 1] = ctx->card_format; 
      osdp_raw_data [ 2] = ctx->card_data_valid;
      osdp_raw_data [ 3] = 0;
      raw_lth = 4+ctx->creds_a_avail;
      memcpy (osdp_raw_data+4, ctx->credentials_data, ctx->creds_a_avail);
      current_length = 0;
fprintf(stderr, "DEBUG: card %d. bits bytes %d.\n",
  ctx->card_data_valid, ctx->creds_a_avail);

dump_buffer_log(ctx, "card data", (unsigned char *)(ctx->credentials_data), ctx->creds_a_avail);
dump_buffer_log(ctx, "card data message(fixed 32)", osdp_raw_data, 32);
      status = send_message_ex (ctx,
        OSDP_RAW, p_card.addr, &current_length, raw_lth, osdp_raw_data,
        OSDP_SEC_SCS_18, 0, NULL);
      osdp_test_set_status(OOC_SYMBOL_rep_raw, OCONFORM_EXERCISED);
      if (ctx->verbosity > 2)
      {
        sprintf (tlogmsg, "Responding with cardholder data (%d bits)",
          ctx->card_data_valid);
        fprintf (ctx->log, "%s\n", tlogmsg);
      };
      ctx->card_data_valid = 0;
    }
    else
    {

// DISABLED not working
#if 0
      /*
        this is the newer multi-part message for bigger credential responses,
        like a FICAM CHUID.
      */
      if (ctx->creds_a_avail > 0)
      {
        done = 1;

        // send another mfgrep message back and update things.

        memset (&mmsg, 0, sizeof (mmsg));
        if (creds_buffer_a_lth > 0xfffe)
        {
          status = ST_BAD_MULTIPART_BUF;
        }
        else
        {
          mmsg.VendorCode [0] = 0x08;
          mmsg.VendorCode [1] = 0x00;
          mmsg.VendorCode [2] = 0x1b;
          mmsg.Reply_ID = MFGREP_OOSDP_CAKCert;
          mmsg.MpdSizeTotal = creds_buffer_a_lth;
          mmsg.MpdOffset = creds_buffer_a_next;

          bufsize = sizeof (mmsg); // used in send operation below
          if (ctx->creds_a_avail > 128)
          {
            to_send = 128;
            ctx->creds_a_avail = ctx->creds_a_avail - 128;
          }
          else
          {
            to_send = ctx->creds_a_avail;
            ctx->creds_a_avail = 0;
          };
          mmsg.MpdFragmentSize = to_send; 

          // filled in all of mmsg now copy it to buffer

          memcpy (buffer, &mmsg, sizeof (mmsg));

          // actual data goes after header in buffer.
          memcpy (buffer+bufsize, creds_buffer_a+creds_buffer_a_next, to_send);

          current_length = 0;
          status = send_message (ctx, OSDP_MFGREP, p_card.addr,
            &current_length, bufsize+to_send, buffer);

          // and after all that move the pointer within the buffer for where
          // the next data is extracted from.

          creds_buffer_a_next = creds_buffer_a_next + to_send;
        };
      };
#endif
    };
  };
  /*
    if all else isn't interesting return a plain ack
  */
  if (!done)
  {
    current_length = 0;
    status = send_message_ex
      (ctx, OSDP_ACK, p_card.addr, &current_length, 0, NULL,
      OSDP_SEC_SCS_16, 0, NULL);
    osdp_test_set_status(OOC_SYMBOL_cmd_poll, OCONFORM_EXERCISED);
    osdp_test_set_status(OOC_SYMBOL_rep_ack, OCONFORM_EXERCISED);
    if (ctx->verbosity > 9)
    {
      sprintf (tlogmsg, "Responding with OSDP_ACK");
      fprintf (ctx->log, "%s\n", tlogmsg);
    };
  };

  // update status json
  if (status EQUALS ST_OK)
    status = oo_write_status (ctx);

  return (status);

} /* action_osdp_POLL */


int
  action_osdp_RAW
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_RAW */

  int bits;
  char cmd [2*1024];
  int display;
  char hstr [1024]; // hex string of raw card data payload
  unsigned char *raw_data;
  int status;


  status = ST_OK;
  display = 0; // assume encrypted and can't see it.
  if (ctx->role EQUALS OSDP_ROLE_CP)
  {
    (void)oosdp_make_message (OOSDP_MSG_RAW, tlogmsg, msg);
    fprintf(ctx->log, "%s\n", tlogmsg); fflush(ctx->log); tlogmsg [0] = 0;

    osdp_test_set_status(OOC_SYMBOL_rep_raw, OCONFORM_EXERCISED);
    osdp_conformance.cmd_poll_raw.test_status = OCONFORM_EXERCISED;
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
if (0)
//(bits EQUALS 26)
      {
int idx;
int bits_to_print;

        bits_to_print = bits;
        idx = 0;
        fprintf(ctx->log, "CARD DATA (%d bits): %02x", bits, raw_data [0]);
        idx++; // just output first octet
        if (bits_to_print > 8)
          bits_to_print = bits_to_print - 8;
        else
          bits_to_print = 0;
        while (bits_to_print > 0)
        {
          fprintf(ctx->log, "-%02x", raw_data [idx]);
          idx++;
          if (bits_to_print > 8)
            bits_to_print = bits_to_print - 8;
          else
            bits_to_print = 0;
        };
        fprintf(ctx->log, "\n");
      };

      // run the action routine with the bytes,bit count,format

      sprintf(cmd,
        "/opt/osdp-conformance/run/ACU-actions/osdp_RAW %s %d %d",
        hstr, bits, *(msg->data_payload+1));
      system(cmd);
    }; // not encrypted
  };

  return (status);

} /* action_osdp_RAW */


int
  action_osdp_RSTAT
    (OSDP_CONTEXT
      *ctx,
    OSDP_MSG
      *msg)

{ /* action_osdp_RSTAT */

  int
    current_length;
  unsigned char
    osdp_rstat_response_data [1];
  int
    status;


  status = ST_OK;
  osdp_conformance.cmd_rstat.test_status = OCONFORM_EXERCISED;
  osdp_rstat_response_data [ 0] = 1; //hard code to "not connected"
  current_length = 0;
  status = send_message (ctx, OSDP_RSTATR, p_card.addr,
    &current_length,
    sizeof (osdp_rstat_response_data), osdp_rstat_response_data);
  if (ctx->verbosity > 2)
  {
    sprintf (tlogmsg, "Responding with OSDP_RSTATR (Ext Tamper)");
    fprintf (ctx->log, "%s\n", tlogmsg); tlogmsg[0]=0;
  };

  return (status);

} /* action_osdp_RSTAT */


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
  osdp_conformance.cmd_text.test_status = OCONFORM_EXERCISED;

  memset (ctx->text, 0, sizeof (ctx->text));
  text_length = (unsigned char) *(msg->data_payload+5);
  strncpy (ctx->text, (char *)(msg->data_payload+6), text_length);

  fprintf (ctx->log, "Text:");
  fprintf (ctx->log,
    " Rdr %x tc %x tsec %x Row %x Col %x Lth %x\n",
     *(msg->data_payload + 0), *(msg->data_payload + 1), *(msg->data_payload + 2),
      *(msg->data_payload + 3), *(msg->data_payload + 4), *(msg->data_payload + 5));

  memset (tlogmsg, 0, sizeof (tlogmsg));
  strncpy (tlogmsg, (char *)(msg->data_payload+6), text_length);
  fprintf (ctx->log, "Text: %s\n", tlogmsg);

  // we always ack the TEXT command regardless of param errors

  current_length = 0;
  status = send_message
    (ctx, OSDP_ACK, p_card.addr, &current_length, 0, NULL);
  ctx->pd_acks ++;
  if (ctx->verbosity > 2)
    fprintf (ctx->log, "Responding with OSDP_ACK\n");

  return (status);

} /* action_osdp_TEXT */

