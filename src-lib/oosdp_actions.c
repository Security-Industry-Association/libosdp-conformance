/*
  oosdp-actions - open osdp action routines

  (C)Copyright 2017-2018 Smithee Solutions LLC
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
char tlogmsg [1024];


int
  action_osdp_CCRYPT
    (OSDP_CONTEXT
      *ctx,
    OSDP_MSG
      *msg)

{ /* action_osdp_CCRYPT */

  struct AES_ctx
    aes_context_s_enc;
  OSDP_SC_CCRYPT
    *ccrypt_payload;
  unsigned char
    *client_cryptogram;
  int
    current_length;
  unsigned char
    iv [16];
  unsigned char
    message [16];
  unsigned char
    sec_blk [1];
  OSDP_SECURE_MESSAGE
    *secure_message;
  unsigned char
    server_cryptogram [16];
  int
    status;

  status = ST_OK;
  memset (iv, 0, sizeof (iv));

  // check for proper state

  if (ctx->secure_channel_use [OO_SCU_ENAB] EQUALS 128+OSDP_SEC_SCS_11)
  {
    secure_message = (OSDP_SECURE_MESSAGE *)(msg->ptr);
    if (ctx->enable_secure_channel EQUALS 2)
      if (secure_message->sec_blk_data != OSDP_KEY_SCBK_D)
        status = ST_OSDP_UNKNOWN_KEY;

    if (ctx->enable_secure_channel EQUALS 1)
      if (secure_message->sec_blk_data != OSDP_KEY_SCBK)
        status = ST_OSDP_UNKNOWN_KEY;

    if (status EQUALS ST_OK)
    {
      ccrypt_payload = (OSDP_SC_CCRYPT *)(msg->data_payload);
      client_cryptogram = ccrypt_payload-> cryptogram;
      // decrypt the client cryptogram (validate header, RND.A, collect RND.B)
if (ctx->verbosity > 8)
{
  int i;
  fprintf (stderr, "s_enc: ");
  for (i=0; i<OSDP_KEY_OCTETS; i++)
    fprintf (stderr, "%02x", ctx->s_enc [i]);
  fprintf (stderr, "\n");
};
      AES_init_ctx (&aes_context_s_enc, ctx->s_enc);
      AES_ctx_set_iv (&aes_context_s_enc, iv);
      memcpy (message, client_cryptogram, sizeof (message));
      AES_CBC_decrypt_buffer (&aes_context_s_enc, message, sizeof (message));
//      AES_CBC_decrypt_buffer (message, client_cryptogram, sizeof (message), ctx->s_enc, iv);

      if (0 != memcmp (message, ctx->rnd_a, sizeof (ctx->rnd_a)))
        status = ST_OSDP_CHLNG_DECRYPT;
    };
    if (status EQUALS ST_OK)
    {
      // client crytogram looks ok, save RND.B

      memcpy (ctx->rnd_b, message + sizeof (ctx->rnd_a), sizeof (ctx->rnd_b));

      memcpy (message, ctx->rnd_b, sizeof (ctx->rnd_b));
      memcpy (message+sizeof (ctx->rnd_b), ctx->rnd_a, sizeof (ctx->rnd_a));
      AES_ctx_set_iv (&aes_context_s_enc, iv);
      memcpy (server_cryptogram, message, sizeof (server_cryptogram));
      AES_CBC_encrypt_buffer (&aes_context_s_enc, server_cryptogram, sizeof (server_cryptogram));
//      AES_CBC_encrypt_buffer (server_cryptogram, message, sizeof (server_cryptogram), ctx->s_enc, iv);

      if (ctx->enable_secure_channel EQUALS 1)
        sec_blk [0] = OSDP_KEY_SCBK;
      if (ctx->enable_secure_channel EQUALS 2)
        sec_blk [0] = OSDP_KEY_SCBK_D;

      status = send_secure_message (ctx,
        OSDP_SCRYPT, p_card.addr, &current_length, 
        sizeof (server_cryptogram), server_cryptogram,
        OSDP_SEC_SCS_13, sizeof (sec_blk), sec_blk);
    };
  }
  else
    status = ST_OSDP_SC_WRONG_STATE;
  return (status);

} /* action_osdp_CCRYPT */


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
    status = write_status (ctx);
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
    status = write_status (ctx);
  return (status);

} /* action_osdp_FTSTAT */


int
  action_osdp_MFG
    (OSDP_CONTEXT
      *ctx,
    OSDP_MSG
      *msg)

{ /* action_osdp_MFG */

  int current_length;
  OSDP_MFG_HEADER *mfg;
  int status;

  status = ST_OK;
  mfg = (OSDP_MFG_HEADER *)(msg->data_payload);
fprintf (stderr, "osdp_MFG action stub\n");
fprintf(stderr, "1:%02x 2:%02x 3:%02x cmd:%02x data:%02x\n",
  mfg->vendor_code [0], mfg->vendor_code [1], mfg->vendor_code [2],
  mfg->command_id, mfg->data);

  // for the moment just ack it

  current_length = 0;
  status = send_message(ctx, OSDP_ACK, p_card.addr, &current_length, 0, NULL);
  ctx->pd_acks ++;

#if 0
  unsigned char
    buffer [1024];
  int
    bufsize;
  extern unsigned char
    creds_buffer_a [];
  extern int
    creds_buffer_a_lth;
  extern int
    creds_buffer_a_next;
  extern int
    zzcreds_buffer_a_remaining;
  int
    current_length;
  OSDP_MULTI_HDR
    mmsg;
  int
    to_send;

  status = ST_OK;
  /*
    set up to send the header and what's in creds buffer a
  */
  memset (&mmsg, 0, sizeof (mmsg));
  mmsg.oui [0] = 0x08;
  mmsg.oui [1] = 0x00;
  mmsg.oui [2] = 0x1b;
  mmsg.total = creds_buffer_a_lth;
  mmsg.cmd = 0;
  bufsize = sizeof (mmsg);
  creds_buffer_a_next = 0;
  mmsg.offset = creds_buffer_a_next;
  if (creds_buffer_a_lth > 128)
  {
    to_send = 128;
    creds_buffer_a_remaining = creds_buffer_a_lth - 128;
  }
  else
  {
    to_send = creds_buffer_a_lth;
    creds_buffer_a_remaining = 0;
  };
  mmsg.length = to_send; 

  // filled in all of mmsg now copy it to buffer

  memcpy (buffer, &mmsg, sizeof (mmsg));

  // actual data goes after header in buffer.
  memcpy (buffer+bufsize, creds_buffer_a+creds_buffer_a_next, to_send);

  current_length = 0;
  status = send_message (ctx, OSDP_MFGREP, p_card.addr,
    &current_length,
    bufsize+to_send, buffer);
#endif

  return (status);

} /* action_osdp_MFG */


int
  action_osdp_OUT
    (OSDP_CONTEXT
      *ctx,
    OSDP_MSG
      *msg)

{ /* action_osdp_OUT */

  unsigned char
    buffer [1024];
  int
    current_length;
  int
    done;
  OSDP_OUT_MSG
    *outmsg;
  int
    status;
  int
    to_send;


  status = ST_OK;
  osdp_conformance.cmd_out.test_status = OCONFORM_EXERCISED;
fprintf (stderr, "data_length in OSDP_OUT: %d\n",
  msg->data_length);
#if 0
// if too many for me (my MAX) then error and NAK?
// set 'timer' to msb*256+lsb
#define OSDP_OUT_NOP              (0)
#define OSDP_OUT_OFF_PERM_ABORT   (1)
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
      (outmsg->output_number > OSDP_MAX_OUT))
      status = ST_OUT_TOO_MANY;
    if (status EQUALS ST_OK)
    {
      switch (outmsg->control_code)
      {
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
    status = send_message (ctx, OSDP_OSTATR, p_card.addr,
      &current_length, to_send, buffer);
  };
  status = ST_OK;
  return (status);

} /* action_osdp_OUT */


int
  action_osdp_PDCAP
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_PDCAP */

  OSDP_PDCAP_ENTRY *entry;
  int i;
  int num_entries;
  unsigned char *ptr;
  int status;


  status = ST_OK;
  num_entries = msg->data_length / 3;
  ptr = msg->data_payload;
  entry = (OSDP_PDCAP_ENTRY *)ptr;
  for (i=0; i<num_entries; i++)
  {
    switch (entry->function_code)
    {
    case OSDP_CAP_REC_MAX:
      ctx->pd_cap.rec_max = entry->compliance + 256*entry->number_of;
      break;
    default:
      status = ST_OSDP_UNKNOWN_CAPABILITY;
fprintf(stderr, "unimplemented capability: 0x%02x\n", entry->function_code);
      status = ST_OK;
      break;
    };
    entry ++;
  };
  status = oosdp_make_message (OOSDP_MSG_PD_CAPAS, tlogmsg, msg);
  fprintf (ctx->log, "%s\n", tlogmsg);
  return(status);

} /* action_osdp_PDCAP */


int
  action_osdp_POLL
    (OSDP_CONTEXT
      *ctx,
    OSDP_MSG
      *msg)
{ /* action_osdp_POLL */

  unsigned char
    buffer [1024];
  int
    bufsize;
  extern unsigned char
    creds_buffer_a [];
  extern int
    creds_buffer_a_lth;
  extern int
    creds_buffer_a_next;
  int
    current_length;
  int
    done;
  OSDP_MULTI_HDR
    mmsg;
  unsigned char
    osdp_lstat_response_data [2];
  unsigned char
    osdp_raw_data [4+1024];
  int
    raw_lth;
  int
    status;
  int
    to_send;


  status = ST_OK;
  done = 0;

  // i.e. we GOT a poll
  osdp_conformance.cmd_poll.test_status = OCONFORM_EXERCISED;

  /*
    poll response can be many things.  we do one and then return, which
    can cause some turn-the-crank artifacts.  may need multiple polls for
    expected behaviors to happen.

    if there was a power report return that.
  */
  if (!done)
  {
    if (ctx->next_response EQUALS OSDP_BUSY)
    {
      ctx->next_response = 0;
      done = 1;
      current_length = 0;
      status = send_message (ctx,
        OSDP_BUSY, p_card.addr, &current_length,
        0, NULL);
      SET_PASS (ctx, "4-16-1");
      if (ctx->verbosity > 2)
      {
        sprintf (tlogmsg, "Responding with OSDP_BUSY");
        fprintf (ctx->log, "%s\n", tlogmsg);
      };
    };
  };
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
    status = send_message (ctx,
      OSDP_LSTATR, p_card.addr, &current_length,
      sizeof (osdp_lstat_response_data), osdp_lstat_response_data);
    SET_PASS (ctx, "3-1-3");
    SET_PASS (ctx, "4-5-1");
    SET_PASS (ctx, "4-5-3");
    if (ctx->verbosity > 2)
    {
      sprintf (tlogmsg, "Responding with OSDP_LSTATR (%s)", details);
      fprintf (ctx->log, "%s\n", tlogmsg);
    };
  }
  if (!done)
  {
    /*
      the presence of card data to return is indicated because either the
      "raw" buffer or the "big" buffer is marked as non-empty when you get here.
    */
    /*
      if there's card data to return, do that.
      this is for the older "raw data" style.
    */
    if (ctx->card_data_valid > 0)
    {
      done = 1;
      // send data if it's there (value is number of bits)
      osdp_raw_data [ 0] = 0; // one reader, reader 0
      osdp_raw_data [ 1] = 0; 
      osdp_raw_data [ 2] = p_card.bits;
      osdp_raw_data [ 3] = 0;
      raw_lth = 4;
      memcpy (osdp_raw_data+4, p_card.value, p_card.value_len);
      raw_lth = raw_lth + p_card.value_len;
      current_length = 0;
      status = send_message (ctx,
        OSDP_RAW, p_card.addr, &current_length, raw_lth, osdp_raw_data);
      osdp_conformance.rep_raw.test_status = OCONFORM_EXERCISED;
      if (ctx->verbosity > 2)
      {
        sprintf (tlogmsg, "Responding with cardholder data (%d bits)",
          p_card.bits);
        fprintf (ctx->log, "%s\n", tlogmsg);
      };
      ctx->card_data_valid = 0;
    }
    else
    {
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
      }
    };
  };
  if (!done)
  {
    /*
      if all else isn't interesting return a plain ack
    */
    current_length = 0;
    status = send_message
      (ctx, OSDP_ACK, p_card.addr, &current_length, 0, NULL);
    osdp_conformance.cmd_poll.test_status = OCONFORM_EXERCISED;
    osdp_conformance.rep_ack.test_status = OCONFORM_EXERCISED;
    if (ctx->verbosity > 9)
    {
      sprintf (tlogmsg, "Responding with OSDP_ACK");
      fprintf (ctx->log, "%s\n", tlogmsg);
    };
  };

  // update status json
  if (status EQUALS ST_OK)
    status = write_status (ctx);

  return (status);

} /* action_osdp_MFG */


int
  action_osdp_RAW
    (OSDP_CONTEXT
      *ctx,
    OSDP_MSG
      *msg)

{ /* action_osdp_RAW */

  int
    bits;
  int
    processed;
  unsigned char
    *raw_data;
  long int
    sample_1 [4];
  int
    status;


  status = ST_OK;
  osdp_conformance.rep_raw.test_status = OCONFORM_EXERCISED;
  osdp_conformance.cmd_poll_raw.test_status = OCONFORM_EXERCISED;
  processed = 0;
  raw_data = msg->data_payload + 4;
  /*
    this processes an osdp_RAW.  byte 0=rdr, b1=format, 2-3 are length (2=lsb)
  */
  bits = *(msg->data_payload+2) + ((*(msg->data_payload+3))<<8);
  ctx->last_raw_read_bits = bits;

  {
    int octets;
    octets = (bits+7)/8;
    if (octets > sizeof (ctx->last_raw_read_data))
      octets = sizeof (ctx->last_raw_read_data);
    memcpy (ctx->last_raw_read_data, raw_data, octets);
  };
  status = write_status (ctx);
  if (bits EQUALS 26)
  {
    fprintf (ctx->log, "CARD DATA (%d bits):", bits);
    fprintf (ctx->log,
      " %02x-%02x-%02x-%02x\n",
      *(raw_data+0),
      *(raw_data+1),
      *(raw_data+2),
      *(raw_data+3));
    processed = 1;
    system("sudo mpg123 /opt/osdp-conformance/etc/beep.mp3");
  };
  if (bits EQUALS 75)
  {
    int i; unsigned char *p;
long int tmp1_l;
    p = (unsigned char *)&(sample_1 [0]);
    for (i=0; i<10; i++)
      *(p+i) = *(raw_data+i);
tmp1_l = *(long int *)(raw_data);
sample_1 [0] = tmp1_l;
    status = fasc_n_75_to_string (tlogmsg, sample_1);
    fprintf (ctx->log, "CARD DATA (%d bits):\n%s\n",
      bits, tlogmsg);
    processed = 1;
  };
  if (!processed)
  {
    unsigned
      d;
    int
      i;
    char
      hstr [1024];
    int
      octet_count;
    char
      tstr [32];

    hstr [0] = 0;
    fprintf (stderr, "Raw Unknown:");
    octet_count = (bits+7)/8;
    for (i=0; i<octet_count; i++)
    {
      d = *(unsigned char *)(msg->data_payload+4+i);
      fprintf (stderr, " %02x", d);
      sprintf (tstr, " %02x", d);
      strcat (hstr, tstr);
    };
    fprintf (stderr, "\n");
    fprintf (ctx->log, "Unknown RAW CARD DATA (%d. bits) first byte %02x\n %s\n",
      bits, *(msg->data_payload+4), hstr);
    processed = 1;
  };

  return (status);

} /* action_osdp_RAW */


int
  action_osdp_RMAC_I
    (OSDP_CONTEXT
      *ctx,
    OSDP_MSG
      *msg)

{ /* action_osdp_RMAC_I */

  unsigned char
    iv [16];
  int
    status;


  status = ST_OK;
  memset (iv, 0, sizeof (iv));

  // check for proper state

  if (ctx->secure_channel_use [OO_SCU_ENAB] EQUALS 128+OSDP_SEC_SCS_13)
  {
    memcpy (ctx->current_received_mac, msg->data_payload, msg->data_length);
    ctx->secure_channel_use [OO_SCU_ENAB] = OO_SCS_OPERATIONAL;
    fprintf (ctx->log, "*** SECURE CHANNEL OPERATIONAL***\n");
  }
  else
  {
    status = ST_OSDP_SC_WRONG_STATE;
    osdp_reset_secure_channel (ctx);
  };
  return (status);

} /* action_osdp_RMAC_I */


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
  action_osdp_SCRYPT
    (OSDP_CONTEXT
      *ctx,
    OSDP_MSG
      *msg)

{ /* action_osdp_SCRYPT */

  struct AES_ctx
    aes_context_s_enc;
  struct AES_ctx
    aes_context_mac1;
  struct AES_ctx
    aes_context_mac2;
  int
    current_key_slot;
  int
    current_length;
  unsigned char
    iv [16];
  unsigned char
    message1 [16];
  unsigned char
    message2 [16];
  unsigned char
    message3 [16];
  unsigned char
    sec_blk [1];
  unsigned char
    server_cryptogram [16]; // size of RND.B plus RND.A
  int
    status;


  status = ST_OK;
fprintf (stderr,"TODO: osdp_SCRYPT\n");
  memset (iv, 0, sizeof (iv));

  // check for proper state

  if (ctx->secure_channel_use [OO_SCU_ENAB] EQUALS 128+OSDP_SEC_SCS_12)
  {
    status = osdp_get_key_slot (ctx, msg, &current_key_slot);
    if (status EQUALS ST_OK)
    {
      AES_init_ctx (&aes_context_s_enc, ctx->s_enc);
      AES_ctx_set_iv (&aes_context_s_enc, iv);
      AES_CBC_decrypt_buffer (&aes_context_s_enc, server_cryptogram, sizeof (server_cryptogram));
      //AES_CBC_decrypt_buffer (server_cryptogram, msg->data_payload, msg->data_length, ctx->s_enc, iv);
      if ((0 != memcmp (server_cryptogram, ctx->rnd_b, sizeof (ctx->rnd_b))) ||
        (0 != memcmp (server_cryptogram+sizeof (ctx->rnd_b), ctx->rnd_a, sizeof (ctx->rnd_a))))
        status = ST_OSDP_SCRYPT_DECRYPT;
    };
    if (status EQUALS ST_OK)
    {
      sec_blk [0] = 1; // means server cryptogram was good

      memcpy (message1, msg->data_payload, sizeof (server_cryptogram));
      AES_init_ctx (&aes_context_mac1, ctx->s_mac1);
      AES_init_ctx (&aes_context_mac2, ctx->s_mac2);

      memcpy (message2, message1, sizeof (message2));
      AES_ctx_set_iv (&aes_context_mac1, iv);
      AES_CBC_encrypt_buffer (&aes_context_mac1, message2, sizeof (message2));

      memcpy (message3, message2, sizeof (message3));
      AES_ctx_set_iv (&aes_context_mac2, iv);
      AES_CBC_encrypt_buffer (&aes_context_mac2, message3, sizeof (message3));

      ctx->secure_channel_use [OO_SCU_ENAB] = 128+OSDP_SEC_SCS_14;
      current_length = 0;
      status = send_secure_message (ctx,
        OSDP_RMAC_I, p_card.addr, &current_length, 
        sizeof (message3), message3,
        OSDP_SEC_SCS_14, sizeof (sec_blk), sec_blk);
    };
  }
  else
  {
    status = ST_OSDP_SC_WRONG_STATE;
    osdp_reset_secure_channel (ctx);
  };
  return (status);

} /* action_osdp_SCRYPT */


int
  action_osdp_TEXT
    (OSDP_CONTEXT
      *ctx,
    OSDP_MSG
      *msg)

{ /* action_osdp_TEXT */

  int
    current_length;
  int
    status;
  int
    text_length;
  char
    tlogmsg  [1024];


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

