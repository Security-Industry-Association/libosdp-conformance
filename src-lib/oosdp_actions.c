/*
  oosdp-actions - open osdp action routines

  (C)Copyright 2014-2015 Smithee,Spelvin,Agnew & Plinge, Inc.

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


#include <gnutls/gnutls.h>


#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>


extern OSDP_INTEROP_ASSESSMENT
  osdp_conformance;
extern OSDP_PARAMETERS
  p_card;
char
  tlogmsg [1024];


int
  action_osdp_MFG
    (OSDP_CONTEXT
      *ctx,
    OSDP_MSG
      *msg)

{ /* action_osdp_MFG */

  int
    status;
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
fprintf (stderr, "osdp_MFG action stub\n");
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
status = -1;
return (status);

} /* action_osdp_MFG */


int
  action_osdp_OUT
    (OSDP_CONTEXT
      *ctx,
    OSDP_MSG
      *msg)

{ /* action_osdp_OUT */

  int
    status;


  osdp_conformance.cmd_out.test_status = OCONFORM_EXERCISED;
  sprintf (tlogmsg, "  Output Control: Onum %02x Ctl %02x LSB %02x MSB %02x",
    *(msg->data_payload + 0), *(msg->data_payload + 1),
    *(msg->data_payload + 2), *(msg->data_payload + 3));
  fprintf (ctx->log, "%s\n", tlogmsg);
  status = ST_OK;
  return (status);

} /* action_osdp_OUT */


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

  // i.e. we GOT a poll
  osdp_conformance.cmd_poll.test_status = OCONFORM_EXERCISED;

  /*
    poll response can be many things.  we do one and then return, which
    can cause some turn-the-crank artifacts.  may need multiple polls for
    expected behaviors to happen.

    if there was a power report return that.
  */
  if (ctx->power_report EQUALS 1)
  {
    // power change not yet reported
    ctx->power_report = 0;
    osdp_lstat_response_data [ 0] = ctx->tamper;
    osdp_lstat_response_data [ 1] = 1; // report power failure
    current_length = 0;
    status = send_message (ctx,
      OSDP_LSTATR, p_card.addr, &current_length,
      sizeof (osdp_lstat_response_data), osdp_lstat_response_data);
    if (ctx->verbosity > 2)
    {
      sprintf (tlogmsg, "Responding with OSDP_LSTAT (Power)");
      fprintf (ctx->log, "%s\n", tlogmsg);
    };
  }
  else
  {
    /*
      the presence of card data to return is indicated because either the "raw" buffer or the "big" 
      buffer is marked as non-empty when you get here.
    */
    /*
      if there's card data to return, do that.
      this is for the older "raw data" style.
    */
    if (ctx->card_data_valid > 0)
    {
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
      else
      {
        /*
          if all else isn't interesting return a plain ack
        */
        current_length = 0;
        status = send_message
          (ctx, OSDP_ACK, p_card.addr, &current_length, 0, NULL);
        ctx->pd_acks ++;
        osdp_conformance.rep_ack.test_status = OCONFORM_EXERCISED;
        if (ctx->verbosity > 4)
        {
          sprintf (tlogmsg, "Responding with OSDP_ACK");
          fprintf (ctx->log, "%s\n", tlogmsg);
        };
      };
    };
  };

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
  processed = 0;
  raw_data = msg->data_payload + 4;
  /*
    this processes an osdp_RAW.  byte 0=rdr, b1=format, 2-3 are length (2=lsb)
  */
  bits = *(msg->data_payload+2) + ((*(msg->data_payload+3))<<8);
if (ctx->special_1 EQUALS 3)
{
  fprintf (stderr, "Special case 2: bits at beginning of RAW\n");
  bits = *(msg->data_payload+0) + ((*(msg->data_payload+1))<<8);
  raw_data = msg->data_payload + 2;
};

  if (bits EQUALS 26)
  {
    fprintf (ctx->log, "CARD DATA (%d bits):", bits);
    fprintf (ctx->log,
      " %02x-%02x-%02x-%02x\n",
      *(raw_data+0),
      *(raw_data+1),
      *(raw_data+2),
      *(raw_data+3));
#if 0
      *(msg->data_payload + 2), *(msg->data_payload + 3),
      *(msg->data_payload + 4), *(msg->data_payload + 5));
#endif
    processed = 1;
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
    (OSDP_CONTEXT
      *ctx,
    OSDP_MSG
      *msg)

{ /* action_osdp_TEXT */

  int
    current_length;
  int
    status;
  char
    tlogmsg  [1024];


  status = ST_OK;
  osdp_conformance.cmd_text.test_status = OCONFORM_EXERCISED;
  fprintf (ctx->log, "Text:");
  fprintf (ctx->log,
    " Rdr %x tc %x tsec %x Row %x Col %x Lth %x\n",
     *(msg->data_payload + 0), *(msg->data_payload + 1), *(msg->data_payload + 2),
      *(msg->data_payload + 3), *(msg->data_payload + 4), *(msg->data_payload + 5));

  memset (tlogmsg, 0, sizeof (tlogmsg));
fflush (ctx->log);
  strncpy (tlogmsg, (char *)(msg->data_payload+6), (int)*(msg->data_payload+5));
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

