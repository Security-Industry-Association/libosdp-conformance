/*
  oo_util2 - more open-osdp util routines

  (C)Copyright 2017-2025 Smithee Solutions LLC

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
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>


#include <jansson.h>


#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>


extern OSDP_INTEROP_ASSESSMENT osdp_conformance;
extern OSDP_CONTEXT context;
extern OSDP_PARAMETERS p_card;
extern char trace_out_buffer [4*OSDP_OFFICIAL_MSG_MAX];
extern unsigned char last_command_received;
extern unsigned char last_message_sent [2048];
extern int last_message_sent_length;


/// retry

void do_retry
  (OSDP_CONTEXT *ctx)

{ /* do_retry */

  unsigned char buf [2];  // note use for spacer so not always 1 byte
  int status;

    buf [0] = 0xff;
    status = send_osdp_data (ctx, buf, 1);
    if (status EQUALS ST_OK)
    {
      status = send_osdp_data (ctx, last_message_sent, last_message_sent_length);
    };
    last_message_sent_length = 0;
    ctx->do_retry = 0;
}

/*
  under idle conditions send a poll (possibly securely)
*/

int
  background
    (OSDP_CONTEXT *ctx)

{ /* background */

  int current_length;
  int send_secure_poll;
  int send_poll;
  int status;
  unsigned char sec_blk [1];


  status = ST_OK;
  send_poll = 0;
  send_secure_poll = 0;

  // if we're not in a file transfer...
  // if we're not set up with an operational secure channel
  // if we're not enabled for secure channel

  if (ctx->role EQUALS OSDP_ROLE_ACU)
  {
    if (ctx->xferctx.total_length EQUALS 0)
    {
      if (ctx->verbosity > 9)
        fprintf(ctx->log,
"background: tl %d. ns %d lsr %d lwp %d response timer %d\n", ctx->xferctx.total_length,
          ctx->next_sequence, ctx->last_sequence_received, ctx->last_was_processed,
          ctx->timer [OSDP_TIMER_RESPONSE].status EQUALS OSDP_TIMER_STOPPED);
      if (ctx->secure_channel_use [OO_SCU_ENAB] != OO_SCS_OPERATIONAL)
        if (!(ctx->secure_channel_use [OO_SCU_ENAB] & 0x80))
          send_poll = 1;
    };
  };

  // for an ACU, considering file transfer, if we're in secure channel

  if ((ctx->role EQUALS OSDP_ROLE_ACU) && (ctx->secure_channel_use [OO_SCU_ENAB] EQUALS OO_SCS_OPERATIONAL))
  {
    if (ctx->verbosity > 9)
      fprintf(stderr, "ACU and secure channel, background\n");
  };
  if (ctx->role EQUALS OSDP_ROLE_ACU)
  {
    if (ctx->xferctx.total_length EQUALS 0)
    {
      if (ctx->secure_channel_use [OO_SCU_ENAB] EQUALS OO_SCS_OPERATIONAL)
      {
        send_secure_poll = 1;
      };
    };
  };

  // if waiting for response to last cleartext message then do NOT poll

  if (ctx->verbosity > 9)
    fprintf(ctx->log, "wait: send_poll %d awaiting... %d\n",
      send_poll, osdp_awaiting_response(ctx));
  if (send_poll)
  {
    if (osdp_awaiting_response(ctx))
    {
      if (ctx->timeout_retries > 0)
      {
        send_poll = 0;
        ctx->timeout_retries --;
        if (ctx->timeout_retries EQUALS 0)
        {
          if (ctx->verbosity > 3)
            fprintf(ctx->log, "Timeout while polling, retries (%d) exceeded.)\n", OOSDP_TIMEOUT_RETRIES);
          send_poll = 1;
          if (ctx->post_command_action EQUALS OO_POSTCOMMAND_SINGLESTEP)
          {
            fprintf(ctx->log, "---> Disabled Polling by request at poll timeout <---\n");
            ctx->enable_poll = OO_POLL_NEVER;
            send_poll = 0;
          };
        };
      };
    };
  };

  // if waiting for response to last secure message then do NOT poll

  if (send_secure_poll)
  {
    if (osdp_awaiting_response(ctx))
    {
      if (ctx->timeout_retries > 0)
      {
        send_secure_poll = 0;
        fprintf(ctx->log, "Background: waiting for response (%d)\n", ctx->timeout_retries);
        ctx->timeout_retries --;
        if (ctx->timeout_retries EQUALS 0)
        {
          fprintf(ctx->log, "Background: timed out waiting for response, polling.\n");
          send_secure_poll = 1;
        };
      };
    };
  };

  // if polling is not enabled do not send one
  // (resume is used to start at a given command)

  if ((OO_POLL_NEVER EQUALS (ctx->enable_poll)) ||
    (OO_POLL_RESUME EQUALS (ctx->enable_poll)))
      send_poll = 0;

  // dump the trace buffer 
  if (context.trace)
    osdp_trace_dump(&context, 0);

  /*
    if we're in the middle of a file transfer but the last command was
    not osdp_FILETRANSFER we are finishing a "poll response waiting" event.
  */
  if ( (context.xferctx.total_length > 0) &&
    (context.xferctx.total_length > context.xferctx.current_offset) )
  {
    // code flows for both command and response.

    if ((last_command_received != OSDP_FILETRANSFER) && (last_command_received != OSDP_FTSTAT))
    {
      fprintf(context.log, "File transfer interrupted by poll response, resuming file transfer lcr %02X\n",
        last_command_received);
      status = osdp_send_filetransfer(&context);
      send_poll = 0;
    };
  };

  if (send_poll)
  {
    current_length = 0;
    status = send_message_ex(ctx, OSDP_POLL, p_card.addr, &current_length,
      0, NULL, OSDP_SEC_SCS_15, 0, NULL);
  };
  if (send_secure_poll)
  {
    status = send_secure_message(ctx, OSDP_POLL, p_card.addr,
      &current_length, 0, NULL, OSDP_SEC_SCS_15, 0, sec_blk);
  };

  return (status);

} /* background */


int
  calc_parity
    (unsigned short
      value,
     int
       length,
     int
       sense)

{
  int
    i;
  unsigned short int
    mask_bit;
  int
    results;

  results = 0;
  mask_bit = 1;
  for (i=0; i<length; i++)
  {
    if (mask_bit & value)
      results++;
    mask_bit = mask_bit * 2;
  };
  results= results & 1;
  if (!sense)
  {
    if (!results)
      results = 1;
  }
  else
  {
    if (results)
      results = 1;
  };
  return (results);
}


unsigned char
  checksum
    (unsigned char
      *msg,
    int
      length)
{
  unsigned char
    checksum;
  int
    i;
  int
    whole_checksum;


  whole_checksum = 0;
  for (i=0; i<length; i++)
  {
    whole_checksum = whole_checksum + msg [i];
    checksum = ~(0xff & whole_checksum)+1;
  };
  return (checksum);

} /* checksum */


int
  fasc_n_75_to_string
    (char * s, long int *sample_1)

{ /* fasc_n_75_to_string */

  int
    status;
   char
    ret_string [1024];


  status = 0;
  {
    unsigned long long tmp1_64;
    unsigned long long tmp3_64;

{
  int j;
  char * p;
unsigned long long int z64;
  p = (char *)sample_1;
  tmp1_64 = 0;
  for (j=0; j<8; j++)
  {
    tmp1_64 = tmp1_64 << 8;
    tmp1_64 = tmp1_64 | (0xff & ((unsigned int)*(p+j)));
    tmp1_64 = tmp1_64 | (0xff & ((unsigned int)*(p+j)));
  };
  tmp3_64 = 0xff & (unsigned int)*(p+8);
  tmp3_64 = tmp3_64 <<(32+24);
z64 = (0xff & (unsigned int)*(p+9));
  tmp3_64 = tmp3_64 | (z64 << (32+16));
};

    long long v1,v2,v3,v4;

    v1 = (0x7ffe000000000000ll & tmp1_64) >> 49;
    v2 = (0x0001fff800000000ll & tmp1_64) >> 35;
    v3 = (0x00000007ffff8000ll & tmp1_64) >> 15;
    v4 = (0x0000000000007fffll & tmp1_64) << 10;
    v4 = v4 | ((0xffc0000000000000ll & tmp3_64) >> 54);

    sprintf (ret_string,
"Agency Code: %lld System Code: %lld Card Number: %lld Expiration: %lld",
      v1, v2, v3, v4);
  };

  strcpy (s, ret_string);
  return (status);

} /* fasc_n_75_to_string */


int
  osdp_timeout
    (OSDP_CONTEXT *ctx,
    struct timespec *last_time_ex)

{ /* osdp_timeout */

  long delta_nanotime;
  int delta_time;
  int i;
  int return_value;
  int status_posix;
  struct timespec time_spec;


  return_value = 0;
  status_posix = clock_gettime (CLOCK_REALTIME, &time_spec);
  if (status_posix == -1)
    ctx->last_errno = errno;

  // update timers (new style)


  for (i=0; i<ctx->timer_count; i++)
  {
    if (ctx->timer [i].status != OSDP_TIMER_STOPPED)
    {
      ctx->timer [i].status = OSDP_TIMER_RUNNING;
      if (ctx->timer [i].i_sec > 0)
      {
        // it's a 1-second resolution timer

        delta_time = time_spec.tv_sec - last_time_ex->tv_sec;
        if (delta_time > 0)
        {
          if (ctx->timer [i].current_seconds >= delta_time)
            ctx->timer [i].current_seconds =
              ctx->timer [i].current_seconds - delta_time;
          else
            ctx->timer [i].current_seconds =  0;
        };
        if (ctx->timer [i].current_seconds == 0)
        {
          ctx->timer [i].status = OSDP_TIMER_STOPPED;
          return_value = 1;
          if (ctx->timer [i].timeout_action EQUALS OSDP_TIMER_RESTART_ALWAYS)
          {
            ctx->timer [i].current_seconds = ctx->timer [i].i_sec;
            ctx->timer [i].status = OSDP_TIMER_RESTARTED;
          };
        };
      };
      if (ctx->timer [i].i_nsec > 0)
      {
        // it's a nanosecond resolution timer

        delta_nanotime = time_spec.tv_nsec - last_time_ex->tv_nsec;
        if (delta_nanotime > 0)
        {
          if (ctx->timer [i].current_nanoseconds >= delta_nanotime)
            ctx->timer [i].current_nanoseconds =
              ctx->timer [i].current_nanoseconds - delta_nanotime;
          else
            ctx->timer [i].current_nanoseconds =  0;
        };
        if (ctx->timer [i].current_nanoseconds == 0)
        {
if (i != OSDP_TIMER_RESPONSE)
  fprintf(stderr, "%d (n) stopped not %d\n", i, OSDP_TIMER_RESPONSE);
          ctx->timer [i].status = OSDP_TIMER_STOPPED;
          return_value = 1;
          if (ctx->timer [i].timeout_action EQUALS OSDP_TIMER_RESTART_ALWAYS)
          {
            ctx->timer [i].current_nanoseconds = ctx->timer [i].i_nsec;
            ctx->timer [i].status = OSDP_TIMER_RESTARTED;
          };
        };
      };
    }; // timer not stopped
    if (ctx->verbosity > 9)
    {
      if (i EQUALS OSDP_TIMER_RESPONSE)
      {
        fprintf(ctx->log, "timer %d status %d\n", i, ctx->timer[i].status);
      };
    };
  };
  last_time_ex->tv_sec = time_spec.tv_sec;;
   last_time_ex->tv_nsec = time_spec.tv_nsec;;
  return (return_value);

} /* osdp_timeout */
   

/*
  send_comset - sends the actual osdp_COMSET command

  send_style is 1 if you are to stand down from secure channel to send this in the clear
*/
int
  send_comset
    (OSDP_CONTEXT *ctx,
    unsigned char pd_address,
    unsigned char new_address,
    char *speed_string,
    int send_style)

{ /* send_comset */

  int current_length;
  int new_speed;
  unsigned char param [5];
  int status;


  sscanf (speed_string, "%d", &new_speed);
  param [0] = new_address; // byte 0: new address
  param [1] =        new_speed & 0xff;
  param [2] =     (new_speed & 0xff00) >> 8;
  param [3] =   (new_speed & 0xff0000) >> 16;
  param [4] = (new_speed & 0xff000000) >> 24;
  current_length = 0;
  osdp_test_set_status(OOC_SYMBOL_cmd_comset, OCONFORM_EXERCISED);
  if (send_style)
  {
    status = send_message_ex(ctx, OSDP_COMSET, pd_address, &current_length,
      sizeof (param), param, OSDP_SEC_STAND_DOWN, 0, NULL);
  }
  else
  {
    status = send_message_ex(ctx, OSDP_COMSET, pd_address, &current_length,
      sizeof(param), param, OSDP_SEC_SCS_17, 0, NULL);
  };
  return (status);

} /* send_comset */


/*
  send_message - send an OSDP message

  assumes command is a valid value.
*/

int
  send_message
    (OSDP_CONTEXT *ctx,
    int command,
    int dest_addr,
    int *current_length,
    int data_length,
    unsigned char *data)

{ /* send_message */

  unsigned char buf [2];  // note use for spacer so not always 1 byte
  int status;
  unsigned char test_blk [1600];
  int true_dest;


  // starting fresh on the processing
  ctx->last_was_processed = 0;
  ctx->timeout_retries = OOSDP_TIMEOUT_RETRIES;

  if (ctx->verbosity > 9)
  {
    fprintf (ctx->log, "Top of send_message cmd=%02x:\n", command);
    fflush (ctx->log);
  };
  status = ST_OK;
  true_dest = dest_addr;
  *current_length = 0;

  if (ctx->verbosity > 3)
  {
    if (command EQUALS OSDP_NAK)
    {
      osdp_test_set_status(OOC_SYMBOL_rep_nak, OCONFORM_EXERCISED);
      fprintf (stderr, "NAK being sent...%02x\n", *data);
    };
  };
  status = osdp_build_message(ctx, test_blk, // message itself
    current_length, // returned message length in bytes
    command, true_dest, ctx->next_sequence, data_length, // data length to use
    data, 0); // no security
  if (status EQUALS ST_OK)
  {

    // if (context->verbosity > 3)
    {
      OSDP_MSG m;
      int parse_role;
      OSDP_HDR returned_hdr;
      int status_monitor;

      memset (&m, 0, sizeof (m));

      m.ptr = test_blk; // marshalled outbound message
      m.lth = *current_length;

      // parse the message for display.  role to parse is the OTHER guy
      parse_role = OSDP_ROLE_ACU;
      if (ctx->role EQUALS OSDP_ROLE_ACU)
        parse_role = OSDP_ROLE_PD;
      status_monitor = osdp_parse_message (ctx, parse_role,
        &m, &returned_hdr);
      if (status_monitor != ST_OK)
      {
        if (ctx->verbosity > 3)
          fprintf(stderr, "DEBUG: ignoring osdp_parse_message status %d.\n", status);
        status_monitor = ST_OK;
      };
      if (ctx->verbosity > 8)
      {
        if (status_monitor != ST_OK)
        {
          sprintf (tlogmsg,"parse_message for monitoring returned %d.\n",
            status_monitor);
          status = oosdp_log (ctx, OSDP_LOG_STRING_CP, 1, tlogmsg);
        };
      };
      (void)monitor_osdp_message (ctx, &m);
    };

    if (status EQUALS ST_OK)
    {
      if (ctx->conformance_suppress_response)
      {
        fprintf(ctx->log, "Test in progress: response suppressed.  Next response will be allowed.\n");
        ctx->conformance_suppress_response = 0;
      }
      else
      {
        oo_next_sequence(ctx);

        memcpy(last_message_sent, test_blk, *current_length);
        last_message_sent_length = *current_length;

        // send start-of-message marker (normally one 0xff)

        buf [0] = 0xff;
        status = send_osdp_data (ctx, buf, 1);
        if (status EQUALS ST_OK)
        {
          status = send_osdp_data (ctx, test_blk, *current_length);

          // and after we sent the whole PDU bump the counter
          ctx->pdus_sent++;
        };
      };

    };
  };
  if (status EQUALS ST_OK)
  {
    ctx->timer [OSDP_TIMER_RESPONSE].current_nanoseconds = ctx->timer [OSDP_TIMER_RESPONSE].i_nsec;
    ctx->timer [OSDP_TIMER_RESPONSE].status = OSDP_TIMER_RUNNING;
    ctx->last_command_sent = command;
  };

  return (status);

} /* send_message */


/*
  send_message_ex - send an OSDP message (extended features)

  sends a message in cleartext or secure channel.
*/

int
  send_message_ex
    (OSDP_CONTEXT *ctx,
    int command,
    int dest_addr,
    int *current_length,
    int data_length,
    unsigned char *data,
    int sec_block_type,
    int sec_block_length,
    unsigned char *sec_block)

{ /* send_message_ex */

  unsigned char current_sec_block [3];
  int current_sec_block_length;
  int current_sec_block_type;
  int send_response_message;
  int status;


  status = ST_OK;
  if (ctx->role != OSDP_ROLE_MONITOR)
  {
    // starting fresh on the processing
    ctx->last_was_processed = 0;
    ctx->timeout_retries = OOSDP_TIMEOUT_RETRIES;

    // dump trace buffers so in's and out's land in correct order

    if (context.verbosity > 3)
      osdp_trace_dump(&context, 1);
    else
      osdp_trace_dump(&context, 0);

    current_sec_block_type = sec_block_type;
    current_sec_block_length = sec_block_length;
    memset(current_sec_block, 0, sizeof(current_sec_block));
    if (sec_block != NULL)
      memcpy(current_sec_block, sec_block, sizeof(current_sec_block));

    // if we're not in secure channel it's all cleartext

    if (ctx->secure_channel_use [OO_SCU_ENAB] != OO_SCS_OPERATIONAL)
      current_sec_block_type = OSDP_SEC_NOT_SCS;

    // if we're in secure channel and it's not a known block it's an SCS_15/16
    // unless there's data in which case it's a 17/18

    current_sec_block_length = 0;

    if (current_sec_block_type EQUALS OSDP_SEC_NOT_SCS)
    {
      if (ctx->secure_channel_use [OO_SCU_ENAB] EQUALS OO_SCS_OPERATIONAL)
      {
        if (ctx->verbosity > 3)
        {
          fprintf(ctx->log, "send: SC; dlth %d\n", data_length);
        };
        if (data_length > 0)
        {
          if (ctx->role EQUALS OSDP_ROLE_ACU)
            current_sec_block_type = OSDP_SEC_SCS_17;
          else
            current_sec_block_type = OSDP_SEC_SCS_18;
        };
        if (data_length EQUALS 0)
        {
          if (ctx->role EQUALS OSDP_ROLE_ACU)
            current_sec_block_type = OSDP_SEC_SCS_15;
          else
            current_sec_block_type = OSDP_SEC_SCS_16;
        };
      };
    };

    // the caller asked us to chillax even if it's in secure mode.

    if (current_sec_block_type EQUALS OSDP_SEC_STAND_DOWN)
      current_sec_block_type = OSDP_SEC_NOT_SCS;

    send_response_message = 1;

    if (current_sec_block_type != OSDP_SEC_NOT_SCS)
    {
      if (send_response_message)
      {
        if (ctx->verbosity > 9)
        {
          fprintf(ctx->log, "send: SC-%x\n", current_sec_block_type);
        };
        status = send_secure_message(ctx, command, dest_addr,
          current_length, data_length, data,
          current_sec_block_type, current_sec_block_length, current_sec_block);
      };
    }
    else
    {
      if (send_response_message)
      {
        status = send_message (ctx, command, dest_addr, current_length,
          data_length, data);
      };
    };

    // dump trace buffers after also so in's and out's land in correct order

    if (context.verbosity > 3)
      osdp_trace_dump(&context, 1);
    else
      osdp_trace_dump(&context, 0);
  }; // not monitor
  return(status);

} /* osdp_send_message_ex */

