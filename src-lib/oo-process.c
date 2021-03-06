unsigned char leftover_command;
unsigned char leftover_data [4*1024];
int leftover_length;

/*
  oo-process - process OSDP message input

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
#include <memory.h>


#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>


extern OSDP_CONTEXT context;
extern unsigned char last_command_received;
extern unsigned char last_check_value;
extern unsigned char last_sequence_received;
OSDP_BUFFER osdp_buf;
extern OSDP_INTEROP_ASSESSMENT osdp_conformance;
extern OSDP_PARAMETERS p_card;
extern int saved_next;
extern char trace_in_buffer [];


int
  process_osdp_input
    (OSDP_BUFFER *osdp_buf)

{ /* process_osdp_input */

  OSDP_MSG msg;
  int nak_not_msg;
  OSDP_HDR parsed_msg;
  int status;
  OSDP_BUFFER temp_buffer;


  // assume all incoming commands are ok until we see a bad one.
  osdp_test_set_status(OOC_SYMBOL_CMND_REPLY, OCONFORM_EXERCISED);

  memset (&msg, 0, sizeof (msg));

  msg.lth = osdp_buf->next;
  msg.ptr = osdp_buf->buf;
  status = osdp_parse_message (&context, context.role, &msg, &parsed_msg);
  if (status EQUALS ST_OK)
  {
    context.last_sequence_received = msg.sequence;

    if (msg.check_size EQUALS 2)
      osdp_test_set_status(OOC_SYMBOL_CRC, OCONFORM_EXERCISED);
    else
      osdp_test_set_status(OOC_SYMBOL_checksum, OCONFORM_EXERCISED);
  };

  /*
    if it didn't look right to the parser, dump it and let the retry process handle it.
  */
  if ((status EQUALS ST_MSG_TOO_LONG) || (status EQUALS ST_MSG_BAD_SOM))
  {
    context.dropped_octets = context.dropped_octets + osdp_buf->next;
    osdp_buf->next = 0;
    status = ST_MSG_TOO_SHORT;
  };
  if ((status != ST_OK) && (status != ST_MSG_TOO_SHORT) &&
    (status != ST_NOT_MY_ADDR) && (status != ST_SERIAL_IN))
  {
    int current_length;
    unsigned char osdp_nak_response [2];
    int send_response;

    send_response = 0;

    // if we're the PD then NAK it.

    if (context.role EQUALS OSDP_ROLE_PD)
    {
unsigned short int current_check_value;


      current_check_value = *(unsigned short int *)(msg.crc_check);
      if (msg.check_size EQUALS 1)
        current_check_value = 0xff & current_check_value; // crc is 2 bytes checksum is the low order byte

      fprintf(context.log,
        "  NAK: last-cmd %02x last-seq %d last-checkval %04x\n",
        last_command_received, last_sequence_received, last_check_value);

      // is it a resend?

      if ((last_command_received EQUALS parsed_msg.command) && (last_check_value EQUALS current_check_value))
      {
int old_s;
old_s = context.next_sequence;
if (context.next_sequence EQUALS 1)
  context.next_sequence = 3;
else
  context.next_sequence --;
context.retries ++;
fprintf(context.log, "DEBUG: retry %d. in progress, don't NAK it. old s %d s %d\n",
  context.retries, old_s, context.next_sequence);
fflush(context.log);

send_response = 0;
status = ST_OK;
      }
      if (status != ST_OK) {
        current_length = 0;
      osdp_nak_response [0] = 0xff;
      send_response = 1;

      // adjust NAK to the reason
      switch(status)
      {
      default:
        nak_not_msg = 1;
        osdp_nak_response [0] = OO_NAK_CMD_UNABLE;
        break;
      case ST_NOT_MY_ADDR:
        send_response = 0; // not for me, don't answer.
        break;
      case ST_OSDP_SC_BAD_HASH:
        nak_not_msg = 1;
        osdp_nak_response [0] = OO_NAK_ENC_REQ;
        fprintf(context.log, "  NAK: Bad hash, sending NAK %d\n", OO_NAK_ENC_REQ);
        break;
      case ST_OSDP_BAD_SEQUENCE:
        nak_not_msg = 1;
        osdp_nak_response [0] = OO_NAK_SEQUENCE;

        // reset the current sequence number to zero (for the NAK)
        context.next_sequence = 0;
        break;
        };
      };

      if (send_response)
      {
        char cmd [1024];
        if (context.verbosity > 3)
          fprintf(context.log, "DEBUG: NAK: %d.\n", osdp_nak_response [0]);
        (void)send_message_ex(&context,
          OSDP_NAK, p_card.addr, &current_length,
          1, osdp_nak_response, OSDP_SEC_NOT_SCS, 0, NULL);
        sprintf(cmd, "/opt/osdp-conformance/run/ACU-actions/osdp_NAK transmitted"); system(cmd);
        context.sent_naks ++;

        if (nak_not_msg)
          osdp_test_set_status(OOC_SYMBOL_resp_nak_not_msg, OCONFORM_EXERCISED);

        // if we just sent a bad-sequence NAK then reset the sequence number.
        // (for subsequent packets)
        if (osdp_nak_response [0] EQUALS OO_NAK_SEQUENCE)
          context.next_sequence = 0;
      };
    };
  };
  if (context.verbosity > 9)
  {
    if (status != ST_MSG_TOO_SHORT)
    {
      fprintf(stderr,
        "after input s=%d leftover_length %d\n", status, leftover_length);
    };
  };
  if (status EQUALS ST_MSG_TOO_SHORT)
    status = ST_SERIAL_IN;
  if (status EQUALS ST_OK)
  {
    // the message was good.  update conformance status.
    osdp_test_set_status(OOC_SYMBOL_multibyte_data_encoding, OCONFORM_EXERCISED);
    if (!(parsed_msg.ctrl & 0x08))
      osdp_conformance.scb_absent.test_status =
        OCONFORM_EXERCISED;

    if (context.verbosity > 9)
    {
      int i;
      fprintf (stderr, "Parsing input (%d. bytes):\n",
        msg.lth);
      for (i=0; i<msg.lth; i++)
      {
        fprintf (stderr, " %02x", osdp_buf->buf [i]);
        fflush (stderr);
       };
      fprintf (stderr, "\n");
    };
    status = process_osdp_message (&context, &msg);
  };

  // if there's a leftover command to send then send it now.  Only get to do one of these.

  if (status EQUALS ST_OK)
  {
    if (context.left_to_send > 0)
    {
      int current_length; 

      current_length = 0;
      status = send_message (&context, leftover_command,
        p_card.addr, &current_length, leftover_length, leftover_data);
      context.left_to_send = 0;
      leftover_length = 0;
    };
  };

  // do special things for tests in progress.

  if (0 EQUALS strcmp (context.test_in_progress, "2-2-1"))
  {
    if (osdp_conformance.conforming_messages >= PARAM_MMT)
    {
      osdp_conformance.signalling.test_status = OCONFORM_EXERCISED;
      osdp_conformance.address_config.test_status = OCONFORM_EXERCISED;
      SET_PASS ((&context), "2-2-1");
      context.test_in_progress [0] = 0;
    };
  };
  if (0 EQUALS strcmp (context.test_in_progress, "2-2-2"))
  {
    if (osdp_conformance.conforming_messages >= PARAM_MMT)
    {
      osdp_conformance.alt_speed_2.test_status = OCONFORM_EXERCISED;
      osdp_conformance.address_config.test_status = OCONFORM_EXERCISED;
      SET_PASS ((&context), "2-2-2");
      context.test_in_progress [0] = 0;
    };
  };
  if (0 EQUALS strcmp (context.test_in_progress, "2-2-3"))
  {
    if (osdp_conformance.conforming_messages >= PARAM_MMT)
    {
      osdp_conformance.alt_speed_3.test_status = OCONFORM_EXERCISED;
      osdp_conformance.address_config.test_status = OCONFORM_EXERCISED;
      SET_PASS ((&context), "2-2-3");
      context.test_in_progress [0] = 0;
    };
  };
  if (0 EQUALS strcmp (context.test_in_progress, "2-2-4"))
  {
    if (osdp_conformance.conforming_messages >= PARAM_MMT)
    {
      osdp_conformance.alt_speed_4.test_status = OCONFORM_EXERCISED;
      osdp_conformance.address_config.test_status = OCONFORM_EXERCISED;
      SET_PASS ((&context), "2-2-4");
      context.test_in_progress [0] = 0;
    };
  };

  // move the existing buffer up to the front if it was unknown, not mine,
  // monitor only, or processed

  //fprintf(stderr, "DEBUG: MOVE MOVE MOVE MOVE status %d\n", status);
  if ((status EQUALS ST_PARSE_UNKNOWN_CMD) || \
    (status EQUALS ST_BAD_CRC) || \
    (status EQUALS ST_OSDP_BAD_SEQUENCE) || \
    (status EQUALS ST_BAD_CHECKSUM) || \
    (status EQUALS ST_OSDP_SC_BAD_HASH) || \
    (status EQUALS ST_NOT_MY_ADDR) || \
    (status EQUALS ST_MONITOR_ONLY) || \
    (status EQUALS ST_OK))
  {
    int length;
    length = (parsed_msg.len_msb << 8) + parsed_msg.len_lsb;
// zzz
{
  int i;
  char new_trace_buffer [3*1024];
  char tmps [1024];

  new_trace_buffer [0] = 0;
  for (i=0; i<length; i++)
  {
    sprintf(tmps, " %02x", osdp_buf->buf[0]);
    strcat(new_trace_buffer, tmps);
  };
  strcat(new_trace_buffer, "\n");
  //fprintf(stderr, "DEBUG: new trace buffer %s\n", new_trace_buffer);
}
    memcpy (temp_buffer.buf, osdp_buf->buf+length, osdp_buf->next-length);
    temp_buffer.next = osdp_buf->next-length;
    memcpy (osdp_buf->buf, temp_buffer.buf, temp_buffer.next);
    osdp_buf->next = temp_buffer.next;
    if (status != ST_OK)
      // if we experienced an error we just reset things and continue
      status = ST_SERIAL_IN;
  };
  if (0) //(status EQUALS ST_OK)
  {
    int i;
    char temps [4096];
    char octet_string [1024];

    temps[0] = 0;
    for (i=0; i<msg.lth; i++)
    {
      sprintf(octet_string, " %02x", *(msg.ptr+i));
      strcat(temps, octet_string);
    };
    if (context.trace & 1)
      strcpy(trace_in_buffer, temps);

    // print trace to log if verbose

    if (context.verbosity > 3)
      osdp_trace_dump(&context, 1);
    else
      osdp_trace_dump(&context, 0);
  };
  return (status);

} /* process_osdp_input */


/*
  osdp_stream_read - processes bytes just read in from whatever stream we're running
*/

int
  osdp_stream_read
    (OSDP_CONTEXT *ctx,
    char *buffer,
    int buffer_input_length)

{ /* osdp_stream_read */

  int i;
  char octet [1024];
  int status;
  char temp_buffer [2048];


  status = ST_OK;

  if (buffer_input_length <= 0)
    status = ST_OSDP_BAD_INPUT_COUNT;
  if (buffer_input_length > 0)
  {
    if (ctx->verbosity > 9)
      fprintf(ctx->log, "stream contained %4d octets\n", buffer_input_length);
    for (i=0; i<buffer_input_length; i++)
    {
fflush(ctx->log);
      ctx->bytes_received++;
      if (ctx->trace & 1)
      {
        sprintf(octet, " %02x", buffer [i]);
        strcat(trace_in_buffer, octet);
// if (context.verbosity > 9)
{ fprintf(stderr, "DEBUG: trace in now %s\n", trace_in_buffer); };
      };

      status = ST_SERIAL_IN;
fprintf(stderr, "DEBUG: next before add is %d\n", osdp_buf.next);
      if (osdp_buf.next < sizeof (osdp_buf.buf))
      {
fprintf(stderr, "DEBUG: storing %02x in buffer[%d]\n", buffer [i], osdp_buf.next);
        osdp_buf.buf [osdp_buf.next] = buffer [i];
        osdp_buf.next ++;

        // if we're reading noise dump bytes until a clean header starts

        // messages start with SOM, anything else is noise.
        // (checksum mechanism copes with SOM's in the middle of a msg.)

        if (!(osdp_buf.buf [0] EQUALS C_SOM)) //really index zero, first octet of buffer
        {
fprintf(stderr, "DEBUG: drop %02x next was %d dropped before %d\n",
  osdp_buf.buf[0], osdp_buf.next, context.dropped_octets);
          context.dropped_octets = context.dropped_octets + 1;
          osdp_buf.next --;
          if (osdp_buf.next > 1)
          {
            memcpy(temp_buffer, osdp_buf.buf+1, osdp_buf.next);
            memcpy(osdp_buf.buf, temp_buffer, osdp_buf.next);
          };
        };
      }
      else
      {
        fprintf(context.log, "Serial Overflow, resetting input buffer\n");
        context.dropped_octets = context.dropped_octets + osdp_buf.next;
        osdp_buf.overflow ++;
        osdp_buf.next = 0;
      };
    };
  };
fprintf(stderr, "DEBUG: osdp_stream_read - bottom: next %d overflow %d inlength %d\n", osdp_buf.next, osdp_buf.overflow, buffer_input_length);
  return(status);

} /* osdp_stream_read */

