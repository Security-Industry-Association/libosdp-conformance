unsigned char leftover_command;
unsigned char leftover_data [4*1024];
int leftover_length;

/*
  oo-process - process OSDP message input

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
#include <memory.h>


#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>


extern OSDP_INTEROP_ASSESSMENT
  osdp_conformance;
extern OSDP_CONTEXT
  context;
extern OSDP_PARAMETERS
  p_card;

int
  process_osdp_input
    (OSDP_BUFFER *osdp_buf)

{ /* process_osdp_input */

  OSDP_MSG msg;
  OSDP_HDR parsed_msg;
  int status;
  OSDP_BUFFER temp_buffer;


  // assume all incoming commands are ok until we see a bad one.
  osdp_test_set_status(OOC_SYMBOL_CMND_REPLY, OCONFORM_EXERCISED);

  memset (&msg, 0, sizeof (msg));

  msg.lth = osdp_buf->next;
  msg.ptr = osdp_buf->buf;
  status = osdp_parse_message (&context, context.role, &msg, &parsed_msg);

  /*
    if it was too long it's noise so dump the whole thing and let the retry
    process handle it.
  */
  if (status EQUALS ST_MSG_TOO_LONG)
  {
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
      current_length = 0;
      osdp_nak_response [0] = 0xff;
      send_response = 1;

      // adjust NAK to the reason
      switch(status)
      {
      default:
        osdp_nak_response [0] = OO_NAK_CMD_UNABLE;
        break;
      case ST_NOT_MY_ADDR:
        send_response = 0; // not for me, don't answer.
        break;
      case ST_OSDP_SC_BAD_HASH:
        osdp_nak_response [0] = OO_NAK_ENC_REQ;
        fprintf(context.log, "  NAK: Bad hash, sending NAK %d\n", OO_NAK_ENC_REQ);
        break;
      case ST_OSDP_BAD_SEQUENCE:
        osdp_nak_response [0] = OO_NAK_SEQUENCE;

        // reset the current sequence number to zero (for the NAK)
        context.next_sequence = 0;
        break;
      };

      if (send_response)
      {
        if (context.verbosity > 3)
          fprintf(context.log, "DEBUG: NAK: %d.\n", osdp_nak_response [0]);
        (void)send_message_ex(&context,
          OSDP_NAK, p_card.addr, &current_length,
          1, osdp_nak_response, OSDP_SEC_NOT_SCS, 0, NULL);
        context.sent_naks ++;

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
    osdp_conformance.multibyte_data_encoding.test_status =
      OCONFORM_EXERCISED;
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
    memcpy (temp_buffer.buf, osdp_buf->buf+length, osdp_buf->next-length);
    temp_buffer.next = osdp_buf->next-length;
    memcpy (osdp_buf->buf, temp_buffer.buf, temp_buffer.next);
    osdp_buf->next = temp_buffer.next;
    if (status != ST_OK)
      // if we experienced an error we just reset things and continue
      status = ST_SERIAL_IN;
  };
  return (status);

} /* process_osdp_input */

