/*
  oo-process - process OSDP message input

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
char
  multipart_message_buffer_1 [64*1024];
extern OSDP_PARAMETERS
  p_card;

int
  process_osdp_input
    (OSDP_BUFFER
      *osdp_buf)

{ /* process_osdp_input */

  OSDP_MSG
    msg;
  OSDP_HDR
    parsed_msg;
  int
    status;
  OSDP_BUFFER
    temp_buffer;


  // assume all incoming commands are ok until we see a bad one.
  osdp_conformance.CMND_REPLY.test_status = OCONFORM_EXERCISED;

  memset (&msg, 0, sizeof (msg));

  msg.lth = osdp_buf->next;
  msg.ptr = osdp_buf->buf;
  status = parse_message (&context, &msg, &parsed_msg);
  if (status EQUALS ST_MSG_TOO_SHORT)
    status = ST_SERIAL_IN;
  if (status EQUALS ST_OK)
  {
    status = process_osdp_message (&context, &msg);
  };
  // things may have changed.  after processing this incoming message
  // adjust for changes.
  p_card.addr = context.new_address;

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
    (status EQUALS ST_BAD_CHECKSUM) || \
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

