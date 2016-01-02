/*
  oo-process - process OSDP message input

  (C)Copyright 2014-2015 Smithee Spelvin Agnew & Plinge, Inc.

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

