/*
  oosdp-secure - open osdp secure channel routines

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
#include <unistd.h>


#include <osdp-tls.h>
#include <open-osdp.h>

extern OSDP_CONTEXT
  context;


int
  osdp_build_secure_message
    (unsigned char
        *buf,
    int
      *updated_length,
    unsigned char
      command,
    int
      dest_addr,
    int
      sequence,
    int
      data_length,
    unsigned char
      *data,
    int
      sec_blk_type,
    int
      sec_blk_lth,
    unsigned char
      *sec_blk)

{ /* osdp_build_secure_mesage */

  int
    check_size;
  unsigned char
    * cmd_ptr;
  int
    new_length;
  unsigned char
    * next_data;
  OSDP_HDR
    *p;
  int
    status;
  int
    whole_msg_lth;


  status = ST_OK;
  if (m_check EQUALS OSDP_CHECKSUM)
    check_size = 1;
  else
    check_size = 2;
  new_length = *updated_length;

  p = (OSDP_HDR *)buf;
  p->som = C_SOM;
  new_length ++;

  // addr
  p->addr = dest_addr;
  new_length ++;

  // length

  /*
    length goes in before CRC calc.
    length is 5 (fields to CTRL) + [if no sec] 1 for CMND + data
  */
  whole_msg_lth = 5;
  whole_msg_lth = whole_msg_lth + 1; //CMND
  whole_msg_lth = whole_msg_lth + data_length;
  whole_msg_lth = whole_msg_lth + sec_blk_lth +2; //contents+hdr
  whole_msg_lth = whole_msg_lth + check_size; // including CRC

printf ("dl %d. sbl %d. cs %d. whole lth for header %d.\n",
  data_length, sec_blk_lth, check_size, whole_msg_lth);
  p->len_lsb = 0x00ff & whole_msg_lth;
  new_length ++;
  p->len_msb = (0xff00 & whole_msg_lth) >> 8;
  new_length ++;

  // control
  p->ctrl = 0;
  p->ctrl = p->ctrl | (0x3 & sequence);
  if (context.verbosity > 4)
    fprintf (stderr, "build msg: seq %d added ctl now %02x m_check %d\n",
      sequence, p->ctrl, m_check);

  // set CRC depending on current value of global parameter
  if (m_check EQUALS OSDP_CRC)
    p->ctrl = p->ctrl | 0x04;

  new_length ++;

  // secure is bit 3 (mask 0x08)
  {
    p->ctrl = p->ctrl | 0x08;
    cmd_ptr = buf + 5; // STUB pretend security block is 3 bytes len len 1 payload
  };

  // fill in secure data
  {
    unsigned char *sp;
    sp = buf+5;
    *sp = sec_blk_lth+2;
    sp++;
    *sp = sec_blk_type;
    sp++;
    memcpy (sp, sec_blk, sec_blk_lth);
    sp = sp + sec_blk_lth;
    cmd_ptr = sp;
printf ("bef sec block to new length %d.\n", new_length);
    new_length = new_length + 2+ sec_blk_lth; // account for lth/typ
  };
  
  *cmd_ptr = command;
  new_length++;
  next_data = 1+cmd_ptr;

  if (data_length > 0)
  {
    int i;
    unsigned char *sptr;
    sptr = cmd_ptr + 1;
    if (context.verbosity > 3)
      fprintf (stderr, "orig (s) next_data %lx\n", (unsigned long)next_data);
    for (i=0; i<data_length; i++)
    {
      *(sptr+i) = *(i+data);
      new_length ++;
      next_data ++; // where crc goes (after data)
    };
    if (context.verbosity > 3)
    fprintf (stderr, "data_length %d new_length now %d next_data now %lx\n",
      data_length, new_length, (unsigned long)next_data);
  };

  // crc
  if (m_check EQUALS OSDP_CRC)
{
  unsigned short int parsed_crc;
  unsigned char *crc_check;
  crc_check = next_data;
  parsed_crc = fCrcBlk (buf, new_length);

  // low order byte first
  *(crc_check+1) = (0xff00 & parsed_crc) >> 8;
  *(crc_check) = (0x00ff & parsed_crc);
  new_length ++;
  new_length ++;
}
  else
  {
    unsigned char
      cksum;
    unsigned char *
      pchecksum;

    pchecksum = next_data;
    cksum = checksum (buf, new_length);
    *pchecksum = cksum;
    new_length ++;
  };

  *updated_length = new_length;
  return (status);

} /* osdp_build_message */


/*
  send_secure_message - send an OSDP "security" message

  assumes command is a valid value.
*/

int
  send_secure_message
    (OSDP_CONTEXT
      *context,
    int
      command,
    int
      dest_addr,
    int
      *current_length,
    int
      data_length,
    unsigned char
      *data,
    int
      sec_blk_type,
    int
      sec_blk_lth,
    unsigned char
      *sec_blk)

{ /* send_secure_message */

  unsigned char
    buf [2];
  int
    status;
  unsigned char
    test_blk [1024];
  int
    true_dest;


  status = ST_OK;
  true_dest = dest_addr;
  if (context->special_1 EQUALS 1)
    true_dest = 0x7f;
  *current_length = 0;
if (context->verbosity > 3)
{
  printf ("secure send: sl %d l %d\n",
    sec_blk_lth, data_length);
};
  status = osdp_build_secure_message
    (test_blk, // message itself
    current_length, // returned message length in bytes
    command,
    true_dest,
    next_sequence (context),
    data_length, // data length to use
    data,
    sec_blk_type, sec_blk_lth, sec_blk); // security values
  if (status EQUALS ST_OK)
  {
  if ((context->verbosity > 3) || (command != OSDP_ACK))
    if (m_dump)
    {
      int
        i;

       fprintf (context->log, "Sending(secure) lth %d.=", *current_length);
       for (i=0; i<*current_length; i++)
         fprintf (context->log, " %02x", test_blk [i]);
       fprintf (context->log, "\n");
       fflush (context->log);
    };
    buf [0] = 0xff;
    // send start-of-message marker (0xff)
    send_osdp_data (context, &(buf[0]), 1);

    if (context->verbosity > 4)
      fprintf (context->log, "send_secure_message: sending(secure) %d\n", *current_length);
       
    send_osdp_data (context, test_blk, *current_length);
  };
  return (status);

} /* send_secure_message */

