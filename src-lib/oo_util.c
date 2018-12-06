//#define SAMPLE 1
/*
  oo_util - open osdp utility routines

  (C)Copyright 2017-2018 Smithee Solutions LLC
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
#include <unistd.h>
#include <time.h>
#include <stdlib.h>


#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>


extern OSDP_CONTEXT context;
extern OSDP_INTEROP_ASSESSMENT osdp_conformance;
extern OSDP_PARAMETERS p_card;
unsigned int web_color_lookup [16] = {
    0x000000, 0xFF0000, 0x00FF00, 0x008080,
    0x444444, 0x550101, 0x660101, 0x770101,
    0x0000FF, 0x010101, 0x010101, 0x010101,
    0x010101, 0x010101, 0x010101, 0x010101,
  };
time_t previous_time;
char tlogmsg [1024];
char tlogmsg2 [1024];
int mfg_rep_sequence;


int
  osdp_build_message
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
      secure)

{ /* osdp_build_mesage */

  int
    check_size;
  unsigned char
    *cmd_ptr;
  int
    new_length;
  unsigned char
    *next_data;
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
  // if we're the PD set the high order bit
  if (context.role EQUALS OSDP_ROLE_PD)
    p->addr = p->addr | 0x80;

  new_length ++;

  // length

  /*
    length goes in before CRC calc.
    length is 5 (fields to CTRL) + [if no sec] 1 for CMND + data
  */
  whole_msg_lth = 5;
  if (secure != 0)
status = -2;
  else
    whole_msg_lth = whole_msg_lth + 1; //CMND
  whole_msg_lth = whole_msg_lth + data_length;
  whole_msg_lth = whole_msg_lth + check_size; // including CRC

  p->len_lsb = 0x00ff & whole_msg_lth;
  new_length ++;
  p->len_msb = (0xff00 & whole_msg_lth) >> 8;
  new_length ++;

  // control
  p->ctrl = 0;
  p->ctrl = p->ctrl | (0x3 & sequence);

  // set CRC depending on current value of global parameter
  if (m_check EQUALS OSDP_CRC)
    p->ctrl = p->ctrl | 0x04;

  new_length ++;

  // secure is bit 3 (mask 0x08)
  if (secure)
  {
    p->ctrl = p->ctrl | 0x08;
    cmd_ptr = buf + 8; // STUB pretend sec blk is 3 bytes len len 1 payload
  }
  else
  {
    cmd_ptr = buf + 5; // skip security stuff
  };
  // hard-coded off for now
  if (secure != 0)
    status = -1;
  
  *cmd_ptr = command;
  new_length++;
  next_data = 1+cmd_ptr;

  if (data_length > 0)
  {
    int i;
    unsigned char *sptr;
    sptr = cmd_ptr + 1;
    for (i=0; i<data_length; i++)
    {
      *(sptr+i) = *(i+data);
      new_length ++;
      next_data ++; // where crc goes (after data)
    };
    if (context.verbosity > 5)
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

  if (context.verbosity > 9)
  {
    fprintf (stderr, "build: sequence %d. Lth %d\n", sequence, new_length);
  }
  
  *updated_length = new_length;
  return (status);

} /* osdp_build_message */


int
  osdp_check_command_reply
    (int
      role,
    int
      command,
    OSDP_MSG
      *m,
    char
      *tlogmsg2)

{ /* osdp_check_command_reply */

  OSDP_CONTEXT
    *ctx;
  int
    status;


  ctx = &context;
  status = ST_OK;
  if ((role EQUALS OSDP_ROLE_PD) || (role EQUALS OSDP_ROLE_MONITOR))
  {
    switch (command)
    {
    default:
      if ((role != OSDP_ROLE_MONITOR) && (ctx->verbosity > 8))
        fprintf (ctx->log,
"top of osdp_check_command_reply: possible unknown command 0x%x\n",
          command);
      break;

#define OSDP_CHECK_CMDREP(osdp_tag,conformance_test, data_offset) \
      status = ST_OSDP_CMDREP_FOUND; \
      m->data_payload = m->cmd_payload + data_offset; \
      if (ctx->verbosity > 2) \
        strcpy (tlogmsg2, osdp_command_reply_to_string(command, ctx->role)); /* osdp_tag */ \
      osdp_conformance.conformance_test.test_status = OCONFORM_EXERCISED; \
      if (osdp_conformance.conforming_messages < PARAM_MMT) \
        osdp_conformance.conforming_messages ++;

    case OSDP_BUZ:
#ifndef NOSQUISH
      OSDP_CHECK_CMDREP ("osdp_BUZZ", cmd_buz, 1);
#endif
#ifdef NOSQUISH
      status = ST_OSDP_CMDREP_FOUND;
      m->data_payload = m->cmd_payload + 1;
      if (ctx->verbosity > 2)
        strcpy (tlogmsg2, "osdp_BUZZ");

      osdp_conformance.cmd_buz.test_status = OCONFORM_EXERCISED;

      if (osdp_conformance.conforming_messages < PARAM_MMT)
        osdp_conformance.conforming_messages ++;
#endif
      break;

    case OSDP_CAP:
      OSDP_CHECK_CMDREP ("osdp_CAP", cmd_pdcap, 1);
      break;

    case OSDP_CHLNG:
      OSDP_CHECK_CMDREP ("osdp_zCHLNG", cmd_chlng, 1);
      break;

    case OSDP_COMSET:
      OSDP_CHECK_CMDREP ("osdp_COMSET", cmd_comset, 1);
      break;

    case OSDP_FILETRANSFER:
      status = ST_OSDP_CMDREP_FOUND;
      m->data_payload = m->cmd_payload + 1;
      if (ctx->verbosity > 2)
        strcpy (tlogmsg2, "osdp_FILETRANSFER");

      osdp_conformance.cmd_filetransfer.test_status = OCONFORM_EXERCISED;

      if (osdp_conformance.conforming_messages < PARAM_MMT)
        osdp_conformance.conforming_messages ++;
      break;

    case OSDP_ID:
      status = ST_OSDP_CMDREP_FOUND;
      m->data_payload = m->cmd_payload + 1;
      if (ctx->verbosity > 2)
        strcpy (tlogmsg2, "osdp_ID");

      osdp_conformance.cmd_id.test_status = OCONFORM_EXERCISED;

      if (osdp_conformance.conforming_messages < PARAM_MMT)
        osdp_conformance.conforming_messages ++;
      break;

    case OSDP_ISTAT:
      status = ST_OSDP_CMDREP_FOUND;
      m->data_payload = m->cmd_payload + 1;
      if (ctx->verbosity > 2)
        strcpy (tlogmsg2, "osdp_ISTAT");

      osdp_conformance.cmd_istat.test_status = OCONFORM_EXERCISED;

      if (osdp_conformance.conforming_messages < PARAM_MMT)
        osdp_conformance.conforming_messages ++;
      break;

    case OSDP_KEEPACTIVE:
      status = ST_OSDP_CMDREP_FOUND;
      m->data_payload = m->cmd_payload + 1;
      if (ctx->verbosity > 2)
        strcpy (tlogmsg2, "osdp_KEEPACTIVE");
      osdp_conformance.cmd_keepactive.test_status = OCONFORM_EXERCISED;
      break;

    case OSDP_LED:
      status = ST_OSDP_CMDREP_FOUND;
      m->data_payload = m->cmd_payload + 1;
      if (ctx->verbosity > 2)
        strcpy (tlogmsg2, "osdp_LED");

//      osdp_conformance.cmd_led.test_status = OCONFORM_EXERCISED;

      if (osdp_conformance.conforming_messages < PARAM_MMT)
        osdp_conformance.conforming_messages ++;
      break;

    case OSDP_LSTAT:
fprintf(stderr, "lstat 335\n");
      status = ST_OSDP_CMDREP_FOUND;
      m->data_payload = m->cmd_payload + 1;
      if (ctx->verbosity > 2)
        strcpy (tlogmsg2, "osdp_LSTAT");

      osdp_conformance.cmd_lstat.test_status = OCONFORM_EXERCISED;

      if (osdp_conformance.conforming_messages < PARAM_MMT)
        osdp_conformance.conforming_messages ++;
      break;

    case OSDP_MFG:
      {
        OSDP_HDR *p;

        status = ST_OSDP_CMDREP_FOUND;
        p = (OSDP_HDR *)m->ptr;
        m->data_payload = m->cmd_payload + 1;

      // if the reply bit is set it's an FTSTAT else it's an MFG

      if (0x80 & (p->addr))
      {
        if (ctx->verbosity > 2)
          strcpy (tlogmsg2, "osdp_FTSTAT");
      }
      else
      {
        if (ctx->verbosity > 2)
          strcpy (tlogmsg2, "osdp_MFG");
        osdp_conformance.cmd_mfg.test_status = OCONFORM_EXERCISED;
      };

        if (osdp_conformance.conforming_messages < PARAM_MMT)
          osdp_conformance.conforming_messages ++;
      }
      break;

    case OSDP_OSTAT:
      status = ST_OSDP_CMDREP_FOUND;
      m->data_payload = m->cmd_payload + 1;
      if (ctx->verbosity > 2)
        strcpy (tlogmsg2, "osdp_OSTAT");

      osdp_conformance.cmd_ostat.test_status = OCONFORM_EXERCISED;

      if (osdp_conformance.conforming_messages < PARAM_MMT)
        osdp_conformance.conforming_messages ++;
      break;

    case OSDP_OUT:
      status = ST_OSDP_CMDREP_FOUND;
      m->data_payload = m->cmd_payload + 1;
      if (ctx->verbosity > 2)
        strcpy (tlogmsg2, "osdp_OUT");

      osdp_conformance.cmd_out.test_status = OCONFORM_EXERCISED;

      if (osdp_conformance.conforming_messages < PARAM_MMT)
        osdp_conformance.conforming_messages ++;
      break;

    case OSDP_POLL:
      status = ST_OSDP_CMDREP_FOUND;
      m->data_payload = NULL;
      m->data_length = 0;
      if (ctx->verbosity > 2)
        strcpy (tlogmsg2, "osdp_POLL");

      ctx->cp_polls ++;
      if (osdp_conformance.conforming_messages < PARAM_MMT)
        osdp_conformance.conforming_messages ++;
      break;

    case OSDP_RSTAT:
      status = ST_OSDP_CMDREP_FOUND;
      m->data_payload = m->cmd_payload + 1;
      if (ctx->verbosity > 2)
        strcpy (tlogmsg2, "osdp_RSTAT");

      osdp_conformance.cmd_rstat.test_status = OCONFORM_EXERCISED;

      if (osdp_conformance.conforming_messages < PARAM_MMT)
        osdp_conformance.conforming_messages ++;
      break;

    case OSDP_TEXT:
      status = ST_OSDP_CMDREP_FOUND;
      m->data_payload = m->cmd_payload + 1;
      if (ctx->verbosity > 2)
        strcpy (tlogmsg2, "osdp_TEXT");

      osdp_conformance.cmd_text.test_status = OCONFORM_EXERCISED;

      if (osdp_conformance.conforming_messages < PARAM_MMT)
        osdp_conformance.conforming_messages ++;
      break;
    };
  };

  // if we're the CP look at the message as if it's incoming.
  // if we're in monitor mode look at it (if it's not been already seen)

  if ((status != ST_OSDP_CMDREP_FOUND) && 
    ((role EQUALS OSDP_ROLE_CP) || (role EQUALS OSDP_ROLE_MONITOR)))
  {
    switch (command)
    {
    default:
      fprintf(stderr, "possible bad response 0x%02x\n", command);
      // status = ST_OSDP_BAD_COMMAND_REPLY;
      m->data_payload = m->cmd_payload + 1;
      if (ctx->verbosity > 2)
        strcpy (tlogmsg2, "\?\?\?");

      // if we don't recognize the command/reply code it fails 2-15-1
      osdp_conformance.CMND_REPLY.test_status = OCONFORM_FAIL;
      SET_FAIL (ctx, "2-15-1");
      break;

    case OSDP_ACK:
      status = ST_OSDP_CMDREP_FOUND;
      m->data_payload = NULL;
      m->data_length = 0;
      if (ctx->verbosity > 2)
        strcpy (tlogmsg2, "osdp_ACK");
      ctx->pd_acks ++;

      osdp_conformance.cmd_poll.test_status = OCONFORM_EXERCISED;
      osdp_conformance.rep_ack.test_status = OCONFORM_EXERCISED;

      // if we just got an ack for an OSTAT mark that too.
      if (ctx->last_command_sent EQUALS OSDP_OSTAT)
        osdp_conformance.cmd_ostat_ack.test_status = OCONFORM_EXERCISED;

      if (osdp_conformance.conforming_messages < PARAM_MMT)
        osdp_conformance.conforming_messages ++;
      break;

    case OSDP_BUSY:
      OSDP_CHECK_CMDREP ("osdp_BUSY", resp_busy, 1);
      break;

    case OSDP_CCRYPT:
      status = ST_OSDP_CMDREP_FOUND;
      m->data_payload = m->cmd_payload + 1;
      strcpy (tlogmsg2, "osdp_CCRYPT");
      break;

    case OSDP_COM:
      OSDP_CHECK_CMDREP ("osdp_COM", cmd_comset, 1);
      break;

    case OSDP_FTSTAT:
      status = ST_OSDP_CMDREP_FOUND;
      m->data_payload = m->cmd_payload + 1;
      strcpy (tlogmsg2, "osdp_FTSTAT");
      break;

    case OSDP_KEYPAD:
      status = ST_OSDP_CMDREP_FOUND;
      m->data_payload = m->cmd_payload + 1;
      if (ctx->verbosity > 2)
        strcpy (tlogmsg2, "osdp_KEYPAD");

      osdp_conformance.resp_keypad.test_status = OCONFORM_EXERCISED;

      if (osdp_conformance.conforming_messages < PARAM_MMT)
        osdp_conformance.conforming_messages ++;
      break;

    case OSDP_ISTATR:
      status = ST_OSDP_CMDREP_FOUND;
      m->data_payload = m->cmd_payload + 1;
      if (ctx->verbosity > 2)
        strcpy (tlogmsg2, "osdp_ISTATR");

      osdp_conformance.cmd_istat.test_status = OCONFORM_EXERCISED;

      if (osdp_conformance.conforming_messages < PARAM_MMT)
        osdp_conformance.conforming_messages ++;
      break;

    case OSDP_LSTATR:
      status = ST_OSDP_CMDREP_FOUND;
      m->data_payload = m->cmd_payload + 1;
      if (ctx->verbosity > 2)
        strcpy (tlogmsg2, "osdp_LSTATR");

      osdp_conformance.cmd_lstat.test_status = OCONFORM_EXERCISED;

      if (osdp_conformance.conforming_messages < PARAM_MMT)
        osdp_conformance.conforming_messages ++;
      break;

    case OSDP_MFG:
      status = ST_OSDP_CMDREP_FOUND;
      m->data_payload = m->cmd_payload + 1;
      if (ctx->verbosity > 2)
        strcpy (tlogmsg2, "osdp_MFG");

      osdp_conformance.cmd_mfg.test_status = OCONFORM_EXERCISED;

      if (osdp_conformance.conforming_messages < PARAM_MMT)
        osdp_conformance.conforming_messages ++;
      break;

    case OSDP_MFGREP:
      status = ST_OSDP_CMDREP_FOUND;
      m->data_payload = m->cmd_payload + 1;
      if (ctx->verbosity > 2)
        strcpy (tlogmsg2, "osdp_MFGREP");

      osdp_conformance.resp_mfg.test_status = OCONFORM_EXERCISED;

      if (osdp_conformance.conforming_messages < PARAM_MMT)
        osdp_conformance.conforming_messages ++;
      break;

    case OSDP_NAK:
      status = ST_OSDP_CMDREP_FOUND;
      m->data_payload = m->cmd_payload + 1;
      if (ctx->verbosity > 2)
        strcpy (tlogmsg2, "osdp_NAK");

      osdp_conformance.rep_nak.test_status = OCONFORM_EXERCISED;

      if (osdp_conformance.conforming_messages < PARAM_MMT)
        osdp_conformance.conforming_messages ++;
      break;

    case OSDP_OSTATR:
      status = ST_OSDP_CMDREP_FOUND;
      m->data_payload = m->cmd_payload + 1;
      if (ctx->verbosity > 2)
        strcpy (tlogmsg2, "osdp_OSTATR");

      osdp_conformance.cmd_ostat.test_status = OCONFORM_EXERCISED;

      if (osdp_conformance.conforming_messages < PARAM_MMT)
        osdp_conformance.conforming_messages ++;
      break;

    case OSDP_PDCAP:
      status = ST_OSDP_CMDREP_FOUND;
      m->data_payload = m->cmd_payload + 1;
      if (ctx->verbosity > 2)
        strcpy (tlogmsg2, "osdp_PDCAP");

      osdp_conformance.rep_device_capas.test_status = OCONFORM_EXERCISED;

      if (osdp_conformance.conforming_messages < PARAM_MMT)
        osdp_conformance.conforming_messages ++;
      break;

    case OSDP_PDID:
      OSDP_CHECK_CMDREP ("osdp_PDID", rep_device_ident, 1);
      break;

    case OSDP_RAW:
      status = ST_OSDP_CMDREP_FOUND;
      m->data_payload = m->cmd_payload + 1;
      if (ctx->verbosity > 2)
        strcpy (tlogmsg2, "osdp_RAW");

      osdp_conformance.rep_raw.test_status = OCONFORM_EXERCISED;

      if (osdp_conformance.conforming_messages < PARAM_MMT)
        osdp_conformance.conforming_messages ++;
      break;

    case OSDP_RMAC_I:
      status = ST_OSDP_CMDREP_FOUND;
      m->data_payload = m->cmd_payload + 1;
      strcpy (tlogmsg2, "osdp_RMAC_I");
      break;

    case OSDP_RSTATR:
      status = ST_OSDP_CMDREP_FOUND;
      m->data_payload = m->cmd_payload + 1;
      if (ctx->verbosity > 2)
        strcpy (tlogmsg2, "osdp_RSTATR");

      osdp_conformance.cmd_rstat.test_status = OCONFORM_EXERCISED;

      if (osdp_conformance.conforming_messages < PARAM_MMT)
        osdp_conformance.conforming_messages ++;
      break;

    case OSDP_XRD:
      status = ST_OSDP_CMDREP_FOUND;
      m->data_payload = m->cmd_payload + 1;
      if (ctx->verbosity > 2)
        strcpy (tlogmsg2, "osdp_XRD");
      break;
    };
  };
  if (ctx->verbosity > 8)
  {
    if ((status != ST_OSDP_CMDREP_FOUND) && (status != ST_OK))
      fprintf (stderr,
        "bottom of osdp_check_command_reply: bad status %d\n", status);
  };
  return (status);

} /* osdp_check_command_reply */


/*
  osdp_parse_message - parses OSDP message

  Note: if verbosity is set (global m_verbosity) it also prints the PDU
  to stderr.
*/
int
  osdp_parse_message
    (OSDP_CONTEXT *context,
    int role,
    OSDP_MSG *m,
    OSDP_HDR *returned_hdr)

{ /* osdp_parse_message */

  int display;
  int i;
  char logmsg [1024];
  unsigned int msg_lth;
  int msg_check_type;
  int msg_data_length;
  int msg_scb;
  int msg_sqn;
  OSDP_HDR *p;
  unsigned short int parsed_crc;
  int sec_blk_length;
  int sec_block_type;
  int status;
  unsigned short int wire_crc;


  status = ST_MSG_TOO_SHORT;
  logmsg [0] = 0;

  m->data_payload = NULL;
  m->security_block_length = 0; // assume no security block
  msg_data_length = 0;
  p = (OSDP_HDR *)m->ptr;

  msg_check_type = (p->ctrl) & 0x04;
  if (msg_check_type EQUALS 0)
  {
    m->check_size = 1;
    m_check = OSDP_CHECKSUM; // Issue #11
    if (context->verbosity > 3)
      fprintf(context->log, "m_check set to CHECKSUM (parse)\n");
    osdp_conformance.checksum.test_status =
      OCONFORM_EXERCISED;
  }
  else
  {
    m->check_size = 2;
    m_check = OSDP_CRC;
  };

  if (m->lth >= (m->check_size+sizeof (OSDP_HDR)))
  {
    status = ST_OK;
    msg_lth = p->len_lsb + (256*p->len_msb);
    if ((m->lth) > msg_lth)
      m->remainder = msg_lth - m->lth;

    // now that we have a bit of header figure out how much the whole thing is.  need all of it to process it.
    if (m->lth < msg_lth)
      status = ST_MSG_TOO_SHORT;
    else
      osdp_conformance.multibyte_data_encoding.test_status =
        OCONFORM_EXERCISED;
  };
  if (status != ST_OK)
  {
    if (status != ST_MSG_TOO_SHORT)
    {
      fprintf (context->log,
        "parse_message did not clear the header.  msg_data_length %d. msg_check_type 0x%x m->check_size %d. m->lth %d. msg_lth %d status %d.\n",
        msg_data_length, msg_check_type, m->check_size, m->lth, msg_lth,
        status);
      fflush (context->log);
    };
  };
  if (status EQUALS ST_OK)
  {    
    tlogmsg [0] = 0;
    if (context->verbosity > 3)
      // prints low 7 bits of addr field i.e. not request/reply
      sprintf (tlogmsg,
"A:%02x L:%d. C:%02x\n",
        (0x7f & p->addr), msg_lth, p->ctrl);
   
    // must start with SOM
    if (p->som != C_SOM)
      status = ST_MSG_BAD_SOM;
  };
  if (status EQUALS ST_OK)
  {
    // first few fields are always in same place
    returned_hdr -> som = p->som;
    returned_hdr -> addr = 0x7f & p->addr; // low 7 bits are address
    returned_hdr -> len_lsb = p->len_lsb;
    returned_hdr -> len_msb = p->len_msb;
    returned_hdr -> ctrl = p->ctrl;

    // various control info in CTRL byte
    msg_sqn = (p->ctrl) & 0x03;
    msg_scb = (p->ctrl) & 0x08;

    // depending on whether it's got a security block or not
    // the command/data starts at a different place
    if (msg_scb EQUALS 0)
    {
      m -> cmd_payload = m->ptr + 5;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk

      // really was a 0 in the Security Control Block marker, in unencrypted 
      // messages.  sanity check for conformance.

      osdp_conformance.scb_absent.test_status =
        OCONFORM_EXERCISED;
    }
    else
    {
      tlogmsg[0] = 0;
      sprintf(tlogmsg2, "Msg (Secure): ");
      strcat(tlogmsg, tlogmsg2);
      for (i=0; i<16; i++)
      {
        sprintf(tlogmsg2, "%02x", (m->ptr)[i]);
        strcat(tlogmsg, tlogmsg2);
        if (3 == (i % 4))
          if (i != 15)
          {
            sprintf(tlogmsg2, "-");
            strcat(tlogmsg, tlogmsg2);
          };
      };
      strcat(tlogmsg, "\n");
//      fprintf (context->log, "%s", tlogmsg);
      tlogmsg [0] = 0;
      tlogmsg2 [0] = 0;

      // packet is SOM, ADDR, LEN_LSB, LEN_MSB, CTRL (5 bytes) and then...

      // sec_blk_length -

      msg_data_length = p->len_lsb + (p->len_msb << 8);

      // if there's a security block and it's the proper type here's 4 bytes
      // of MAC at the end.

      sec_block_type = (unsigned)*(m->ptr+6); // second byte of sec block
      if ((sec_block_type EQUALS OSDP_SEC_SCS_15) ||
        (sec_block_type EQUALS OSDP_SEC_SCS_16) ||
        (sec_block_type EQUALS OSDP_SEC_SCS_17) ||
        (sec_block_type EQUALS OSDP_SEC_SCS_18))
        msg_data_length = msg_data_length - 4;
      sec_blk_length = (unsigned)*(m->ptr + 5);
      m->security_block_length = sec_blk_length;
      if (context->verbosity > 8)
        fprintf (stderr, "SECBLK: LEN=%d.(0x%02x) SEC_BLK_LEN=%d.\n",
          msg_data_length, msg_data_length, sec_blk_length);
      m -> cmd_payload = m->ptr + 5 + sec_blk_length;

      // whole thing less 5 hdr less 1 cmd less sec blk less 2 crc
      msg_data_length = msg_data_length - 6 - sec_blk_length - 2;

      fflush (stdout);fflush (stderr);
    };

    // extract the command
    returned_hdr -> command = (unsigned char) *(m->cmd_payload);
    m->msg_cmd = returned_hdr->command;
    m->direction = 0x80 & p->addr;
    m->data_payload = m->cmd_payload + 1;

    // dump the trace buffer even if it's poll/ack...
    osdp_trace_dump(context);

    // if it wasn't a poll or an ack report the secure header if there is one
    if ((m->msg_cmd != OSDP_POLL) && (m->msg_cmd != OSDP_ACK))
      fprintf (context->log, "%s", tlogmsg);
    if ((context->verbosity > 2) || (m->msg_cmd != OSDP_ACK))
    {
      sprintf (tlogmsg2, " Cmd %02x", returned_hdr->command);
      strcat (tlogmsg, tlogmsg2);
    };

    // display it.  Unless it's a poll/ack or filetransfer/ftstat.  or verbosity is high enough.

    display = 0;
    if (context->verbosity > 4)
      display = 1;
    if ((m->msg_cmd != OSDP_POLL) && (m->msg_cmd != OSDP_ACK))
    {
      if ((m->msg_cmd != OSDP_FILETRANSFER) && (m->msg_cmd != OSDP_FTSTAT))
      {
        display = 1;
      };
      if ((m->msg_cmd EQUALS OSDP_FILETRANSFER) &&
          (context->xferctx.current_offset EQUALS 0))
      {
        display = 1;
      };
      if (m->msg_cmd EQUALS OSDP_FTSTAT)
      {
        unsigned short int ft_status_detail;
        OSDP_HDR_FTSTAT *ft;

        ft = (OSDP_HDR_FTSTAT *)(m->data_payload);
        osdp_array_to_doubleByte(ft->FtStatusDetail, &ft_status_detail);
        if (ft_status_detail != 0)
        {
fprintf(stderr, "d 1 at 811\n");
          display = 1;
        };
      };
    };
if (m->msg_cmd EQUALS OSDP_FILETRANSFER)
  display = 1;
    if (display)
    {
      char dirtag [1024];
        int i;
        unsigned char
          *p1;
        char
          tlogmsg [1024];


        strcpy (tlogmsg, "");
        p1 = m->ptr;
        if (*(p1+1) & 0x80)
          strcpy (dirtag, "PD");
        else
          strcpy (dirtag, "CP");
        if (0 EQUALS strcmp (dirtag, "CP"))
          status = oosdp_log (context, OSDP_LOG_STRING_CP, 1, tlogmsg);
        else
          status = oosdp_log (context, OSDP_LOG_STRING_PD, 1, tlogmsg);
      
        // p2 = p1+5; // command/reply
        if (p->ctrl & 0x08)
        {
          strcpy(tlogmsg, osdp_sec_block_dump(p1+5));
          fprintf(context->log, "%s\n", tlogmsg);
          fflush (context->log);
          // p2 = p1+5+*(p1+5); // before-secblk and secblk
        };
        if (context->verbosity > 3)
        {
          if (msg_data_length > 0)
          {
            fprintf (context->log,
              "  DATA (%d. bytes):\n",
              msg_data_length);
            p1 = m->ptr + (msg_lth-msg_data_length-2);
            for (i=0; i<msg_data_length; i++)
            {
              fprintf (context->log, " %02x", *(i+p1));
              if (31 EQUALS (i % 32))
                fprintf(context->log, "\n");
            };
          if (32 != (msg_data_length % 32))
            fprintf (context->log, "\n");
        };
      };
    };

    m->data_length = msg_data_length;
    // go check the command field
    status = osdp_check_command_reply (role, returned_hdr->command, m, tlogmsg2);
    msg_data_length = m->data_length;
    if (status != ST_OSDP_CMDREP_FOUND)
    {
      if (status != ST_OK)
        fprintf (stderr,
          "Status %d Unknown command? (%02x), default msg_data_length was %d\n",
          status, returned_hdr->command, msg_data_length);

    if (context->verbosity > 8)
    {
      fprintf(stderr, "osdp_parse_message: command %02x\n", returned_hdr->command);
    };
fprintf(stderr, "oo_util 999 cmd %0x\n", returned_hdr->command);

    switch (returned_hdr->command)
    {
    default:
      //status = ST_PARSE_UNKNOWN_CMD;
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = 0;
      fprintf (stderr,
        "Unknown command (%02x), default msg_data_length was %d\n",
        returned_hdr->command, msg_data_length);
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "\?\?\?");

      // if we don't recognize the command/reply code it fails 2-15-1
      osdp_conformance.CMND_REPLY.test_status = OCONFORM_FAIL;
      SET_FAIL ((context), "2-15-1");
      break;

    case OSDP_BIOREAD:
      m->data_payload = NULL;
      msg_data_length = 0;
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_BIOREAD");
      osdp_conformance.cmd_bioread.test_status = OCONFORM_EXERCISED;
      break;

    case OSDP_BUSY:
      m->data_payload = NULL;
      msg_data_length = 0;
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_BUSY");
      osdp_conformance.resp_busy.test_status = OCONFORM_EXERCISED;
      break;

    case OSDP_FTSTAT:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_FTSTAT");
      break;

    case OSDP_NAK:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      context->sent_naks ++;
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_NAK");
      break;

    case OSDP_BUZ:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_BUZ");
      break;

    case OSDP_CAP:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_CAP");
      break;

    case OSDP_COM:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_COM");
      break;

    case OSDP_COMSET:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = 5;
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_COMSET");
      break;

    case OSDP_ID:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_ID");
      break;

    case OSDP_ISTAT:
      m->data_payload = NULL;
      msg_data_length = 0;
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_ISTAT");
      break;

   case OSDP_ISTATR:
fprintf(stderr, "second istatr switch\n");
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_ISTATR");
      break;

    case OSDP_KEEPACTIVE:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_KEEEPACTIVE");
      break;

    case OSDP_KEYPAD:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_KEYPAD");
      break;

    case OSDP_LED:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_LED");
      break;

    case OSDP_LSTAT:
fprintf(stderr, "lstat 1000\n");
      m->data_payload = NULL;
      msg_data_length = 0;
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_LSTAT");
      break;

   case OSDP_LSTATR:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_LSTATR");
      break;

    case OSDP_MFG:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_MFG");
      break;

    case OSDP_MFGREP:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_MFGREP");
      break;

    case OSDP_OSTAT:
      m->data_payload = NULL;
      msg_data_length = 0;
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_OSTAT");
      break;

    case OSDP_OSTATR:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_OSTATR");
      break;

    case OSDP_OUT:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_OUT");
      break;

    case OSDP_PDCAP:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_PDCAP");
      osdp_conformance.cmd_pdcap.test_status = OCONFORM_EXERCISED;
      osdp_conformance.rep_device_capas.test_status = OCONFORM_EXERCISED;
      break;

    case OSDP_PDID:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
// ASSUMES NO SECURITY
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_PDID");
      if (context->last_command_sent EQUALS OSDP_ID)
        osdp_conformance.cmd_id.test_status = OCONFORM_EXERCISED;
      osdp_conformance.rep_device_ident.test_status = OCONFORM_EXERCISED;
      break;

    case OSDP_RAW:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_RAW");
      break;

    case OSDP_RSTAT:
      m->data_payload = NULL;
      msg_data_length = 0;
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_RSTAT");
      break;

    case OSDP_RSTATR:
      // sending osdp_RSTATR
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      osdp_conformance.resp_rstatr.test_status = OCONFORM_EXERCISED;
      // if this is in response to an RSTAT then mark that too.
      if (context->last_command_sent EQUALS OSDP_RSTAT)
        osdp_conformance.cmd_rstat.test_status = OCONFORM_EXERCISED;
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_RSTATR");
      break;

    case OSDP_TEXT:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_TEXT");
      break;

    case OSDP_XRD:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_XRD");
      break;

    case OSDP_XWR:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_XWR");
      break;
    };
    }; // bolt-on for PD/CP switch statements.
    // if it was found it's ok
    if (status EQUALS ST_OSDP_CMDREP_FOUND)
      status = ST_OK;

    // for convienience save the data payload length

///    m->data_length = msg_data_length;

    if (m->check_size EQUALS 2)
    {
      // figure out where crc or checksum starts
      m->crc_check = m->cmd_payload + 1 + msg_data_length;

      // if it's an SCS with a MAC suffix move the CRC pointer

      if (msg_scb)
        if ((sec_block_type EQUALS OSDP_SEC_SCS_15) ||
          (sec_block_type EQUALS OSDP_SEC_SCS_16) ||
          (sec_block_type EQUALS OSDP_SEC_SCS_17) ||
          (sec_block_type EQUALS OSDP_SEC_SCS_18))
          m->crc_check = 4 + m->cmd_payload + 1 + msg_data_length;

      parsed_crc = fCrcBlk (m->ptr, msg_lth - 2);

      wire_crc = *(1+m->crc_check) << 8 | *(m->crc_check);
      if (parsed_crc != wire_crc)
      {
        if (context->verbosity > 2)
        {
          fprintf(context->log, "Bad CRC: Got %04x Expected %04x\n",
            wire_crc, parsed_crc);
        };
        status = ST_BAD_CRC;
      };
    }
    else
    {
      unsigned parsed_cksum;
      unsigned wire_cksum;

      // checksum

      parsed_cksum = checksum (m->ptr, m->lth-1);

// hmmm

// checksum is in low-order byte of 16 bit message suffix
      wire_cksum = *(m->cmd_payload + 2 + msg_data_length);
// ("experimental") if it's a reply and it has no data
// then use the last byte as the checksum

if (0) //if ((p->addr & 0x80) && (m->lth == 7))
{
  char *p;
  int i;
  unsigned old;
  old = wire_cksum;
  wire_cksum = *(m->cmd_payload + 1 + msg_data_length);
  fprintf(stderr, "wck old %x now %x, p %x cmd %x\n", old, wire_cksum, parsed_cksum, returned_hdr->command);
  p = (char *)(m->ptr);
  for (i=0; i<16; i++)
    fprintf(stderr, " %02x", (unsigned)*(p+i)); 
  fprintf(stderr, "\n");
};
wire_cksum = (unsigned char)*(m->lth -1 + m->ptr);
      if (context->verbosity > 99)
      {
        fprintf (stderr, "pck %04x wck %04x\n",
          parsed_cksum, wire_cksum);
      };
      if (parsed_cksum != wire_cksum)
      {
char *p;
int i;
fprintf(stderr, "Checksum error != c=%x p %x %x\n",
  (unsigned)(returned_hdr->command), (unsigned)parsed_cksum, (unsigned)wire_cksum);
p = (char *)(m->ptr);
for (i=0; i<16; i++)
  fprintf(stderr, " %02x", *(unsigned char *)(p+i)); 
fprintf(stderr, "\n"); fflush(stderr);
        status = ST_BAD_CHECKSUM;
status = ST_OK; // tolerate checksum error and continue
        context->checksum_errs ++;
      };
    };
    if ((context->verbosity > 2) || (m_dump > 0))
    {
      char cmd_rep_tag [1024];
      char log_line [1024];

      strcpy(cmd_rep_tag,
        osdp_command_reply_to_string(returned_hdr->command, m->direction));
      sprintf (log_line, "  Message: %s %s", cmd_rep_tag, tlogmsg);
      sprintf (tlogmsg2, " A:%02x S:%02x Ck %x Sec %x CRC %04x",
        (0x7F & p->addr), msg_sqn, msg_check_type, msg_scb, wire_crc);
      strcat (log_line, tlogmsg2);
      if (((returned_hdr->command != OSDP_POLL) &&
        (returned_hdr->command != OSDP_ACK)) ||
        (context->verbosity > 3))
      {
        fprintf (context->log, "%s\n", log_line);
        fflush (context->log);
      };
      tlogmsg [0] = 0; tlogmsg2 [0] = 0;
    };
  };
  if (status EQUALS ST_OK)
  {
    /*
      at this point we think it's a whole well-formed frame.  might not be for
      us but it's a frame.
    */
    context->packets_received ++;

    if (context->role EQUALS OSDP_ROLE_PD)
      if ((p_card.addr != (0x7f & p->addr)) && (p->addr != 0x7f))
      {
        if (context->verbosity > 3)
          fprintf (stderr, "addr mismatch for: %02x me: %02x\n",
            p->addr, p_card.addr);
        status = ST_NOT_MY_ADDR;
      };
    if (context->role EQUALS OSDP_ROLE_MONITOR)
    {
      // pretty print the message if there are juicy details.
      (void)monitor_osdp_message (context, m);

      status = ST_MONITOR_ONLY;
    };
  };

  // if there was an error dump the log buffer

  if ((status != ST_OK) && (status != ST_MSG_TOO_SHORT))
  {
    if (strlen (logmsg) > 0)
      fprintf (context->log, "%s\n", logmsg);

    // if parse failed report the status code
    if ((context->verbosity > 3) && (status != ST_MONITOR_ONLY))
    {
      fflush (context->log);
      fprintf (context->log,
        "Message input parsing failed, status %d\n", status);
    };
  };
  return (status);

} /* parse_message */


/*
  monitor_osdp_message - output the message to the log for tracing
*/
int
  monitor_osdp_message
    (OSDP_CONTEXT *context,
    OSDP_MSG *msg)

{ /* monitor_osdp_message */

  int status;
  char tlogmsg [1024];


  status = ST_OK;
  if (msg->direction EQUALS 0)
  {
    switch (msg->msg_cmd)
    {
    case OSDP_ACURXSIZE:
      status = oosdp_make_message (OOSDP_MSG_ACURXSIZE, tlogmsg, msg);
      if (status == ST_OK)
        status = oosdp_log (context, OSDP_LOG_NOTIMESTAMP, 1, tlogmsg);
      break;
    case OSDP_BUZ:
      status = oosdp_make_message (OOSDP_MSG_BUZ, tlogmsg, msg);
      if (status == ST_OK)
        status = oosdp_log (context, OSDP_LOG_NOTIMESTAMP, 1, tlogmsg);
      break;
    case OSDP_CHLNG:
      status = oosdp_make_message (OOSDP_MSG_CHLNG, tlogmsg, msg);
      if (status == ST_OK)
        status = oosdp_log (context, OSDP_LOG_NOTIMESTAMP, 1, tlogmsg);
      break;
    case OSDP_COMSET:
      status = oosdp_make_message (OOSDP_MSG_COMSET, tlogmsg, msg);
      if (status == ST_OK)
        status = oosdp_log (context, OSDP_LOG_NOTIMESTAMP, 1, tlogmsg);
      break;
    case OSDP_KEEPACTIVE:
      status = oosdp_make_message (OOSDP_MSG_KEEPACTIVE, tlogmsg, msg);
      if (status == ST_OK)
        status = oosdp_log (context, OSDP_LOG_NOTIMESTAMP, 1, tlogmsg);
      break;
    case OSDP_MFG:
      status = oosdp_make_message (OOSDP_MSG_MFG, tlogmsg, msg);
      if (status == ST_OK)
        status = oosdp_log (context, OSDP_LOG_NOTIMESTAMP, 1, tlogmsg);
      break;
    case OSDP_OUT:
      status = oosdp_make_message(OOSDP_MSG_OUT, tlogmsg, msg);
      if (status == ST_OK)
        status = oosdp_log (context, OSDP_LOG_NOTIMESTAMP, 1, tlogmsg);
      break;
    case OSDP_XWR:
      status = oosdp_make_message(OOSDP_MSG_XWRITE, tlogmsg, msg);
      if (status == ST_OK)
        status = oosdp_log (context, OSDP_LOG_NOTIMESTAMP, 1, tlogmsg);
      break;
    };
  };
  if (msg->direction != 0)
  {
    switch (msg->msg_cmd)
    {
    case OSDP_CCRYPT:
      status = oosdp_make_message (OOSDP_MSG_CCRYPT, tlogmsg, msg);
      if (status == ST_OK)
        status = oosdp_log (context, OSDP_LOG_NOTIMESTAMP, 1, tlogmsg);
      break;
    case OSDP_COM:
      status = oosdp_make_message (OOSDP_MSG_COM, tlogmsg, msg);
      if (status == ST_OK)
        status = oosdp_log (context, OSDP_LOG_NOTIMESTAMP, 1, tlogmsg);
      break;
    case OSDP_ISTATR:
      status = oosdp_make_message (OOSDP_MSG_ISTATR, tlogmsg, msg);
      if (status == ST_OK)
        status = oosdp_log (context, OSDP_LOG_NOTIMESTAMP, 1, tlogmsg);
      break;
    case OSDP_XRD:
      status = oosdp_make_message (OOSDP_MSG_XREAD, tlogmsg, msg);
      if (status == ST_OK)
        status = oosdp_log (context, OSDP_LOG_NOTIMESTAMP, 1, tlogmsg);
      break;
    };
  };
  switch (msg->msg_cmd)
  {
  case OSDP_FILETRANSFER:
    if (context->verbosity > 3)
    {
      status = oosdp_make_message (OOSDP_MSG_FILETRANSFER, tlogmsg, msg);
      if (status == ST_OK)
        status = oosdp_log (context, OSDP_LOG_NOTIMESTAMP, 1, tlogmsg);
    };
    break;

  case OSDP_FTSTAT:
    if (context->verbosity > 3)
    {
      status = oosdp_make_message (OOSDP_MSG_FTSTAT, tlogmsg, msg);
      if (status == ST_OK)
        status = oosdp_log (context, OSDP_LOG_NOTIMESTAMP, 1, tlogmsg);
    };
    break;

  case OSDP_KEYPAD:
    status = oosdp_make_message (OOSDP_MSG_KEYPAD, tlogmsg, msg);
    if (status == ST_OK)
      status = oosdp_log (context, OSDP_LOG_NOTIMESTAMP, 1, tlogmsg);
    break;

  case OSDP_LED:
    status = oosdp_make_message (OOSDP_MSG_LED, tlogmsg, msg);
    if (status == ST_OK)
      status = oosdp_log (context, OSDP_LOG_NOTIMESTAMP, 1, tlogmsg);
    break;

  case OSDP_LSTATR:
    status = oosdp_make_message (OOSDP_MSG_LSTATR, tlogmsg, msg);
    if (status == ST_OK)
      status = oosdp_log (context, OSDP_LOG_NOTIMESTAMP, 1, tlogmsg);
    break;

  case OSDP_MFGREP:
    status = oosdp_make_message (OOSDP_MSG_MFGREP, tlogmsg, msg);
    if (status == ST_OK)
      status = oosdp_log (context, OSDP_LOG_NOTIMESTAMP, 1, tlogmsg);
    break;

  case OSDP_NAK:
    context->sent_naks ++; // nobody updated it in monitor mode
    status = oosdp_make_message (OOSDP_MSG_NAK, tlogmsg, msg);
    if (status == ST_OK)
      status = oosdp_log (context, OSDP_LOG_NOTIMESTAMP, 1, tlogmsg);
    break;

  case OSDP_PDCAP:
    status = oosdp_make_message (OOSDP_MSG_PD_CAPAS, tlogmsg, msg);
    if (status == ST_OK)
      status = oosdp_log (context, OSDP_LOG_NOTIMESTAMP, 1, tlogmsg);
    break;

  case OSDP_PDID:
    status = oosdp_make_message (OOSDP_MSG_PD_IDENT, tlogmsg, msg);
    if (status == ST_OK)
      status = oosdp_log (context, OSDP_LOG_NOTIMESTAMP, 1, tlogmsg);
    break;

  case OSDP_RAW:
    // in monitor mode we're really not supposed to use 'action' routines
    // but all it does is printf.

    status = action_osdp_RAW (context, msg);
    break;
  };
  return (status);

} /* monitor_osdp_message */


int
  process_osdp_message
    (OSDP_CONTEXT
      *context,
     OSDP_MSG
       *msg)

{ /* process_osdp_message */

  int count;
  int current_length;
  int i;
  char logmsg [1024];
  unsigned char osdp_nak_response_data [2];
  OSDP_HDR *oh;
  int status;
  unsigned char this_command;
  char tlog2 [1024];
  char tlogmsg [1024];


  status = ST_MSG_UNKNOWN;
  oh = (OSDP_HDR *)(msg->ptr);
  if (context -> role EQUALS OSDP_ROLE_PD)
  {
    if (context->verbosity > 9)
    {
      fprintf (context->log, "PD: command %02x\n",
        context->role);
    };
    if ((oh->ctrl & 0x03) EQUALS 0)
    {
      fprintf (context->log,
        "CP sent sequence 0 - resetting sequence numbers\n");
      context->next_sequence = 0;
    };

    // if they asked for a NAK mangle the command so we hit the default case of the switch

    this_command = msg->msg_cmd;
    if (context->next_nak)
      this_command = OSDP_BOGUS;

    switch (this_command)
    {
    case OSDP_BIOREAD:
      sprintf (logmsg, "BIOREAD rdr=%02x type=%02x format=%02x quality=%02x\n",
          *(msg->data_payload + 0), *(msg->data_payload + 1),
          *(msg->data_payload + 2), *(msg->data_payload + 3));
      fprintf (context->log, "%s", logmsg);
      fprintf (stderr, "%s", logmsg);
      logmsg[0]=0;

      // we don't actually DO a biometrics read at this time, so NAK it.
      {
        current_length = 0;
        osdp_nak_response_data [0] = OO_NAK_UNK_CMD;
        osdp_nak_response_data [1] = 0xff;
        status = send_message (context,
          OSDP_NAK, p_card.addr, &current_length, 1, osdp_nak_response_data);
        context->sent_naks ++;
        osdp_conformance.rep_nak.test_status = OCONFORM_EXERCISED;
        if (context->verbosity > 2)
        {
          fprintf (context->log, "Responding with OSDP NAK\n");
          fprintf (stderr, "CMD %02x Unknown\n", msg->msg_cmd);
        };
      };
      osdp_conformance.cmd_bioread.test_status =
        OCONFORM_EXERCISED;
      current_length = 0;
      status = send_message
        (context, OSDP_ACK, p_card.addr, &current_length, 0, NULL);
      context->pd_acks ++;
      break;

    case OSDP_BUZ:
      {
        sprintf (logmsg, "BUZZER %02x %02x %02x %02x %02x\n",
          *(msg->data_payload + 0), *(msg->data_payload + 1),
          *(msg->data_payload + 2), *(msg->data_payload + 3),
          *(msg->data_payload + 4));
        fprintf (context->log, "%s", logmsg);
        fprintf (stderr, "%s", logmsg);
        logmsg[0]=0;
      };
      osdp_conformance.cmd_buz.test_status =
        OCONFORM_EXERCISED;
      current_length = 0;
      status = send_message
        (context, OSDP_ACK, p_card.addr, &current_length, 0, NULL);
      context->pd_acks ++;
      break;

    case OSDP_CAP:
      {
        unsigned char
          osdp_cap_response_data [3*(14-1)] = {
            1,2,OOSDP_CFG_INPUTS, // 8 inputs, on/of/nc/no
            2,2,8, // 8 outputs, on/off/drive
            3,1,0, // 1024 bits max
            4,1,8, // on/off only, 8 LED's
            5,1,1, // audible annunciator present, claim on/off only
            6,1,1, // 1 row of 16 characters
            //7 // assume 7 (time keeping) is deprecated
            8,1,0, // supports CRC-16
#ifndef OSDP_SECURITY
            9,0,0, //no security
#endif
#if OSDP_SECURITY
            9,1,1, //SCBK_D, AES 128
#endif
            10,0xff & OSDP_BUF_MAX, (0xff00&OSDP_BUF_MAX)>>8, // rec buf max
            11,0xff & OSDP_BUF_MAX, (0xff00&OSDP_BUF_MAX)>>8, // largest msg
            12,0,0, // no smartcard
            13,0,0, // no keypad
            14,0,0  // no biometric
            };

        status = ST_OK;
        current_length = 0;
        status = send_message (context,
          OSDP_PDCAP, p_card.addr, &current_length,
          sizeof (osdp_cap_response_data), osdp_cap_response_data);
        osdp_conformance.cmd_pdcap.test_status =
          OCONFORM_EXERCISED;
        osdp_conformance.rep_device_capas.test_status =
          OCONFORM_EXERCISED;
        if (context->verbosity > 2)
          fprintf (stderr, "Responding with OSDP_PDCAP\n");
      };
      break;

    case OSDP_COMSET:
      status = action_osdp_COMSET(context, msg);
      break;

    case OSDP_CHLNG:
      status = action_osdp_CHLNG(context, msg);
      break;

    case OSDP_FILETRANSFER:
      status = action_osdp_FILETRANSFER (context, msg);
      break;

    case OSDP_ID:
      {
        unsigned char
          osdp_pdid_response_data [12];

        osdp_pdid_response_data [ 0] = context->vendor_code [0];
        osdp_pdid_response_data [ 1] = context->vendor_code [1];
        osdp_pdid_response_data [ 2] = context->vendor_code [2];
        osdp_pdid_response_data [ 3] = context->model;;
        osdp_pdid_response_data [ 4] = context->version;
        osdp_pdid_response_data [ 5] = 0xca;
        osdp_pdid_response_data [ 6] = 0xfe;
        osdp_pdid_response_data [ 7] = 0xde;
        osdp_pdid_response_data [ 8] = 0xad;
        osdp_pdid_response_data [ 9] =
          context->fw_version [0] = OSDP_VERSION_MAJOR;
        osdp_pdid_response_data [10] = m_version_minor;
        osdp_pdid_response_data [11] = m_build;
        status = ST_OK;
        current_length = 0;
        status = send_message (context, OSDP_PDID, p_card.addr,
          &current_length,
          sizeof (osdp_pdid_response_data), osdp_pdid_response_data);
        osdp_conformance.cmd_id.test_status = OCONFORM_EXERCISED;
        osdp_conformance.rep_device_ident.test_status = OCONFORM_EXERCISED;
        SET_PASS (context, "4-3-2");
        if (context->verbosity > 2)
        {
          sprintf (logmsg, "Responding with OSDP_PDID");
          fprintf (context->log, "%s\n", logmsg);
        };
      }
    break;

    case OSDP_ISTAT:
      status = ST_OK;
      {
        unsigned char
          osdp_istat_response_data [OOSDP_CFG_INPUTS];

        // hard code to show all inputs in '0' state.

        memset (osdp_istat_response_data, 0, sizeof (osdp_istat_response_data));
        osdp_conformance.cmd_istat.test_status =
          OCONFORM_EXERCISED;
        osdp_conformance.resp_input_stat.test_status =
          OCONFORM_EXERCISED;
        current_length = 0;
        status = send_message (context, OSDP_ISTATR, p_card.addr,
          &current_length, sizeof (osdp_istat_response_data), osdp_istat_response_data);
        if (context->verbosity > 2)
        {
          sprintf (logmsg, "Responding with OSDP_ISTAT (hard-coded all zeroes)");
          fprintf (context->log, "%s\n", logmsg);
        };
      };
      break;

    case OSDP_KEEPACTIVE:
      status = action_osdp_KEEPACTIVE (context, msg);
      break;

    case OSDP_LED:
      /*
        There are 256 LED's.  They all use the colors in the spec.
        They switch on or off.  They don't blink.
      */
      {
        int
          count;
        OSDP_RDR_LED_CTL
          *led_ctl;

        status = ST_OK;
        oh = (OSDP_HDR *)(msg->ptr);
        led_ctl = (OSDP_RDR_LED_CTL *)(msg->data_payload);
        count = oh->len_lsb + (oh->len_msb << 8);
        count = count - 7;
        count = count / sizeof (*led_ctl);
        fprintf (context->log, "LED Control cmd count %d\n", count);
        fprintf (context->log, "LED Control Payload:\n");
        for (i=0; i<count; i++)
        {
          fprintf (context->log, "[%02d] Rdr %d LED %d Tcmd %d Pcmd %d\n",
            i, led_ctl->reader, led_ctl->led, led_ctl->temp_control,
            led_ctl->perm_control);
          if (led_ctl->reader EQUALS 0)
            if (led_ctl->temp_control EQUALS OSDP_LED_TEMP_SET)
            {
              if (context->verbosity > 2)
              {
                fprintf(context->log, "LED-TEMP: On: C=%d T=%d Off C=%d T=%d timer %02x %02x\n",
                  led_ctl->temp_on_color, led_ctl->temp_on, led_ctl->temp_off_color, led_ctl->temp_off,
                  led_ctl->temp_timer_lsb, led_ctl->temp_timer_msb);
#define MILLISEC_IN_NANOSEC (1000000) 
              };
            };


            if (led_ctl->perm_control EQUALS OSDP_LED_SET)
            {
              context->led [led_ctl->led].state = OSDP_LED_ACTIVATED;
              context->led [led_ctl->led].web_color =
                web_color_lookup [led_ctl->perm_on_color];

              // for conformance tests 3-10-1/3-10-2 we specifically look for LED 0 Color 1 (Red) or Color 2 (Green)

              if (led_ctl->perm_on_color EQUALS 1)
                osdp_conformance.cmd_led_red.test_status =
                  OCONFORM_EXERCISED;
              if (led_ctl->perm_on_color EQUALS 2)
                osdp_conformance.cmd_led_green.test_status =
                  OCONFORM_EXERCISED;
            };
          led_ctl = led_ctl + sizeof(OSDP_RDR_LED_CTL);
        };

        // we always ack the LED command regardless of how many LED's
        // it asks about

        current_length = 0;
        status = send_message
          (context, OSDP_ACK, p_card.addr, &current_length, 0, NULL);
        context->pd_acks ++;
        if (context->verbosity > 9)
          fprintf (stderr, "Responding with OSDP_ACK\n");
      };
      break;

    case OSDP_OUT:
      status = action_osdp_OUT (context, msg);
      break;

    case OSDP_POLL:
      status = action_osdp_POLL (context, msg);
      break;

    case OSDP_LSTAT:
fprintf(stderr, "lstat 1684\n");
    status = ST_OK;
    {
      unsigned char
        osdp_lstat_response_data [2];

      osdp_conformance.cmd_lstat.test_status =
        OCONFORM_EXERCISED;
      osdp_lstat_response_data [ 0] = context->tamper;
      osdp_lstat_response_data [ 1] = context->power_report; // report power failure
      current_length = 0;
      status = send_message (context, OSDP_LSTATR, p_card.addr,
        &current_length,
        sizeof (osdp_lstat_response_data), osdp_lstat_response_data);
      if (context->verbosity > 2)
      {
        sprintf (logmsg, "Responding with OSDP_LSTATR (Power)");
        fprintf (context->log, "%s\n", logmsg);
      };
      SET_PASS (context, "3-5-1");
      SET_PASS (context, "4-5-1");
    };
    break;

    case OSDP_MFG:
      status = action_osdp_MFG (context, msg);
      break;

    case OSDP_RSTAT:
      status = action_osdp_RSTAT (context, msg);
      break;

    case OSDP_TEXT:
      status = action_osdp_TEXT (context, msg);
      break;

    case OSDP_BOGUS:
    default:
      status = ST_OK;
      {
        unsigned char
          osdp_nak_response_data [2];
        current_length = 0;
        osdp_nak_response_data [0] = OO_NAK_UNK_CMD;
        osdp_nak_response_data [1] = 0xff;
 
        // if it was an induced NAK then call it error code 0xff and detail 0xee
        if (context->next_nak)
        {
          osdp_nak_response_data [0] = 0xff;
          osdp_nak_response_data [1] = 0xee;
        };

        status = send_message (context,
          OSDP_NAK, p_card.addr, &current_length, 1, osdp_nak_response_data);
        context->sent_naks ++;
        osdp_conformance.rep_nak.test_status = OCONFORM_EXERCISED;
        if (context->verbosity > 2)
        {
          fprintf (stderr, "CMD %02x Unknown\n", msg->msg_cmd);
        };
      };
      break;
    };
  } /* role PD */
  if (context -> role EQUALS OSDP_ROLE_CP)
  {
    // if we're here we think it's a whole sane response so we can say the last was processed.
    context->last_was_processed = 1;
    status = osdp_timer_start(context, OSDP_TIMER_RESPONSE);

    context->last_response_received = msg->msg_cmd;
    switch (msg->msg_cmd)
    {
    case OSDP_ACK:
      status = ST_OK;

      // for the moment receiving an ACK is considered processing.
      // really should be more fine-grained

      context->last_was_processed = 1;
      break;

    case OSDP_BUSY:
      status = ST_OK;
      fprintf (context->log, "PD Responded BUSY\n");
      break;

    case OSDP_CCRYPT:
      status = action_osdp_CCRYPT (context, msg);
      break;

    case OSDP_FTSTAT:
      status = action_osdp_FTSTAT(context, msg);
      break;

    case OSDP_ISTATR:
      status = ST_OK;
      count = oh->len_lsb + (oh->len_msb << 8);
      count = count - 8;
      sprintf(tlog2, "\n  Count: %d Data:", count);
      strcat(tlogmsg, tlog2);
      for (i=0; i<count; i++)
      {
        sprintf(tlog2, " %02x", *(i+msg->data_payload));
        strcat(tlogmsg, tlog2);
      };
      fprintf (context->log, "Input Status: %s\n", tlogmsg);
      osdp_conformance.resp_input_stat.test_status =
        OCONFORM_EXERCISED;
      break;

    case OSDP_KEYPAD:
      status = ST_OK;
      sprintf (tlogmsg, "Reader: %d. Digits: %d. First Digit: 0x%02x",
          *(0+msg->data_payload),
          *(1+msg->data_payload),
          *(2+msg->data_payload));
      fprintf (context->log, "PD Keypad Buffer: %s\n", tlogmsg);
      {
        char temp [8];
        memcpy (temp, context->last_keyboard_data, 7);
        memcpy (context->last_keyboard_data+1, temp, 7);
        context->last_keyboard_data [0] = *(2+msg->data_payload);
      };
      osdp_conformance.resp_keypad.test_status =
        OCONFORM_EXERCISED;
      break;

    case OSDP_NAK:
      status = ST_OK;
      context->sent_naks ++;
      context->last_nak_error = *(0+msg->data_payload);

      if (context->verbosity > 2)
      {
        sprintf (tlogmsg, "osdp_NAK: Error Code %02x Data %02x",
          *(0+msg->data_payload), *(1+msg->data_payload));
        fprintf (context->log, "%s\n", tlogmsg);
        fprintf (stderr, "%s\n", tlogmsg);
        switch(*(0+msg->data_payload))
        {
        case 1:
          fprintf(context->log, "  NAK: Bad CRC/Checksum\n");
          break;
        case 3:
          fprintf(context->log, "  NAK: Command not implemented by PD\n");
          break;
        };
      };
      osdp_conformance.rep_nak.test_status = OCONFORM_EXERCISED;

      // if the PD NAK'd an ID fail the test.
      if (context->last_command_sent EQUALS OSDP_ID)
      {
        osdp_conformance.cmd_id.test_status = OCONFORM_FAIL;
        SET_FAIL ((context), "3-2-1");
      };
      // if the PD NAK'd an ISTAT fail the test.
      if (context->last_command_sent EQUALS OSDP_ISTAT)
      {
        osdp_conformance.cmd_istat.test_status = OCONFORM_FAIL;
        SET_FAIL ((context), "3-6-1");
      };
      // if the PD NAK'd an LSTAT fail the test.
      if (context->last_command_sent EQUALS OSDP_LSTAT)
      {
        osdp_conformance.cmd_lstat.test_status = OCONFORM_FAIL;
        SET_FAIL ((context), "3-5-1");
      };
      // if the PD NAK'd a CAP fail the test.
      if (context->last_command_sent EQUALS OSDP_CAP)
      {
        osdp_conformance.cmd_pdcap.test_status = OCONFORM_FAIL;
        SET_FAIL ((context), "3-3-1");
      };
      // if the PD NAK'd during secure channel set-up then reset out of secure channel
      if (context->secure_channel_use [OO_SCU_ENAB] & 0x80)
        osdp_reset_secure_channel (context);

      context->last_was_processed = 1; // if we got a NAK that processes the cmd
      break;

    case OSDP_COM:
      status = ST_OK;
      osdp_conformance.resp_com.test_status = OCONFORM_EXERCISED;
      if (context->verbosity > 2)
      {
        fprintf (stderr, "osdp_COM: Addr %02x Baud (m->l) %02x %02x %02x %02x\n",
          *(0+msg->data_payload), *(1+msg->data_payload), *(2+msg->data_payload),
          *(3+msg->data_payload), *(4+msg->data_payload));
      };
      break;

    case OSDP_LSTATR:
      status = ST_OK;
      fprintf (context->log, "Local Status Report:");
      fprintf (context->log,
        " Tamper %d Power %d\n",
        *(msg->data_payload + 0), *(msg->data_payload + 1));
      osdp_conformance.cmd_poll_lstatr.test_status =
        OCONFORM_EXERCISED; // 3-1-3
      osdp_conformance.resp_lstatr.test_status =
        OCONFORM_EXERCISED;
      if (*(msg->data_payload) > 0)
        osdp_conformance.resp_lstatr_tamper.test_status =
          OCONFORM_EXERCISED;
      if (*(msg->data_payload + 1) > 0)
        osdp_conformance.resp_lstatr_power.test_status =
          OCONFORM_EXERCISED;
      break;

    case OSDP_MFGREP:
      {
        OSDP_MFG_HEADER *mfg;

        status = ST_OK;
        oh = (OSDP_HDR *)(msg->ptr);
        count = oh->len_lsb + (oh->len_msb << 8);
        count = count - 7;
        count = count - sizeof(OSDP_MFG_HEADER);
        
        mfg = (OSDP_MFG_HEADER *)(msg->data_payload);
        sprintf (tlogmsg,
          "OUI %02x%02x%02x Length %d",
          mfg->vendor_code [0], mfg->vendor_code [1], mfg->vendor_code [2], count);
        fprintf (context->log, "  Mfg Reply %s\n", tlogmsg);
        dump_buffer_log(context, "MFGREP: ", &(mfg->data), count);
        {
          char cmd [1024];
          FILE *mrdat;
          char mfg_rep_data_file [1024];

          sprintf(mfg_rep_data_file, "/opt/osdp-conformance/run/CP/pd_%02d_mfgrep.dat", p_card.addr);
          mrdat = fopen(mfg_rep_data_file, "w");
          if (mrdat != NULL)
          {
            int total_length;
//KLUDGE count-6 blindly assumes 2-totlen 2-fraglen 2-fragoff
            fwrite(6+&(mfg->data), sizeof(unsigned char), count-6, mrdat);

            if (context->verbosity > 3)
            { 
              fprintf(stderr, "multi: add at %05d. lth %d.\n",
                context->next_in, count-6);
            };
            memcpy(context->mmsgbuf+context->next_in, 6+&(mfg->data), count-6);
            context->next_in = context->next_in + (count-6);
            total_length = mfg->data;
            total_length = total_length + 256 * *(&(mfg->data) + 1);
            if (context->next_in EQUALS total_length)
            {
              FILE *asmf;
              asmf = fopen("/opt/osdp-conformance/run/CP/mfg-rep.bin", "w");
              if (asmf != NULL)
              {
                fwrite(context->mmsgbuf, sizeof(unsigned char), total_length, asmf);
                fclose(asmf);
                context->next_in = 0;
              };
            };              
// CHECK SECURE CHANNEL
            fclose(mrdat);
            if (context->verbosity > 3)
            {
              sprintf(cmd, "mv /opt/osdp-conformance/run/CP/pd_%02d_mfgrep.dat /opt/osdp-conformance/run/CP/%02X_mfgrep.dat",
                p_card.addr, mfg_rep_sequence);
              system(cmd);
              mfg_rep_sequence++;
            };
          };
        };

#if 0 // not multi-part now...
        /*
          process a multi-part message fragment
        */
	// if we're already started cannot restart
        if ((mmsg->MpdOffset == 0) && (context->total_len != 0))
          status = ST_MMSG_SEQ_ERR;
        if (status == ST_OK)
        {
          if (mmsg->MpdOffset == 0)
          {
            // starting a new one
            context->total_len = mmsg->MpdSizeTotal;
          };
        };
        if (status == ST_OK)
        {
          // must be in sequential order
          if (mmsg->MpdOffset != context->next_in)
            status = ST_MMSG_OUT_OF_ORDER;
        };
        if (status == ST_OK)
        {
          if ((mmsg->MpdFragmentSize + context->next_in) > context->total_len)
            status = ST_MMSG_LAST_FRAG_TOO_BIG;
        };
        if (status == ST_OK)
        {
          // values checked out.  add this fragment
          memcpy (context->mmsgbuf+context->next_in,
            sizeof (OSDP_MULTI_HDR) + msg->data_payload,
            mmsg->MpdFragmentSize);

          if ((context->next_in + mmsg->MpdFragmentSize) == context->total_len)
          {
            // finished, process it now
printf ("MMSG DONE\n");

            // and clean up when done processing
            context->total_len = 0;
            context->next_in = 0;
          }
          else
          {
            context->next_in = context->next_in + mmsg->MpdFragmentSize;
          };
        };
#endif
      };
      break;

    case OSDP_OSTATR:
      osdp_conformance.resp_output_stat.test_status = OCONFORM_EXERCISED;

      // if this is in response to an OSTAT then mark that too.
      if (context->last_command_sent EQUALS OSDP_OSTAT)
        osdp_conformance.cmd_ostat.test_status = OCONFORM_EXERCISED;

      status = oosdp_make_message (OOSDP_MSG_OUT_STATUS, tlogmsg, msg);
      fprintf (context->log, "%s\n", tlogmsg);
      break;

    case OSDP_PDCAP:
      status = action_osdp_PDCAP(context, msg);
      break;

    case OSDP_PDID:
      status = oosdp_make_message (OOSDP_MSG_PD_IDENT, tlogmsg, msg);
      if (status == ST_OK)
        status = oosdp_log (context, OSDP_LOG_NOTIMESTAMP, 1, tlogmsg);

      // consistency check (test 4-3-2)
      // OUI must not be zero

      if ((msg->data_payload [0] EQUALS 0) &&
        (msg->data_payload [1] EQUALS 0) &&
        (msg->data_payload [2] EQUALS 0))
      {
        SET_FAIL ((context), "4-3-2");
      }
      else
      {
        context->vendor_code [0] = *(0+msg->data_payload);
        context->vendor_code [1] = *(1+msg->data_payload);
        context->vendor_code [2] = *(2+msg->data_payload);
        context->model = *(3+msg->data_payload);
        context->version = *(4+msg->data_payload);
        context->serial_number [0] = *(5+msg->data_payload);
        context->serial_number [1] = *(6+msg->data_payload);
        context->serial_number [2] = *(7+msg->data_payload);
        context->serial_number [3] = *(8+msg->data_payload);
        context->fw_version [0] = *(9+msg->data_payload);
        context->fw_version [1] = *(10+msg->data_payload);
        context->fw_version [2] = *(11+msg->data_payload);
        SET_PASS ((context), "4-3-2");
      };

      context->last_was_processed = 1;

      osdp_conformance.rep_device_ident.test_status = OCONFORM_EXERCISED;
      break;

    case OSDP_SCRYPT:
      status = action_osdp_SCRYPT (context, msg);
      break;

    case OSDP_XRD:
fprintf(stderr, "stub: osdp_XRD not yet processed.\n");
      status = oosdp_make_message (OOSDP_MSG_XREAD, tlogmsg, msg);
      if (status == ST_OK)
        status = oosdp_log (context, OSDP_LOG_NOTIMESTAMP, 1, tlogmsg);
      break;

    default:
      if (context->verbosity > 2)
      {
        fprintf (stderr, "CMD %02x Unknown to CP\n", msg->msg_cmd);
      };
    break;

    case OSDP_RAW:
      status = action_osdp_RAW (context, msg);
      break;

    case OSDP_RMAC_I:
      status = action_osdp_RMAC_I (context, msg);
      break;

    case OSDP_RSTATR:
      {
        unsigned char reader_0_tamper_status;
        char *tstatus;

        // received osdp_RSTATR.  Assume it's for one attached reader.

        status = ST_OK;
        reader_0_tamper_status = *(msg->data_payload + 0);
        fprintf (context->log, "Reader Tamper Status Report:");
        switch(reader_0_tamper_status)
        {
        case 0: tstatus = "Normal"; break;
        case 1: tstatus = "Not Connected"; break;
        case 2: tstatus = "Tamper"; break;
        };
        fprintf (context->log, " Ext Rdr %d Tamper Status %s\n",
          0, tstatus);
        osdp_conformance.resp_rstatr.test_status = OCONFORM_EXERCISED;
      };
      break;
    };
  } /* role CP */
  if (status EQUALS ST_MSG_UNKNOWN)
    osdp_conformance.last_unknown_command = msg->msg_cmd;
  if (status != ST_OK)
  {
    fprintf(context->log, "Error %d. in process_osdp_message, recovering.\n", status);
    status = ST_OK;
  };

  fflush (context->log);
  return (status);

} /* process_osdp_message */

