/*
  oo_util - open osdp utility routines

  (C)Copyright 2017-2020 Smithee Solutions LLC
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
#include <iec-xwrite.h>


extern OSDP_CONTEXT context;
extern OSDP_INTEROP_ASSESSMENT osdp_conformance;
extern OSDP_PARAMETERS p_card;
time_t previous_time;
char tlogmsg [1024];
char tlogmsg2 [3*1024];
int mfg_rep_sequence;


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
  int hashable_length;
  int i;
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
  unsigned wire_cksum;
  unsigned short int wire_crc;


  status = ST_MSG_TOO_SHORT;

  m->data_payload = NULL;
  m->security_block_length = 0; // assume no security block
  msg_data_length = 0;
  p = (OSDP_HDR *)m->ptr;

  msg_check_type = (p->ctrl) & 0x04;
  if (msg_check_type EQUALS 0)
  {
    m->check_size = 1;
    m_check = OSDP_CHECKSUM; // Issue #11
    if (context->verbosity > 9)
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
    hashable_length = msg_lth;
    if ((m->lth) > msg_lth)
      m->remainder = msg_lth - m->lth;

    // now that we have a bit of header figure out how much the whole thing is.  need all of it to process it.
    if (m->lth < msg_lth)
      status = ST_MSG_TOO_SHORT;
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
      m->security_block_type = sec_block_type;
      m->security_block_length = sec_blk_length;
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

    osdp_trace_dump(context, display);

    if (display)
    {
      char dirtag [1024];
      unsigned char *p1;
      char tlogmsg [1024];


        strcpy (tlogmsg, "");
        p1 = m->ptr;
        if (*(p1+1) & 0x80)
          strcpy (dirtag, "PD");
        else
          strcpy (dirtag, "ACU");
        if (0 EQUALS strcmp (dirtag, "ACU"))
          status = oosdp_log (context, OSDP_LOG_STRING_CP, 1, tlogmsg);
        else
          status = oosdp_log (context, OSDP_LOG_STRING_PD, 1, tlogmsg);
      
// don't dump sec block here, gets dumped in oo_util 
        // p2 = p1+5; // command/reply
        if (0) //(p->ctrl & 0x08)
        {
          strcpy(tlogmsg, osdp_sec_block_dump(p1+5));
          fprintf(context->log, "%s\n", tlogmsg);
          fflush (context->log);
          // p2 = p1+5+*(p1+5); // before-secblk and secblk
        };
    };

    m->data_length = msg_data_length;
    // go check the command field
    status = osdp_check_command_reply (role, returned_hdr->command, m, tlogmsg2);
    msg_data_length = m->data_length;

    // if we're the ACU and we are looking at sequence 0 then the DUT passes the seq zero test

    if (1) // status is ST_OK or status is ST_OSDP_CMDREP_FOUND ?
    {

      if ((context->role EQUALS OSDP_ROLE_ACU) && (context->role EQUALS role))
      {
        if (msg_sqn EQUALS 0)
        {
          osdp_test_set_status(OOC_SYMBOL_seq_zero, OCONFORM_EXERCISED);
        };
      };
    };
    if (status != ST_OSDP_CMDREP_FOUND)
    {
      if (status != ST_OK)
        fprintf (context->log,
          "***Status %d Unknown command? (%02x), default msg_data_length was %d\n",
          status, returned_hdr->command, msg_data_length);

    if (context->verbosity > 8)
    {
      fprintf(context->log, "osdp_parse_message: command %02x\n", returned_hdr->command);
    };

    switch (returned_hdr->command)
    {
    default:
      if ((context->role EQUALS OSDP_ROLE_PD) && !(0x80 & p->addr))
      {
        // it's not for another PD
        m->data_payload = m->cmd_payload + 1;
        msg_data_length = 0;
        if (context->verbosity > 2)
          strcpy (tlogmsg2, "\?\?\?");

        // if we don't recognize the command/reply code it fails 2-15-1
        osdp_test_set_status(OOC_SYMBOL_CMND_REPLY, OCONFORM_FAIL);
      };
      break;

    case OSDP_ACURXSIZE:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_BIOREAD");
      osdp_conformance.cmd_bioread.test_status = OCONFORM_EXERCISED;
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
      osdp_test_set_status(OOC_SYMBOL_resp_busy, OCONFORM_EXERCISED);
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

    case OSDP_MFGERRR:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_MFGERRR");
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
      osdp_test_set_status(OOC_SYMBOL_cmd_pdcap, OCONFORM_EXERCISED);
      osdp_test_set_status(OOC_SYMBOL_rep_device_capas, OCONFORM_EXERCISED);
      break;

    case OSDP_PDID:
      m->data_payload = m->cmd_payload + 1;
      msg_data_length = p->len_lsb + (p->len_msb << 8);
      msg_data_length = msg_data_length - 6 - 2; // less hdr,cmnd, crc/chk
// ASSUMES NO SECURITY
      if (context->verbosity > 2)
        strcpy (tlogmsg2, "osdp_PDID");

      // if we had sent an osdp_ID then that worked.
      if (context->last_command_sent EQUALS OSDP_ID)
        osdp_test_set_status(OOC_SYMBOL_cmd_id, OCONFORM_EXERCISED);

      osdp_test_set_status(OOC_SYMBOL_rep_device_ident, OCONFORM_EXERCISED);
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

    // crc_check is a pointer, used even if it's a checksum

    m->crc_check = m->cmd_payload + 1 + msg_data_length;

    if (m->check_size EQUALS 2)
    {
      hashable_length = hashable_length - 2;

      // figure out where crc or checksum starts
//...

      // if it's an SCS with a MAC suffix move the CRC pointer

      if (msg_scb)
      {

        // if we're the CP and we get an SCS but we're not in Secure Channel then
        // ditch the link session

        if ((sec_block_type EQUALS OSDP_SEC_SCS_15) || (sec_block_type EQUALS OSDP_SEC_SCS_16) ||
          (sec_block_type EQUALS OSDP_SEC_SCS_17) || (sec_block_type EQUALS OSDP_SEC_SCS_18))
        {
          if ((context->secure_channel_use [OO_SCU_ENAB] != OO_SCS_OPERATIONAL) &&
            (context->role EQUALS OSDP_ROLE_ACU))
          {
            fprintf(context->log, "sec_block_type was %x but not in secure channel, resetting\n",
              sec_block_type);
            status = ST_SCS_FROM_PD_UNEXPECTED;
            context->next_sequence = 0;
          }
          else
          {
            m->crc_check = 4 + m->cmd_payload + 1 + msg_data_length;
          };
        };
      };

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
        context->crc_errs ++;
      };
    }
    else
    {
      unsigned parsed_cksum;

      hashable_length = hashable_length - 1;

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

    // if the sequence number didn't line up report
    {
      int bad;
      int rcv_seq;
      int wire_sequence;

      wire_sequence = msg_sqn;
      rcv_seq = msg_sqn;

      //increment by 1, loops around at 3, never goes back to zero
      rcv_seq = (rcv_seq + 1) % 4;
      if (!rcv_seq)
        rcv_seq = 1;

      if (context->verbosity > 9)
        fprintf(stderr, "DEBUG: wire seq %d. rcv seq %d. next seq %d.\n",
          wire_sequence, rcv_seq, context->next_sequence);
      bad = 0;

      if (p_card.addr EQUALS (0x7f & p->addr))
      {
        /*
          if we're the ACU and it's from the correct source then the sequence number should 
          match
        */
        if ((role EQUALS OSDP_ROLE_ACU) && (rcv_seq != context->next_sequence))
          bad = 1;

        // if we're the PD the received sequence number should match the sequence number on the wire
        if ((role EQUALS OSDP_ROLE_PD) && (wire_sequence != context->next_sequence))
          bad = 1;
      };

      if (bad)
      {
        // if we're not just displaying it...
        if ((role != OSDP_ROLE_MONITOR) &&
          (role EQUALS context->role))
        {
          if (wire_sequence != 0)
          {
            fprintf(context->log, "***sequence number mismatch got %d expected %d\n", msg_sqn, context->next_sequence);
            status = ST_OSDP_BAD_SEQUENCE;
            context->seq_bad++;
          };
        };
      };
    };

    // check the MAC if it's secure channel formatted

    if (status EQUALS ST_OK)
    {
      if (msg_scb != 0)
      {
        // skip hash check if we're in monitor mode.
        // rolling hash/mac calculation gets screwed up...

        if (role != OSDP_ROLE_MONITOR)
        {
          status = oo_hash_check(context, m->ptr, sec_block_type,
            m->crc_check-4, hashable_length);
          if (status EQUALS ST_OK)
            status = osdp_decrypt_payload(context, m);
          if (status != ST_OK)
            fprintf(context->log,
              "Payload decryption failed, status %d.\n", status);
        };
        if (status != ST_OK)
        {
          if (context->verbosity > 3)
            fprintf(context->log,
              "  ..Secure Channel Hash check failed (%d).\n", status);
        };
      }; 
    };

    if ((context->verbosity > 2) || (m_dump > 0))
    {
      char cmd_rep_tag [1024];
      char log_line [3*1024]; // 'cause contents could be 1k already
      char tlogmsg [1024];


      strcpy(cmd_rep_tag,
        osdp_command_reply_to_string(returned_hdr->command, m->direction));

      // print "IEC" details of message
      (void)oosdp_message_header_print(context, m, tlogmsg);
      if (((returned_hdr->command != OSDP_POLL) &&
        (returned_hdr->command != OSDP_ACK)) ||
        (context->verbosity > 3))
      {
        fprintf (context->log, "%s\n", tlogmsg);
        tlogmsg [0] = 0;
        if (context->verbosity > 3)
          dump_buffer_log(context, "  Raw input: ", m->ptr, m->lth);
      };

      sprintf (log_line, "  Pkt: %04d Message: %s %s", context->packets_received, cmd_rep_tag, tlogmsg);

      {
        char scb_tag[1024];
        char check_tag [1024];

        if (msg_check_type EQUALS 4)
          sprintf(check_tag, "Check:CRC(%04x)",
            *(1+m->crc_check) << 8 | *(m->crc_check));
        else
          strcpy(check_tag, "Check:Cksum");
        strcpy(scb_tag, "");
        if (msg_scb)
          strcpy(scb_tag, "Sec block present;");

        sprintf (tlogmsg2, " A:%02x Lth:%d. S:%02x %s %s",
          (0x7F & p->addr), (p->len_msb)*256+(p->len_lsb),
          msg_sqn, check_tag, scb_tag);

      };
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
      if ((p_card.addr != (0x7f & p->addr)) && (p->addr != OSDP_CONFIGURATION_ADDRESS))
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

  if ((status != ST_OK) && (status != ST_MSG_TOO_SHORT) &&
    (status != ST_NOT_MY_ADDR))
  {
    // if parse failed report the status code
    if ((context->verbosity > 3) && (status != ST_MONITOR_ONLY))
    {
      fflush (context->log);
      fprintf (context->log,
        "Message input parsing failed, status %d\n", status);
    };
  };
  return (status);

} /* osdp_parse_message */


int
  process_osdp_message
    (OSDP_CONTEXT *context,
     OSDP_MSG *msg)

{ /* process_osdp_message */

  char cmd [1024];
  int count;
  int current_length;
  int current_security;
  char details [1024];
  int i;
  char logmsg [1024];
  char nak_code;
  char nak_data;
  unsigned char osdp_nak_response_data [2];
  OSDP_HDR *oh;
  int oo_osdp_max_packet;
  int status;
  unsigned char this_command;
  char tlog2 [1024];
  char tlogmsg [1024];
  extern unsigned int web_color_lookup [];


  status = ST_MSG_UNKNOWN;
  oo_osdp_max_packet = 768; // less than the 1K in some of the buffer routines
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
        "  ACU sent sequence 0 - resetting sequence numbers\n");
      context->next_sequence = 0;
      osdp_reset_secure_channel(context);
    };

    // if they asked for a NAK mangle the command so we hit the default case of the switch

    this_command = msg->msg_cmd;
    if (context->next_nak)
      this_command = OSDP_BOGUS;
    if (oh->addr EQUALS OSDP_CONFIGURATION_ADDRESS)
    {
      if ((this_command != OSDP_ID) && (this_command != OSDP_CAP) && (this_command != OSDP_COMSET))
      {
        this_command = OSDP_ILLICIT;
      };
    };

    // update count of whole messages
    context->pdus_received ++;
//TODO pdus_received v.s packets_received

    (void)monitor_osdp_message (context, msg);

    switch (this_command)
    {
    case OSDP_ACURXSIZE:
      context->max_acu_receive = 
        (*(msg->data_payload + 1) * 256) + *(msg->data_payload + 0);

      sprintf (logmsg, "  ACU Receive Buffer %d. bytes\n",
        context->max_acu_receive);
      fprintf (context->log, "%s", logmsg);
      logmsg[0]=0;
      osdp_conformance.cmd_max_rec.test_status =
        OCONFORM_EXERCISED;
      current_length = 0;
      current_security = OSDP_SEC_SCS_15;
      status = send_message_ex(context, OSDP_ACK, p_card.addr,
        &current_length, 0, NULL, current_security, 0, NULL);
      context->pd_acks ++;
      break;

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
fprintf(context->log, "DEBUG2: NAK: %d.\n", osdp_nak_response_data [0]);
        status = send_message (context,
          OSDP_NAK, p_card.addr, &current_length, 1, osdp_nak_response_data);
        context->sent_naks ++;
        osdp_test_set_status(OOC_SYMBOL_rep_nak, OCONFORM_EXERCISED);
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
      osdp_test_set_status(OOC_SYMBOL_cmd_buz, OCONFORM_EXERCISED);
      current_length = 0;
      current_security = OSDP_SEC_SCS_15;
      status = send_message_ex(context, OSDP_ACK, p_card.addr,
        &current_length, 0, NULL, current_security, 0, NULL);
      context->pd_acks ++;
      break;

    case OSDP_CAP:
      {
        unsigned char *response_cap;
        int response_length;
        unsigned char
          osdp_cap_response_short [] = {
            3,1,0, // 1024 bits max
            4,1,8, // on/off only, 8 LED's
            5,1,1, // audible annunciator present, claim on/off only
            6,1,1, // 1 row of 16 characters
            8,1,0, // supports CRC-16
            9,1,1, // security
            };
        unsigned char
          osdp_cap_response_data [3*(16-1)] = {
            1,2,OOSDP_CFG_INPUTS, // 8 inputs, on/of/nc/no
            2,2,8, // 8 outputs, on/off/drive
            3,1,0, // 1024 bits max
            4,1,8, // on/off only, 8 LED's
            5,1,1, // audible annunciator present, claim on/off only
            6,1,1, // 1 row of 16 characters
            //7 // assume 7 (time keeping) is deprecated
            8,1,0, // supports CRC-16
#define CAP_SCHAN_INDEX (7) // where in the array
            9,0,0, //no security
            10,0xff & oo_osdp_max_packet, (0xff00 & oo_osdp_max_packet)>>8, // rec buf max
            11,0xff & oo_osdp_max_packet, (0xff00 & oo_osdp_max_packet)>>8, // largest msg
            12,0,0, // no smartcard
            13,0,0, // no keypad
            14,0,0, // no biometric
            15,0,0, // no SPE support (secure pin entry)
            16,1,0  // IEC version
            };

         response_cap = osdp_cap_response_data;
         response_length = sizeof(osdp_cap_response_data);
         if (context->pdcap_select)
         {
           response_cap = osdp_cap_response_short;
           response_length = sizeof(osdp_cap_response_short);
         };

         // for any kind of secure channel enablement set the PDCAP values
         // "we always support SCBK-D"

         if (context->enable_secure_channel > 0)
         {
           // if enabled say AES128 support and SCBK-D support
           osdp_cap_response_data [ (3*CAP_SCHAN_INDEX) + 1] = 1;
           osdp_cap_response_data [ (3*CAP_SCHAN_INDEX) + 2] = 1;
         };

        status = ST_OK;
        current_length = 0;

        // SPECIAL CASE: if osdp_CAP comes in in cleartext, answer it in cleartext

        current_security = OSDP_SEC_SCS_18;
        if (msg->security_block_length EQUALS 0)
          current_security = OSDP_SEC_STAND_DOWN;
        status = send_message_ex(context,
          OSDP_PDCAP, p_card.addr, &current_length,
            response_length, response_cap,
            current_security, 0, NULL);
        osdp_test_set_status(OOC_SYMBOL_cmd_pdcap, OCONFORM_EXERCISED);
        osdp_test_set_status(OOC_SYMBOL_rep_device_capas, OCONFORM_EXERCISED);
      };
      break;

    case OSDP_CHLNG:
      status = action_osdp_CHLNG(context, msg);
      break;

    case OSDP_COMSET:
      status = action_osdp_COMSET(context, msg);
      break;

    case OSDP_CRAUTH:
      status = action_osdp_CRAUTH(context, msg);
      break;

    case OSDP_FILETRANSFER:
      status = action_osdp_FILETRANSFER (context, msg);
      break;

    case OSDP_ID:
      {
        unsigned char osdp_pdid_response_data [12];

        osdp_pdid_response_data [ 0] = context->vendor_code [0];
        osdp_pdid_response_data [ 1] = context->vendor_code [1];
        osdp_pdid_response_data [ 2] = context->vendor_code [2];
        osdp_pdid_response_data [ 3] = context->model;;
        osdp_pdid_response_data [ 4] = context->version;
        osdp_pdid_response_data [ 5] = context->serial_number [0];
        osdp_pdid_response_data [ 6] = context->serial_number [1];
        osdp_pdid_response_data [ 7] = context->serial_number [2];
        osdp_pdid_response_data [ 8] = context->serial_number [3];
        osdp_pdid_response_data [ 9] =
          context->fw_version [0] = OSDP_VERSION_MAJOR;
        osdp_pdid_response_data [10] = m_version_minor;
        osdp_pdid_response_data [11] = m_build;
        status = ST_OK;
        current_length = 0;
        current_security = OSDP_SEC_SCS_18;

        // SPECIAL CASE: if osdp_ID comes in in cleartext, answer it in cleartext

        if (msg->security_block_length EQUALS 0)
          current_security = OSDP_SEC_STAND_DOWN;
        status = send_message_ex(context, OSDP_PDID, oo_response_address(context, oh->addr),
          &current_length, sizeof(osdp_pdid_response_data), osdp_pdid_response_data, current_security, 0, NULL);
        osdp_conformance.cmd_id.test_status = OCONFORM_EXERCISED;
        osdp_conformance.rep_device_ident.test_status = OCONFORM_EXERCISED;
        osdp_test_set_status(OOC_SYMBOL_rep_device_ident, OCONFORM_EXERCISED);
        if (context->verbosity > 2)
        {
          sprintf (logmsg, "Responding with OSDP_PDID");
          fprintf (context->log, "%s\n", logmsg);
        };
      }
      sprintf(cmd,
        "/opt/osdp-conformance/run/ACU-actions/osdp_ID");
      system(cmd);
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

    case OSDP_KEYSET:
      status = action_osdp_KEYSET (context, msg);
      break;

    case OSDP_LED:
      /*
        There are 256 LED's.  They all use the colors in the spec.
        They switch on or off.  They don't blink.
      */
      {
        int count;
        OSDP_RDR_LED_CTL *led_ctl;

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
                osdp_test_set_status(OOC_SYMBOL_cmd_led_red, OCONFORM_EXERCISED);
              if (led_ctl->perm_on_color EQUALS 2)
                osdp_test_set_status(OOC_SYMBOL_cmd_led_green, OCONFORM_EXERCISED);
            };
          led_ctl = led_ctl + sizeof(OSDP_RDR_LED_CTL);
        };

        // we always ack the LED command regardless of how many LED's
        // it asks about

        current_length = 0;
        status = send_message_ex (context, OSDP_ACK, p_card.addr, &current_length,
          0, NULL, OSDP_SEC_NOT_SCS, 0, NULL);
        context->pd_acks ++;
        if (context->verbosity > 9)
          fprintf (stderr, "Responding with OSDP_ACK\n");
      };
      break;

    case OSDP_OSTAT:
      status = action_osdp_OSTAT(context, msg);
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

      osdp_test_set_status(OOC_SYMBOL_cmd_lstat, OCONFORM_EXERCISED);
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

    case OSDP_SCRYPT:
      status = action_osdp_SCRYPT (context, msg);
      break;

    case OSDP_TEXT:
      status = action_osdp_TEXT (context, msg);
      break;

    case OSDP_ILLICIT:
      {
        osdp_nak_response_data [0] = 0xe0;
fprintf(context->log, "DEBUG3: NAK: %d.\n", osdp_nak_response_data [0]);
        status = send_message_ex(context, OSDP_NAK, p_card.addr,
          &current_length, 1, osdp_nak_response_data, OSDP_SEC_SCS_18, 0, NULL);
        context->sent_naks ++;
      };
      break;

    case OSDP_BOGUS:
    default:
      status = ST_OK;
      {
        int nak_length;
        unsigned char osdp_nak_response_data [2];

        nak_length = 1;
        current_length = 0;
        osdp_nak_response_data [0] = OO_NAK_UNK_CMD;
        osdp_nak_response_data [1] = 0xff;
        nak_length = 2;
 
        // if it was an induced NAK then call it error code 0xff and detail 0xee
        if (context->next_nak)
        {
          osdp_nak_response_data [0] = 0xff;
          osdp_nak_response_data [1] = 0xee;
          nak_length = 2;
        };

        status = send_message (context,
          OSDP_NAK, p_card.addr, &current_length, nak_length, osdp_nak_response_data);
        context->sent_naks ++;
        osdp_test_set_status(OOC_SYMBOL_rep_nak, OCONFORM_EXERCISED);
        if (context->verbosity > 2)
        {
          fprintf (stderr, "CMD %02x Unknown\n", msg->msg_cmd);
        };
      };
      break;
    };
  } /* role PD */
  if (context -> role EQUALS OSDP_ROLE_ACU)
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

      if (msg->security_block_type >= OSDP_SEC_SCS_11)
      {
        if (context->verbosity > 9)
          fprintf(stderr, "Received SCS %02x on osdp_ACK\n", msg->security_block_type);
      };
      break;

    case OSDP_BUSY:
      status = ST_OK;
      fprintf (context->log, "PD Responded BUSY\n");
      break;

    case OSDP_CCRYPT:
      status = action_osdp_CCRYPT (context, msg);
      break;

    case OSDP_CRAUTHR:
      status = action_osdp_CRAUTHR(context, msg);
      break;

    case OSDP_FTSTAT:
      status = action_osdp_FTSTAT(context, msg);
      break;

    case OSDP_GENAUTHR:
      status = action_osdp_GENAUTHR(context, msg);
      break;

    case OSDP_ISTATR:
      status = ST_OK;
      count = oh->len_lsb + (oh->len_msb << 8);
      count = count - 8;
      sprintf(tlogmsg, "\n  Count: %d Data:", count);
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

    // action for NAK

    case OSDP_NAK:
      status = ST_OK;
      context->sent_naks ++;
      context->last_nak_error = *(0+msg->data_payload);

      if (context->verbosity > 2)
      {
        count = oh->len_lsb + (oh->len_msb << 8);
        count = count - 6 - 2; // less header less CRC

        nak_code = *(msg->data_payload);
        nak_data = 0;
        if (count > 1)
        {
          nak_data = *(1+msg->data_payload);
          sprintf (tlogmsg, "osdp_NAK: Error Code %02x Data %02x",
            nak_code, *(1+msg->data_payload));
        }
        else
        {
          sprintf (tlogmsg, "osdp_NAK: Error Code %02x", nak_code);
        };

        sprintf(cmd,
          "/opt/osdp-conformance/run/ACU-actions/osdp_NAK %x %x",
          nak_code, nak_data);
        system(cmd);

        fprintf (context->log, "%s\n", tlogmsg);
        switch(*(0+msg->data_payload))
        {
//not yet displayed: OO_NAK_COMMAND_LENGTH OO_NAK_BIO_TYPE_UNSUPPORTED OO_NAK_BIO_FMT_UNSUPPORTED OO_NAK_CMD_UNABLE
        case OO_NAK_CHECK_CRC:
          fprintf(context->log, "  NAK: (1)Bad CRC/Checksum\n");
          break;
        case OO_NAK_UNK_CMD:
          fprintf(context->log, "  NAK: (3)Command not implemented by PD\n");
          break;
        case OO_NAK_SEQUENCE:
          fprintf(context->log, "  NAK: (4)Unexpected sequence number\n");
          context->seq_bad ++;
            // hopefully not double counted, works in monitor mode
          context->next_sequence = 0; // reset sequence due to NAK
          break;
        case OO_NAK_UNSUP_SECBLK:
          fprintf(context->log, "  NAK: (5)Security block not accepted.\n");
          break;
        case OO_NAK_ENC_REQ:
          // drop out of secure channel and in fact reset the sequence number

          fprintf(context->log, "  NAK: (%d)Encryption required.\n", nak_code);
          osdp_reset_secure_channel(context);
          context->next_sequence = 0; 
          break;

        };
      };
      osdp_test_set_status(OOC_SYMBOL_rep_nak, OCONFORM_EXERCISED);

      // if the PD NAK'd a BIOREAD fail the test.
      if (context->last_command_sent EQUALS OSDP_BIOREAD)
      {
        osdp_test_set_status(OOC_SYMBOL_cmd_bioread, OCONFORM_FAIL);
      };
      // if the PD NAK'd a BIOMATCH fail the test.
      if (context->last_command_sent EQUALS OSDP_BIOMATCH)
      {
        osdp_test_set_status(OOC_SYMBOL_cmd_biomatch, OCONFORM_FAIL);
      };
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
      // if the PD NAK'd a KEYSET fail the test.
      if (context->last_command_sent EQUALS OSDP_KEYSET)
      {
        osdp_test_set_status(OOC_SYMBOL_cmd_keyset, OCONFORM_FAIL);
      };
      // if the PD NAK'd an LSTAT fail the test.
      if (context->last_command_sent EQUALS OSDP_LSTAT)
      {
        osdp_test_set_status(OOC_SYMBOL_cmd_lstat, OCONFORM_FAIL);
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
      osdp_test_set_status(OOC_SYMBOL_resp_com, OCONFORM_EXERCISED);
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
      if (context->last_command_sent EQUALS OSDP_LSTAT)
        osdp_test_set_status(OOC_SYMBOL_poll_lstat, OCONFORM_EXERCISED);
      osdp_test_set_status(OOC_SYMBOL_resp_lstatr, OCONFORM_EXERCISED);
      if (*(msg->data_payload) > 0)
        osdp_test_set_status(OOC_SYMBOL_resp_lstatr_tamper, OCONFORM_EXERCISED);
      if (*(msg->data_payload + 1) > 0)
        osdp_test_set_status(OOC_SYMBOL_resp_lstatr_power, OCONFORM_EXERCISED);
      break;

    case OSDP_MFGERRR:
      status = action_osdp_MFGERRR(context, msg);
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

fprintf(stderr, "Opened %s for writing\n", mfg_rep_data_file);
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
fprintf(stderr, "Opened %s for writing\n", "/opt/osdp-conformance/run/CP/mfg-rep.bin");
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

      sprintf(details,
"\"pd-oui\":\"%02x%02x%02x\",\"pd-model\":\"%d\",\"pd-version\":\"%d\",\"pd-serial\":\"%02x%02x%02x%02x\",\"pd-firmware\":\"%d-%d-%d\",",
        msg->data_payload [0], msg->data_payload [1], msg->data_payload [2],
        msg->data_payload [3], msg->data_payload [4],
        msg->data_payload [5], msg->data_payload [6], msg->data_payload [7], msg->data_payload [8],
        msg->data_payload [9], msg->data_payload [10], msg->data_payload [11]);

      osdp_test_set_status_ex(OOC_SYMBOL_rep_device_ident, OCONFORM_EXERCISED, details);
      if ((msg->data_payload [0] EQUALS 0) &&
        (msg->data_payload [1] EQUALS 0) &&
        (msg->data_payload [2] EQUALS 0))
      {
        fprintf(context->log, "OUI in PDID is invalid (all 0's)\n");
        osdp_test_set_status(OOC_SYMBOL_rep_pdid_check, OCONFORM_FAIL);
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

        sprintf(cmd, "/opt/osdp-conformance/ACU-actions/osdp_PDID OUI %02x%02x%02x M-V %d-%d SN %02x%02x%02x%02x FW %d.%d.%d",
          context->vendor_code [0], context->vendor_code [1], context->vendor_code [2],
          context->model, context->version,
          context->serial_number [0], context->serial_number [1],
          context->serial_number [2], context->serial_number [3],
          context->fw_version [0], context->fw_version [1], context->fw_version [2]);
        system(cmd);

        osdp_test_set_status(OOC_SYMBOL_rep_pdid_check, OCONFORM_EXERCISED);
      };

      context->last_was_processed = 1;

      osdp_conformance.rep_device_ident.test_status = OCONFORM_EXERCISED;
      break;

    case OSDP_XRD:
      status = action_osdp_XRD(context, msg);
      break;
#if 0
      status = oosdp_make_message (OOSDP_MSG_XREAD, tlogmsg, msg);
      if (status == ST_OK)
        status = oosdp_log (context, OSDP_LOG_NOTIMESTAMP, 1, tlogmsg);
#endif

    default:
      if (context->verbosity > 2)
      {
        fprintf (stderr, "CMD %02x Unknown to ACU\n", msg->msg_cmd);
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

