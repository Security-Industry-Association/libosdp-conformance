/*
  oo-logmsg.c - prints log messages

  (C)Copyright 2017-2025 Smithee Solutions LLC

  Support provided by the Security Industry Association
  OSDP Working Group community.

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

#if 0
typedef struct __attribute__((packed)) osdp_msc_crauth
{
  char vendor_code [3];
  char command_id;
  unsigned short int mpd_size_total;
  unsigned short int mpd_offset;
  unsigned short int mpd_fragment_size;
  unsigned char data [2]; // just first 2 of data.  algref and keyref in first block
} OSDP_MSC_CR_AUTH;

typedef struct __attribute__((packed)) osdp_msc_crauth_response
{
  char vendor_code [3];
  char command_id;
  unsigned short int mpd_size_total;
  unsigned short int mpd_offset;
  unsigned short int mpd_fragment_size;
  unsigned char data;
} OSDP_MSC_CR_AUTH_RESPONSE;

typedef struct __attribute__((packed)) osdp_getpiv
{
  char piv_object [3];
  char piv_element;
  char piv_offset [2];
} OSDP_GETPIV;
typedef struct __attribute__((packed)) osdp_msc_getpiv
{
  char vendor_code [3];
  char command_id;
  char piv_object [3];
  char piv_element;
  char piv_offset [2];
} OSDP_MSC_GETPIV;
  
typedef struct __attribute__((packed)) osdp_msc_kp_act
{
  char vendor_code [3];
  char command_id;
  unsigned short int kp_act_time;
} OSDP_MSC_KP_ACT;
  
typedef struct __attribute__((packed)) osdp_piv_data
{
  unsigned short int mpd_size_total;
  unsigned short int mpd_offset;
  unsigned short int mpd_fragment_size;
  unsigned char data;
} OSDP_PIV_DATA;
typedef struct __attribute__((packed)) osdp_msc_piv_data
{
  char vendor_code [3];
  char command_id;
  unsigned short int mpd_size_total;
  unsigned short int mpd_offset;
  unsigned short int mpd_fragment_size;
  unsigned char data;
} OSDP_MSC_PIV_DATA;

typedef struct __attribute__((packed)) osdp_msc_status
{
  char vendor_code [3];
  char command_id;
  char status;
  char info [2];
} OSDP_MSC_STATUS;
#endif

#include <stdio.h>
#include <time.h>
#include <string.h>


#include <osdp-tls.h>
#include <open-osdp.h>

extern OSDP_CONTEXT context;
extern OSDP_PARAMETERS p_card;


/*
  oosdp_make_message - construct useful log text for output

  used for monitor mode and logging
*/
int
  oosdp_make_message
    (int msgtype,
    char *logmsg,
    void *aux)
    
{ /* oosdp_make_message */

  OSDP_SC_CCRYPT *ccrypt_payload; int count;
  OSDP_MULTI_HDR_IEC *crauth_msg;
  OSDP_MULTI_HDR_IEC *crauthr_msg;
  int d;
  OSDP_HDR_FILETRANSFER *filetransfer_message;
  char file_transfer_status_detail [1024];
  OSDP_HDR_FTSTAT *ftstat;
  OSDP_MULTI_HDR_IEC *genauth_msg;
  OSDP_MULTI_HDR_IEC *genauthr_msg;
  OSDP_HDR *hdr;
  char hstr [1024];
  int i;
  int idx;
  OSDP_MSG *msg;
  unsigned short int newdelay;
  unsigned short int newmax;
  char octet [3];
  OSDP_HDR *oh;
  unsigned char osdp_command;
  OSDP_HDR *osdp_wire_message;
  unsigned char *payload;
  int payload_size;
  int scb_present;
  char *score_text;
  char *sec_block;
  char tlogmsg [30000];
  char tmps [1024];
  char tmpstr [2*1024];
  char tmpstr2 [3*1024];
  int status;
  unsigned short int ustmp; // throw-away unsigned short integer (fits a "doubleByte")
  unsigned int utmp; // throw-away unsigned integer (fits a "quadByte")


  status = ST_OK;
  msg = NULL;
  oh = NULL;
  memset(hstr, 0, sizeof(hstr));
  tlogmsg [0] = 0;

  // set up the OSDP header structure (if we have something to work with)
  if (aux)
  {
    msg = (OSDP_MSG *) aux;
    oh = (OSDP_HDR *)(msg->ptr);

    // calculate the payload size, accounting for CRC vs. CHECKSUM
    count = oh->len_lsb + (oh->len_msb << 8);
    count = count - sizeof(*oh);
    if (oh->ctrl & 0x04)
      count = count - 2;
    else
      count = count - 1;
  };

  switch (msgtype)
  {
  case OOSDP_MSG_ACURXSIZE:
    {
      int c;

      msg = (OSDP_MSG *) aux;

      // per spec it is lsb/msb

      c = (msg->data_payload [0]) + 256 * (msg->data_payload [1]);
      if (context.verbosity > 2)
        sprintf(tlogmsg, "  ACU Rx Size: %0d.\n", c);
    };
    break;

  case OOSDP_MSG_BIOMATCH:
    sprintf(tlogmsg, "  BIO Match: Rdr %02X Typ %02X Fmt %02X Qual %02X (lth %d.) ",
      msg->data_payload [0], msg->data_payload [1], msg->data_payload [2], msg->data_payload [3],
      (msg->data_payload [5])*256 + msg->data_payload [4]);
    for (i=0; i<count-6; i++)
    {
      if (context.pii_display)
        sprintf(octet, "%02x", msg->data_payload [4+i]);
      else
        sprintf(octet, "**");
      strcat(tlogmsg, octet);
    };
    strcat(tlogmsg, ")\n");
    break;

  case OOSDP_MSG_BIOMATCHR:
    score_text = "";
    if (msg->data_payload [2] EQUALS 0)
      score_text = "(No match)";
    else
    {
      if (msg->data_payload [2] EQUALS 0)
        score_text = "(Best match)";
    };
    sprintf(tlogmsg, "  BIO Match Response: Rdr %02X Stat %02X Score %02X %s\n",
      msg->data_payload [0], msg->data_payload [1], msg->data_payload [2], score_text);
    break;

  case OOSDP_MSG_BIOREAD:
    sprintf(tlogmsg, "  BIO Read: Rdr %02X Typ %02X Fmt %02X Qual %02X\n",
      msg->data_payload [0], msg->data_payload [1], msg->data_payload [2], msg->data_payload [3]);
    break;

  case OOSDP_MSG_BIOREADR:
    sprintf(tlogmsg, "  BIO Read Response: Rdr %02X Status %02X Typ %02x Qual %02X (lth %d.) (",
      msg->data_payload [0], msg->data_payload [1], msg->data_payload [2], msg->data_payload [3], count);
    for (i=0; i<count-4; i++)
    {
      if (context.pii_display)
        sprintf(octet, "%02x", msg->data_payload [4+i]);
      else
        sprintf(octet, "**");
      strcat(tlogmsg, octet);
    };
    strcat(tlogmsg, ")\n");
    break;

  case OOSDP_MSG_BUZ:
    msg = (OSDP_MSG *) aux;
    if (msg->security_block_length > 0)
    {
      oh = (OSDP_HDR *)(msg->ptr);
      tlogmsg [0] = 0;
      count = oh->len_lsb + (oh->len_msb << 8);
      count = count - 8;
      for (i=0; i<count; i++)
      {
        d = *(unsigned char *)(msg->data_payload+i);
        sprintf(tmpstr, "%02x", d);
        strcat(hstr, tmpstr);
      };
      sprintf(tlogmsg,
        "  Encrypted BUZ Payload (%d. bytes) %s\n", count, hstr);
    }
    else
    {
      sprintf(tlogmsg, "BUZ: Rdr %02x Tone Code %02x On=%d(ms) Off=%d(ms) Count %d\n",
        *(msg->data_payload + 0), *(msg->data_payload + 1),
        100 * *(msg->data_payload + 2), 100 * *(msg->data_payload + 3),
        *(msg->data_payload + 4));
    };
    break;

  case OOSDP_MSG_CCRYPT:
    msg = (OSDP_MSG *) aux;
    ccrypt_payload = (OSDP_SC_CCRYPT *)(msg->data_payload);
    sprintf (tlogmsg,
"  CCRYPT: cUID %02x%02x%02x%02x-%02x%02x%02x%02x RND.B %02x%02x%02x%02x-%02x%02x%02x%02x Client Cryptogram %02x%02x%02x%02x-%02x%02x%02x%02x %02x%02x%02x%02x-%02x%02x%02x%02x\n",
      ccrypt_payload->client_id [0], ccrypt_payload->client_id [1],
      ccrypt_payload->client_id [2], ccrypt_payload->client_id [3],
      ccrypt_payload->client_id [4], ccrypt_payload->client_id [5],
      ccrypt_payload->client_id [6], ccrypt_payload->client_id [7],
      ccrypt_payload->rnd_b [0], ccrypt_payload->rnd_b [1],
      ccrypt_payload->rnd_b [2], ccrypt_payload->rnd_b [3],
      ccrypt_payload->rnd_b [4], ccrypt_payload->rnd_b [5],
      ccrypt_payload->rnd_b [6], ccrypt_payload->rnd_b [7],
      ccrypt_payload->cryptogram [0], ccrypt_payload->cryptogram [1],
      ccrypt_payload->cryptogram [2], ccrypt_payload->cryptogram [3],
      ccrypt_payload->cryptogram [4], ccrypt_payload->cryptogram [5],
      ccrypt_payload->cryptogram [6], ccrypt_payload->cryptogram [7],
      ccrypt_payload->cryptogram [8], ccrypt_payload->cryptogram [9],
      ccrypt_payload->cryptogram [10], ccrypt_payload->cryptogram [11],
      ccrypt_payload->cryptogram [12], ccrypt_payload->cryptogram [13],
      ccrypt_payload->cryptogram [14], ccrypt_payload->cryptogram [15]);
    break;

  case OOSDP_MSG_CHLNG:
    msg = (OSDP_MSG *) aux;
    status = oosdp_print_message_CHLNG(&context, msg, tlogmsg);
    break;

  case OOSDP_MSG_COM:
    {
      int speed;

      msg = (OSDP_MSG *) aux;
      speed = *(1+msg->data_payload) + (*(2+msg->data_payload) << 8) +
        (*(3+msg->data_payload) << 16) + (*(4+msg->data_payload) << 24);

      sprintf(tlogmsg, "COM Returns New Address %02x New Speed %d.\n",
        *(0+msg->data_payload), speed);
    };
    break;

  case OOSDP_MSG_COMSET:
    {
      int speed;

      msg = (OSDP_MSG *) aux;
      speed = *(1+msg->data_payload) + (*(2+msg->data_payload) << 8) +
        (*(3+msg->data_payload) << 16) + (*(4+msg->data_payload) << 24);

      sprintf(tlogmsg, "COMSET will use New Address %02x New Speed %d.\n",
        *(0+msg->data_payload), speed);
    };
    break;

  case OOSDP_MSG_CRAUTH:
    msg = (OSDP_MSG *) aux;
    crauth_msg = (OSDP_MULTI_HDR_IEC *) msg->data_payload;
    payload = &(crauth_msg->algo_payload);
    payload_size = (crauth_msg->total_msb*256)+crauth_msg->total_lsb;
    sprintf(tlogmsg, "CRAUTH multi-total %4d multi-offset %4d multi-frag %4d\n",
      (crauth_msg->total_msb*256)+crauth_msg->total_lsb,
      (crauth_msg->offset_msb*256)+crauth_msg->offset_lsb,
      (crauth_msg->data_len_msb*256)+crauth_msg->data_len_lsb);
    sprintf(tmpstr, "CRAUTH Algo %02x Key %02x Challenge(l=%4d) %02x%02x%02x...\n",
      *(payload), *(payload+1), 
      payload_size - 2,
      *(payload+2), *(payload+3), *(payload+4));
    strcat(tlogmsg, tmpstr);
    break;

  case OOSDP_MSG_CRAUTHR:
    msg = (OSDP_MSG *) aux;
    crauthr_msg = (OSDP_MULTI_HDR_IEC *) msg->data_payload;
    payload = &(crauthr_msg->algo_payload);
    payload_size = (crauthr_msg->total_msb*256)+crauthr_msg->total_lsb;
    sprintf(tlogmsg, "CRAUTH multi-total %4d multi-offset %4d multi-frag %4d\n",
      (crauthr_msg->total_msb*256)+crauthr_msg->total_lsb,
      0, 0);
    break;

  case OOSDP_MSG_FILETRANSFER:
    msg = (OSDP_MSG *) aux;
    filetransfer_message = (OSDP_HDR_FILETRANSFER *)(msg->data_payload);
    tlogmsg[0] = 0;
    osdp_array_to_quadByte(filetransfer_message->FtSizeTotal, &utmp);
    osdp_array_to_doubleByte(filetransfer_message->FtFragmentSize, &ustmp);
    sprintf(tmpstr,
"  File Transfer: Type %02X Fragment Size %5d.",
      filetransfer_message->FtType, ustmp);
    strcat(tlogmsg, tmpstr);
    sprintf(tmpstr,
" Total %02X:%02X:%02X:%02X(%12d.)",
      filetransfer_message->FtSizeTotal [0], filetransfer_message->FtSizeTotal [1],
      filetransfer_message->FtSizeTotal [2], filetransfer_message->FtSizeTotal [3],
      utmp);
    strcat(tlogmsg, tmpstr);
    osdp_array_to_quadByte(filetransfer_message->FtOffset, &utmp);
    sprintf(tmpstr,
" Offset %02X:%02X:%02X:%02X(%5d.)\n",
      filetransfer_message->FtOffset [0], filetransfer_message->FtOffset [1],
      filetransfer_message->FtOffset [2], filetransfer_message->FtOffset [3],
      utmp);
    strcat(tlogmsg, tmpstr);
    break;

  case OOSDP_MSG_FTSTAT:
    msg = (OSDP_MSG *) aux;
    ftstat = (OSDP_HDR_FTSTAT *)(msg->data_payload);

    // dump the FTSTAT response in case it's weird
    if (context.verbosity > 9)
      dump_buffer_log(&context, "  FTSTAT: ", (unsigned char *)ftstat, msg->lth);

    tlogmsg[0] = 0;
    osdp_array_to_doubleByte(ftstat->FtDelay, &newdelay);
    osdp_array_to_doubleByte(ftstat->FtUpdateMsgMax, &newmax);
    {
      unsigned short int i;
      i = (ftstat->FtStatusDetail[1] << 8) + ftstat->FtStatusDetail [0];
      switch (i)
      {
      case OSDP_FTSTAT_OK:
        sprintf(file_transfer_status_detail, "%d (OK to proceed)", i);
        break;
      case OSDP_FTSTAT_REBOOTING:
        sprintf(file_transfer_status_detail, "%d (PD is rebooting)", i);
        break;
      case OSDP_FTSTAT_DATA_UNACCEPTABLE:
        sprintf(file_transfer_status_detail, "%d (file data unacceptable or malformed)", i);
        break;
      default:
        sprintf(file_transfer_status_detail, "%d.", (short int)i);
        break;
      };
    };
    sprintf(tmpstr,
"  Response: osdp_FTSTAT.  Detail (Status %s); Action %02x Delay %02x-%02x(%d. ms) Update-max %02x-%02x(%d.)\n",
      file_transfer_status_detail,
      ftstat->FtAction,
      ftstat->FtDelay [0], ftstat->FtDelay [1], newdelay,
      ftstat->FtUpdateMsgMax [0], ftstat->FtUpdateMsgMax [1], newmax);
    strcat(tlogmsg, tmpstr);
    break;

  case OOSDP_MSG_GENAUTH:
    msg = (OSDP_MSG *) aux;
    genauth_msg = (OSDP_MULTI_HDR_IEC *) msg->data_payload;
    payload = &(genauth_msg->algo_payload);
    payload_size = (genauth_msg->total_msb*256)+genauth_msg->total_lsb;
    sprintf(tlogmsg, "GENAUTH multi-total %4d multi-offset %4d multi-frag %4d\n",
      (genauth_msg->total_msb*256)+genauth_msg->total_lsb,
      (genauth_msg->offset_msb*256)+genauth_msg->offset_lsb,
      (genauth_msg->data_len_msb*256)+genauth_msg->data_len_lsb);
    break;

  case OOSDP_MSG_GENAUTHR:
    msg = (OSDP_MSG *) aux;
    genauthr_msg = (OSDP_MULTI_HDR_IEC *) msg->data_payload;
    payload = &(genauthr_msg->algo_payload);
    payload_size = (genauthr_msg->total_msb*256)+genauthr_msg->total_lsb;
    sprintf(tlogmsg, "GENAUTHR multi-total %4d multi-offset %4d multi-frag %4d\n",
      (genauthr_msg->total_msb*256)+genauthr_msg->total_lsb,
      0,
      (genauthr_msg->data_len_msb*256)+genauthr_msg->data_len_lsb);
    break;

  case OOSDP_MSG_ISTATR:
    msg = (OSDP_MSG *) aux;
    oh = (OSDP_HDR *)(msg->ptr);
    tlogmsg [0] = 0;
    if (msg->security_block_length > 0)
    {
      if (context.verbosity > 2)
        strcat(tlogmsg, "  (ISTATR message contents encrypted)\n");
    };
    if (msg->security_block_length EQUALS 0)
    {
      int i;
      unsigned char *p;
      i = 0;
      count = oh->len_lsb + (oh->len_msb << 8);
      count = count - 8;
      strcat(tlogmsg, "Input Status:\n");
      p = msg->data_payload;
      while (count > 0)
      {
        if (*p)
          sprintf(tmpstr, " IN-%d Active(%02x)", i, *p);
        else
          sprintf(tmpstr, " IN-%d Inactive(%02x)", i, *p);
        strcat(tlogmsg, tmpstr);
        count --; // decrement SDU octet count
        i++; // increment input number (index into data)
        p++; // increment pointer into data
      };
      strcat(tlogmsg, "\n");
    };
    break;

  case OOSDP_MSG_KEEPACTIVE:
    {
      msg = (OSDP_MSG *) aux;
      if (msg->security_block_length > 0)
      {
        if (context.verbosity > 2)
          strcat(tlogmsg, "  (KEEPACTIVE message contents encrypted)\n");
      };
      if (msg->security_block_length EQUALS 0)
      {
        sprintf (tlogmsg,
"Keep credential read active (bytes 0..1) %02x%02x\n",
          *(msg->data_payload+0), *(msg->data_payload+1));
      };
    };
    break;

  case OOSDP_MSG_KEYPAD:
    msg = (OSDP_MSG *) aux;
    status = oosdp_print_message_KEYPAD(&context, msg, tlogmsg);
    break;

  case OOSDP_MSG_KEYSET:
    msg = (OSDP_MSG *) aux;
    status = oosdp_print_message_KEYSET(&context, msg, tlogmsg);
    break;

  case OOSDP_MSG_LED:
    msg = (OSDP_MSG *) aux;
    status = oosdp_print_message_LED(&context, msg, tlogmsg);
    break;

  case OOSDP_MSG_LSTATR:
    {
      unsigned char *osdp_lstat_response_data;

      tlogmsg [0] = 0;
      msg = (OSDP_MSG *) aux;
      if (msg->security_block_length > 0)
      {
        if (context.verbosity > 2)
          strcat(tlogmsg, "  (LSTATR message contents encrypted)\n");
      };
      if (msg->security_block_length EQUALS 0)
      {
        osdp_lstat_response_data = (unsigned char *)(msg->data_payload);
        sprintf(tlogmsg, "LSTAT Response: Tamper %d Power-cycle %d\n",
          osdp_lstat_response_data [0], osdp_lstat_response_data [1]);
      };
    };
    break;

  case OOSDP_MSG_MFG:
    msg = (OSDP_MSG *) aux;
    status = oosdp_print_message_MFG(&context, msg, tlogmsg);
    break;

  case OOSDP_MSG_MFGERRR:
    msg = (OSDP_MSG *) aux;
    oh = (OSDP_HDR *)(msg->ptr);
    count = oh->len_lsb + (oh->len_msb << 8);
    count = count - 8; // assumes cleartext CRC
    sprintf(tlogmsg, "  osdp_MFGERRR (len=%d.) %02x%02x%02x...\n",
      count, (msg->data_payload) [0], (msg->data_payload) [1], (msg->data_payload) [2]);
    dump_buffer_log(&context, "  MFGERRR Details: ", (unsigned char *)(msg->data_payload), count);
    break;

  case OOSDP_MSG_MFGREP:
    {
      int dumpcount;
      OSDP_MFGREP_RESPONSE *mrep;
      unsigned char *p;


      dumpcount = 0;
      // unwind the headers so we have the osdp_MFGREP payload in hand...
      memset(tlogmsg, 0, sizeof(tlogmsg));
      msg = (OSDP_MSG *) aux;
      oh = (OSDP_HDR *)(msg->ptr);
      count = oh->len_lsb + (oh->len_msb << 8);
      count = count - 6; // assumes cleartext
      dumpcount = count - msg->check_size;
      dumpcount = dumpcount - 4; // for OUI and response code
      mrep = (OSDP_MFGREP_RESPONSE *)(msg->data_payload);

      if (context.role EQUALS OSDP_ROLE_ACU)
      {
        status = oo_mfg_reply_action(&context, msg, mrep);
        status = ST_OK; // ok regardless
      };

      p = (unsigned char *)&(mrep->data);
      p++; // skip return code
      sprintf(tlogmsg, "  MFG Response: OUI:%02x-%02x-%02x RCMD %02X followed by 0x%02x octets",
        mrep->vendor_code [0], mrep->vendor_code [1], mrep->vendor_code [2], mrep->data, dumpcount);

      strcat(tlogmsg, "\n");
      strcat(tlogmsg, "    Contents:");
      for (idx=0; idx < dumpcount; idx++)
      {
        sprintf(tmps, " %02X", *(p+idx));
        strcat(tlogmsg, tmps);
      };
      strcat(tlogmsg, "\n");
    };
    break;

  case OOSDP_MSG_NAK:
    {
      int nak_code;
      char nak_detail_text [1024];
      char tmpmsg2 [2*1024];

      if ((msg->security_block_length EQUALS 0) || (msg->payload_decrypted))
      {
        msg = (OSDP_MSG *) aux;
        nak_code = *(0+msg->data_payload);
        // it's 1 if just a nak code and more if there is nak 'data'
        strcpy(nak_detail_text, oo_lookup_nak_text(nak_code));

        // for monitoring track nak count
        if (nak_code EQUALS OO_NAK_SEQUENCE)
          context.seq_bad++;

        sprintf(tmpmsg2, " (%s)", nak_detail_text);
        if (msg->data_length > 1)
        {
          sprintf(tlogmsg, "  NAK: Error Code %02x%s Data %02x\n",
            *(0+msg->data_payload), tmpmsg2, *(1+msg->data_payload));
        }
        else
        {
          sprintf (tlogmsg, "  NAK: Error Code %02x%s\n",
            *(0+msg->data_payload), tmpmsg2);
        };
      }
      else
      {
        sprintf(tlogmsg, "  NAK: (Details encrypted)\n");
      };
    };
    break;

  // special case - this outputs the basic "Message:.." message
  case OOSDP_MSG_OSDP:
    osdp_command = *(unsigned char *)aux;
    hdr = 2+aux;

    // dump as named in the IEC spec
    msg = (OSDP_MSG *) aux;
    osdp_wire_message = (OSDP_HDR *)(msg->ptr); // actual message off the wire
    if (osdp_wire_message->ctrl & 0x08)
      sprintf(tmpstr2, "Msg: [SECURE] ");
    else
      sprintf(tmpstr2, "Msg: [Clear]  ");
    strcat(tlogmsg, tmpstr2); tmpstr2 [0] = 0;
    sprintf(tmpstr2, "C/R=%02x A=%02x LSB=%02x MSB=%02x\n",
      osdp_wire_message->cmd_s, osdp_wire_message->addr, osdp_wire_message->len_lsb,
      osdp_wire_message->len_msb);
    strcat(tlogmsg, tmpstr2); tmpstr2 [0] = 0;
    sprintf(tlogmsg, "  CTRL=%02x (", osdp_wire_message->ctrl);
    strcat(tlogmsg, tmpstr2); tmpstr2 [0] = 0;
    if (osdp_wire_message->ctrl & 0x08)
    {
      scb_present = 1;
      sprintf(tlogmsg, "Security Control Block Present; ");
      strcat(tlogmsg, tmpstr2); tmpstr2 [0] = 0;
    }
    else
    {
      scb_present = 0;
      sprintf(tlogmsg, "No Security Control Block; ");
      strcat(tlogmsg, tmpstr2); tmpstr2 [0] = 0;
    };
    if (scb_present)
    {
      sec_block = (char *)&(osdp_wire_message->cmd_s);
      switch (sec_block[1])  // "sec block type"
      {
      case OSDP_SEC_SCS_11:
        sprintf(tlogmsg, "SCS_11; ");
        strcat(tlogmsg, tmpstr2); tmpstr2 [0] = 0;
        break;
      case OSDP_SEC_SCS_12:
        sprintf(tlogmsg, "SCS_12; ");
        strcat(tlogmsg, tmpstr2); tmpstr2 [0] = 0;
        break;
      default:
fprintf(stderr, "unknown Security Block %d.\n", sec_block [1]);
        break;
      };
      if (sec_block [2] EQUALS OSDP_KEY_SCBK_D)
        sprintf(tlogmsg, "Key=SCBK-D(default) ");
      else
        sprintf(tlogmsg, "Key=SCBK ");
      strcat(tlogmsg, tmpstr2); tmpstr2 [0] = 0;
      strcat(tlogmsg, "\n");
    };

    strcpy(tmpstr, osdp_command_reply_to_string(osdp_command, *(unsigned char *)(1+aux)));
    sprintf(tmpstr2, " Frm: %04d Msg: %s\n", context.packets_received, tmpstr);
    strcpy(tmpstr, osdp_sec_block_dump(2+aux+sizeof(*hdr)-1));
    strcat(tlogmsg, tmpstr2);
    strcat(tlogmsg, tmpstr);
    strcat(tlogmsg, "\n");
    break;

  case OOSDP_MSG_OUT:
    {
      OSDP_OUT_MSG *out_message;
      msg = (OSDP_MSG *) aux;
      out_message = (OSDP_OUT_MSG *)msg->data_payload;

      // assume one only

      if (msg->security_block_length > 0)
      {
        sprintf(tlogmsg, "  (OUT message contents encrypted)\n");
      };
      if (msg->security_block_length EQUALS 0)
      {
        sprintf (tlogmsg, "  Out: Line %02x Ctl %02x LSB %02x MSB %02x\n",
          out_message->output_number, out_message->control_code,
          out_message->timer_lsb, out_message->timer_msb);
      };
    };
    break;

  case OOSDP_MSG_OUT_STATUS:
    {
      int i;
      unsigned char *out_status;
      char tmpstr [1024];

      tlogmsg [0] = 0;
      if ((msg->security_block_length EQUALS 0) || (msg->payload_decrypted))
      {
        strcpy(tlogmsg, "I/O Status-OUT:");
        out_status = msg->data_payload;
        for (i=0; i<count; i++)
        {
          sprintf (tmpstr, " %02d:%d",
            i, out_status [i]);
          strcat (tlogmsg, tmpstr);
        };
        strcat(tlogmsg, "\n");
      };
    };
    break;

  case OOSDP_MSG_PD_CAPAS:
    {
      int i;
      OSDP_HDR *oh;
      char tstr [2*1024];
      int value;

      msg = (OSDP_MSG *) aux;
      oh = (OSDP_HDR *)(msg->ptr);
      count = oh->len_lsb + (oh->len_msb << 8);
      count = count - 8;
      if (msg->security_block_length > 0)
        sprintf(tstr, "PD Capabilities payload encrypted.\n");
      if ((msg->security_block_length EQUALS 0) || (msg->payload_decrypted))
      {
        sprintf (tstr, "PD Capabilities Report (%d. entries)\n", (msg->data_length)/3);
        strcpy (tlogmsg, tstr);

        for (i=0; i<msg->data_length; i=i+3)
        {
          switch (*(i+0+msg->data_payload))
          {
          case 4:
            {
              int compliance;
              char tstr2 [1024];
              compliance = *(i+1+msg->data_payload);
              sprintf(tstr2, "?(0x%x)", compliance);
              if (compliance == 1) strcpy (tstr2, "On/Off Only");
              if (compliance == 2) strcpy (tstr2, "Timed");
              if (compliance == 3) strcpy (tstr2, "Timed, Bi-color");
              if (compliance == 4) strcpy (tstr2, "Timed, Tri-color");
              sprintf (tstr, "  Capability Entry %02d. %s %d LED's Compliance:%s;\n",
                1+i/3, osdp_pdcap_function (*(i+0+msg->data_payload)), 
                *(i+2+msg->data_payload),
                tstr2);
            };
            break;
          case OSDP_CAP_REC_MAX:
            value = *(i+1+msg->data_payload) + 256 * (*(i+2+msg->data_payload));
            sprintf (tstr, "  Capability Entry %02d. %s %d;\n",
              1+i/3, osdp_pdcap_function (*(i+0+msg->data_payload)), value);
            break;
          case OSDP_CAP_MAX_MULTIPART:
            value = *(i+1+msg->data_payload) + 256 * (*(i+2+msg->data_payload));
            sprintf (tstr, "  Capability Entry %02d. %s %d;\n",
              1+i/3, osdp_pdcap_function (*(i+0+msg->data_payload)), value);
            break;
          default:
            sprintf (tstr, "  Capability Entry %02d. %s %02x %02x;\n",
              1+i/3, osdp_pdcap_function (*(i+0+msg->data_payload)), *(i+1+msg->data_payload), *(i+2+msg->data_payload));
            break;
          };
          strcat (tlogmsg, tstr);
        };
      }; // decrypted or cleartext payload
    };
    break;

  case OOSDP_MSG_PD_IDENT:
    msg = (OSDP_MSG *) aux;
    status = oosdp_print_message_PD_IDENT(&context, msg, tlogmsg);
    break;

  case OOSDP_MSG_PKT_STATS:
    sprintf (tlogmsg, " ACU-Polls %6d PD-Acks %6d PD-NAKs %6d CkSumErr %6d\n",
      context.acu_polls, context.pd_acks, context.sent_naks,
      context.checksum_errs);
    break;

  case OOSDP_MSG_PIVDATA:
    msg = (OSDP_MSG *)aux;
    status = oosdp_print_message_PIVDATA(&context, msg, tlogmsg);
    break;

  case OOSDP_MSG_PIVDATAR:
    msg = (OSDP_MSG *)aux;
    status = oosdp_print_message_PIVDATAR(&context, msg, tlogmsg);
    break;

  case OOSDP_MSG_POLL:
    msg = (OSDP_MSG *)aux;
    status = oosdp_print_message_POLL(&context, msg, tlogmsg);
    break;

  case OOSDP_MSG_RAW:
    msg = (OSDP_MSG *) aux;
    status = oosdp_print_message_RAW(&context, msg, tlogmsg);
    break;

  case OOSDP_MSG_RMAC_I:
    msg = (OSDP_MSG *) aux;
    status = oosdp_print_message_RMAC_I(&context, msg, tlogmsg);
    break;

  case OOSDP_MSG_SCRYPT:
    msg = (OSDP_MSG *) aux;
    status = oosdp_print_message_SCRYPT(&context, msg, tlogmsg);
    break;

  case OOSDP_MSG_TEXT:
    msg = (OSDP_MSG *) aux;
    status = oosdp_print_message_TEXT(&context, msg, tlogmsg);
    break;

  case OOSDP_MSG_XREAD:
    msg = (OSDP_MSG *) aux;
    status = oosdp_print_message_XRD(&context, msg, tlogmsg);
    break;

  case OOSDP_MSG_XWRITE:
    msg = (OSDP_MSG *) aux;
    sprintf(tlogmsg, "Extended Write: %02x %02x %02x %02x\n",
      *(msg->data_payload + 0), *(msg->data_payload + 1),
      *(msg->data_payload + 2), *(msg->data_payload + 3));
    break;

  default:
    sprintf (tlogmsg, "Unknown message type %d", msgtype);
    break;
  };
  strcpy (logmsg, tlogmsg);
  return (status);
}


int
  oosdp_log
    (OSDP_CONTEXT
      *context,
    int logtype,
    int level,
    char *message)

{ /* oosdp_log */

  time_t current_raw_time;
  struct tm *current_cooked_time;
  int llogtype;
  char *role_tag;
  int status;
  char timestamp [2*1024];


  status = ST_OK;

  // dump the trace buffer before creating the log message
#ifdef PREV_TRACE
  osdp_trace_dump(context, 1);
#endif

  if (context->verbosity > 2)
  {
    llogtype = logtype;
    role_tag = "";
    strcpy (timestamp, "");
    if (logtype EQUALS OSDP_LOG_STRING_CP)
    {
      role_tag = "ACU";
      llogtype = OSDP_LOG_STRING;
    };
    if (logtype EQUALS OSDP_LOG_STRING_PD)
    {
      role_tag = "PD";
      llogtype = OSDP_LOG_STRING;
    };
    if (llogtype == OSDP_LOG_STRING)
    {
      char address_suffix [1024];
      struct timespec
      current_time_fine;

      clock_gettime (CLOCK_REALTIME, &current_time_fine);
      (void) time (&current_raw_time);
      current_cooked_time = localtime (&current_raw_time);
      if (strcmp ("ACU", role_tag)==0)
        sprintf (address_suffix, " DestAddr=%02x(hex)", context->this_message_addr);
      else
        sprintf (address_suffix, " A=%02x(hex)", context->this_message_addr);
      sprintf (timestamp,
"\n---OSDP %s Frame:%04d%s Timestamp:%04d%02d%02d-%02d%02d%02d (Sec/Nanosec: %09ld %09ld)\n",
      role_tag, context->packets_received, address_suffix,
      1900+current_cooked_time->tm_year, 1+current_cooked_time->tm_mon,
      current_cooked_time->tm_mday,
      current_cooked_time->tm_hour, current_cooked_time->tm_min, 
      current_cooked_time->tm_sec,
      current_time_fine.tv_sec, current_time_fine.tv_nsec);
    };
    if (context->role == OSDP_ROLE_MONITOR)
    {
      fprintf (context->log, "%s%s", timestamp, message);
      fflush (context->log);
    }
    else
      if (context->verbosity >= level)
      {
        fprintf (context->log, "%s%s", timestamp, message);
        fflush (context->log);
      };
  }; // verbosity above 2
  
  return (status);

} /* oosdp_log */

