/*
  oo-telemetry.c - create log messages

  (C)Copyright 2017-2023 Smithee Solutions LLC

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


#include <string.h>


#include <open-osdp.h>


#if 0
#include <stdio.h>
#include <time.h>


#include <osdp-tls.h>

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
  OSDP_MSC_CR_AUTH *cr_auth;
  int d;
  OSDP_HDR_FILETRANSFER *filetransfer_message;
  char file_transfer_status_detail [1024];
  OSDP_HDR_FTSTAT *ftstat;
  OSDP_MULTI_HDR_IEC *genauth_msg;
  OSDP_MULTI_HDR_IEC *genauthr_msg;
  OSDP_MSC_GETPIV *get_piv;
  OSDP_HDR *hdr;
  char hstr [1024];
  int i;
  int idx;
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
  char tmpstr2 [3*1024];
  unsigned short int ustmp; // throw-away unsigned short integer (fits a "doubleByte")
  unsigned int utmp; // throw-away unsigned integer (fits a "quadByte")


  case OOSDP_MSG_KEYPAD:
#endif

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
              sprintf (tstr, "  [%02d] %s %d LED's Compliance:%s;\n",
                1+i/3, osdp_pdcap_function (*(i+0+msg->data_payload)), 
                *(i+2+msg->data_payload),
                tstr2);
            };
            break;
          case OSDP_CAP_REC_MAX:
            value = *(i+1+msg->data_payload) + 256 * (*(i+2+msg->data_payload));
            sprintf (tstr, "  [%02d] %s %d;\n",
              1+i/3, osdp_pdcap_function (*(i+0+msg->data_payload)), value);
            break;
          case OSDP_CAP_MAX_MULTIPART:
            value = *(i+1+msg->data_payload) + 256 * (*(i+2+msg->data_payload));
            sprintf (tstr, "  [%02d] %s %d;\n",
              1+i/3, osdp_pdcap_function (*(i+0+msg->data_payload)), value);
            break;
          default:
            sprintf (tstr, "  [%02d] %s %02x %02x;\n",
              1+i/3, osdp_pdcap_function (*(i+0+msg->data_payload)), *(i+1+msg->data_payload), *(i+2+msg->data_payload));
            break;
          };
          strcat (tlogmsg, tstr);
        };
      }; // decrypted or cleartext payload
    };
    break;


#endif

