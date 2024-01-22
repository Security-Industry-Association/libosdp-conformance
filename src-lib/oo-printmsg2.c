/*
  oo-printmsg - more open osdp message printing routines

  (C)Copyright 2017-2024 Smithee Solutions LLC

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
#include <string.h>


#include <open-osdp.h>
#include <osdp-800-53.h>


int
  oosdp_print_message_KEYPAD
  (OSDP_CONTEXT *ctx,
  OSDP_MSG *msg,
  char *tlogmsg)

{ /* oosdp_print_message_KEYPAD */

  int i;
  int keycount;
  int status;
  char tmpstr [2*1024];


  status = ST_OK;
  tlogmsg [0] = 0;
      if (msg->security_block_length > 0)
      {
        strcat(tlogmsg, "  (KEYPAD message contents encrypted)\n");
      };
      if (msg->security_block_length EQUALS 0)
      {
        char character [8];
        char tstring [1024];

        keycount = *(msg->data_payload+1);
        memset (tmpstr, 0, sizeof (tmpstr));
        tstring [0] = 0;
        memcpy (tmpstr, msg->data_payload+2, *(msg->data_payload+1));
        for (i=0; i<keycount; i++)
        {
          memset(character, 0, sizeof(character));
          character [0] = tmpstr[i];

          // asterisk is DEL (0x7F)

          if (tmpstr [i] EQUALS 0x7F)
            character [0] = '*';

          // octothorpe is CR (0x0D)

          if (tmpstr [i] EQUALS 0x0D)
            character [0] = '#';

          // if not printable ascii and not already found character

          if ((tmpstr [i] < 0x20) ||
            (tmpstr [i] > 0x7e))
              if (character [0] != 0)
                sprintf(tmpstr, "<%02x>", tmpstr [i]);
          strcat(tstring, character);
        };
        sprintf (tlogmsg,
"Keypad Input Rdr %d, %d digits: %s\n",
          *(msg->data_payload+0), keycount, tstring);
      };

  return(status);

} /* oosdp_print_message_KEYPAD */


int
  oosdp_print_message_MFG
  (OSDP_CONTEXT *ctx,
  OSDP_MSG *msg,
  char *tlogmsg)

{ /* oosdp_print_message_MFG */

  int count;
  OSDP_MSC_CR_AUTH *cr_auth;
  OSDP_MSC_GETPIV *get_piv;
  int i;
  OSDP_MFG_COMMAND *mrep;
  char octet [3];
  OSDP_HDR *oh;
  int process_as_special;
  int status;
  char tmps [1024];


  status = ST_OK;
  tlogmsg [0] = 0;
  if ((msg->security_block_length EQUALS 0) || (msg->payload_decrypted))
  {
    process_as_special = 0;
    oh = (OSDP_HDR *)(msg->ptr);
    count = oh->len_lsb + (oh->len_msb << 8);
    count = count - sizeof(*oh);
    if (oh->ctrl & 0x04)
    {
      count = count - 2;
    }
    else
    {
      count = count - 1;
    };

    mrep = (OSDP_MFG_COMMAND *)(msg->data_payload);
    process_as_special = 0;
    if (0 EQUALS memcmp(mrep->vendor_code, OSDP_VENDOR_INID, sizeof(OSDP_VENDOR_INID)))
    {
      process_as_special = 1;
    };
    if (0 EQUALS memcmp(mrep->vendor_code, OSDP_VENDOR_WAVELYNX, sizeof(OSDP_VENDOR_WAVELYNX)))
    {
      process_as_special = 1;
    };

    if (!process_as_special)
    {
      sprintf(tlogmsg,
"  (General) MFG Request: OUI:%02x-%02x-%02x Command: %02x ",
        mrep->vendor_code [0], mrep->vendor_code [1], mrep->vendor_code [2],
        mrep->mfg_command_id);

      tmps [0] = 0;
      if ((count - 4) > 0)
      {
        strcat(tlogmsg, "Payload: ");
        // count bytes in payload, OUI and command are the first four bytes.
        for (i=0; i<(count-4); i++)
        {
          sprintf(octet, "%02X", *((&(mrep->data))+i) );
          strcat(tmps, octet);
        };
        strcat(tlogmsg, tmps);
      };
      strcat(tlogmsg, "\n");
    };
      if (process_as_special)
      {
        sprintf(tlogmsg,
          "  MFG Request: OUI:%02x-%02x-%02x Command: %02x\n",
          mrep->vendor_code [0], mrep->vendor_code [1], mrep->vendor_code [2],
          mrep->mfg_command_id);
        switch (mrep->mfg_command_id)
        {
        case OSDP_CMD_MSC_CR_AUTH:
          {
            cr_auth = (OSDP_MSC_CR_AUTH *)(msg->data_payload);

            sprintf(tmps,
"MSC CRAUTH\n  TotSize:%d. Offset:%d FragSize: %d",
              cr_auth->mpd_size_total, cr_auth->mpd_offset,
              cr_auth->mpd_fragment_size);
            strcat(tlogmsg, tmps);
            if (cr_auth->mpd_offset EQUALS 0)
            {
              sprintf(tmps, " AlgRef %02x KeyRef %02x",
                cr_auth->data[0], cr_auth->data[1]);
              strcat(tlogmsg, tmps);
            };
            strcat(tlogmsg, "\n");
          };
          break;
        case OSDP_CMD_MSC_GETPIV:
          {
            get_piv = (OSDP_MSC_GETPIV *)(msg->data_payload);
            sprintf(tmps,
"MSC PIVDATAGET\n  PIV-Object:%02x %02x %02x Element: %02x Offset: %02x %02x",
              get_piv->piv_object [0], get_piv->piv_object [1],
              get_piv->piv_object [2],
              get_piv->piv_element,
              get_piv->piv_offset [0], get_piv->piv_offset [1]);
            strcat(tlogmsg, tmps);
            strcat(tlogmsg, "\n");
            count = sizeof(*get_piv) - sizeof(get_piv->vendor_code)
              - sizeof(get_piv->command_id);
          };
          break;
        case OSDP_CMD_MSC_KP_ACT:
          {
            OSDP_MSC_KP_ACT *keep_active;
            keep_active = (OSDP_MSC_KP_ACT *)(msg->data_payload);
            sprintf(tmps,
"MSC KP_ACT\n  KP_ACT_TIME %d. ms\n",
              keep_active->kp_act_time);
            strcat(tlogmsg, tmps);
            count = sizeof(*keep_active) - sizeof(keep_active->vendor_code)
              - sizeof(keep_active->command_id);
          };
          break;
        default:
          sprintf(tlogmsg,
"MSC (MFG) Request: OUI:%02x-%02x-%02x Command: %02x\n",
            mrep->vendor_code [0], mrep->vendor_code [1], mrep->vendor_code [2],
            mrep->mfg_command_id);
          break;
        };
      }; 
      count = count - 4; // less OUI (3) and command (1)
      if (count > 0)
      {
        dump_buffer_log(ctx, "  Raw(MFG): ", &(mrep->data), count);
      };
      }
      else
      {
        sprintf(tlogmsg,
          "  (MFG message contents encrypted)\n");
      };

  return(status);

} /* oosdp_print_message_MFG */

