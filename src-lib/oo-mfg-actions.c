/*
  oo-mfg-actions - action call-outs for manufacturer specific commands

  (C)Copyright 2017-2024 Smithee Solutions LLC

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


#include <string.h>


#include <open-osdp.h>
extern OSDP_PARAMETERS p_card;
char OSDP_VENDOR_LIBOSDP_CONFORMANCE_LOCAL [] = { 0x0A, 0x00, 0x17 };
char OSDP_VENDOR_INID [] = { 0x00, 0x75, 0x32 };
char *osdp_manufacturer_list [] = {
  OSDP_VENDOR_LIBOSDP_CONFORMANCE_LOCAL,
  OSDP_VENDOR_INID,
  NULL
  };

// INID specials
#define OSDP_CMD_MSC_GETPIV  (0x10)
#define OSDP_CMD_MSC_KP_ACT  (0x13)
#define OSDP_CMD_MSC_CR_AUTH (0x14)
#define OSDP_REP_MSC_PIVDATA (0x10)
#define OSDP_REP_MSC_CR_AUTH (0x14)
#define OSDP_REP_MSC_STAT    (0xFD)
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


int
  action_osdp_MFG
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_MFG */

  char cmd [4096]; //C_STRING_MX];
  int count;
  int current_length;
  char hex_buffer [2000];
  int matches_conformance_oui;
  int matches_vendor_oui;
  OSDP_MFG_COMMAND *mfg;
  OSDP_HDR *oh;
  int status;
  int unknown;


  status = ST_OK;
  unknown = 1;
  oh = (OSDP_HDR *)(msg->ptr);
  count = oh->len_lsb + (oh->len_msb << 8);
  count = count - 6; // assumes no SCS header
  if (ctx->secure_channel_use [OO_SCU_ENAB] EQUALS OO_SCS_OPERATIONAL)
    count = count - 2; // for SCS 18
  count = count - msg->check_size;

  mfg = (OSDP_MFG_COMMAND *)(msg->data_payload);

  matches_vendor_oui = memcmp(mfg->vendor_code, ctx->vendor_code, 3);
  matches_conformance_oui = memcmp(mfg->vendor_code, OOSDP_MFG_VENDOR_CODE, sizeof(OOSDP_MFG_VENDOR_CODE));
  if (ctx->verbosity > 3)
    fprintf(ctx->log, "OUI match conformance %d match vendor %d\n",
      matches_conformance_oui, matches_vendor_oui);
  if ((matches_vendor_oui EQUALS 0) && (matches_conformance_oui != 0))
    unknown = 0; // if it was the one explicitly specified but not (mine) it's not unknown

  if (matches_conformance_oui EQUALS 0) //memcmp returns 0 on match
  {
    switch (mfg->mfg_command_id)
    {
    case OOSDP_MFG_PING:
      {
        unsigned char mfg_response [sizeof(struct osdp_mfg_command) + 4];
        OSDP_MFG_COMMAND *mh;

        unknown = 0; // we known this guy
        mh = (OSDP_MFG_COMMAND *)mfg_response;
        memcpy(mh->vendor_code, OOSDP_MFG_VENDOR_CODE, sizeof(OOSDP_MFG_VENDOR_CODE));
        mh->mfg_command_id = OOSDP_MFGR_PING_ACK;
        memcpy(&(mh->data), (char *)&(mfg->data), 4); // arbitrarily copy the 4 detail bytes back at ya
        current_length = 0;
        status = send_message(ctx, OSDP_MFGREP, p_card.addr, &current_length, sizeof(mfg_response), mfg_response);
      };
      break;

    case OOSDP_MFG_PIRATE:
      {
        unsigned char mfg_response [500];
        int response_payload_length;

        unknown = 0; // we known this guy
        memset(mfg_response, 0, sizeof(mfg_response));
        response_payload_length = count - 4; // payload length includes OUI, command
        memcpy(mfg_response, &(mfg->data), msg->data_length);
        current_length = 0;
        if (ctx->verbosity > 3)
        {
          fprintf(ctx->log, "DEBUG: Authenticate like a pirate - unknown %d response payload length %d first payload octet 0x%02X\n",
            unknown, response_payload_length, mfg->data);
        };
        status = send_message_ex (ctx, OSDP_MFGERRR, ctx->pd_address,
          &current_length, response_payload_length, mfg_response,
          OSDP_SEC_SCS_18, 0, NULL);
      };
      break;
    };
  };

  if (!unknown)
  {
    // and after we do whatever we did, call the action script.
    /*
      ACTION SCRIPT ARGS: 1=6 hexit OUI 2=MFG command 2 hexit 3=first octet of data 2hexit 4=data payload length

      length is payload less 4 (oui and id)
    */

    status = oo_bytes_to_hex_string(ctx, &(mfg->data), msg->data_length - 4, hex_buffer, sizeof(hex_buffer));
    if (status EQUALS ST_OK)
    {
      sprintf(cmd, "\"{\\\"1\\\":\\\"%02X\\\",\\\"2\\\":\\\"%02X%02X%02X\\\",\\\"3\\\":\\\"%02X\\\",\\\"4\\\":\\\"%s\\\"}\"",
        ctx->pd_address,
        mfg->vendor_code [0], mfg->vendor_code [1], mfg->vendor_code [2], mfg->mfg_command_id, hex_buffer);
      status = oosdp_callout(ctx, "osdp_MFG", cmd);
    };
    if (status EQUALS ST_OK)
    {
      current_length = 0;
      status = send_message_ex (ctx, OSDP_ACK, p_card.addr, &current_length, 0, NULL, OSDP_SEC_SCS_16, 0, NULL);
    };
  };
  if (unknown)
  {
    // dunno this mfg command, nak it

    int nak_length;
    unsigned char osdp_nak_response_data [1024];

    current_length = 0;
    osdp_nak_response_data [0] = OO_NAK_UNK_CMD;
    memcpy(osdp_nak_response_data, mfg->vendor_code, 3);
    nak_length = 3;
fprintf(ctx->log, "DEBUG: 5 NAK: %d.\n", osdp_nak_response_data [0]);
    status = send_message (ctx, OSDP_NAK, p_card.addr, &current_length, nak_length,
      osdp_nak_response_data); ctx->sent_naks ++;
  };

  return (status);

} /* action_osdp_MFG */


int
  oo_mfg_reply_action
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg,
    OSDP_MFGREP_RESPONSE *mrep)

{ /* oo_mfg_reply_action */

  int osdp_manufacturer_index;
  int status;
  char tmps [1024];
  char tlogmsg [3*1024];

  // INID
  OSDP_MSC_CR_AUTH_RESPONSE *cr_auth_response;
  OSDP_MSC_STATUS *msc_status;
  OSDP_MSC_PIV_DATA *piv_data;


  status = ST_OK;
  memset(tmps, 0, sizeof(tmps));
  osdp_manufacturer_index = -1; // 
  if (0 EQUALS memcmp(mrep->vendor_code, OSDP_VENDOR_LIBOSDP_CONFORMANCE_LOCAL, sizeof(OSDP_VENDOR_LIBOSDP_CONFORMANCE_LOCAL)))
    osdp_manufacturer_index = 0;
  if (0 EQUALS memcmp(mrep->vendor_code, OSDP_VENDOR_INID, sizeof(OSDP_VENDOR_INID)))
    osdp_manufacturer_index = 1;
  switch(osdp_manufacturer_index)
  {
  default:
    if (ctx->verbosity > 3)
      fprintf(ctx->log, "MFG Reply Action: no action taken. (OUI: %02x:%02x:%02x Command ID %02x value2 %02x, payload was %d. bytes)\n",
      mrep->vendor_code [0], mrep->vendor_code [1], mrep->vendor_code [2],
      0, 0,
      0);
    break;

  case 1: // INID
    status = ST_OSDP_MFG_VENDOR_DETECTED;
#define RESPONSE_STATUS (*(&(mrep->data)+0))
    switch (RESPONSE_STATUS)
    {
    case OSDP_REP_MSC_CR_AUTH:
      status = ST_OSDP_MFG_VENDOR_PROCESSED;
      {
            cr_auth_response = (OSDP_MSC_CR_AUTH_RESPONSE *)(msg->data_payload);
            sprintf(tmps,
"MSC CRAUTH RESPONSE TotSize:%d. Offset:%d FragSize: %d\n",
              cr_auth_response->mpd_size_total, cr_auth_response->mpd_offset,
              cr_auth_response->mpd_fragment_size);
            strcat(tlogmsg, tmps);
      };
      break;

  case OSDP_REP_MSC_PIVDATA:
      status = ST_OSDP_MFG_VENDOR_PROCESSED;
      {
            piv_data = (OSDP_MSC_PIV_DATA *)(msg->data_payload);
            sprintf(tmps,
"MSC PIVDATA\n  TotSize:%d. Offset:%d FragSize: %d\n",
              piv_data->mpd_size_total, piv_data->mpd_offset,
              piv_data->mpd_fragment_size);
            strcat(tlogmsg, tmps);
      };
      break;
    case OSDP_REP_MSC_STAT:
      status = ST_OSDP_MFG_VENDOR_PROCESSED;
      {
            msc_status = (OSDP_MSC_STATUS *)(msg->data_payload);
            sprintf(tmps, "MSC STATUS %02x Info %02x %02x\n", 
              msc_status->status, msc_status->info [0], msc_status->info [1]);
      };
      break;
    };
    break;
  };

  return(status);

} /* oo_mfg_reply_action */

