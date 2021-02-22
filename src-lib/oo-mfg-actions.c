/*
  oo-mfg-actions - action call-outs for manufacturer specific commands

  (C)Copyright 2017-2021 Smithee Solutions LLC

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
    fprintf(ctx->log, "MFG Reply Action: no action taken. (OUI: %02x:%02x:%02x Command ID %02x value2 %02x, payload was %d. bytes)\n",
      0, 0, 0,
      0, 0,
      0);
    break;

  case 1: // INID
    status = ST_OSDP_MFG_VENDOR_DETECTED;
    switch (mrep->mfg_response_status)
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

