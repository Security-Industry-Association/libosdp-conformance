#define OSDP_CMD_MSC_GETPIV  (0x10)
#define OSDP_CMD_MSC_KP_ACT  (0x13)
#define OSDP_CMD_MSC_CR_AUTH (0x14)
#define OSDP_REP_MSC_PIVDATA (0x10)
#define OSDP_REP_MSC_CR_AUTH (0x14)
#define OSDP_REP_MSC_STAT    (0xFD)

char OSDP_VENDOR_INID [] = { 0x00, 0x75, 0x32 };

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

/*
  oosdp-logmsg - open osdp log message routines

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
#include <time.h>
#include <string.h>


#include <osdp-tls.h>
#include <open-osdp.h>

extern OSDP_CONTEXT context;
extern OSDP_PARAMETERS p_card;
extern char trace_in_buffer [];
extern char trace_out_buffer [];


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

  OSDP_SC_CCRYPT *ccrypt_payload;
  OSDP_SC_CHLNG *chlng_payload;
  int count;
  OSDP_MSC_CR_AUTH *cr_auth;
  OSDP_MSC_CR_AUTH_RESPONSE *cr_auth_response;
  char filename [1024];
  OSDP_HDR_FILETRANSFER *filetransfer_message;
  OSDP_HDR_FTSTAT *ftstat;
  OSDP_MSC_GETPIV *get_piv;
  OSDP_HDR *hdr;
  FILE *identf;
  int idx;
  OSDP_MSC_STATUS *msc_status;
  OSDP_MSG *msg;
  unsigned short int newdelay;
  unsigned short int newmax;
  OSDP_HDR *oh;
  unsigned char osdp_command;
  OSDP_MSC_PIV_DATA *piv_data;
  char tlogmsg [1024];
  char tmps [1024];
  char tmpstr [1024];
  char tmpstr2 [1024];
  int status;
  unsigned short int ustmp; // throw-away unsigned short integer (fits a "doubleByte")
  unsigned int utmp; // throw-away unsigned integer (fits a "quadByte")


  status = ST_OK;
  switch (msgtype)
  {
  case OOSDP_MSG_ACURXSIZE:
    {
    int c;

    msg = (OSDP_MSG *) aux;
    c = msg->data_payload [0];
    c = 256*c + msg->data_payload [1];
    sprintf(tlogmsg, "ACU Receive Size: %0x\n", c);
    };
    break;
  case OOSDP_MSG_BUZ:
    msg = (OSDP_MSG *) aux;
    sprintf(tlogmsg, "BUZ: Rdr %02x Tone Code %02x On=%d(ms) Off=%d(ms) Count %d\n",
      *(msg->data_payload + 0), *(msg->data_payload + 1),
      100 * *(msg->data_payload + 2), 100 * *(msg->data_payload + 3),
      *(msg->data_payload + 4));
    break;

  case OOSDP_MSG_CCRYPT:
    msg = (OSDP_MSG *) aux;
    ccrypt_payload = (OSDP_SC_CCRYPT *)(msg->data_payload);
    sprintf (tlogmsg,
"CCRYPT: cUID %02x%02x%02x%02x-%02x%02x%02x%02x RND.B %02x%02x%02x%02x-%02x%02x%02x%02x Client Cryptogram %02x%02x%02x%02x-%02x%02x%02x%02x\n",
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
      ccrypt_payload->cryptogram [6], ccrypt_payload->cryptogram [7]);
    break;

  case OOSDP_MSG_CHLNG:
    // in this case 'aux' is a pointer to a marshalled message that's just been sent out the door.
    msg = (OSDP_MSG *) aux;
    chlng_payload = (OSDP_SC_CHLNG *)(msg->data_payload);
    sprintf (tlogmsg,
"CHLNG: RND.A %02x%02x%02x%02x-%02x%02x%02x%02x\n",
      chlng_payload->rnd_a [0], chlng_payload->rnd_a [1],
      chlng_payload->rnd_a [2], chlng_payload->rnd_a [3],
      chlng_payload->rnd_a [4], chlng_payload->rnd_a [5],
      chlng_payload->rnd_a [6], chlng_payload->rnd_a [7]);
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

      sprintf(tlogmsg, "COMSET Will use New Address %02x New Speed %d.\n",
        *(0+msg->data_payload), speed);
    };
    break;

  case OOSDP_MSG_FILETRANSFER:
    msg = (OSDP_MSG *) aux;
    filetransfer_message = (OSDP_HDR_FILETRANSFER *)(msg->data_payload);
    tlogmsg[0] = 0;
    osdp_array_to_quadByte(filetransfer_message->FtSizeTotal, &utmp);
    sprintf(tmpstr,
"File Transfer: Type %02x\n",
      filetransfer_message->FtType);
    strcat(tlogmsg, tmpstr);
    sprintf(tmpstr,
"                           Size %02x-%02x-%02x-%02x(%d.)\n",
      filetransfer_message->FtSizeTotal [0], filetransfer_message->FtSizeTotal [1],
      filetransfer_message->FtSizeTotal [2], filetransfer_message->FtSizeTotal [3],
      utmp);
    strcat(tlogmsg, tmpstr);
    osdp_array_to_quadByte(filetransfer_message->FtOffset, &utmp);
    sprintf(tmpstr,
"                         Offset %02x%02x%02x%02x(%d.)\n",
      filetransfer_message->FtOffset [0], filetransfer_message->FtOffset [1],
      filetransfer_message->FtOffset [2], filetransfer_message->FtOffset [3],
      utmp);
    strcat(tlogmsg, tmpstr);
    osdp_array_to_doubleByte(filetransfer_message->FtFragmentSize, &ustmp);
    sprintf(tmpstr,
"                  Fragment Size %02x-%02x(%d.)\n  First data: %02x\n",
      filetransfer_message->FtFragmentSize [0], filetransfer_message->FtFragmentSize [1],
      ustmp, filetransfer_message->FtData);
    strcat(tlogmsg, tmpstr);
    sprintf(tmpstr,
"  Current Offset %8d. Total Length %8d. Current Send Length %d. Handle %lx\n",
      context.xferctx.current_offset, context.xferctx.total_length, context.xferctx.current_send_length,
      (unsigned long)(context.xferctx.xferf));
    strcat(tlogmsg, tmpstr);
    break;

  case OOSDP_MSG_FTSTAT:
    msg = (OSDP_MSG *) aux;
    ftstat = (OSDP_HDR_FTSTAT *)(msg->data_payload);
    tlogmsg[0] = 0;
    osdp_array_to_doubleByte(ftstat->FtDelay, &newdelay);
    osdp_array_to_doubleByte(ftstat->FtUpdateMsgMax, &newmax);
    sprintf(tmpstr,
"File Transfer STATUS: Detail %02x%02x Action %02x Delay %02x-%02x(%d.) Update-max %02x-%02x(%d.)\n",
      ftstat->FtStatusDetail [0], ftstat->FtStatusDetail [1],
      ftstat->FtAction,
      ftstat->FtDelay [0], ftstat->FtDelay [1], newdelay,
      ftstat->FtUpdateMsgMax [0], ftstat->FtUpdateMsgMax [1], newmax);
    strcat(tlogmsg, tmpstr);
    break;

  case OOSDP_MSG_ISTATR:
    msg = (OSDP_MSG *) aux;
    oh = (OSDP_HDR *)(msg->ptr);
    tlogmsg [0] = 0;
    if (msg->security_block_length > 0)
    {
      strcat(tlogmsg, "(ISTATR message contents encrypted)\n");
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
          sprintf(tmpstr, " IN-%d Active", i);
        else
          sprintf(tmpstr, " IN-%d Inactive", i);
        strcat(tlogmsg, tmpstr);
        count --;
        i++;
      };
      strcat(tlogmsg, "\n");
    };
    break;

  case OOSDP_MSG_KEEPACTIVE:
    {
      msg = (OSDP_MSG *) aux;
      if (msg->security_block_length > 0)
      {
        strcat(tlogmsg, "(KEYPAD message contents encrypted)\n");
      };
      if (msg->security_block_length EQUALS 0)
      {
        sprintf (tlogmsg,
"Keep credential read active %02x %02x",
          *(msg->data_payload+0), *(msg->data_payload+1));
      };
    };
    break;

  case OOSDP_MSG_KEYPAD:
    {
      int
        i;
      int
        keycount;

      msg = (OSDP_MSG *) aux;

      if (msg->security_block_length > 0)
      {
        strcat(tlogmsg, "(KEYPAD message contents encrypted)\n");
      };
      if (msg->security_block_length EQUALS 0)
      {
        keycount = *(msg->data_payload+1);
        memset (tmpstr, 0, sizeof (tmpstr));
        memcpy (tmpstr, msg->data_payload+2, *(msg->data_payload+1));
        for (i=0; i<keycount; i++)
        {
          if (tmpstr [i] EQUALS 0x7F)
            tmpstr [i] = '#';
          if (tmpstr [i] EQUALS 0x0D)
            tmpstr [i] = '*';
        };
        sprintf (tlogmsg,
"Keypad Input Rdr %d, %d digits: %s",
          *(msg->data_payload+0), keycount, tmpstr);
      };
    };
    break;

  case OOSDP_MSG_LED:
    {
      char color_name_off [1024];
      char color_name_on [1024];
      int count;
      int i;
      int j;
      OSDP_RDR_LED_CTL *led_ctl;
      unsigned char *p;
      char tmpstr [1024];


      msg = (OSDP_MSG *) aux;

      // count of LED command structures is inferred from message header
      oh = (OSDP_HDR *)(msg->ptr);
      count = oh->len_lsb + (oh->len_msb << 8);
      count = count - 7;
      count = count / sizeof (*led_ctl);

      // msg body is one or more of these structures per section 3.10 of 2.1.7
      led_ctl = (OSDP_RDR_LED_CTL *)(msg->data_payload);
      tlogmsg [0] = 0;

      if (msg->security_block_length > 0)
      {
        strcat(tlogmsg, "(LED message contents encrypted)\n");
      };
      if (msg->security_block_length EQUALS 0)
      {
        sprintf(tmpstr, "LED Control: %d. commands\n", count);
        strcat(tlogmsg, tmpstr);
        for (i=0; i<count; i++)
        {
        strcpy(color_name_on, osdp_led_color_lookup(led_ctl->temp_on_color));
        strcpy(color_name_off, osdp_led_color_lookup(led_ctl->temp_off_color));
        sprintf(tmpstr,
" %02d Rdr %02d LED %02d Temp Ctl=%02d ON=%d(ms)-%s OFF %d(ms)-%s blinkTime %d.(ms)\n",
          i, led_ctl->reader, led_ctl->led,
          led_ctl->temp_control,
          led_ctl->temp_on*100, color_name_on,
          led_ctl->temp_off*100, color_name_off,
          ((led_ctl->temp_timer_msb * 256) + led_ctl->temp_timer_lsb) * 100);
        strcat(tlogmsg, tmpstr);
        strcpy(color_name_on, osdp_led_color_lookup(led_ctl->perm_on_color));
        strcpy(color_name_off, osdp_led_color_lookup(led_ctl->perm_off_color));
        sprintf(tmpstr,
"                  Perm Ctl=%02d ON %d(ms)-%s OFF %d(ms)-%s\n",
          led_ctl->perm_control, led_ctl->perm_on_time*100, color_name_on,
          led_ctl->perm_off_time, color_name_off);
        strcat(tlogmsg, tmpstr);
        if (context.verbosity > 3)
        {
          strcpy(tmpstr, "(Raw(LED):");
          strcat(tlogmsg, tmpstr);
          tmpstr [0] = 0;
          p = (unsigned char *)led_ctl;
          for (j=0; j<16; j++)
          {
            sprintf(tmpstr, " %02x", *p);
            p++;
            strcat(tlogmsg, tmpstr);
          };
          strcat(tlogmsg, ")\n");
        };

        led_ctl++; // increment structure pointer to next LED
      };
    };
    };
    break;

  case OOSDP_MSG_LSTATR:
    {
      unsigned char *osdp_lstat_response_data;

      msg = (OSDP_MSG *) aux;
      if (msg->security_block_length > 0)
      {
        strcat(tlogmsg, "(LSTATR message contents encrypted)\n");
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
    {
      OSDP_MFG_HEADER *mrep;
      int process_as_special;

      memset(tlogmsg, 0, sizeof(tlogmsg));
      process_as_special = 0;
      msg = (OSDP_MSG *) aux;
      oh = (OSDP_HDR *)(msg->ptr);
      count = oh->len_lsb + (oh->len_msb << 8);
fprintf(stderr, "count is whole packet: %04x\n", count);
      count = count - sizeof(*oh);
fprintf(stderr, "count less main hdr: %04x\n", count);
      if (oh->ctrl & 0x04)
        count = count - 2;
      else
        count = count - 1;
fprintf(stderr, "count less CRC/Checksum: %04x\n", count);

      mrep = (OSDP_MFG_HEADER *)(msg->data_payload);
      process_as_special = 0;
      if (0 EQUALS memcmp(mrep->vendor_code, OSDP_VENDOR_INID, sizeof(OSDP_VENDOR_INID)))
        process_as_special = 1;
      if (!process_as_special)
      {
        sprintf(tlogmsg,
"(General) MFG Request: OUI:%02x-%02x-%02x Command: %02x\n",
          mrep->vendor_code [0], mrep->vendor_code [1], mrep->vendor_code [2],
          mrep->command_id);
      };
      if (process_as_special)
      {
        sprintf(tlogmsg,
          "  MFG Request: OUI:%02x-%02x-%02x Command: %02x\n",
          mrep->vendor_code [0], mrep->vendor_code [1], mrep->vendor_code [2],
          mrep->command_id);
        switch (mrep->command_id)
        {
        case OSDP_CMD_MSC_CR_AUTH:
          {
            cr_auth = (OSDP_MSC_CR_AUTH *)(msg->data_payload);

            // adjust buffer count so dump is accurate
            count = count - sizeof(cr_auth->vendor_code);
            count = count - sizeof(cr_auth->command_id);
fprintf(stderr, "count without CRAUTH(%ld) hdr: %04x\n", sizeof(*cr_auth), count);

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
            mrep->command_id);
          break;
        };
      }; 
      if (count > 0)
      {
        dump_buffer_log(&context, "  Raw(MFG): ", &(mrep->data), count);
      };
    };
    break;

  case OOSDP_MSG_MFGREP:
    {
      OSDP_MFG_HEADER *mrep;
      int process_as_special;

      memset(tlogmsg, 0, sizeof(tlogmsg));
      process_as_special = 0;

      msg = (OSDP_MSG *) aux;
      oh = (OSDP_HDR *)(msg->ptr);
      count = oh->len_lsb + (oh->len_msb << 8);
      count = count - sizeof(*mrep) + 1;
      mrep = (OSDP_MFG_HEADER *)(msg->data_payload);

      process_as_special = 0;
      if (0 EQUALS memcmp(mrep->vendor_code, OSDP_VENDOR_INID, sizeof(OSDP_VENDOR_INID)))
        process_as_special = 1;

      if (!process_as_special)
      {
        sprintf(tlogmsg, "(General) MFG Reply: OUI:%02x-%02x-%02x RepID: %02x\n",
          mrep->vendor_code [0], mrep->vendor_code [1], mrep->vendor_code [2],
          mrep->command_id);
      };
      if (process_as_special)
      {
        sprintf(tlogmsg, "MFG Reply: OUI:%02x-%02x-%02x RepID: %02x\n",
          mrep->vendor_code [0], mrep->vendor_code [1], mrep->vendor_code [2],
          mrep->command_id);
        switch (mrep->command_id)
        {
        case OSDP_REP_MSC_CR_AUTH:
          {
            cr_auth_response = (OSDP_MSC_CR_AUTH_RESPONSE *)(msg->data_payload);
            sprintf(tmps,
"MSC CRAUTH RESPONSE TotSize:%d. Offset:%d FragSize: %d\n",
              cr_auth_response->mpd_size_total, cr_auth_response->mpd_offset,
              cr_auth_response->mpd_fragment_size);
            strcat(tlogmsg, tmps);
            count = sizeof(*cr_auth_response) + cr_auth_response->mpd_fragment_size - 1 - sizeof(cr_auth_response->vendor_code)
              - sizeof(cr_auth_response->command_id);
          };
          break;

        case OSDP_REP_MSC_PIVDATA:
          {
            piv_data = (OSDP_MSC_PIV_DATA *)(msg->data_payload);
            sprintf(tmps,
"MSC PIVDATA\n  TotSize:%d. Offset:%d FragSize: %d\n",
              piv_data->mpd_size_total, piv_data->mpd_offset,
              piv_data->mpd_fragment_size);
            strcat(tlogmsg, tmps);
            count = sizeof(*piv_data) + piv_data->mpd_fragment_size - 1 - sizeof(piv_data->vendor_code)
              - sizeof(piv_data->command_id);
          };
          break;
        case OSDP_REP_MSC_STAT:
          {
            msc_status = (OSDP_MSC_STATUS *)(msg->data_payload);
            sprintf(tmps, "MSC STATUS %02x Info %02x %02x\n", 
              msc_status->status, msc_status->info [0], msc_status->info [1]);
            count = sizeof(*msc_status) - sizeof(piv_data->vendor_code)
              - sizeof(piv_data->command_id);
          };
          break;
        default:
          sprintf(tlogmsg, "(General) MFG Response: OUI:%02x-%02x-%02x RepID: %02x\n",
            mrep->vendor_code [0], mrep->vendor_code [1], mrep->vendor_code [2],
            mrep->command_id);
          break;
        };
      };

      strcat(tlogmsg, "  Raw:");
      for (idx=0; idx<count; idx++)
      {
        sprintf(tmps, " %02x", *(unsigned char *)(&(mrep->data)+idx));
        strcat(tlogmsg, tmps);
      };
      strcat(tlogmsg, "\n");
    };
    break;

  case OOSDP_MSG_NAK:
    msg = (OSDP_MSG *) aux;
    sprintf (tlogmsg, "NAK: Error Code %02x Data %02x\n",
      *(0+msg->data_payload), *(1+msg->data_payload));
    break;

  // special case - this outputs the basic "Message:.." message
  case OOSDP_MSG_OSDP:
    osdp_command = *(unsigned char *)aux;
    hdr = 2+aux;
    strcpy(tmpstr, osdp_command_reply_to_string(osdp_command, *(unsigned char *)(1+aux)));
    sprintf(tmpstr2, "Message: %s\n", tmpstr);
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

      sprintf (tlogmsg, "  Out: Line %02x Ctl %02x LSB %02x MSB %02x\n",
        out_message->output_number, out_message->control_code,
        out_message->timer_lsb, out_message->timer_msb);
    };
    break;

  case OOSDP_MSG_OUT_STATUS:
    {
      int
        i;
      unsigned char *out_status;
      char tmpstr [1024];

      msg = (OSDP_MSG *) aux;
      oh = (OSDP_HDR *)(msg->ptr);
      count = oh->len_lsb + (oh->len_msb << 8);
      count = count - 8;
      tlogmsg [0] = 0;
      out_status = msg->data_payload;
      for (i=0; i<count; i++)
      {
        sprintf (tmpstr, " Out-%02d = %d\n",
          i, out_status [i]);
        strcat (tlogmsg, tmpstr);
      };
    };
    break;

  case OOSDP_MSG_PD_CAPAS:
    {
      int
        i;
      OSDP_HDR
        *oh;
      char
        tstr [1024];
      int
        value;

      msg = (OSDP_MSG *) aux;
      oh = (OSDP_HDR *)(msg->ptr);
      count = oh->len_lsb + (oh->len_msb << 8);
      count = count - 8;
      sprintf (tstr, "PD Capabilities (%d)\n", count/3);
      strcpy (tlogmsg, tstr);

      for (i=0; i<count; i=i+3)
      {
        switch (*(i+0+msg->data_payload))
        {
        case 4:
          {
            int compliance;
            char tstr2 [1024];
            compliance = *(i+1+msg->data_payload);
            strcpy (tstr2, "Compliance=?");
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
        case 10:
          value = *(i+1+msg->data_payload) + 256 * (*(i+2+msg->data_payload));
          sprintf (tstr, "  [%02d] %s %d;\n",
            1+i/3, osdp_pdcap_function (*(i+0+msg->data_payload)), value);
          break;
        case 11:
          value = *(i+1+msg->data_payload) + 256 * (*(i+2+msg->data_payload));
          context.max_message = value; // SIDE EFFECT (naughty me) - sets value when displaying it.
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
    };
    break;

  case OOSDP_MSG_PD_IDENT:
    msg = (OSDP_MSG *) aux;
    oh = (OSDP_HDR *)(msg->ptr);
    sprintf (filename, 
      "/opt/osdp-conformance/run/CP/ident_from_PD%02x.json",
      (0x7f&oh->addr));
    identf = fopen (filename, "w");
    if (identf != NULL)
    {
      fprintf (identf, "{\n");
      fprintf (identf, "  \"#\" : \"PD address %02x\",\n",
        (0x7f&oh->addr));
      fprintf (identf, "  \"OUI\" : \"%02x-%02x-%02x\",\n",
        *(msg->data_payload + 0), *(msg->data_payload + 1),
        *(msg->data_payload + 2));
      fprintf (identf, "  \"version\" : \"model-%d-ver-%d\",\n",
        *(msg->data_payload + 3), *(msg->data_payload + 4));
      fprintf (identf, "  \"serial\" : \"%02x%02x%02x%02x\",\n",
        *(msg->data_payload + 5), *(msg->data_payload + 6),
        *(msg->data_payload + 7), *(msg->data_payload + 8));
      fprintf (identf, "  \"firmware\" : \"%d.%d-build-%d\"\n",
        *(msg->data_payload + 9), *(msg->data_payload + 10),
        *(msg->data_payload + 11));
      fprintf (identf, "}\n");
      fclose (identf);
    };
    sprintf (tlogmsg, 
"  PD Identification\n    OUI %02x-%02x-%02x Model %d Ver %d SN %02x%02x%02x%02x FW %d.%d Build %d\n",
        *(msg->data_payload + 0), *(msg->data_payload + 1),
        *(msg->data_payload + 2), *(msg->data_payload + 3),
        *(msg->data_payload + 4), *(msg->data_payload + 5),
        *(msg->data_payload + 6), *(msg->data_payload + 7),
        *(msg->data_payload + 8), *(msg->data_payload + 9),
        *(msg->data_payload + 10), *(msg->data_payload + 11));
    break;

  case OOSDP_MSG_PKT_STATS:
    sprintf (tlogmsg, " CP-Polls %6d PD-Acks %6d PD-NAKs %6d CkSumErr %6d\n",
      context.cp_polls, context.pd_acks, context.sent_naks,
      context.checksum_errs);
    break;

  case OOSDP_MSG_XREAD:
    msg = (OSDP_MSG *) aux;

    // default...

    sprintf(tlogmsg, "Extended Read: %02x %02x %02x %02x\n",
      *(msg->data_payload + 0), *(msg->data_payload + 1),
      *(msg->data_payload + 2), *(msg->data_payload + 3));

    // if we know it's 7.25.3

    if (*(msg->data_payload + 0) EQUALS 0)
    {
      if (*(msg->data_payload + 1) EQUALS 1)
      {
        sprintf(tlogmsg,
"Extended Read: osdp_PR00REQR Current Mode %02x Configuration %02x\n",
          *(msg->data_payload + 2), *(msg->data_payload + 3));
      };
    };

    // if we know it's 7.25.5

    if (*(msg->data_payload + 0) EQUALS 1)
    {
      if (*(msg->data_payload + 1) EQUALS 1)
      {
        sprintf(tlogmsg,
"Extended Read: Card Present - Interface not specified.  Rdr %d Status %02x\n",
          *(msg->data_payload + 2), *(msg->data_payload + 3));
      };
    };
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
    int
      logtype,
    int
      level,
    char
      *message)

{ /* oosdp_log */

  time_t
    current_raw_time;
  struct tm
    *current_cooked_time;
  int
    llogtype;
  char
    *role_tag;
  int
    status;
  char
    timestamp [1024];


  status = ST_OK;

  // dump the trace buffer before creating the log message
  osdp_trace_dump(context);

  llogtype = logtype;
  role_tag = "";
  strcpy (timestamp, "");
  if (logtype EQUALS OSDP_LOG_STRING_CP)
  {
    role_tag = "CP";
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
if (strcmp ("CP", role_tag)==0)
  sprintf (address_suffix, " DestAddr=%02x(hex)", context->this_message_addr);
else
  sprintf (address_suffix, " A=%02x(hex)", context->this_message_addr);
    sprintf (timestamp,
"OSDP %s Frame:%04d%s\nTimestamp:%04d%02d%02d-%02d%02d%02d (Sec/Nanosec: %ld %ld)\n",
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
  
  return (status);

} /* oosdp_log */

