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


char
  *osdp_led_color_lookup
    (unsigned char led_color_number)

{ /* osdp_led_color_lookup */

  static char value [1024];


  switch(led_color_number)
  {
  default:
    sprintf(value, "?(%02x)", led_color_number);
    break;
  case OSDP_LEDCOLOR_AMBER:
    sprintf(value, "\'Amber\'(%02x)", led_color_number);
    break;
  case OSDP_LEDCOLOR_BLUE:
    sprintf(value, "\'Blue\'(%02x)", led_color_number);
    break;
  case OSDP_LEDCOLOR_BLACK:
    sprintf(value, "Black");
    break;
  case OSDP_LEDCOLOR_GREEN:
    sprintf(value, "Green");
    break;
  case OSDP_LEDCOLOR_RED:
    sprintf(value, "Red");
    break;
  };
  return (value); 

} /* osdp_led_color_lookup */


char
  *osdp_message
    (int
      status,
    int
      detail_1,
    int
      detail_2,
    int
      detail_3)

{ /* osdp_message */

  char
    *retmsg;


  retmsg = 0;
  switch (status)
  {
  case ST_OSDP_TLS_NOCERT:
    retmsg = "Certificate files unavailable";
    break;
  };

  return (retmsg);

} /* osdp_message */


char
  *osdp_pdcap_function
    (int func)
{
  static char funcname [1024];
  switch (func)
  {
  default:
    sprintf (funcname, "Unknown(0x%2x)", func);
    break;
  case 1:
    strcpy (funcname, "Contact Status Monitoring");
    break;
  case 2:
    strcpy (funcname, "Output Control");
    break;
  case 3:
    strcpy (funcname, "Card Data Format");
    break;
  case 4:
    strcpy (funcname, "Reader LED Control");
    break;
  case 5:
    strcpy (funcname, "Reader Audible Output");
    break;
  case 6:
    strcpy (funcname, "Reader Text Output");
    break;
  case 7:
    strcpy (funcname, "Time Keeping");
    break;
  case 8:
    strcpy (funcname, "Check Character Support");
    break;
  case 9:
    strcpy (funcname, "Communication Security");
    break;
  case 10:
    strcpy (funcname, "Receive Buffer Size");
    break;
  case 11:
    strcpy (funcname, "Max Multi-Part Size");
    break;
  case 12:
    strcpy (funcname, "Smart Card Support");
    break;
  case 13:
    strcpy (funcname, "Readers");
    break;
  case 14:
    strcpy (funcname, "Biometrics");
    break;
  };
  return (funcname);
}


/*
  osdp_log_summary - logs the summary stats
*/

int
  osdp_log_summary
    (OSDP_CONTEXT *ctx)

{ /* osdp_log_summary */

  int status;
  char tlogmsg [1024];


  status = oosdp_make_message (OOSDP_MSG_PKT_STATS, tlogmsg, NULL);
  if (status == ST_OK)
    status = oosdp_log (ctx, OSDP_LOG_STRING, 1, tlogmsg);
  return (ST_OK);

} /* osdp_log_summary */


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
  char filename [1024];
  OSDP_HDR_FILETRANSFER *filetransfer_message;
  OSDP_HDR_FTSTAT *ftstat;
  OSDP_HDR *hdr;
  FILE *identf;
  OSDP_MSG *msg;
  unsigned short int newdelay;
  unsigned short int newmax;
  OSDP_HDR *oh;
  unsigned char osdp_command;
  char tlogmsg [1024];
  char tmpstr [1024];
  char tmpstr2 [1024];
  int status;
  unsigned short int ustmp; // throw-away unsigned short integer (fits a "doubleByte")
  unsigned int utmp; // throw-away unsigned integer (fits a "quadByte")


  status = ST_OK;
  switch (msgtype)
  {
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
fprintf(stderr, "tlogmsg %s before Input...\n", tlogmsg);
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
          strcpy(tmpstr, "(Raw:");
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

      msg = (OSDP_MSG *) aux;
      mrep = (OSDP_MFG_HEADER *)(msg->data_payload);
      sprintf(tlogmsg, "MFG Request: OUI:%02x-%02x-%02x Command: %02x\n",
        mrep->vendor_code [0], mrep->vendor_code [1], mrep->vendor_code [2],
        mrep->command_id);
    };
    break;

  case OOSDP_MSG_MFGREP:
    {
      OSDP_MFG_HEADER *mrep;

      msg = (OSDP_MSG *) aux;
      mrep = (OSDP_MFG_HEADER *)(msg->data_payload);
      sprintf(tlogmsg, "MFG Reply: OUI:%02x-%02x-%02x RepID: %02x\n",
        mrep->vendor_code [0], mrep->vendor_code [1], mrep->vendor_code [2],
        mrep->command_id);
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
  if (strlen(trace_in_buffer) > 0)
  {
    fprintf(context->log, " Trace Data IN: %s\n", trace_in_buffer);
    trace_in_buffer [0] = 0;
  };
  if (strlen(trace_out_buffer) > 0)
  {
    fprintf(context->log, "Trace Data OUT: %s\n", trace_out_buffer);
    trace_out_buffer [0] = 0;
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


int
  oosdp_log_key
    (OSDP_CONTEXT
      *ctx,
    char
      *prefix_message,
    unsigned char
      *key)

{ /* oosdp_log_key */

  int
    i;
  int
    status;
  char
    tlogmsg [1024];
  char
    tlogmsg2 [1024];


  status = ST_OK;
  if (ctx->verbosity > 8)
  {
    strcpy (tlogmsg, prefix_message);
    for (i=0; i<OSDP_KEY_OCTETS; i++)
    {
      sprintf (tlogmsg2, "%02x", key [i]);
      strcat (tlogmsg, tlogmsg2);
    };
    fprintf (ctx->log, "%s\n", tlogmsg);
  };
  return (status);

} /* oosdp_log_key */

