/*
  oo-printmsg - open osdp message printing routines

  (C)Copyright 2017-2022 Smithee Solutions LLC

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
#include <string.h>


#include <open-osdp.h>


int
  oosdp_print_message_CHLNG
  (OSDP_CONTEXT *ctx,
  OSDP_MSG *osdp_msg,
  char *tlogmsg)

{ /* oosdp_print_message_CHLNG */

  OSDP_SC_CHLNG *chlng_payload;
  int status;


  status = ST_OK;
  // in this case 'aux' is a pointer to a marshalled message that's
  // just been sent out the door.
  chlng_payload = (OSDP_SC_CHLNG *)(osdp_msg->data_payload);
  sprintf (tlogmsg,
"CHLNG: RND.A %02x%02x%02x%02x-%02x%02x%02x%02x\n",
    chlng_payload->rnd_a [0], chlng_payload->rnd_a [1],
    chlng_payload->rnd_a [2], chlng_payload->rnd_a [3],
    chlng_payload->rnd_a [4], chlng_payload->rnd_a [5],
    chlng_payload->rnd_a [6], chlng_payload->rnd_a [7]);

  return(status);

} /* oosdp_print_message_CHLNG */


int
  oosdp_print_message_KEYSET
  (OSDP_CONTEXT *ctx,
  OSDP_MSG *osdp_msg,
  char *tlogmsg)

{ /* oosdp_print_message_KEYSET */

  int count;
  char hstr [1024];
  int i;
  unsigned char *keyset_payload;
  OSDP_HDR *oh;
  int status;
  char tstr [2*1024];


  status = ST_OK;
  *tlogmsg = 0;
  oh = (OSDP_HDR *)(osdp_msg->ptr);
  count = oh->len_lsb + (oh->len_msb << 8);
  count = count - 8;  // payload
  keyset_payload = (unsigned char *)(osdp_msg->data_payload);
  count = osdp_msg->data_length;

  sprintf(tstr, "  Key_Type %02x Key Length %d.\n",
    keyset_payload [0], keyset_payload [1]);

  *hstr = 0;
  for (i=0; i<(count-2); i++)
  {
    sprintf(tstr, "%02x", keyset_payload [2+i]);
    strcat(hstr, tstr);
    if (i != (count-1))
      if (3 EQUALS (i%4))
        strcat(hstr, "-");
  };
  sprintf(tstr, "  New SCBK (Type=%02x Length=%02x): %s\n",
    keyset_payload [0], keyset_payload [1], hstr);
    strcat(tlogmsg, tstr);
  return(status);

} /* oosdp_print_message_KEYSET */


int
  oosdp_print_message_LED
  (OSDP_CONTEXT *ctx,
  OSDP_MSG *osdp_msg,
  char *tlogmsg)

{ /* oosdp_print_message_LED */

  char color_name_off [1024];
  char color_name_on [1024];
  int count;
  int i;
  int j;
  OSDP_RDR_LED_CTL *led_ctl;
  OSDP_HDR *oh;
  unsigned char *p;
  int status;
  char tmpstr [3*1024];


  status = 0;
  // count of LED command structures is inferred from message header
  oh = (OSDP_HDR *)(osdp_msg->ptr);
  count = oh->len_lsb + (oh->len_msb << 8);
  count = count - 7;
  count = count / sizeof (*led_ctl);

  // msg body is one or more of these structures per section 3.10 of 2.1.7
  led_ctl = (OSDP_RDR_LED_CTL *)(osdp_msg->data_payload);
  tlogmsg [0] = 0;

  if (osdp_msg->security_block_length > 0)
  {
    strcat(tlogmsg, "  (LED message contents encrypted)\n");
  };
  if ((osdp_msg->security_block_length EQUALS 0) || (osdp_msg->payload_decrypted))
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
        led_ctl->perm_off_time*100, color_name_off);
      strcat(tlogmsg, tmpstr);
      if (ctx->verbosity > 3)
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

  return(status);

} /* oosdp_print_message_LED */


int
  oosdp_print_message_PD_IDENT
  (OSDP_CONTEXT *ctx,
  OSDP_MSG *osdp_msg,
  char *tlogmsg)

{ /* oosdp_print_message_PD_IDENT */

  char filename [3072];
  FILE *identf;
  OSDP_HDR *oh;
  int status;


  status = ST_OK;
  tlogmsg [0] = 0;
  oh = (OSDP_HDR *)(osdp_msg->ptr);
  if (osdp_msg->security_block_length > 0)
  {
    strcat(tlogmsg, "  (PDID message contents encrypted)\n");
  };
  if ((osdp_msg->security_block_length EQUALS 0) || (osdp_msg->payload_decrypted))
  {
    sprintf (filename, "ident_from_PD%02x.json", (0x7f&oh->addr));
    identf = fopen (filename, "w");
  if (identf != NULL)
  {
    fprintf (identf, "{\n");
    fprintf (identf, "  \"#\" : \"PD address %02x\",\n",
      (0x7f&oh->addr));
    fprintf (identf, "  \"OUI\" : \"%02x-%02x-%02x\",\n",
      *(osdp_msg->data_payload + 0), *(osdp_msg->data_payload + 1),
      *(osdp_msg->data_payload + 2));
    fprintf (identf, "  \"version\" : \"Model %d V %d\",\n",
      *(osdp_msg->data_payload + 3), *(osdp_msg->data_payload + 4));
    fprintf (identf, "  \"serial\" : \"%02x%02x%02x%02x\",\n",
      *(osdp_msg->data_payload + 5), *(osdp_msg->data_payload + 6),
      *(osdp_msg->data_payload + 7), *(osdp_msg->data_payload + 8));
    fprintf (identf, "  \"firmware\" : \"%d.%d Build %d\"\n",
      *(osdp_msg->data_payload + 9), *(osdp_msg->data_payload + 10),
      *(osdp_msg->data_payload + 11));
    fprintf (identf, "}\n");
    fclose (identf);
  };
  sprintf (tlogmsg, 
"  PD Identification: OUI %02x-%02x-%02x Model %d Ver %d SN %02x-%02x-%02x-%02x FW %d.%d Build %d\n",
     *(osdp_msg->data_payload + 0), *(osdp_msg->data_payload + 1),
     *(osdp_msg->data_payload + 2), *(osdp_msg->data_payload + 3),
     *(osdp_msg->data_payload + 4), *(osdp_msg->data_payload + 5),
     *(osdp_msg->data_payload + 6), *(osdp_msg->data_payload + 7),
     *(osdp_msg->data_payload + 8), *(osdp_msg->data_payload + 9),
     *(osdp_msg->data_payload + 10), *(osdp_msg->data_payload + 11));
  };

  return(status);

} /* oosdp_print_message_PD_IDENT */


int
  oosdp_print_message_PIVDATA
  (OSDP_CONTEXT *ctx,
  OSDP_MSG *osdp_msg,
  char *tlogmsg)
{ /* oosdp_print_message_PIVDATA */

  int status;


  status = ST_OK;
  tlogmsg [0] = 0;
  sprintf(tlogmsg,
    "  PIV Data Get: Object ID %02x%02x%02x Element ID %02x Offset %02d.\n",
    *(osdp_msg->data_payload+0), *(osdp_msg->data_payload+1), *(osdp_msg->data_payload+2),
    *(osdp_msg->data_payload+3), *(osdp_msg->data_payload+4));
  return(status);

} /* oosdp_print_message_PIVDATA */


int
  oosdp_print_message_PIVDATAR
  (OSDP_CONTEXT *ctx,
  OSDP_MSG *osdp_msg,
  char *tlogmsg)
{ /* oosdp_print_message_PIVDATA */

  int i;
  int status;


  status = ST_OK;
  strcpy(tlogmsg, "  PIVDATA Response: ");
  for (i=0; i<100; i++)
  {
    char octet [3];
    sprintf(octet, "%02x", *(unsigned char *)(osdp_msg->data_payload+i));
    strcat(tlogmsg, octet);
  };
  strcat(tlogmsg, "...");
  return(status);

} /* oosdp_print_message_PIVDATA */


int
  oosdp_print_message_RAW
  (OSDP_CONTEXT *ctx,
  OSDP_MSG *osdp_msg,
  char *tlogmsg)

{ /* oosdp_print_message_RAW */

  int bits;
  int count;
  unsigned d;
  char hstr [1024];
  int i;
  OSDP_HDR *oh;
  char raw_fmt [1024];
  int status;
  char tstr [2*1024];


  status = ST_OK;
  oh = (OSDP_HDR *)(osdp_msg->ptr);
  count = oh->len_lsb + (oh->len_msb << 8);
  count = count - 6;  // strip header
  if ((oh->ctrl) & 0x04)
    count = count - 2; // CRC
  else
    count = count - 1; // Checksum

  count = count - 4; // 1 for reader number, 1 for format, 2 for no. of bits
  hstr [0] = 0;
  tlogmsg [0] = 0;
  /*
    this processes an osdp_RAW.  byte 0=rdr, b1=format, 2-3 are length (2=lsb)
  */
  if (osdp_msg->security_block_length > 0)
  {
    tlogmsg [0] = 0;
    for (i=0; i<count; i++)
    {
      d = *(unsigned char *)(osdp_msg->data_payload+i);
      sprintf(tstr, "%02x", d);
      strcat(hstr, tstr);
    };
    sprintf(tlogmsg,
      "  Encrypted RAW Payload (%d. bytes) %s\n", count, hstr);
  }
  else
  {
    strcpy(raw_fmt, "unspecified");
    if (*(osdp_msg->data_payload+1) EQUALS 1)
      strcpy(raw_fmt, "P/data/P");
    if (*(osdp_msg->data_payload+1) > 1)
      sprintf(raw_fmt, "unknown(%d)", *(osdp_msg->data_payload+1));

    bits = *(osdp_msg->data_payload+2) + ((*(osdp_msg->data_payload+3))<<8);
    sprintf(tlogmsg,
      "  Raw card: Format %s (Reader %d) %d bits (%d bytes in payload)\n",
      raw_fmt, *(osdp_msg->data_payload+0), bits, count);

    hstr [0] = 0;
    for (i=0; i<count; i++)
    {
      d = *(unsigned char *)(osdp_msg->data_payload+4+i);
      sprintf(tstr, "%02x", d);
      strcat(hstr, tstr);
    };
    sprintf(tstr, "  Card data: %s\n", hstr);
    strcat(tlogmsg, tstr);
  };

  return(status);

} /* oosdp_print_message_RAW */


int
  oosdp_print_message_RMAC_I
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *osdp_msg,
    char *tlogmsg)

{ /* oosdp_print_message_RMAC_I */

  int count;
  char hstr [1024];
  int i;
  OSDP_HDR *oh;
  unsigned char *mac_i;
  int status;
  char tstr [2*1024];


  status = ST_OK;
  *tlogmsg = 0;
  *hstr = 0;
  oh = (OSDP_HDR *)(osdp_msg->ptr);
  count = oh->len_lsb + (oh->len_msb << 8);
  count = count - 8;  // payload
  count = count - 3; // sec block
  mac_i = (unsigned char *)(osdp_msg->data_payload);
  for (i=0; i<count; i++)
  {
    sprintf(tstr, "%02x", mac_i [i]);
    strcat(hstr, tstr);
    if (i != (count-1))
      if (3 EQUALS (i%4))
        strcat(hstr, "-");
  };
  sprintf(tstr, "  MAC_I: %s\n", hstr);
    strcat(tlogmsg, tstr);
  return(status);

} /* oosdp_print_message_RMAC_I */

int
  oosdp_print_message_SCRYPT
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *osdp_msg,
    char *tlogmsg)

{ /* oosdp_print_message_SCRYPT */

  int count;
  char hstr [1024];
  int i;
  OSDP_HDR *oh;
  unsigned char *server_cryptogram;
  int status;
  char tstr [2*1024];


  status = ST_OK;
  *tlogmsg = 0;
  *hstr = 0;
  oh = (OSDP_HDR *)(osdp_msg->ptr);
  count = oh->len_lsb + (oh->len_msb << 8);
  count = count - 8;  // payload
  server_cryptogram = (unsigned char *)(osdp_msg->data_payload);
  for (i=0; i<count; i++)
  {
    sprintf(tstr, "%02x", server_cryptogram [i]);
    strcat(hstr, tstr);
    if (i != (count-1))
      if (3 EQUALS (i%4))
        strcat(hstr, "-");
  };
  sprintf(tstr, "  Server Cryptogram: %s\n", hstr);
    strcat(tlogmsg, tstr);

  return(status);

} /* oosdp_print_message_SCRYPT */


int
  oosdp_print_message_TEXT
  (OSDP_CONTEXT *ctx,
  OSDP_MSG *osdp_msg,
  char *tlogmsg)

{ /* oosdp_print_message_TEXT */

  int count;
  unsigned d;
  char hstr [1024];
  int i;
  OSDP_HDR *oh;
  int status;
  char tstr [32];


  status = ST_OK;
  oh = (OSDP_HDR *)(osdp_msg->ptr);
  count = oh->len_lsb + (oh->len_msb << 8);
  count = count - 8;  // payload
  count = count - 4; // 1 for reader number, 1 for format, 2 for no. of bits
  hstr [0] = 0;
  tlogmsg [0] = 0;
  if (osdp_msg->security_block_length > 0)
  {
    tlogmsg [0] = 0;
    for (i=0; i<count; i++)
    {
      d = *(unsigned char *)(osdp_msg->data_payload+i);
      sprintf(tstr, "%02x", d);
      strcat(hstr, tstr);
    };
    sprintf(tlogmsg,
      "  Encrypted TEXT Payload (%d. bytes) %s\n", count, hstr);
  }
  else
  {
    char text_message [1024];

    memset(text_message, 0, sizeof(text_message));
    memcpy(text_message, osdp_msg->data_payload+6, (unsigned int)*(osdp_msg->data_payload+5));
    sprintf(tlogmsg,
      "Text: Rdr %d. Cmd %d. Temp time %d. Row %d. Column %d. Text length %d.\n  %s\n",
      *(osdp_msg->data_payload+0), *(osdp_msg->data_payload+1), *(osdp_msg->data_payload+2),
      *(osdp_msg->data_payload+3), *(osdp_msg->data_payload+4), *(osdp_msg->data_payload+5),
      text_message);
  };

  return(status);

} /* oosdp_print_message_TEXT */


int
  oosdp_print_message_XRD
  (OSDP_CONTEXT *ctx,
  OSDP_MSG *osdp_msg,
  char *tlogmsg)

{ /* oosdp_print_message_XRD */

  int status;


  status = ST_OK;

  // default...

  sprintf(tlogmsg, "Extended Read: %02x %02x %02x %02x\n",
    *(osdp_msg->data_payload + 0), *(osdp_msg->data_payload + 1),
    *(osdp_msg->data_payload + 2), *(osdp_msg->data_payload + 3));

  // if we know it's 7.25.3

  if (*(osdp_msg->data_payload + 0) EQUALS 0)
  {
    if (*(osdp_msg->data_payload + 1) EQUALS 1)
    {
      sprintf(tlogmsg,
"Extended Read: osdp_PR00REQR Current Mode %02x Configuration %02x\n",
        *(osdp_msg->data_payload + 2), *(osdp_msg->data_payload + 3));
    };
  };

  // if we know it's 7.25.5

  if (*(osdp_msg->data_payload + 0) EQUALS 1)
    {
      if (*(osdp_msg->data_payload + 1) EQUALS 1)
      {
        sprintf(tlogmsg,
"Extended Read: Card Present - Interface not specified.  Rdr %d Status %02x\n",
          *(osdp_msg->data_payload + 2), *(osdp_msg->data_payload + 3));
      };
    };
  return(status);

} /* oosdp_print_message_XRD */

