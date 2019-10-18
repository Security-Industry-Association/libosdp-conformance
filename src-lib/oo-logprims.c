/*
  oo-logprims - open osdp logging sub-functions

  (C)Copyright 2017-2019 Smithee Solutions LLC
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
#include <string.h>


#include <open-osdp.h>
extern char trace_in_buffer [];
extern char trace_out_buffer [];


int
  oosdp_message_header_print
  (OSDP_CONTEXT *ctx,
  OSDP_MSG *msg,
  char *tlogmsg)

{ /* osdp_message_header_print */

  OSDP_HDR *osdp_wire_message;
  int scb_present;
  char *sec_block;
  char sec_block_decoded [1024];
  int status;
  char tmpstr2 [1024];
  unsigned short int wire_cksum;
  unsigned short int wire_crc;


  status = ST_OK;
  tlogmsg [0] = 0;
  // dump as named in the IEC spec
  osdp_wire_message = (OSDP_HDR *)(msg->ptr); // actual message off the wire
  sprintf(tmpstr2, "  SOM ADDR=%02x LEN_LSB=%02x LEN_MSB=%02x",
    osdp_wire_message->addr, osdp_wire_message->len_lsb,
    osdp_wire_message->len_msb);
  strcat(tlogmsg, tmpstr2); tmpstr2 [0] = 0;
  sprintf(tmpstr2, " CTRL=%02x", osdp_wire_message->ctrl);
  strcat(tlogmsg, tmpstr2); tmpstr2 [0] = 0;

  // "Chk/CRC" is either 1 byte or 2 depending on Checksum or CRC used.

  wire_crc = *(1+msg->crc_check) << 8 | *(msg->crc_check);
  wire_cksum = *(1+msg->crc_check);

  sprintf(tmpstr2, " CRC=%04x", wire_crc);
  if (msg->check_size != 2)
    sprintf(tmpstr2, " Checksum=%02x", wire_cksum);
  strcat(tlogmsg, tmpstr2); tmpstr2 [0] = 0;

  if (osdp_wire_message->ctrl & 0x08)
  {
    scb_present = 1;
    sprintf(tmpstr2, " [SCB; ");
    strcat(tlogmsg, tmpstr2); tmpstr2 [0] = 0;
  }
  else
  {
    scb_present = 0;
    sprintf(tmpstr2, " "); //"No Security Control Block; ");
    strcat(tlogmsg, tmpstr2); tmpstr2 [0] = 0;
  };
  if (scb_present)
  {
    sec_block_decoded [0] = 0;
    sec_block = (char *)&(osdp_wire_message->command);
    if (sec_block[1] < OSDP_SEC_SCS_15)
    {
      if (sec_block [2] EQUALS OSDP_KEY_SCBK_D)
        sprintf(sec_block_decoded, "Key=SCBK-D(default)");
      else
        sprintf(sec_block_decoded, "Key=SCBK");
    };
    switch (sec_block[1])  // "sec block type"
    {
    case OSDP_SEC_SCS_11:
      sprintf(tmpstr2, "SCS_11; ");
      strcat(tlogmsg, tmpstr2); tmpstr2 [0] = 0;
      break;
    case OSDP_SEC_SCS_12:
      sprintf(tmpstr2, "SCS_12; ");
      strcat(tlogmsg, tmpstr2); tmpstr2 [0] = 0;
      break;
    case OSDP_SEC_SCS_13:
      sprintf(tmpstr2, "SCS_13; ");
      strcat(tlogmsg, tmpstr2); tmpstr2 [0] = 0;
      break;
    case OSDP_SEC_SCS_14:
      sprintf(tmpstr2, "SCS_14; ");
      strcat(tlogmsg, tmpstr2); tmpstr2 [0] = 0;
      if (sec_block [2] EQUALS 1)
        strcpy(sec_block_decoded, "Session-ok");
      else
        strcpy(sec_block_decoded, "Session-bad");
      break;
    case OSDP_SEC_SCS_15:
      sprintf(tmpstr2, "SCS_15");
      strcat(tlogmsg, tmpstr2); tmpstr2 [0] = 0;
      break;
    case OSDP_SEC_SCS_16:
      sprintf(tmpstr2, "SCS_16");
      strcat(tlogmsg, tmpstr2); tmpstr2 [0] = 0;
      break;
    case OSDP_SEC_SCS_17:
      sprintf(tmpstr2, "SCS_17");
      strcat(tlogmsg, tmpstr2); tmpstr2 [0] = 0;
      break;
    case OSDP_SEC_SCS_18:
      sprintf(tmpstr2, "SCS_18");
      strcat(tlogmsg, tmpstr2); tmpstr2 [0] = 0;
      break;
    default:
fprintf(stderr, "unknown Security Block %d.\n", sec_block [1]);
      break;
    };
    strcat(tlogmsg, sec_block_decoded); tmpstr2 [0] = 0;
    strcat(tlogmsg, "]");
  };

  return(status);

} /* osdp_message_header_print */


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
    (int status,
    int detail_1,
    int detail_2,
    int detail_3)

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
  case OSDP_CAP_VERSION:
    strcpy(funcname, "OSDP Protocol Version");
    break;
  };
  return (funcname);
}



int
  oosdp_log_key
    (OSDP_CONTEXT *ctx,
    char *prefix_message,
    unsigned char *key)

{ /* oosdp_log_key */

  int i;
  int status;
  char tlogmsg [1024];
  char tlogmsg2 [1024];


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
    fflush(ctx->log);
  };
  return (status);

} /* oosdp_log_key */


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


void
  osdp_trace_dump
    (OSDP_CONTEXT *ctx)

{ /* osdp_trace_dump */

  struct timespec current_time_fine;
  FILE *tf;

  clock_gettime (CLOCK_REALTIME, &current_time_fine);
  tf = fopen(OSDP_TRACE_FILE, "a+");
  if (tf)
  {
    if (strlen(trace_out_buffer) > 0)
      fprintf(tf,
"{ \"time\" : \"%010ld.%09ld\", \"io\" : \"out\", \"data\" : \"%s\", \"osdp-trace-version\":\"%d\", \"osdp-source\":\"libosdp-conformance %d.%d-%d\" }\n",
        current_time_fine.tv_sec, current_time_fine.tv_nsec, trace_out_buffer,
        OSDP_TRACE_VERSION_0, OSDP_VERSION_MAJOR, OSDP_VERSION_MINOR, OSDP_VERSION_BUILD);
    fflush(tf);
    if (strlen(trace_in_buffer) > 0)
      fprintf(tf,
"{ \"time\" : \"%010ld.%09ld\", \"io\" : \"in\", \"data\" : \"%s\", \"osdp-trace-version\":\"%d\", \"osdp-source\":\"libosdp-conformance %d.%d-%d\" }\n",
        current_time_fine.tv_sec, current_time_fine.tv_nsec, trace_in_buffer,
        OSDP_TRACE_VERSION_0, OSDP_VERSION_MAJOR, OSDP_VERSION_MINOR, OSDP_VERSION_BUILD);
    fflush(tf);
    fclose(tf);
  };

  if (strlen(trace_out_buffer) > 0)
  {
    fprintf(ctx->log,
"\nOUTPUT Trace: %s\n", trace_out_buffer);
    trace_out_buffer [0] = 0;
  };
  if (strlen(trace_in_buffer) > 0)
  {
    fprintf(ctx->log,
"\n INPUT Trace: %s\n", trace_in_buffer);
    trace_in_buffer [0] = 0;
  };

} /* osdp_trace_dump */

