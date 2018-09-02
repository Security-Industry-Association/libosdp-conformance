/*
  oo-logprims - open osdp logging sub-functions

  (C)Copyright 2017-2018 Smithee Solutions LLC
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
  };
  return (funcname);
}



int
  oosdp_log_key
    (OSDP_CONTEXT *ctx,
    char *prefix_message,
    unsigned char *key)

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

  if (strlen(trace_out_buffer) > 0)
  {
    fprintf(ctx->log, "Trace Data OUT: %s\n", trace_out_buffer);
    trace_out_buffer [0] = 0;
  };
  if (strlen(trace_in_buffer) > 0)
  {
    fprintf(ctx->log, " Trace Data IN: %s\n", trace_in_buffer);
    trace_in_buffer [0] = 0;
  };

} /* osdp_trace_dump */

