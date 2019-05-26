/*
  open-osdp-PD-status - display PD status as refreshing HTML page

  (C)Copyright 2017-2019 Smithee Solutions LLC
  (C)Copyright 2015-2016 Smithee,Spelvin,Agnew & Plinge, Inc.

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
#include <stdlib.h>
#include <string.h>
#include <time.h>


#include <jansson.h>
#include <open-osdp.h>
OSDP_CONTEXT osdp_context;


void
  display_sim_reader
  (OSDP_CONTEXT *ctx,
  char *buffer)
{
  char field [1024];
  int found_field;
  char json_string [4096];
  int i;
  char message_string [1024];
  char *out_status [OSDP_MAX_OUT];
  json_t *root;
  int status;
  json_error_t status_json;
  json_t *value;

  unsigned int led_color;
  int pd_address;


  status = ST_OK;
  found_field = 0;
  pd_address = 0;
  led_color = 0;
  for (i=0; i<OSDP_MAX_OUT; i++)
  {
    out_status [i] = malloc(1024);
    *(out_status [i]) = 0;
  };
  if (status EQUALS ST_OK)
  {
    root = json_loads (buffer, 0, &status_json);
    if (!root)
    {
      printf ("JSON parser failed.  String was ->\n%s<-\n",
        json_string);
      status = ST_CMD_ERROR;
    };
  }; 
  if (status EQUALS ST_OK)
  {
    found_field = 1;
    strcpy (field, "led_color_00");
    value = json_object_get (root, field);
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    char vstr [1024];
    unsigned int i;
    strcpy (vstr, json_string_value (value));
    sscanf (vstr+1, "%x", &i);
    led_color = i;
  };
  if (status EQUALS ST_OK)
  {
    found_field = 1;
    strcpy (field, "pd_address");
    value = json_object_get (root, field);
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    char vstr [1024];
    int i;
    strcpy (vstr, json_string_value (value));
    sscanf (vstr, "%d", &i);
    pd_address = i;
  };
  if (status EQUALS ST_OK)
  {
    found_field = 1;
    strcpy (field, "text");
    value = json_object_get (root, field);
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    strcpy (ctx->text, json_string_value (value));
  };
  printf ("<H3>libosdp-conformance PD Reader</H3>\n");
  printf ("A: %02x<BR>\n",
    pd_address);
  printf ("<SPAN STYLE=\"BACKGROUND-COLOR:%06x;\">LED ZERO</SPAN>\n",
    led_color);
  printf ("Message Text: %s<BR>\n",
    ctx->text);
  message_string [0] = 0;
  for (i=0; i<OSDP_MAX_OUT; i++)
  {
    sprintf(field, "out-%02d", i);
    value = json_object_get (root, field);
    if (!json_is_string (value))
      sprintf(out_status [i], "&nbsp; &nbsp;");
    else
    {
      char vstring [1024];
      strcpy(vstring, json_string_value(value));

      if (0 EQUALS strcmp(vstring, "0"))
        sprintf(out_status [i], "&nbsp; &nbsp; %s ", vstring);
      else
        sprintf(out_status [i], "&nbsp; &nbsp; <SPAN STYLE=\"BACKGROUND-COLOR:DODGERBLUE;\">%s</SPAN>\n", vstring);
    };
    strcat(message_string, out_status [i]);
  };
  printf("%s<BR>\n", message_string);
  printf(
"&nbsp; 00 &nbsp; 01 &nbsp; 02 &nbsp; 03 &nbsp; 04 &nbsp; 05 &nbsp; 06 &nbsp; 07 &nbsp; 08 &nbsp; 09 &nbsp; 10 &nbsp 11 &nbsp 12 &nbsp 13 &nbsp 14 &nbsp 15<BR>\n");

  // yes I'm sloppy and left the out strings allocated.
}


int
  main
    (int argc,
    char *argv [])

{ /* main for open-osdp-PD-status */

  char
    buffer [16384];
  time_t
    current_time;
  struct timespec
    current_time_fine;
  FILE
    *sf;
  int
    status;


  status = ST_OK;
  printf ("Content-type: text/html\n\n");
  printf ("<HTML><HEAD><TITLE>open-osdp PD Status</TITLE>");
  printf ("<META HTTP-EQUIV=\"REFRESH\" CONTENT=\"3;\">");
  printf ("</HEAD><BODY>");

  buffer [0] = 0;
  sf = fopen ("/opt/osdp-conformance/run/PD/osdp-status.json", "r");
  if (sf != NULL)
  {
    (void) fread (buffer, sizeof (buffer [0]), sizeof (buffer), sf);
    fclose (sf);
  };
  clock_gettime (CLOCK_REALTIME, &current_time_fine);
  current_time = time (NULL);
  display_sim_reader (&osdp_context, buffer);

  printf ("<PRE>\n");
  printf ("Timestamp: %08ld.%08ld %s",
      (unsigned long int)current_time_fine.tv_sec, current_time_fine.tv_nsec,
      asctime (localtime (&current_time)));

  printf("PD Config:\n");
  fflush(stdout);
  system
    ("cd /opt/osdp-conformance/run/PD;/opt/osdp-conformance/bin/osdp-config-print");
  printf("PD Status Block:\n");
  if (strlen (buffer) > 0)
  {
    printf ("%s", buffer);
  };
  printf ("</PRE>\n");

  printf ("</BODY></HTML>\n");
  return (status);

} /* main for open-osdp-PD-status */

