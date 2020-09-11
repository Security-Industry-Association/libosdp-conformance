/*
  open-osdp-PD-status - display PD status as refreshing HTML page

  (C)Copyright 2017-2020 Smithee Solutions LLC

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
char parameter_speed [1024];


void
  display_sim_reader
  (OSDP_CONTEXT *ctx,
  char *buffer)
{
  time_t current_time;
  struct timespec current_time_fine;
  char field [1024];
  int found_field;
  int i;
  char last_update [1024];
  char message_string [1024];
  char *out_status [OSDP_MAX_OUT];
  json_t *root;
  int status;
  int stat_acu_polls;
  int stat_buffer_overflows;
  int stat_checksum_errs;
  int stat_crc_errs;
  int stat_hash_bad;
  int stat_hash_ok;
  int stat_naks;
  int stat_pdus_received;
  int stat_pdus_sent;
  int stat_seq_errs;
  char stat_key [1024];
  char stat_key_slot [1024];
  int stat_pd_acks;
  json_error_t status_json;
  json_t *value;

  unsigned int led_color;
  int pd_address;


  status = ST_OK;
  stat_buffer_overflows = 0;
  stat_checksum_errs = 0;
  stat_crc_errs = 0;
  stat_hash_ok = 0;
  stat_key_slot [0] = 0;
  stat_key [0] = 0;

  clock_gettime (CLOCK_REALTIME, &current_time_fine);
  current_time = time (NULL);
  strcpy(last_update, "?");
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
      printf ("Please stand by.  Updating status...\n");
      status = ST_CMD_ERROR;
    };
  }; 
  if (status EQUALS ST_OK) {
    found_field = 1; value = json_object_get (root, "buffer-overflows");
    if (!json_is_string (value)) found_field = 0; };
  if (found_field) { char vstr [1024]; int i;
    strcpy (vstr, json_string_value (value));
    sscanf (vstr, "%d", &i);
    stat_buffer_overflows = i; };
  if (status EQUALS ST_OK) {
    found_field = 1; value = json_object_get (root, "checksum_errs");
    if (!json_is_string (value)) found_field = 0; };
  if (found_field) { char vstr [1024]; int i;
    strcpy (vstr, json_string_value (value));
    sscanf (vstr, "%d", &i);
    stat_checksum_errs = i; };
  if (status EQUALS ST_OK)
  {
    found_field = 1;
    value = json_object_get (root, "acu-polls");
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    char vstr [1024];
    int i;
    strcpy (vstr, json_string_value (value));
    sscanf (vstr, "%d", &i);
    stat_acu_polls = i;
  };
  if (status EQUALS ST_OK) {
    found_field = 1; value = json_object_get (root, "pdus-received");
    if (!json_is_string (value)) found_field = 0; };
  if (found_field) { char vstr [1024]; int i;
    strcpy (vstr, json_string_value (value));
    sscanf (vstr, "%d", &i);
    stat_pdus_received = i; };
  if (status EQUALS ST_OK) {
    found_field = 1; value = json_object_get (root, "pdus-sent");
    if (!json_is_string (value)) found_field = 0; };
  if (found_field) { char vstr [1024]; int i;
    strcpy (vstr, json_string_value (value));
    sscanf (vstr, "%d", &i);
    stat_pdus_sent = i; };
  if (status EQUALS ST_OK) {
    found_field = 1; value = json_object_get (root, "crc_errs");
    if (!json_is_string (value)) found_field = 0; };
  if (found_field) { char vstr [1024]; int i;
    strcpy (vstr, json_string_value (value));
    sscanf (vstr, "%d", &i);
    stat_crc_errs = i; };
  if (status EQUALS ST_OK) {
    found_field = 1; value = json_object_get (root, "pd-naks");
    if (!json_is_string (value)) found_field = 0; };
  if (found_field) { char vstr [1024]; int i;
    strcpy (vstr, json_string_value (value));
    sscanf (vstr, "%d", &i);
    stat_naks = i; };
  if (status EQUALS ST_OK) {
    found_field = 1; value = json_object_get (root, "seq-bad");
    if (!json_is_string (value)) found_field = 0; };
  if (found_field) { char vstr [1024]; int i;
    strcpy (vstr, json_string_value (value));
    sscanf (vstr, "%d", &i);
    stat_seq_errs = i; };
  if (status EQUALS ST_OK) {
    found_field = 1; value = json_object_get (root, "hash-bad");
    if (!json_is_string (value)) found_field = 0; };
  if (found_field) { char vstr [1024]; int i;
    strcpy (vstr, json_string_value (value));
    sscanf (vstr, "%d", &i);
    stat_hash_bad = i; };
  if (status EQUALS ST_OK) {
    found_field = 1; value = json_object_get (root, "hash-ok");
    if (!json_is_string (value)) found_field = 0; };
  if (found_field) { char vstr [1024]; int i;
    strcpy (vstr, json_string_value (value));
    sscanf (vstr, "%d", &i);
    stat_hash_ok = i; };
  if (status EQUALS ST_OK)
  {
    found_field = 1;
    value = json_object_get (root, "last_update");
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field) { strcpy (last_update, json_string_value (value)); };
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
    value = json_object_get (root, "pd-acks");
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    char vstr [1024];
    int i;
    strcpy (vstr, json_string_value (value));
    sscanf (vstr, "%d", &i);
    stat_pd_acks = i;
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
  { found_field = 1; value = json_object_get (root, "text"); if (!json_is_string (value)) found_field = 0; };
  if (found_field) { strcpy (ctx->text, json_string_value (value)); };

  if (status EQUALS ST_OK)
  { found_field = 1; value = json_object_get (root, "key-slot"); if (!json_is_string (value)) found_field = 0; };
  if (found_field) { strcpy (stat_key_slot, json_string_value (value)); };
  if (status EQUALS ST_OK)
  { found_field = 1; value = json_object_get (root, "scbk"); if (!json_is_string (value)) found_field = 0; };
  if (found_field) { strcpy (stat_key, json_string_value (value)); };
  if ('1' EQUALS stat_key_slot [0])
  {
    strcpy(stat_key_slot, "SCBK-D");
  }
  else
  {
    if ('2' EQUALS stat_key_slot [0])
    {
      strcpy(stat_key_slot, "SCBK");
    }
    else
    {
      stat_key [0] = 0;
    };
  };

  printf ("<H2>Reader(PD) Status</H2>\n");
  printf("<TABLE><TR>\n");
  printf ("<TD>LED</TD><TD><SPAN STYLE=\"BACKGROUND-COLOR:%06x;\">_0_</SPAN></TD>\n", led_color);
  printf ("<TD>Text</TD><TD>%s</TD>\n", ctx->text);
  printf("</TR></TABLE>\n");
  printf("<TABLE>\n");
  printf("<TR>\n");
  printf("<TD>Address</TD><TD>%2x</TD>\n", pd_address);
  printf("<TD>Speed</TD><TD>%s</TD>\n", parameter_speed);
  printf("<TD>Received</TD><TD>%5d</TD>\n", stat_pdus_received);
  printf("<TD>Sent</TD><TD>%5d</TD>\n", stat_pdus_sent);
  printf("<TD>NAK</TD><TD>%5d</TD>\n", stat_naks);
  printf("</TR>\n");
  printf("</TABLE>\n");
  printf("<TABLE>\n");
  printf("<TR><TD>Test Time</TD><TD>%08ld.%08ld</TD></TR>\n",
    (unsigned long int)current_time_fine.tv_sec, current_time_fine.tv_nsec);
  printf("<TR><TD>Local</TD><TD>%s</TD></TR>\n", asctime (localtime (&current_time)));
printf("<TR><TD>Last update</TD><TD>%s</TD></TR>\n", last_update);
  printf("</TABLE>\n");
  printf("<BR>Output<BR>\n");
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

  printf("<BR><PRE>Statistics:\n%5d ACU Polls %5d PD Acks %5d HASH OK\n",
    stat_acu_polls, stat_pd_acks, stat_hash_ok);
  printf("%5d HASH Bad %5d Seq Errs %5d CRC Errs %5d Checksum Errs %5d Buffer Overflows\n",
    stat_hash_bad, stat_seq_errs, stat_crc_errs, stat_checksum_errs,
    stat_buffer_overflows);
  if (strlen(stat_key) > 0)
  {
    printf("  Key %s (%s)", stat_key, stat_key_slot);
  };
  printf("\n");
}


int
  main
    (int argc,
    char *argv [])

{ /* main for open-osdp-PD-status */

  char buffer [16384];
  json_t *config_root;
  FILE *sf;
  int status;
  json_error_t status_json;
  json_t *value;


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

  config_root = NULL;
  config_root = json_load_file("/opt/osdp-conformance/run/PD/open-osdp-params.json", 0, &status_json);
  if (config_root)
  {
    value = json_object_get (config_root, "serial_speed");
    if (json_is_string (value))
    {
      strcpy (parameter_speed, json_string_value (value));
    };
  };

  display_sim_reader (&osdp_context, buffer);

  printf ("<PRE>\n");
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

