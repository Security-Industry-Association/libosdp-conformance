/*
  (C)Copyright 2017-2025 Smithee Solutions LLC

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


#include <jansson.h>


#include <open-osdp.h>


int
  main
    (int argc,
    char *argv [])

{
  char buffer [16384];
  int found_field;
  char *osdp_config_file = "./open-osdp-params.json";
  char parameter [1024];
  json_t *root;
  FILE *sf;
  int status;
  json_error_t status_json;
  json_t *value;


  status = ST_OK;

  // open config in current directory

  buffer [0] = 0;
  sf = fopen (osdp_config_file, "r");
  if (sf != NULL)
  {
    (void) fread (buffer, sizeof (buffer [0]), sizeof (buffer), sf);
    fclose (sf);
  }
  else
  {
    status = -1;
  };
  if (status EQUALS ST_OK)
  {
    root = json_loads (buffer, 0, &status_json);
    if (!root)
    {
      status = -2;
    };
  };

  // fetch address

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    value = json_object_get (root, "address");
    if (!json_is_string (value))
      found_field = 0;
    if (found_field)
    {
      strcpy (parameter, json_string_value (value));

      // really should confirm role PD first
      printf(
"             PD Address: %s\n", parameter);
    };
  };

  // fetch enable-secure-channel

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    value = json_object_get (root, "enable-secure-channel");
    if (!json_is_string (value))
      found_field = 0;
    if (found_field)
    {
      strcpy (parameter, json_string_value (value));
      printf(
"         Secure Channel: ENABLED\n");
    };
  };

  // fetch role

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    value = json_object_get (root, "role");
    if (!json_is_string (value))
      found_field = 0;
    if (found_field)
    {
      strcpy (parameter, json_string_value (value));
      printf(
"                   Role: %s\n", parameter);
    };
  };

  // fetch speed

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    value = json_object_get (root, "serial-speed");
    if (!json_is_string (value))
      found_field = 0;
    if (found_field)
    {
      strcpy (parameter, json_string_value (value));
      printf(
"Serial Port Speed (BPS): %s\n", parameter);
    };
  };

  // fetch verbosity

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    value = json_object_get (root, "verbosity");
    if (!json_is_string (value))
      found_field = 0;
    if (found_field)
    {
      strcpy (parameter, json_string_value (value));

      // really should confirm role PD first
      printf(
"              Verbosity: %s\n", parameter);
    };
  };

  // if ok fetch speed, present card data, max msg, oui, version, serial, verbosity

  if (status EQUALS -1)
    fprintf(stderr, "Failed to open %s\n", osdp_config_file);
  if (status EQUALS -2)
    fprintf(stderr, "Failed to process JSON file.  File contents:\n%s\n", buffer);
  return (status);
}

#ifdef NOT_THERE
///
zzz
#include <stdio.h>
#include <stdlib.h>
#include <time.h>


OSDP_CONTEXT
  osdp_context;


void
  display_sim_reader
  (OSDP_CONTEXT 
    *ctx,
  char
    *buffer)
{
  char
    field [1024];
  char
    json_string [4096];
  int
    status;

  unsigned int
    led_color;
  int
    pd_address;


  status = ST_OK;
  found_field = 0;
  pd_address = 0;
  led_color = 0;
  if (status EQUALS ST_OK)
  {
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
fprintf (stdout, "led color %06x\n", i);
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
  printf ("libosdp PD Reader<BR>\n");
  printf ("A: %02x<BR>\n",
    pd_address);
printf ("<BR><SPAN STYLE=\"BACKGROUND-COLOR:%06x;\">LED ZERO</SPAN>\n",
  led_color);
  printf ("Message Text: %s<BR>\n",
    ctx->text);
}


int
  main
    (int
      argc,
    char
      *argv [])

{ /* main for open-osdp-PD-status */

  time_t
    current_time;
  struct timespec
    current_time_fine;
  int
    status;


  display_sim_reader (&osdp_context, buffer);

  printf ("<PRE>\n");
  printf ("Timestamp: %08ld.%08ld %s",
      (unsigned long int)current_time_fine.tv_sec, current_time_fine.tv_nsec,
      asctime (localtime (&current_time)));

  if (strlen (buffer) > 0)
  {
    printf ("%s", buffer);
  };
  printf ("</PRE>\n");

  printf ("</BODY></HTML>\n");
  return (status);

} /* main for open-osdp-PD-status */

#endif

