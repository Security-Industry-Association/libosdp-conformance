/*
  osdp-api - bits to implement HUP-based "API"

  (C)Copyright 2015 Smithee,Spelvin,Agnew & Plinge, Inc.

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


#include <gnutls/gnutls.h>


#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>


extern OSDP_TLS_CONFIG
  config;

void
  process_current_command
    (void)

{ /*process_current_command */

  fprintf (stderr, "processing current command...\n");

} /*process_current_command */


void
  preserve_current_command
    (OSDP_TLS_CONFIG
      *cfg)

{ /* preserve_current_command */

  char
    command [1024];


  sprintf (command, "mv %s/osdp-tls_command.json %s/history/%02d_osdp-tls_command.json",
    cfg->cmd_dir,
    cfg->cmd_dir,
    cfg->cmd_hist_counter);
  system (command);
  cfg->cmd_hist_counter ++;
  if (cfg->cmd_hist_counter > 99)
    cfg->cmd_hist_counter = 0;

} /* preserve_current_command */


int
  send_osdp_data
    (OSDP_CONTEXT
      *context,
    unsigned char
      *buf,
    int
      lth)

{ /* send_osdp_data */

  gnutls_record_send (context->tls_session, buf, lth);
  return (ST_OK);

} /* send_osdp_data */


void
  signal_callback_handler
    (int
      signum)

{ /* signal_callback_handler */

  process_current_command ();
  preserve_current_command (&config);

} /* signal_callback_handler */


