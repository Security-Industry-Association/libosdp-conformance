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
#include <unistd.h>


#include <gnutls/gnutls.h>


#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>


extern int
  check_for_command;
//extern OSDP_TLS_CONFIG config;
extern OSDP_CONTEXT
  context;

int
  process_current_command
    (void)

{ /*process_current_command */

  OSDP_COMMAND
    cmd;
  int
    status;


  status = read_command (&context, &cmd);
  if (status EQUALS ST_OK)
  {
    status = process_command (cmd.command, &context);
  };
  if (status != ST_OK)
    fprintf (stderr, "process_current_command: status %d\n",
      status);
  return (status);

} /*process_current_command */


void
  preserve_current_command
    (void)

{ /* preserve_current_command */

  char
    command [1024];
  char
    preserve [1024];


  sprintf (preserve, "%s_%02d",
    context.command_path,
    context.cmd_hist_counter);
  sprintf (command,
    "sudo -n chmod 777 %s",
    context.command_path);
  system (command);
  sprintf (command, "sudo -n mv %s %s",
    context.command_path,
    preserve);
  system (command);
  context.cmd_hist_counter ++;
  if (context.cmd_hist_counter > 99)
    context.cmd_hist_counter = 0;

} /* preserve_current_command */


void
  signal_callback_handler
    (int
      signum)

{ /* signal_callback_handler */

//  int status;


  check_for_command = 1;
#if 0
  status = process_current_command ();
  if (status EQUALS ST_OK)
    preserve_current_command ();
#endif

} /* signal_callback_handler */


