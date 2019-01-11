/*
  osdp-api - bits to implement HUP-based "API"

  (C)Copyright 2015-2017 Smithee,Spelvin,Agnew & Plinge, Inc.

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
#include <memory.h>


#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>


extern OSDP_CONTEXT
  context;

int
  enqueue_command
    (OSDP_CONTEXT *ctx,
    OSDP_COMMAND *cmd)

{ /* enqueue_command */

  int done;
  int i;
  int status;


  status = ST_OK;
  // if the last entry is active it's full

  if (ctx->q [OSDP_COMMAND_QUEUE_SIZE-1].status != 0)
  {
    ctx->cmd_q_overflow ++;
    status = ST_OSDP_COMMAND_OVERFLOW;
  }
  else
  {
    i = 0;
    done = 0;
    while (!done)
    {
      if (ctx->q [i].status EQUALS 0)
      {
        done = 1;
      }
      else
      {
        i++;
      };
    };
fprintf(stderr, "enqueue cmd to entry %2d\n", i);
    memcpy(&(ctx->q [i].cmd), cmd, sizeof(ctx->q [0].cmd));
  };

  return(status);

} /* enqueue_command */


int
  process_current_command
    (OSDP_CONTEXT *ctx)

{ /* process_current_command */

  OSDP_COMMAND cmd;
  int status;


  status = read_command (&context, &cmd);
  if (status EQUALS ST_OK)
  {

    status = enqueue_command(ctx, &cmd);

    status = process_command(cmd.command, &context, cmd.details_length, cmd.details_param_1, (char *)cmd.details);
  };
  if (status != ST_OK)
    fprintf (stderr, "process_current_command: status %d\n",
      status);
  return (status);

} /*process_current_command */


int
  process_command_from_queue
   (OSDP_CONTEXT *ctx)

{ /* process_command_from_queue */

  OSDP_COMMAND *cmd;
  int status;


  status = ST_OK;
  if (ctx->q [0].status EQUALS 0) // meaning there's at least one command in the queue
  {
    cmd = &(ctx->q [0].cmd);

    // move all commands up one position
    memcpy(ctx->q, ctx->q+1, (OSDP_COMMAND_QUEUE_SIZE-1)*sizeof(ctx->q [0]));

    // noop out the last queue entry
    ctx->q [OSDP_COMMAND_QUEUE_SIZE-1].status = 0;

    status = process_command(cmd->command, ctx, cmd->details_length, cmd->details_param_1, (char *)(cmd->details));
  };

  return(status);
  
} /* process_command_from_queue */


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

