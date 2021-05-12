/*
  osdp-api - bits to implement HUP-based "API"

  (C)Copyright 2017-2021 Smithee Solutions LLC

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


extern OSDP_CONTEXT context;

int
  enqueue_command
    (OSDP_CONTEXT *ctx,
    OSDP_COMMAND *cmd)

{ /* enqueue_command */

  int done;
  int i;
  int status;


  status = ST_OK;
  if (ctx->verbosity > 3)
    fprintf(ctx->log, "DEBUG: enqueue_command: top, cmd->command %02x\n",
      cmd->command);

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
    if (i > 0)
      fprintf(ctx->log, "enqueue cmd to entry %2d\n", i);
    memcpy(&(ctx->q [i].cmd), cmd, sizeof(ctx->q [0].cmd));
    ctx->q [i].status = 1;
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
  OSDP_COMMAND extracted;
  int status;
  int waiting;


  status = ST_OK;
  waiting = osdp_awaiting_response(ctx);
if (waiting)
{
  fprintf(stderr, "DEBUG: process_command_from_queue: waiting\n");
};
  if (ctx->verbosity > 9)
    fprintf(ctx->log, "process_command_from_queue: top, w=%d\n", waiting);
  if ((!waiting) && (ctx->q [0].status != 0)) // meaning there's at least one command in the queue
  {

fflush(ctx->log);
fflush(stderr);
    memcpy(&extracted, &(ctx->q [0].cmd), sizeof(extracted));
    cmd = &extracted;

    // move all commands up one position
    memcpy(ctx->q, ctx->q+1, (OSDP_COMMAND_QUEUE_SIZE-1)*sizeof(ctx->q [0]));

    // noop out the last queue entry
    ctx->q [OSDP_COMMAND_QUEUE_SIZE-1].status = 0;

    if (ctx->verbosity > 3)
      fprintf(ctx->log, "process_command_from_queue: processing command %d.\n", cmd->command);
if (cmd->command != 0)
  fprintf(stderr, "DEBUG: processing command %d.\n", cmd->command);
    status = process_command(cmd->command, ctx,
      cmd->details_length, cmd->details_param_1, (char *)(cmd->details));
  };

  return(status);
  
} /* process_command_from_queue */


void
  preserve_current_command
    (void)

{ /* preserve_current_command */

  char command [4*1024];
  char preserve [2*1024];


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
  oosdp_clear_statistics
    (OSDP_CONTEXT *ctx)

{ /* oosdp_clear_statistics */

  ctx->acu_polls = 0;
  ctx->bytes_received = 0;
  ctx->bytes_sent = 0;
  ctx->checksum_errs = 0;
  ctx->crc_errs = 0;
  ctx->dropped_octets = 0;
  ctx->hash_bad = 0;
  ctx->hash_ok = 0;
  ctx->pd_acks = 0;
  ctx->pdus_received = 0;
  ctx->pdus_sent = 0;
  ctx->retries = 0;
  ctx->sent_naks = 0;
  ctx->seq_bad = 0;

} /* oosdp_clear_statistics */

