/*
  osdp-api - bits to implement HUP-based "API"

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
    (OSDP_CONTEXT *ctx,
    char *socket_command)

{ /* process_current_command */

  OSDP_COMMAND cmd;
  int status;


  status = read_command (&context, &cmd, socket_command);
  if (status EQUALS ST_OK)
  {
    status = process_command(cmd.command, &context, cmd.details_length, cmd.details_param_1, (char *)cmd.details);
    if (ctx->verbosity > 9)
      fprintf(stderr, "DEBUG: q %d\n", ctx->q [0].status);
  };
  if (status != ST_OK)
    fprintf (stderr, "process_current_command: status %d\n",
      status);
  return (status);

} /*process_current_command */


/*
  the caller knows if this is an ACU or a PD and handles the waiting logic
*/

int
  process_command_from_queue
   (OSDP_CONTEXT *ctx)

{ /* process_command_from_queue */

  OSDP_COMMAND *cmd;
  OSDP_COMMAND extracted;
  int status;
//  int waiting;


  status = ST_OK;
#if 0
  waiting = osdp_awaiting_response(ctx);
if (waiting)
{
  fprintf(stderr, "DEBUG: process_command_from_queue: waiting\n");
};
  if (ctx->verbosity > 9)
    fprintf(ctx->log, "process_command_from_queue: top, w=%d\n", waiting);
#endif
//  if ((!waiting) && (ctx->q [0].status != 0)) // meaning there's at least one command in the queue
  if (ctx->q [0].status != 0) // meaning there's at least one command in the queue
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
    {
      fprintf(ctx->log, "process_command_from_queue: processing command %d.\n", cmd->command);
      if (cmd->command != 0)
        fprintf(stderr, "DEBUG: processing command %d.\n", cmd->command);
    };
    status = process_command(cmd->command, ctx,
      cmd->details_length, cmd->details_param_1, (char *)(cmd->details));
  };

  return(status);
  
} /* process_command_from_queue */


void
  preserve_current_command
    (void)

{ /* preserve_current_command */

//  char command [4*1024];
//  char preserve [2*1024];


//  sprintf (preserve, "%s_%02d", context.command_path, context.cmd_hist_counter);
//  sprintf (command, "sudo -n chmod 777 %s", context.command_path);
//  system (command);
//  sprintf (command, "sudo -n mv %s %s", context.command_path, preserve);
//  system (command);
  context.cmd_hist_counter ++;
  if (context.cmd_hist_counter > 99)
    context.cmd_hist_counter = 0;

} /* preserve_current_command */


int
  oosdp_callout
    (OSDP_CONTEXT *ctx,
    char *action_command,
    char *details)

{ /* oosdp_callout */

  char command [3*1024]; // three 'cause there are three args to the command sprintf
  int status;


  status = ST_OK;
  sprintf(command, "%s/%s %02X %s", oo_osdp_root(ctx, OO_DIR_ACTIONS), action_command, ctx->pd_address, details);
//  sprintf(command, "%s/run/ACU-actions/%s %02X %s", ctx->service_root, action_command, ctx->pd_address, details);
  if (ctx->verbosity > 3)
  {
    fprintf(ctx->log, "action path: %s\n", oo_osdp_root(ctx, OO_DIR_ACTIONS));
    fprintf(ctx->log, "action: %s\n", command);
  };
  fflush(ctx->log);
  system(command);
  return(status);

} /* oosdp_callout */


void
  oo_clear_statistics
    (OSDP_CONTEXT *ctx)

{ /* oo_clear_statistics */

  ctx->acu_polls = 0;
  ctx->bytes_received = 0;
  ctx->bytes_sent = 0;
  ctx->checksum_errs = 0;
  ctx->crc_errs = 0;
  memset(ctx->last_raw_read_data, 0, sizeof(ctx->last_raw_read_data));
  memset(ctx->last_keyboard_data, 0, sizeof(ctx->last_keyboard_data));
  ctx->dropped_octets = 0;
  ctx->hash_bad = 0;
  ctx->hash_ok = 0;
  ctx->last_raw_read_bits = 0;
  ctx->pd_acks = 0;
  ctx->pdus_received = 0;
  ctx->pdus_sent = 0;
  ctx->retries = 0;
  ctx->sent_naks = 0;
  ctx->seq_bad = 0;

} /* oo_clear_statistics */

/*
  assumes full path less than 1024
  assumes service root less than 512
*/


char *oo_osdp_root
  (OSDP_CONTEXT *ctx,
  int directory)

{ /* oo_osdp_root */

  static char response [1024];
  char service_root [512];

  strcpy(service_root, ctx->service_root);
  strcpy(response, service_root);
  
  switch(directory)
  {
  default:
    if (ctx->verbosity > 3)
      fprintf(ctx->log, "WARNING: OSDP root directory selector unknown (%d)\n", directory);
    // ...and it just uses the service root as initialized above.
    break;
  case OO_DIR_ACTIONS:
    sprintf(response, "%s/actions", service_root);
    break;
  case OO_DIR_CONFORMANCE:
    sprintf(response, "%s/testing", service_root);
    break;
  case OO_DIR_LOG:
    sprintf(response, "%s/log", service_root);
    break;
  case OO_DIR_RESPONSES:
    sprintf(response, "%s/responses", service_root);
    break;
  case OO_DIR_RUN:
    sprintf(response, "%s/run", service_root);
    break;
  };
  return(response);

} /* oo_osdp_root */

