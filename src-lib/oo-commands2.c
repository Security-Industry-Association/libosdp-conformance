// todo - details max length (it's 8k)

/*
  details_1 is the number of command entries or 0 for olde style

  details is tuples thing1 thing2 thing3

// socket command gets loaded into json string which is currently hardcoded to a 16k buffer.  add length checks etc.
// cmd buf in main is only 8k.  harmonize all these and make sure there are length checks.  current config likely
// would not fail, I think

*/
/*
  oo-commands2 - additional command processing routines.

  (C)Copyright 2017-2025 Smithee Solutions LLC

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



#include <string.h>


#include <jansson.h>


#include <open-osdp.h>
extern OSDP_PARAMETERS p_card; 
OSDP_RESPONSE_QUEUE_ENTRY osdp_response_queue [8];
int osdp_response_queue_size;


int oo_command_setup_out
  (OSDP_CONTEXT *ctx,
  json_t *output_command,
  OSDP_COMMAND *cmd)

{ /* oo_command_setup_out */

  int control_code;
  int i;
  int next_detail;
  int out_count;
  json_t *out_item;
  int output_number;
  json_t *output_set;
  int status;
  int timer;
  json_t *value;


  status = ST_OK;
  next_detail = 0;
  cmd->details_param_1 = 0;
  memset(cmd->details, 0, sizeof(cmd->details));
  output_set = json_object_get(output_command, "outputs");
  if (output_set != NULL)
  {
    out_count = 0;
    if (json_is_array(output_set))
    {
        out_count = json_array_size(output_set);
        printf("Command contains %d output specifications.\n", out_count);
    }
    else
    {
      status = ST_OSDP_CMD_OUT_BAD_2;
    };
    if ((status EQUALS ST_OK) && (out_count > 0))
    {
      for (i=0; i<out_count; i++)
      {
        out_item = json_array_get(output_set, i);
        value = json_object_get(out_item, "output-number");
        if (json_is_string(value))
        {
          sscanf(json_string_value(value), "%d", &output_number);
        }
        else
        {
          status = ST_OSDP_CMD_OUT_BAD_3;
        };
        value = json_object_get(out_item, "control-code");
        if (json_is_string(value))
        {
          sscanf(json_string_value(value), "%d", &control_code);
        }
        else
        {
          status = ST_OSDP_CMD_OUT_BAD_4;
        };
        value = json_object_get(out_item, "timer");
        if (json_is_string(value))
        {
          sscanf(json_string_value(value), "%d", &timer);
        }
        else
        {
          status = ST_OSDP_CMD_OUT_BAD_6;
        };
        if (status EQUALS ST_OK)
        {
          cmd->details [next_detail] = output_number;
          cmd->details [next_detail+1] = control_code;
          cmd->details [next_detail+2] = (timer & 0xff);
          cmd->details [next_detail+3] = (timer >> 8);
          cmd->details_param_1 ++;
          next_detail = next_detail + 4;
          if (next_detail EQUALS sizeof(cmd->details))
            status = ST_OSDP_CMD_OUT_BAD_5;
        };
        if ((status EQUALS ST_OK) && (ctx->verbosity > 3))
        {
          fprintf(ctx->log, "output item %d output number %d control code %d timer %d\n", i, output_number, control_code, timer);
        };
      };
    };
  }
  else
  {
    status = ST_OSDP_CMD_OUT_BAD_1;
  };

  return(status);

} /* oo_command_setup_out */


int oo_command_setup_present_card
  (OSDP_CONTEXT *ctx,
  json_t *root,
  OSDP_COMMAND *cmd)

{ /* oo_command_setup_present_card */

  unsigned short buffer_length;
  int i;
  json_t *option;
  int status;
  OSDP_COMMAND temp_command;
  char vstr [1024];


  status = ST_OK;

  temp_command.command = OSDP_CMDB_PRESENT_CARD;

  // if no options are given, use preset value
  temp_command.details_length = p_card.value_len;
  temp_command.details_param_1 = p_card.bits;
  memcpy(temp_command.details, p_card.value, p_card.value_len);

  // if there's a "raw" option it's the data to use.  bits are also specified.

  option = json_object_get (root, "raw");
  if (json_is_string (option))
  {
        strcpy (vstr, json_string_value (option));
        buffer_length = sizeof(cmd->details);
        status = osdp_string_to_buffer(ctx, vstr, temp_command.details, &buffer_length);
        temp_command.details_length = buffer_length;
        temp_command.details_param_1 = 26;  // assume 26 bits unless otherwise specified
  };

      option = json_object_get (root, "bits");
      if (json_is_string (option))
      {
        strcpy (vstr, json_string_value (option));
        sscanf(vstr, "%d", &i);
        temp_command.details_param_1 = i;
      };

      ctx->card_format = 0; // default

      // format can be specified (raw or p/data/p) - use a hex value for others.

      option = json_object_get (root, "format");
      if (json_is_string (option))
      {
        strcpy (vstr, json_string_value (option));
        if (0 EQUALS strcmp(vstr, "p-data-p"))
          ctx->card_format = 1;
        else
        {
          int fmt;

          sscanf(vstr, "%x", &fmt);
          ctx->card_format = 0xff & fmt;
        };
      };

      if (ctx->verbosity > 3)
        if (temp_command.details_length > 0)
          fprintf(ctx->log, "present_card: raw (%d. bytes, %d. bits, fmt %d): %s\n",
            temp_command.details_length, temp_command.details_param_1, ctx->card_format, vstr);

  if (status EQUALS ST_OK)
  {
    // if not interleaved file transfer do as before 

    if ((ctx->xferctx.total_length EQUALS 0) || !(ctx->ft_interleave))
    {
      fprintf(stderr, "normal card read\n");
      memcpy(cmd, &temp_command, sizeof(*cmd));
      status = enqueue_command(ctx, cmd);
      cmd->command = OSDP_CMD_NOOP;
    }
    else
    {
      fprintf(stderr, "interleaved card read\n");
      osdp_response_queue_size = 1;
      osdp_response_queue [0].details_param_1 = temp_command.details_param_1;
      osdp_response_queue [0].details_length = temp_command.details_length;
      memcpy(osdp_response_queue [0].details, temp_command.details, temp_command.details_length);
      ctx->xferctx.ft_action = OSDP_FTACTION_POLL_RESPONSE;
    };
  };

  return(status);

} /* oo_command_setup_present_card */


int oo_command_setup_xwrite
  (OSDP_CONTEXT *ctx,
  json_t *root,
  OSDP_COMMAND *cmd)

{ /* oo_command_setup_xwrite */

  int status;
  json_t *value;
  json_t *value2;


  cmd->command = OSDP_CMDB_XWRITE;

  value = json_object_get (root, "action");
  if (json_is_string (value))
  {
    if (0 EQUALS strcmp(json_string_value(value), "get-mode"))
    {
          cmd->details [0] = 1; // 1 in byte 0 is get-mode
    };
    if (0 EQUALS strcmp(json_string_value(value), "scan"))
    {
          cmd->details [0] = 3; // 3 in byte 0 is scan (for smart card)
    };
    if (0 EQUALS strcmp(json_string_value(value), "set-mode"))
    {
          cmd->details [0] = 2; // 2 in byte 0 is set-mode
    };
    if (0 EQUALS strcmp(json_string_value(value), "set-zero"))
    {
          cmd->details [0] = 4; // 4 in byte 0 is set mode 0
    };
    if (0 EQUALS strcmp(json_string_value(value), "done"))
    {
          cmd->details [0] = 5;
    };
    if (0 EQUALS strcmp(json_string_value(value), "apdu"))
    {
          unsigned short int payload_length;
          char payload_value [1024];

          cmd->details [0] = 6;

          // if there's a "payload" fill it in after the command in details

          value2 = json_object_get (root, "payload");
          if (json_is_string (value2))
          {
            payload_length = sizeof(cmd->details);
            strcpy(payload_value, json_string_value(value2));
            status = osdp_string_to_buffer
              (ctx, payload_value, cmd->details+3, &payload_length);
            *(short int *)(cmd->details+1) = payload_length;
          };
    };
  };
  if (status EQUALS ST_OK)
  {
    status = enqueue_command(ctx, cmd);
    cmd->command = OSDP_CMD_NOOP;
  };

  return(status);

} /* oo_command_setup_xwrite */
