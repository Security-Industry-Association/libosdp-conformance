// todo - details max length (it's 8k)

/*
  details_1 is the number of command entries or 0 for olde style

  details is tuples thing1 thing2 thing3

// socket command gets loaded into json string which is currently hardcoded to a 16k buffer.  add length checks etc.
// cmd buf in main is only 8k.  harmonize all these and make sure there are length checks.  current config likely
// would not fail, I think

*/


#include <string.h>


#include <jansson.h>


#include <open-osdp.h>


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

