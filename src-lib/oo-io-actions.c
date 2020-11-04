// oo-io-actions

int pending_response_length;
unsigned char pending_response_data [1500];
unsigned char pending_response;
/*
  oosdp-actions - open osdp action routines

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
#include <memory.h>
#include <stdlib.h>


#include <aes.h>


#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>


extern OSDP_INTEROP_ASSESSMENT
  osdp_conformance;
extern OSDP_PARAMETERS
  p_card;
char tlogmsg [2*1024];


int
  action_osdp_OUT
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_OUT */

  unsigned char buffer [1024];
  int current_length;
  int done;
  OSDP_OUT_MSG *outmsg;
  int status;
  int to_send;


  status = ST_OK;
  osdp_test_set_status(OOC_SYMBOL_cmd_out, OCONFORM_EXERCISED);
fprintf (stderr, "data_length in OSDP_OUT: %d\n",
  msg->data_length);
#if 0
// if too many for me (my MAX) then error and NAK?
// set 'timer' to msb*256+lsb
#define OSDP_OUT_OFF_PERM_TIMEOUT (3)
#define OSDP_OUT_ON_PERM_TIMEOUT  (4)
#define OSDP_OUT_ON_TEMP_TIMEOUT  (5)
#define OSDP_OUT_OFF_TEMP_TIMEOUT (6)
#endif
  done = 0;
  if (status != ST_OK)
    done = 1;
  while (!done)
  {
    outmsg = (OSDP_OUT_MSG *)(msg->data_payload);
    sprintf (tlogmsg, "  Out: Line %02x Ctl %02x LSB %02x MSB %02x",
      outmsg->output_number, outmsg->control_code,
      outmsg->timer_lsb, outmsg->timer_msb);
    fprintf (ctx->log, "%s\n", tlogmsg);
    if ((outmsg->output_number < 0) ||
      (outmsg->output_number > (OSDP_MAX_OUT-1)))
      status = ST_OUT_TOO_MANY;
    if (status EQUALS ST_OK)
    {
      switch (outmsg->control_code)
      {
      case OSDP_OUT_NOP:
        break;
      case OSDP_OUT_OFF_PERM_ABORT:
        ctx->out [outmsg->output_number].current = 0;
        ctx->out [outmsg->output_number].timer = 0;
        break;  
      case OSDP_OUT_ON_PERM_ABORT:
        ctx->out [outmsg->output_number].current = 1;
        ctx->out [outmsg->output_number].timer = 0;
        break;  
      default:
        status = ST_OUT_UNKNOWN;
        break;
      };
    }
    else
      done = 1;

done = 1; // just first one for now.
  };

  // return osdp_OSTATR with now-current output state
  {
    int j;
    unsigned char out_status [OSDP_MAX_OUT];

    for (j=0; j<OSDP_MAX_OUT; j++)
    {
      out_status [j] = ctx->out[j].current;
    };

    to_send = OSDP_MAX_OUT;
    memcpy (buffer, out_status, OSDP_MAX_OUT);
    current_length = 0;
    status = send_message_ex (ctx, OSDP_OSTATR, p_card.addr,
      &current_length, to_send, buffer, OSDP_SEC_SCS_18, 0, NULL);
  };
  status = ST_OK;
  return (status);

} /* action_osdp_OUT */

int
  action_osdp_OSTAT
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_OSTAT */

  unsigned char buffer [1024];
  int current_length;
  int j;
  unsigned char out_status [OSDP_MAX_OUT];
  int status;
  int to_send;


  status = ST_OK;
  osdp_test_set_status(OOC_SYMBOL_cmd_ostat, OCONFORM_EXERCISED);
  osdp_test_set_status(OOC_SYMBOL_resp_ostatr, OCONFORM_EXERCISED);

  for (j=0; j<OSDP_MAX_OUT; j++)
  {
    out_status [j] = ctx->out[j].current;
  };
  to_send = OSDP_MAX_OUT;
  memcpy (buffer, out_status, OSDP_MAX_OUT);
  current_length = 0;
  status = send_message (ctx, OSDP_OSTATR, p_card.addr,
    &current_length, to_send, buffer);
  return (status);

} /* action_osdp_OSTAT */

