/*
  oo-actions-control - things that control the PD

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


#include <memory.h>
#include <arpa/inet.h>
#include <unistd.h>


#include <open-osdp.h>
#include <osdp_conformance.h>
extern OSDP_PARAMETERS p_card;


int
  action_osdp_COM
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_COM */

  unsigned char new_address;
  int new_speed;
  char new_speed_string [1024];
  int status;


fprintf(stderr, "DEBUG: action_osdp_COM - top\n"); fflush(stderr);
  status = ST_OK;
  osdp_test_set_status(OOC_SYMBOL_resp_com, OCONFORM_EXERCISED);
  new_address = msg->data_payload [0];
  new_speed = *(4+msg->data_payload);
  new_speed = (new_speed << 8) +*(3+msg->data_payload);
  new_speed = (new_speed << 8) +*(2+msg->data_payload);
  new_speed = (new_speed << 8) +*(1+msg->data_payload);
fprintf(stderr, "DEBUG: payload address %02X speed %d\n",
  new_address, new_speed);
  sprintf(new_speed_string, "%d", new_speed);
  switch(new_speed)
  {
  case   9600:
    osdp_test_set_status(OOC_SYMBOL_signalling_9600, OCONFORM_EXERCISED);
    break;
  case  19200:
    osdp_test_set_status(OOC_SYMBOL_signalling_19200, OCONFORM_EXERCISED);
    break;
  case  38400:
    osdp_test_set_status(OOC_SYMBOL_signalling_38400, OCONFORM_EXERCISED);
    break;
  case  57600:
    osdp_test_set_status(OOC_SYMBOL_signalling_57600, OCONFORM_EXERCISED);
    break;
  case 115200:
    osdp_test_set_status(OOC_SYMBOL_signalling_115200, OCONFORM_EXERCISED);
    break;
  case 230400:
    osdp_test_set_status(OOC_SYMBOL_signalling_230400, OCONFORM_EXERCISED);
    break;
  };
fprintf(stderr, "DEBUG: naddr %d ctxa %d nspeed %s ctxspeed %s\n",
  new_address, ctx->pd_address, new_speed_string, ctx->serial_speed);
fflush(stderr);
  if ((new_address != ctx->pd_address) || (strcmp(new_speed_string,ctx->serial_speed)))
  {
    // the PD has sent us (the ACU) an osdp_COM and it was different values than our current setting so use it.

    ctx->pd_address = new_address;
p_card.addr = ctx->pd_address; // legacy param
    strcpy(ctx->serial_speed, new_speed_string);
    status = init_serial (ctx, ctx->serial_device);
  };
  if (ctx->verbosity > 2)
  {
    fprintf (ctx->log, "osdp_COM: Addr %02x Baud (m->l) %02x %02x %02x %02x\n",
      *(0+msg->data_payload), *(1+msg->data_payload), *(2+msg->data_payload),
      *(3+msg->data_payload), *(4+msg->data_payload));
  };
  return (status);

} /* action_osdp_COM */



/*
  action_osdp_COMSET

  requested address is payload 0
  requested speed is payload 1-4, network byte order
*/

int
  action_osdp_COMSET
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_COMSET */

  int current_length;
  unsigned char from_address;
  unsigned char new_addr;
  int new_speed;
  unsigned char osdp_com_response_data [5];
  char logmsg [1024];
  OSDP_HDR *p;
  int status;


  status = ST_OK;
  memset (osdp_com_response_data, 0, sizeof (osdp_com_response_data));
  p = (OSDP_HDR *)(msg->ptr);

  // preset "new" values to old values in case we are not changing

  new_addr = ctx->pd_address;
  sscanf(ctx->serial_speed, "%d", &new_speed);
  if (!ctx->refuse_comset)
  {
    new_speed = *(1+msg->data_payload) + (*(2+msg->data_payload) << 8) +
      (*(3+msg->data_payload) << 16) + (*(4+msg->data_payload) << 24);
    new_addr = *(msg->data_payload); // first byte is new PD addr
  };
  if (ctx->verbosity > 2)
  {
    sprintf(logmsg, "COMSET Data Payload %02x %02x%02x%02x%02x %d. 0x%x",
      *(0+msg->data_payload), *(1+msg->data_payload),
      *(2+msg->data_payload), *(3+msg->data_payload),
      *(4+msg->data_payload), new_speed, new_speed);
    fprintf(ctx->log, "%s\n", logmsg);
    fprintf(ctx->log, "OSDP_COMSET received, setting addr to %02x speed to %s.\n",
      ctx->pd_address, ctx->serial_speed);
  };
  from_address = p->addr;
  osdp_com_response_data [0] = new_addr; // response address
  memcpy((char *)osdp_com_response_data+1, 1+msg->data_payload, 4);

  // send the response to the ACU

  current_length = 0;
  status = send_message_ex (ctx, OSDP_COM, oo_response_address(ctx, from_address),
    &current_length, sizeof (osdp_com_response_data), osdp_com_response_data,
    OSDP_SEC_SCS_18, 0, NULL);
  if (ctx->verbosity > 2)
  {
    sprintf (logmsg, "Responding with OSDP_COM");
    fprintf (ctx->log, "%s\n", logmsg); logmsg[0]=0;
  };

  if (!ctx->refuse_comset)
  {
    // set the new address
    if ((new_addr >= 0) && (new_addr <= 0x7E))
    {
      ctx->pd_address = new_addr;
      p_card.addr = ctx->pd_address;
    };
    fprintf (ctx->log, "PD Address set to %02x\n", ctx->pd_address);
    ctx->new_address = ctx->pd_address;
    sprintf(ctx->serial_speed, "%d", new_speed);
    fprintf(ctx->log, "Changing to address %02x speed %s\n",
      ctx->pd_address, ctx->serial_speed);
    sleep(2);
    (void)oo_save_parameters(ctx, OSDP_SAVED_PARAMETERS, NULL);
    status = init_serial (ctx, ctx->serial_device);
  };

  status = oosdp_callout(ctx, "osdp_COMSET", "");
  osdp_test_set_status(OOC_SYMBOL_cmd_comset, OCONFORM_EXERCISED);
  osdp_test_set_status(OOC_SYMBOL_resp_com, OCONFORM_EXERCISED);
  if (ctx->verbosity > 3)
    fprintf(ctx->log, "action_osdp_COMSET: status return %d.\n", status);
  return (status);

} /* action_osdp_COMSET */

