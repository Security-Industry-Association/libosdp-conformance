/*
  oo-xwrite - extended write and extended reader functions

  (C)Copyright 2020-2026 Smithee Solutions LLC

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
#include <string.h>
#include <stdlib.h>


#include <open-osdp.h>
#include <iec-xwrite.h>
extern OSDP_PARAMETERS p_card;


int
  action_osdp_XRD
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_XRD */

  char cmd [2*8192];
  int i;
  char octet [3];
  int status;


  status = oosdp_make_message (OOSDP_MSG_XREAD, tlogmsg, msg);
  if (status EQUALS ST_OK)
    status = oosdp_log (ctx, OSDP_LOG_NOTIMESTAMP, 1, tlogmsg);

  sprintf(cmd, "%02X %02X ",
    *(msg->data_payload), *(msg->data_payload+1));
  for (i=0; i<msg->data_length-2; i++)
  {
    sprintf(octet, "%02X", *(msg->data_payload+2+i));
    strcat(cmd, octet);
  };
  status = oosdp_callout(ctx, "osdp_XRD", cmd);

  return (status);

} /* action_osdp_XRD */


int
  action_osdp_XWR
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_XWR */

  char callout_args [8192];
  int i;
  char octet [3];
  int pdata_length;
  int status;


// TODO CONFIRM data_payload not cmd_payload

  status = oosdp_make_message (OOSDP_MSG_XWR, tlogmsg, msg);
  if (status EQUALS ST_OK)
    status = oosdp_log (ctx, OSDP_LOG_NOTIMESTAMP, 1, tlogmsg);

  if (status EQUALS ST_OK)
  {
    sprintf(callout_args, "MODE %02X PCMND %02X PDATA ",
      *(msg->data_payload + 0),
      *(msg->data_payload + 1));
    pdata_length = msg->data_length - 2;
    if (pdata_length > 0)
    {
      for(i=0; i<pdata_length; i++)
      {
        sprintf(octet, "%02X", *(msg->data_payload+2+i));
        strcat(callout_args, octet);
      };
    };
    sprintf(tlogmsg,
"Extended Write Mode=%02X PCMND=%02X PDATA contains %d. bytes\n",
      *(msg->data_payload + 0), *(msg->data_payload + 1), pdata_length);
    status = oosdp_log (ctx, OSDP_LOG_NOTIMESTAMP, 1, tlogmsg);
  };
  if (status EQUALS ST_OK)
  {
    status = oosdp_callout(ctx, "osdp_XWR", callout_args);
  };

  return (status);

} /* action_osdp_XWR */


int
  osdp_xwrite_mode1
  (OSDP_CONTEXT *ctx,
  int command,
  unsigned char *payload,
  int payload_length)

{ /* osdp_xwrite_mode1_command */

  unsigned char send_buffer [1024];
  int clth;
  int current_length;
  int status;
  OSDP_XWR_COMMAND xwr_cmd;


  status = ST_OK;
  clth = 3; // mode, pcmd, Reader Number per table 43

  memset(&xwr_cmd, 0, sizeof(xwr_cmd));
  xwr_cmd.xrw_mode = 1;
  xwr_cmd.xwr_pcmnd = command;
  xwr_cmd.xwr_pdata [0] = 0; // reader 0

  fprintf(ctx->log, "Extended Write: Mode 1: Command %d\n",
    xwr_cmd.xwr_pcmnd);
  memcpy(send_buffer, &xwr_cmd, sizeof(xwr_cmd));
  if (command EQUALS OSDP_XWR_1_APDU)
  {
    memcpy(send_buffer+1+clth-1, payload, payload_length);
    clth = clth + payload_length;
  };

  // send command osdp_XWR payload is xwr_cmd
  current_length = 0;
  status = send_message (ctx,
    OSDP_XWR, p_card.addr, &current_length, clth, send_buffer);

  return (status);

} /* osdp_xwrite_mode1_command */


int
  osdp_xwrite_get_mode
  (OSDP_CONTEXT *ctx)

{ /* osdp_xwrite_get_mode */

  int clth;
  int current_length;
  int status;
  OSDP_XWR_COMMAND xwr_cmd;

  status = ST_OK;
  clth = 2; // just first 2 fields
  memset(&xwr_cmd, 0, sizeof(xwr_cmd));
  xwr_cmd.xrw_mode = 0;
  xwr_cmd.xwr_pcmnd = OSDP_XWR_0_GET_MODE;

  // send command osdp_XWR payload is xwr_cmd
  current_length = 0;
  status = send_message (ctx,
    OSDP_XWR, p_card.addr, &current_length, clth, (unsigned char *)&xwr_cmd);
  
  return (status);
   
} /* osdp_xwrite_get_mode */


int
  osdp_xwrite_set_mode
  (OSDP_CONTEXT *ctx,
  int mode)

{ /* osdp_xwrite_set_mode */

  int clth;
  int current_length;
  int status;
  OSDP_XWR_COMMAND xwr_cmd;


  status = ST_OK;
  clth = 4; // mode, pcmd, 2 bytes of pdata for mode code and mode config per table 36

  // always sets mode to 1

  memset(&xwr_cmd, 0, sizeof(xwr_cmd));
  xwr_cmd.xrw_mode = 0;
  xwr_cmd.xwr_pcmnd = OSDP_XWR_0_SET_MODE;
  xwr_cmd.xwr_pdata [0] = mode;
if (mode EQUALS 1)
{
  xwr_cmd.xwr_pdata [1] = 0; // only value for mode 1
};
if (mode EQUALS 0)
{
  xwr_cmd.xwr_pdata [1] = 1; // enable read card info response (mode 0)
};

  fprintf(ctx->log, "Extended Write: Set Mode %d\n",
    xwr_cmd.xwr_pcmnd);

  // send command osdp_XWR payload is xwr_cmd
  current_length = 0;
  status = send_message (ctx,
    OSDP_XWR, p_card.addr, &current_length, clth, (unsigned char *)&xwr_cmd);

  return (status);

} /* osdp_xwr_send_set_mode */


int osdp_xwrite_explicit
  (OSDP_CONTEXT *ctx,
  unsigned char mode,
  unsigned char pcmnd,
  int pdata_length,
  unsigned char *pdata)

{ /* osdp_xwrite_explicit */

  int clth;
  int current_length;
  int status;
  OSDP_XWR_COMMAND xwr_cmd;


  clth = 0;
  xwr_cmd.xrw_mode = mode; clth++;
  xwr_cmd.xwr_pcmnd = pcmnd; clth++;
  memcpy(&(xwr_cmd.xwr_pdata[0]), pdata, pdata_length);
  clth = clth + pdata_length;

  current_length = 0;
  status = send_message (ctx,
    OSDP_XWR, p_card.addr, &current_length, clth, (unsigned char *)&xwr_cmd);

  return(status);

} /* osdp_xwrite_explicit */

