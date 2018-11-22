/*
  oo-logprims - open osdp logging sub-functions
(C)Copyright 2017-2018 Smithee Solutions LLC
  (C)Copyright 2014-2017 Smithee,Spelvin,Agnew & Plinge, Inc.

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


#include <open-osdp.h>
#include <iec-xwrite.h>
extern OSDP_PARAMETERS p_card;
typedef struct osdp_xwr_command
{
  unsigned char xrw_mode;
  unsigned char xwr_pcmnd;
  unsigned char xwr_pdata [2];
} OSDP_XWR_COMMAND;
#define OSDP_XWR_0_GET_MODE (1) // per table 34 in 60839-11-5
#define OSDP_XWR_0_SET_MODE (2) // per table 34 in 60839-11-5
#define OSDP_XWR_1_SMART_CARD_SCAN (4) // per table 34 in 60839-11-5 and table 43


int
  osdp_xwrite_mode1
  (OSDP_CONTEXT *ctx,
  int command)

{ /* osdp_xwrite_mode1_command */

  int clth;
  int current_length;
  int status;
  OSDP_XWR_COMMAND xwr_cmd;


  status = ST_OK;
  clth = 3; // mode, pcmd, Reader Number per table 43

  memset(&xwr_cmd, 0, sizeof(xwr_cmd));
  xwr_cmd.xrw_mode = 1;
  xwr_cmd.xwr_pcmnd = OSDP_XWR_1_SMART_CARD_SCAN;
  xwr_cmd.xwr_pdata [0] = 0; // reader 0

  // send command osdp_XWR payload is xwr_cmd
  current_length = 0;
  status = send_message (ctx,
    OSDP_XWR, p_card.addr, &current_length, clth, (unsigned char *)&xwr_cmd);

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
  xwr_cmd.xwr_pdata [0] = 1; // behaviour mode 1
  xwr_cmd.xwr_pdata [1] = 0; // only value for mode 1
//                          1; // enable read card info response (mode 0)

  // send command osdp_XWR payload is xwr_cmd
  current_length = 0;
  status = send_message (ctx,
    OSDP_XWR, p_card.addr, &current_length, clth, (unsigned char *)&xwr_cmd);

  return (status);

} /* osdp_xwr_send_set_mode */

