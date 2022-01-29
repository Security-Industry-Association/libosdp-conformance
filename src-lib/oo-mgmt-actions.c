/*
  oo-mgmt-actions - action routines for (some) mgmt functions

  (C)Copyright 2021 Smithee Solutions LLC

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


#include <open-osdp.h>
#include <osdp_conformance.h>
extern OSDP_PARAMETERS p_card;


int
  action_osdp_MFGREP
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_MFGREP */

  char cmd [2*1024];
  int count;
  int i;
  OSDP_MFGREP_RESPONSE *mfg;
  unsigned char mfg_command;
  OSDP_HDR *oh;
  char payload [1024];
  int status;
  char tmp1 [1024];


  status = ST_OK;
  oh = (OSDP_HDR *)(msg->ptr);
  count = oh->len_lsb + (oh->len_msb << 8);
  count = count - 6; // assumes no SCS header
  count = count - msg->check_size;
        
  mfg = (OSDP_MFGREP_RESPONSE *)(msg->data_payload);
  mfg_command = *(&(mfg->data));
  sprintf (tlogmsg, "OUI %02x%02x%02x response length %d",
    mfg->vendor_code [0], mfg->vendor_code [1], mfg->vendor_code [2], count);
  fprintf (ctx->log, "  Mfg Reply %s\n", tlogmsg);
  dump_buffer_log(ctx, "MFGREP: ", msg->data_payload, count);

  payload [0] = 0;
  for (i=0; i<count; i++)
  {
    sprintf(tmp1, "%02x", *(&(mfg->data)+1+i));
    strcat(payload, tmp1);
  };
  sprintf(cmd, "%02X%02X%02X %02X %s",
    mfg->vendor_code [0], mfg->vendor_code [1], mfg->vendor_code [2], mfg_command, payload);
  status = oosdp_callout(ctx, "osdp_MFGREP", cmd);
  if (status EQUALS ST_OK)
    status = osdp_test_set_status_ex(OOC_SYMBOL_resp_mfgrep, OCONFORM_EXERCISED, "");

  return(status);

} /* action_osdp_MFGREP */


int
  action_osdp_RSTAT
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_RSTAT */

  int current_length;
  unsigned char osdp_rstat_response_data [1];
  int status;


  status = ST_OK;
  osdp_test_set_status(OOC_SYMBOL_cmd_rstat, OCONFORM_EXERCISED);
  osdp_test_set_status(OOC_SYMBOL_resp_rstatr, OCONFORM_EXERCISED);
  osdp_rstat_response_data [ 0] = 1; //hard code to "not connected"
  current_length = 0;
//  status = send_message (ctx, OSDP_RSTATR, p_card.addr, &current_length, sizeof (osdp_rstat_response_data), osdp_rstat_response_data);
  status = send_message_ex(ctx, OSDP_RSTATR, p_card.addr, &current_length, sizeof (osdp_rstat_response_data), osdp_rstat_response_data, OSDP_SEC_SCS_18, 0, NULL);
  if (ctx->verbosity > 2)
  {
    sprintf (tlogmsg, "Responding with OSDP_RSTATR (Ext Tamper)");
    fprintf (ctx->log, "%s\n", tlogmsg); tlogmsg[0]=0;
  };

  return (status);

} /* action_osdp_RSTAT */

