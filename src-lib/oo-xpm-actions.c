/*
  oo-xpm-actions - action routines for extended packet mode

  (C)Copyright 2019-2021 Smithee Solutions LLC

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


extern OSDP_INTEROP_ASSESSMENT osdp_conformance;
extern OSDP_PARAMETERS p_card;


int
  action_osdp_KEEPACTIVE
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_KEEPACTIVE */

  int current_length;
  int status;


  fprintf(ctx->log, "osdp_KEEPACTIVE called\n");

  current_length = 0;
  status = send_message_ex
    (ctx, OSDP_ACK, p_card.addr, &current_length, 0, NULL,
    OSDP_SEC_SCS_16, 0, NULL);
  if (ctx->verbosity > 3)
  {
    fprintf(ctx->log, "failed to send keepactive (status %d)\n", status);
    fflush(ctx->log);
  };

  osdp_test_set_status(OOC_SYMBOL_cmd_keepactive, OCONFORM_EXERCISED);
  return(ST_OK);

} /* action_osdp_KEEPACTIVE */

