/*
  oo-callout - call out to a shell command when certain commands and responses arrive

  (C)Copyright 2021-2022 Smithee Solutions LLC

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


//#include <stdio.h>
//#include <string.h>
//#include <stdlib.h>


#include <open-osdp.h>
//#include <iec-xwrite.h>
//extern OSDP_PARAMETERS p_card;


int
  oosdp_callout
    (OSDP_CONTEXT *ctx,
    char *action_command,
    char *details)

{ /* oosdp_callout */

  char command [3*1024]; // three 'cause there are three args to the command sprintf
  int status;


  status = ST_OK;
  sprintf(command, "%s/ACU-actions/%s %02X %s", ctx->service_root, action_command, ctx->pd_address, details);
  if (ctx->verbosity > 3)
  {
    fprintf(ctx->log, "action: %s\n", command);
  };
  fflush(ctx->log);
  system(command);
  return(status);

} /* oosdp_callout */

