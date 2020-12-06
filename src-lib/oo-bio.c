/*
  oo-bio - biometrics routines

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
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>


#include <jansson.h>


#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>


int
  send_bio_read_template
    (OSDP_CONTEXT
      *ctx)

{ /* send_bio_read_template */

  int current_length;
  unsigned char param [4];
  int status;


  param [0] = 0; // reader 0
  param [1] = 0; // default bio type
  param [2] = 2; // ANSI/INCITS 378 Fingerprint template "49"
  param [3] = 0xFF; // quality

  current_length = 0;
  if (ctx->verbosity > 2)
    fprintf (ctx->log, "bioread sent\n");
  status = send_message_ex(ctx, OSDP_BIOREAD, ctx->pd_address,
     &current_length, sizeof(param), param, OSDP_SEC_SCS_17, 0, NULL);
  return (status);

} /* send_bio_read_template */

