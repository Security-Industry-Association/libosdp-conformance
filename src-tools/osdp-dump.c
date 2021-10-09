/*
  osdp-dump - dumps argument as if it's an OSDP message hex dump

  command line interface version.

  (C)Copyright 2017-2018 Smithee Solutions LLC

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
OSDP_CONTEXT context;
unsigned char creds_buffer_a [64*1024];
int creds_buffer_a_lth;
int creds_buffer_a_next;
int creds_buffer_a_remaining;
OSDP_OUT_CMD current_output_command [16];
OSDP_BUFFER osdp_buf;
OSDP_INTEROP_ASSESSMENT osdp_conformance;
OSDP_PARAMETERS p_card;
char trace_in_buffer [1024];
char trace_out_buffer [1024];


void
  bytes_from_string
    (char *string,
    char *bytes,
    int *bytes_length);


int
  main
    (int argc,
    char *argv [])

{ /* main for dump-osdp */

  OSDP_CONTEXT *ctx;
  OSDP_MSG m;
  char osdp_message_bytes [1024];
  int osdp_message_length;
  OSDP_HDR returned_hdr;
  int status;


  status = ST_OK;
  ctx = &context;
  memset(ctx, 0, sizeof(*ctx));
  ctx->verbosity = 9;
  ctx->log = fopen("osdp-dump.log", "w");
  ctx->role = OSDP_ROLE_MONITOR;
  memset(&m, 0, sizeof(m));
  status = -1; // no args
  if (argc > 1)
  {
    status = -2; // gotta be at least one octet (2 hexits)
    if (strlen(argv[1]) > 1)
    {
      status = ST_OK;

      fprintf(ctx->log, "OSDP Raw Dump: %s\n", argv [1]);
      osdp_message_length = sizeof(osdp_message_bytes);
      bytes_from_string(argv [1], osdp_message_bytes, &osdp_message_length);
      m.ptr = (unsigned char *)osdp_message_bytes;
      m.lth = osdp_message_length;
      status = osdp_parse_message (ctx, OSDP_ROLE_MONITOR, &m, &returned_hdr);
      if (status EQUALS ST_OK)
        (void)monitor_osdp_message (ctx, &m);
    };
  };
  if (status != ST_OK)
    printf("dump-osdp: terminating with status %d.\n", status);

  return (0);

} /* main for dump-osdp */


int
  send_osdp_data
    (OSDP_CONTEXT *context,
    unsigned char *buf,
    int lth)
{ return (-1); }

void
  bytes_from_string
    (char *string,
    char *bytes,
    int *bytes_length)

{
  int byte;
  int done;
  int len;
  char *pdest;
  char *psource;


  done = 0;
  if (*bytes_length < 1)
    done = 1;
  if (!string)
    done = 1;
  if (!done)
  {
    len = strlen(string);
    if (0 != (len % 2))
      done = 1;
  };
  if (!done)
  {
    psource = string;
    pdest = bytes;
    *bytes_length = 0;
    while (!done && (len > 0))
    {
      char octet [3];
      octet [2] = 0;
      memcpy(octet, psource, 2);
      sscanf(octet, "%x", &byte);
      *pdest = 0xff & byte;
      (*bytes_length) ++;
      pdest++;
      len--; len--; psource++; psource++;
    };
  };
}

