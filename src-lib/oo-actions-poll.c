/*
  oo-actions - open osdp action routines

  (C)Copyright 2017-2026 Smithee Solutions LLC

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
#include <unistd.h>


#include <aes.h>


#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>


// used for responses to osdp_POLL

extern OSDP_RESPONSE_QUEUE_ENTRY osdp_response_queue [8];
extern int osdp_response_queue_size;
unsigned char pending_response_data [1500];
int pending_response_length;
unsigned char pending_response;


int
  action_osdp_POLL
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_POLL */

  int current_length;
  int done;
  unsigned char osdp_lstat_response_data [2];
  unsigned char osdp_raw_data [4+1024];
  int raw_lth;
  unsigned char response_directive;
  int status;


  status = ST_OK;
  done = 0;
  response_directive = OSDP_ACK;

  // i.e. we GOT a poll
  osdp_test_set_status(OOC_SYMBOL_cmd_poll, OCONFORM_EXERCISED);

  /*
    poll response can be many things.  we do one and then return, which
    can cause some turn-the-crank artifacts.  may need multiple polls for
    expected behaviors to happen.
  */
  if (!done)
  {
    if (pending_response_length > 0)
    {
      done = 1;
      current_length = 0;
      status = send_message_ex (ctx,
        pending_response, ctx->pd_address, &current_length,
        pending_response_length, pending_response_data,
        OSDP_SEC_NOT_SCS, 0, NULL);
      pending_response_length = 0;
    };
  };

  // return BUSY if requested

  if (!done)
  {
    if (ctx->next_response EQUALS OSDP_BUSY)
    {
      ctx->next_response = 0;
      done = 1;
      current_length = 0;
      status = send_message_ex (ctx,
        OSDP_BUSY, ctx->pd_address, &current_length,
        0, NULL, OSDP_SEC_NOT_SCS, 0, NULL);
      SET_PASS (ctx, "4-16-1");
      if (ctx->verbosity > 2)
      {
        sprintf (tlogmsg, "Responding with osdp_BUSY");
        fprintf (ctx->log, "%s\n", tlogmsg);
      };
    };
  };

  // if there was an input status requested return that.

  if ((!done) && (ctx->next_istatr EQUALS 1))
  {
    int input_length;
    unsigned char osdp_istat_response_data [OOSDP_DEFAULT_INPUTS];


    memcpy(osdp_istat_response_data, ctx->in_state, OOSDP_DEFAULT_INPUTS);
    input_length = ctx->configured_inputs;
    osdp_test_set_status(OOC_SYMBOL_resp_istatr, OCONFORM_EXERCISED);

    current_length = 0;
    status = send_message_ex(ctx, OSDP_ISTATR, ctx->pd_address,
      &current_length, input_length, osdp_istat_response_data, OSDP_SEC_SCS_18, 0, NULL);
    ctx->xferctx.ft_action = 0; // if were an interleaved poll response clear that.
    ctx->next_istatr = 0;
    done = 1;
  };

  if ((!done) && (ctx->next_huge EQUALS 1))
  {
    // if a large response test was requested send that
    unsigned char value [2048];

    memset (value, 0, sizeof(value));
    current_length = 0;
    status = send_message_ex(ctx, OSDP_ISTATR, ctx->pd_address, &current_length, 1300, value, OSDP_SEC_SCS_17, 0, NULL);
    done = 1;
  };

  // if there was a power report or tamper return that.

  if ((!done) && ((ctx->power_report EQUALS 1) || (ctx->tamper)))
  {
    char details [1024];
    done = 1;

    details [0] = 0;
    if (ctx->tamper)
    {
      strcat(details, "Tamper");
      osdp_test_set_status(OOC_SYMBOL_resp_lstatr_tamper, OCONFORM_EXERCISED);

      osdp_test_set_status(OOC_SYMBOL_poll_lstatr, OCONFORM_EXERCISED);
    };
    if (ctx->power_report)
    {
      if (strlen(details) > 0)
        strcat(details, " ");
      strcat(details, "Power");
      osdp_test_set_status(OOC_SYMBOL_resp_lstatr_power, OCONFORM_EXERCISED);

      // and that's an lstatr response to a poll, too.

      osdp_test_set_status(OOC_SYMBOL_poll_lstatr, OCONFORM_EXERCISED);
    };
    osdp_lstat_response_data [ 0] = ctx->tamper;
    osdp_lstat_response_data [ 1] = ctx->power_report;

    // clear tamper and power now reported
    ctx->tamper = 0;
    ctx->power_report = 0;

    current_length = 0;
    status = send_message_ex (ctx,
      OSDP_LSTATR, ctx->pd_address, &current_length,
      sizeof (osdp_lstat_response_data), osdp_lstat_response_data,
      OSDP_SEC_NOT_SCS, 0, NULL);
    ctx->xferctx.ft_action = 0; // if were an interleaved poll response clear that.
    if (ctx->verbosity > 2)
    {
      sprintf (tlogmsg, "Responding with OSDP_LSTATR (%s)", details);
      fprintf (ctx->log, "%s\n", tlogmsg);
    };
  }

  // send an on-demand LSTATR (to clear tamper)

  if (!done)
  {
    if (ctx->next_response EQUALS OSDP_LSTATR)
    {
      ctx->next_response = 0;
      done = 1;
      osdp_lstat_response_data [ 0] = ctx->tamper;
      osdp_lstat_response_data [ 1] = ctx->power_report;

      current_length = 0;
      status = send_message_ex (ctx, OSDP_LSTATR, ctx->pd_address, &current_length,
        sizeof (osdp_lstat_response_data), osdp_lstat_response_data, OSDP_SEC_NOT_SCS, 0, NULL);
      if (ctx->verbosity > 2)
      {
        sprintf (tlogmsg, "Responding with on-demand osdp_LSTATR (T=%d P=%d)", ctx->tamper, ctx->power_report);
        fprintf (ctx->log, "%s\n", tlogmsg);
      };
    };
  };

  // if there's card data to return, do that.

  if (!done)
  {
    if (ctx->xferctx.total_length > 0)
    {
      if (ctx->xferctx.ft_action & OSDP_FTACTION_POLL_RESPONSE)
      {
        ctx->card_data_valid = osdp_response_queue [0].details_param_1;
        ctx->creds_a_avail = osdp_response_queue [0].details_length;
        memcpy(ctx->credentials_data, osdp_response_queue [0].details, osdp_response_queue [0].details_length);
        osdp_response_queue_size = 0;
      };
    };

    /*
      the presence of card data to return is indicated because either the
      "raw" buffer or the "big" buffer is marked as non-empty when you get here.
    */
    if (ctx->card_data_valid > 0)
    {
      done = 1;
      // send data if it's there (value is number of bits)

      // osdp_RAW is reader, format, countHigh, countLow, data

      osdp_raw_data [ 0] = 0; // one reader, reader 0
      osdp_raw_data [ 1] = ctx->card_format; 
      osdp_raw_data [ 2] = (0xff & ctx->card_data_valid);
      osdp_raw_data [ 3] = (0xff00 & ctx->card_data_valid) >> 8;
      raw_lth = 4+ctx->creds_a_avail;
      memcpy (osdp_raw_data+4, ctx->credentials_data, ctx->creds_a_avail);
      current_length = 0;

      dump_buffer_log(ctx, "card data", (unsigned char *)(ctx->credentials_data), ctx->creds_a_avail);
      status = send_message_ex (ctx,
        OSDP_RAW, ctx->pd_address, &current_length, raw_lth, osdp_raw_data,
        OSDP_SEC_SCS_18, 0, NULL);
      ctx->xferctx.ft_action = 0; // if were an interleaved poll response clear that.
      osdp_test_set_status(OOC_SYMBOL_rep_raw, OCONFORM_EXERCISED);
      if (ctx->verbosity > 2)
      {
        sprintf (tlogmsg, "Responding with cardholder data (%d bits)",
          ctx->card_data_valid);
        fprintf (ctx->log, "%s\n", tlogmsg);
      };
      ctx->card_data_valid = 0;
    };
  };
  response_directive = OSDP_ACK;
  if (ctx->next_response_bad)
  {
    fprintf(ctx->log, "*** BAD RESPONSE INDUCED ***\n");
    response_directive = OSDP_BOGUS;
    ctx->next_response_bad = 0;
  };
  /*
    if all else isn't interesting return a plain ack
  */
  if (!done)
  {
    current_length = 0;
    status = send_message_ex
      (ctx, response_directive, ctx->pd_address, &current_length, 0, NULL,
      OSDP_SEC_SCS_16, 0, NULL);
    osdp_test_set_status(OOC_SYMBOL_cmd_poll, OCONFORM_EXERCISED);
    osdp_test_set_status(OOC_SYMBOL_rep_ack, OCONFORM_EXERCISED);
    if (ctx->verbosity > 9)
    {
      sprintf (tlogmsg, "Responding with OSDP_ACK");
      fprintf (ctx->log, "%s\n", tlogmsg);
    };
  };

  // update status json.  perhaps every single poll is too often.
  // TODO add another timer, do this perhaps once a second.
  // for now kludge it and only do it if in verbose mode

  if (status EQUALS ST_OK)
    if (ctx->verbosity > 3)
      status = oo_write_status (ctx);

  return (status);

} /* action_osdp_POLL */

