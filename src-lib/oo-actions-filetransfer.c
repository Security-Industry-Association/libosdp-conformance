/*
  oo-actions-filetransfer - file transfer action routines

  (C)Copyright 2017-2024 Smithee Solutions LLC

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


#include <memory.h>


#include <open-osdp.h>
#include <osdp_conformance.h>


extern OSDP_PARAMETERS p_card;


int
  action_osdp_FILETRANSFER
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_FILETRANSFER */

  OSDP_HDR_FILETRANSFER *filetransfer_message;
  unsigned short int fragment_size;
  unsigned int offset;
  OSDP_HDR_FTSTAT response;
  int status;
  int status_io;
  unsigned char *transfer_fragment;


  status = ST_OK;
  filetransfer_message = (OSDP_HDR_FILETRANSFER *)(msg->data_payload);
  memset (&response, 0, sizeof(response));

  if (status EQUALS ST_OK)
    status = osdp_filetransfer_validate(ctx, filetransfer_message,
      &fragment_size, &offset);
if (0)
{
  (void)oosdp_make_message (OOSDP_MSG_FILETRANSFER, tlogmsg, msg);
  if (ctx->verbosity > 0)
  {
    fprintf(ctx->log, "%s\n", tlogmsg);
    fflush(ctx->log);
  };
};
// check FtType
// check FtFragmentSize sane

  if (status EQUALS ST_OK)
  {
    transfer_fragment = &(filetransfer_message->FtData);
    if (offset EQUALS 0)
    {
      ctx->xferctx.xferf = fopen("./incoming_data", "w");
      if (ctx->xferctx.xferf EQUALS NULL)
        status = ST_OSDP_BAD_TRANSFER_SAVE;
      if (status != ST_OK)
      {
        // if open of write file failed, send back error and reset

        osdp_doubleByte_to_array(OSDP_FTSTAT_ABORT_TRANSFER,
          response.FtStatusDetail);
        status = oo_send_ftstat(ctx, &response);
        (void) osdp_wrapup_filetransfer(ctx);
      };
    };
  };
  if (status EQUALS ST_OK)
  {
    status_io = fwrite(transfer_fragment, sizeof(transfer_fragment[0]),
      fragment_size, ctx->xferctx.xferf);
    if (status_io != fragment_size)
    {
      // not same error but need to abort so same status code on the wire

      osdp_doubleByte_to_array(OSDP_FTSTAT_ABORT_TRANSFER,
        response.FtStatusDetail);
      status = oo_send_ftstat(ctx, &response);
      if (ctx->verbosity > 3)
      {
        if (status != ST_OK)
          fprintf(ctx->log, "FTSTAT send for abort returned status %d.\n", status);
      };
      osdp_wrapup_filetransfer(ctx);
    }
    else
    {
      // update counters

      ctx->xferctx.current_offset = ctx->xferctx.current_offset + fragment_size;
      if (ctx->xferctx.current_offset EQUALS ctx->xferctx.total_length)
      {
        osdp_doubleByte_to_array(OSDP_FTSTAT_PROCESSED,
          response.FtStatusDetail);
        status = oo_send_ftstat(ctx, &response);
        if (ctx->verbosity > 3)
        {
          if (status != ST_OK)
            fprintf(ctx->log, "FTSTAT send at finish returned status %d.\n", status);
        };
        osdp_wrapup_filetransfer(ctx);
      }
      else
      {
        int offered_size;

        // offer an updated receive size.

        offered_size = oo_filetransfer_SDU_offer(ctx);

// was there to deal with buffer overflow issues.
#if 0
        if (offered_size > 500)
        {
          offered_size = 500;
fprintf(stderr, "DEBUG: trimmed offered size to %d.\n", offered_size);
        };
#endif

        // if there was a configured size, offer that
        if (ctx->pd_filetransfer_payload > 0)
        {
          offered_size = ctx->pd_filetransfer_payload;
fprintf(stderr, "DEBUG: trimmed offered size to  pd_filetransfer_payload (%d.)\n", offered_size);
        };
        if (ctx->verbosity > 3)
          fprintf(ctx->log, "osdp_FTSTAT FTMsgUpdateMax will be %d.\n", offered_size);

fprintf(stderr, "DEBUG: offered %d. (%X) as FtUpdateMsgMax\n", offered_size, offered_size);
        osdp_doubleByte_to_array(offered_size, response.FtUpdateMsgMax);

        fprintf(ctx->log, " Sending FTSTAT:Offset %d Total %d CurrentSDU %d OfferedSDU %d\n",
          ctx->xferctx.current_offset, ctx->xferctx.total_length, ctx->xferctx.current_send_length,
          offered_size);

        if (ctx->verbosity > 3)
        {
          fprintf(stderr, "current_offset : \"%d\n", ctx->xferctx.current_offset);
          fprintf(stderr, "total_length : %d\n", ctx->xferctx.total_length);
          fprintf(stderr, "current_send_length : %d\n", ctx->xferctx.current_send_length);
          fprintf(stderr, "response mmax %02x %02x\n",
            response.FtUpdateMsgMax [0], response.FtUpdateMsgMax [1]);
        };
        osdp_doubleByte_to_array(OSDP_FTSTAT_OK, response.FtStatusDetail);
        status = oo_send_ftstat(ctx, &response);
      };
    };
  };
  if (status != ST_OK)
  {
    // something bad happened.  abort.  But tell the caller we dealt with it.

    osdp_doubleByte_to_array(OSDP_FTSTAT_ABORT_TRANSFER,
      response.FtStatusDetail);
    status = oo_send_ftstat(ctx, &response);
    if (status EQUALS ST_OK)
      osdp_wrapup_filetransfer(ctx);

    status = ST_OK; // 'cause we recovered.
  };

  // update status json
  if (status EQUALS ST_OK)
    status = oo_write_status (ctx);
  return (status);

} /* action_osdp_FILETRANSFER */


/*
  action_osdp_FTSTAT - processing incoming osdp_FTSTAT message at ACU

  this causes the next chunk to be transferred, or terminates the transfer,
  or switches to "finishing" mode if the PD needs more time.
*/
int
  action_osdp_FTSTAT
    (OSDP_CONTEXT *ctx,
    OSDP_MSG *msg)

{ /* action_osdp_FTSTAT */

  OSDP_HDR_FTSTAT *ftstat_message;
  int status;


  status = ST_OK;
  osdp_test_set_status(OOC_SYMBOL_cmd_filetransfer, OCONFORM_EXERCISED);
  osdp_test_set_status(OOC_SYMBOL_resp_ftstat, OCONFORM_EXERCISED);
  ftstat_message = (OSDP_HDR_FTSTAT *)(msg->data_payload);

  status = osdp_ftstat_validate(ctx, ftstat_message);
  fprintf(ctx->log, "%s\n", tlogmsg); fflush(ctx->log);
  if (status EQUALS ST_OSDP_FILEXFER_FINISHING)
  {
    // the filetransfer context was already set to "finishing".
    // (and this is ok so reset the status)
    status = ST_OK;
  };
  if (status EQUALS ST_OSDP_FILEXFER_WRAPUP)
  {
    osdp_wrapup_filetransfer(ctx);
    status = ST_OK;
  }
  else
  {
    if (status EQUALS ST_OK)
    {
    // if more send more

    if (ctx->verbosity > 9)
      fprintf(stderr, "t=%d o=%d\n", ctx->xferctx.total_length, ctx->xferctx.current_offset);

    if ((ctx->xferctx.total_length > 0) && (ctx->xferctx.total_length > ctx->xferctx.current_offset))
    {
      status = osdp_send_filetransfer(ctx);
    };

      if ((ctx->xferctx.total_length EQUALS 0) || (ctx->xferctx.total_length EQUALS ctx->xferctx.current_offset))
      {
        fflush(ctx->log);
        osdp_wrapup_filetransfer(ctx);
      };
    };
  };
  if (status EQUALS ST_OSDP_FILEXFER_POLL_RESPONSE)
  {
    int current_length;

fprintf(stderr, "DEBUG: sending poll to address poll response\n");
    current_length = 0;
    status = send_message_ex(ctx, OSDP_POLL, p_card.addr, &current_length,
      0, NULL, OSDP_SEC_SCS_15, 0, NULL);
  };
  if (status EQUALS ST_OK)
    status = oo_write_status (ctx);
  return (status);

} /* action_osdp_FTSTAT */

