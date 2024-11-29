/*
  oosdp_files - osdp filetransfer management and io/

  (C)2017-2024 Smithee Solutions LLC

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
#include <time.h>
#include <sys/stat.h>
#include <errno.h>


#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>


extern OSDP_PARAMETERS p_card;


/*
  oo_filetransfer_initiate - start a file transfer operation in the ACU.

  details is from the command queue.
  first octet is file type
  2-nth octets are filename
*/
int
  oo_filetransfer_initiate
  (OSDP_CONTEXT *context,
  char *details)

{ /* oo_filetransfer_initiate */

  int current_length;
  OSDP_HDR_FILETRANSFER *file_transfer;
  int size_to_read;
  int status;
  int status_io;
  int transfer_send_size;
  static unsigned char xfer_buffer [OSDP_BUF_MAX];


  status = ST_OK;

  // find and open file

  strcpy(context->xferctx.filename, "./osdp_data_file");
  if (strlen (1+details) > 0)
    strcpy(context->xferctx.filename, 1+details);

  fprintf(context->log, "  File transfer: file %s\n",
    context->xferctx.filename);

  context->xferctx.xferf = fopen (context->xferctx.filename, "r");
  if (context->xferctx.xferf EQUALS NULL)
  {
    fprintf(context->log, "  local open failed, errno %d\n", errno);
          strcpy(context->xferctx.filename, "/opt/osdp-conformance/etc/osdp_data_file");
          context->xferctx.xferf = fopen (context->xferctx.filename, "r");
          if (context->xferctx.xferf EQUALS NULL)
          {
            fprintf(context->log, "SEND: data file not found (checked %s as last resort)\n",
              context->xferctx.filename);
            status = ST_OSDP_BAD_TRANSFER_FILE;
          }
          else 
            if (context->verbosity > 3)
              fprintf(stderr, "data file is /opt/osdp-conformance/etc/osdp_data_file\n");
        }
        else
        {
          if (context->verbosity > 3)
          {
            fprintf(context->log, "  File transfer: Data file is %s\n",
              context->xferctx.filename);
          };
        };

        if (status EQUALS ST_OK)
        {
          struct stat datafile_status;

          stat(context->xferctx.filename, &datafile_status);
          fprintf(context->log,
            "  FIle transfer: data file %s size %d.\n",
            context->xferctx.filename, (int)datafile_status.st_size);
          context->xferctx.total_length = datafile_status.st_size;
          context->xferctx.current_offset = 0; // should be set already but just in case.

          // set up the osdp_FILETRANSFER command.  structure uses 'xfer_buffer' as it's data area.

          memset (xfer_buffer, 0, sizeof(xfer_buffer));
          file_transfer = (OSDP_HDR_FILETRANSFER *)xfer_buffer;

          // file type is first octet of details.  save it in the context for later use.

          file_transfer->FtType = details [0];
          context->xferctx.file_transfer_type = file_transfer->FtType;

          // load data from file starting at msg->FtData

          if (context->pd_cap.rec_max > 0)
          {
            if (context->max_message EQUALS 0)
            {
              context->max_message = context->pd_cap.rec_max;
            };
          };
          if (context->max_message EQUALS 0)
          {
            context->max_message = 128;
            fprintf(stderr, "max message unset, setting it to 128\n");
            context->xferctx.current_send_length = context->max_message;
          };
          size_to_read = context->max_message;

          // wimp out and restrict transfer, got my math wrong somewhere...
          if (size_to_read > 1000)
          {
            fprintf(context->log, "Limiting filetransfer read size to %d (was %d)\n", 1000, size_to_read);
            size_to_read = 1000;
          };

          // adjust for header, crc, secure channel

          size_to_read = size_to_read - 6 - 2;

// if it's checksum use -1 not -2.

          if (context->secure_channel_use [OO_SCU_ENAB] EQUALS OO_SCS_OPERATIONAL)
            size_to_read = size_to_read - 2 - 4; //scs header, mac

          size_to_read = size_to_read + 1 - sizeof(OSDP_HDR_FILETRANSFER);
          if (context->verbosity > 3)
            fprintf(context->log, "Reading %d. from file to start.\n", size_to_read);
          memset(&(file_transfer->FtData), 0, size_to_read);
          status_io = fread (&(file_transfer->FtData), sizeof (unsigned char), size_to_read, context->xferctx.xferf);

          // if what's left is less than allowed size, adjust

          if (status_io < size_to_read)
            size_to_read = status_io;

          context->xferctx.total_sent = size_to_read;
          osdp_doubleByte_to_array(size_to_read, file_transfer->FtFragmentSize);
          osdp_quadByte_to_array(context->xferctx.total_length, file_transfer->FtSizeTotal);
          osdp_quadByte_to_array(context->xferctx.current_offset, file_transfer->FtOffset); 

          if (context->verbosity > 3)
            fprintf (stderr, "Initiating File Transfer\n");

    // send the first chunk.

    context->xferctx.state = OSDP_XFER_STATE_TRANSFERRING;
    current_length = 0;
    transfer_send_size = size_to_read;
    transfer_send_size = transfer_send_size - 1 + sizeof (*file_transfer);
    status = send_message_ex(context, OSDP_FILETRANSFER, p_card.addr, &current_length,
      transfer_send_size, (unsigned char *)file_transfer, OSDP_SEC_SCS_17, 0, NULL);

    // after the send update the current offset
    context->xferctx.current_offset = context->xferctx.current_offset + size_to_read;
  };
  return(status);

} /* oo_filetransfer_initiate */


int
  zoo_filetransfer_initate
    (OSDP_CONTEXT *context)

{ /* oo_filetransfer_initiate */

  int current_length;
  struct stat datafile_status;
  OSDP_HDR_FILETRANSFER *file_transfer;
  int size_to_read;
  int status;
  int status_io;
  int transfer_send_size;
  static unsigned char xfer_buffer [OSDP_BUF_MAX];


// context is set up, initiate file transfer.
// requires figuring out max SDU.

          stat(context->xferctx.filename, &datafile_status);
          fprintf(context->log,
            "  FIle transfer: data file %s size %d.\n",
            context->xferctx.filename, (int)datafile_status.st_size);
          context->xferctx.total_length = datafile_status.st_size;
          context->xferctx.current_offset = 0; // should be set already but just in case.

          memset (xfer_buffer, 0, sizeof(xfer_buffer));
          file_transfer = (OSDP_HDR_FILETRANSFER *)xfer_buffer;

          // load data from file starting at msg->FtData

          if (context->pd_cap.rec_max > 0)
          {
            if (context->max_message EQUALS 0)
            {
              context->max_message = context->pd_cap.rec_max;
            };
          };
          if (context->max_message EQUALS 0)
          {
            context->max_message = 128;
            fprintf(stderr, "max message unset, setting it to 128\n");
            context->xferctx.current_send_length = context->max_message;
          };
          size_to_read = context->max_message;

          // wimp out and restrict transfer, got my math wrong somewhere...
          if (size_to_read > 1000)
          {
            fprintf(context->log, "Limiting filetransfer read size to %d (was %d)\n", 1000, size_to_read);
            size_to_read = 1000;
          };

          // adjust for header, crc, secure channel

          size_to_read = size_to_read - 6 - 2;

// if it's checksum use -1 not -2.

          if (context->secure_channel_use [OO_SCU_ENAB] EQUALS OO_SCS_OPERATIONAL)
            size_to_read = size_to_read - 2 - 4; //scs header, mac

          size_to_read = size_to_read + 1 - sizeof(OSDP_HDR_FILETRANSFER);
          if (context->verbosity > 3)
            fprintf(context->log, "Reading %d. from file to start.\n", size_to_read);
          memset(&(file_transfer->FtData), 0, size_to_read);
          status_io = fread (&(file_transfer->FtData), sizeof (unsigned char), size_to_read, context->xferctx.xferf);

          // if what's left is less than allowed size, adjust

          if (status_io < size_to_read)
            size_to_read = status_io;

          file_transfer->FtType = context->xferctx.file_transfer_type;
          context->xferctx.total_sent = size_to_read;
          osdp_doubleByte_to_array(size_to_read, file_transfer->FtFragmentSize);
          osdp_quadByte_to_array(context->xferctx.total_length, file_transfer->FtSizeTotal);
          osdp_quadByte_to_array(context->xferctx.current_offset, file_transfer->FtOffset); 

          if (context->verbosity > 3)
            fprintf (stderr, "Initiating File Transfer\n");

          context->xferctx.state = OSDP_XFER_STATE_TRANSFERRING;
          current_length = 0;
          transfer_send_size = size_to_read;
          transfer_send_size = transfer_send_size - 1 + sizeof (*file_transfer);
fprintf(stderr, "xfer size %d.\n", transfer_send_size);
          status = send_message_ex(context, OSDP_FILETRANSFER, p_card.addr, &current_length,
            transfer_send_size, (unsigned char *)file_transfer,
          OSDP_SEC_SCS_17, 0, NULL);

          // after the send update the current offset
          context->xferctx.current_offset = context->xferctx.current_offset + size_to_read;

  return(status);

} /* oo_filetransfer_initiate */


int oo_filetransfer_SDU_offer
  (OSDP_CONTEXT *ctx)

{ /* oo_filetransfer_SDU_offer */

  int offered_size;


  offered_size = ctx->max_message;
  if (ctx->verbosity > 3)
    fprintf(ctx->log, "FTMsgUpdateMax-1 %d.\n", offered_size);
  if (ctx->verbosity > 3)
    fprintf(ctx->log, "FTMsgUpdateMax offered: %d.\n", offered_size);

  return(offered_size);

} /* oo_filetransfer_SDU_offer */


/*
  oo_send_ftstat - PD response sent during file transfer.

  May happen inside a secure channel in which case this is an SCS-18.
*/
int oo_send_ftstat
    (OSDP_CONTEXT *ctx,
    OSDP_HDR_FTSTAT *response)

{ /* oo_send_ftstat */

  int current_length;
  int status;
  int to_send;


  status = ST_OK;
  osdp_test_set_status(OOC_SYMBOL_cmd_filetransfer, OCONFORM_EXERCISED);
  osdp_test_set_status(OOC_SYMBOL_resp_ftstat, OCONFORM_EXERCISED);

  to_send = sizeof(*response);
  current_length = 0;
  if ((ctx->verbosity > 3) || (ctx->verbosity_override & VERBOSITY_OVERRIDE_1))
  {
    fprintf(ctx->log, "--sending FTSTAT FtAction %02X FtDelay %02X %02X FtStatusDetail %02X %02X FtUpdateMsgMax %02X %02X\n",
      response->FtAction, response->FtDelay [0], response->FtDelay [1],
      response->FtStatusDetail [0], response->FtStatusDetail [1],
      response->FtUpdateMsgMax [0], response->FtUpdateMsgMax [1]);
  };
  status = send_message_ex(ctx, OSDP_FTSTAT, p_card.addr,
    &current_length, to_send, (unsigned char *)response,
    OSDP_SEC_SCS_18, 0, NULL);
  return(status);

} /* oo_send_ftstat */


// function osdp_filetransfer_validate:
// validates values, returns counters explicitly and in context

int
  osdp_filetransfer_validate
    (OSDP_CONTEXT *ctx,
    OSDP_HDR_FILETRANSFER *ftmsg,
    unsigned short int *fragsize,
    unsigned int *offset)

{ /* osdp_filetransfer_validate */

  unsigned int total_length_claimed;
  int status;


  status = ST_OK;

  // ...extract values from message

  osdp_array_to_quadByte(ftmsg->FtSizeTotal, &total_length_claimed);
  osdp_array_to_quadByte(ftmsg->FtOffset, offset);
  osdp_array_to_doubleByte(ftmsg->FtFragmentSize, fragsize);

  // if there's a transfer in progress, a new one is bad.

  if (ctx->xferctx.total_length && (*offset EQUALS 0))
    status = ST_OSDP_FILEXFER_ALREADY;

  // message offset must match expected

  if (ctx->xferctx.current_offset != *offset)
    status = ST_OSDP_FILEXFER_SKIP;

  if (status EQUALS ST_OK)
  {
    // the message with offset zero gets to declare the total size.

    if (*offset EQUALS 0)
      ctx->xferctx.total_length = total_length_claimed;
  };

  return (status);

} /* osdp_filetransfer_validate */


/*
  osdp_ftstat_validate - validate fields in incoming osdp_FTSTAT msg

  also returns relevant status and updates filetransfer context.
*/
int
  osdp_ftstat_validate
    (OSDP_CONTEXT *ctx,
    OSDP_HDR_FTSTAT *ftstat)

{ /* osdp_ftstat_validate */

  unsigned long delay_nsec;
  unsigned long delay_sec;
  struct timespec delay_time;
  unsigned short int filetransfer_delay;
  unsigned short int filetransfer_status;
  unsigned short int new_size;
  int status;


  status = ST_OK;
  filetransfer_delay = 0;

  // if FtAction bad set status

  osdp_array_to_doubleByte(ftstat->FtStatusDetail, &filetransfer_status);

  filetransfer_delay = 0;
  osdp_array_to_doubleByte(ftstat->FtDelay, &filetransfer_delay);
  delay_sec = 0;
  delay_nsec = 0;

  /*
    per the spec, positive status numbers are advisory, negative mean
    the transfer should be terminated.  "finishing" state causes idle msgs.
  */
  switch (filetransfer_status)
  {
  case OSDP_FTSTAT_OK:

    // if it's ok and there's a delay then pause right here.


// DEBUG: fixme: MS_IN_NS blew up.  1000l*1000l maybe?

#define MS_IN_NS (1000*1000)
delay_nsec = filetransfer_delay;
delay_nsec = delay_nsec * 1000;
delay_nsec = delay_nsec * 1000;
//    delay_nsec = filetransfer_delay * MS_IN_NS;
    if (delay_nsec > 999999999)
    {
      delay_sec = delay_nsec/1000000000;
      delay_nsec = delay_nsec - (delay_sec * 1000000000);
    };
    if (filetransfer_delay > 0)
    {
      // delay likely at front and certainly not at the end.
      // can't use offset of 0 as it's been updated already for the first send

      osdp_test_set_status(OOC_SYMBOL_ftstat_dly_init, OCONFORM_EXERCISED);

      delay_time.tv_sec = delay_sec;
      delay_time.tv_nsec = delay_nsec;
      fprintf(ctx->log, "  Filetransfer: FTSTAT is `OK`, sleep delay %ld %ld\n", delay_time.tv_sec, delay_time.tv_nsec);
      (void) nanosleep(&delay_time, NULL);
    };

    // if there's something there treat it like a transfer in progress

    if (ctx->xferctx.total_length > 0)
    {
      // continue with transfer
      status = ST_OK;
      ctx->xferctx.state = OSDP_XFER_STATE_TRANSFERRING;
    };
    if (ctx->xferctx.total_sent EQUALS ctx->xferctx.total_length)
    {
      ctx->xferctx.state = OSDP_XFER_STATE_FINISHING;
      status = ST_OSDP_FILEXFER_WRAPUP;
      if (ctx->post_command_action EQUALS OO_POSTCOMMAND_SINGLESTEP)
        ctx->enable_poll = OO_POLL_NEVER;
    };

    // if there's nothing there treat it like we're finishing

    if (ctx->xferctx.total_length EQUALS 0)
    {
      status = ST_OSDP_FILEXFER_FINISHING;
      ctx->xferctx.state = OSDP_XFER_STATE_FINISHING;
    };
    break;

  case OSDP_FTSTAT_ABORT_TRANSFER:
    fprintf(ctx->log, "PD aborted transfer\n");
    // stop transfer if there is an error.
    status = ST_OSDP_FILEXFER_WRAPUP;
    break;

  case OSDP_FTSTAT_DATA_UNACCEPTABLE:
    fprintf(ctx->log, "PD reports 'data unacceptable'\n");
    // stop transfer if there is an error.
    status = ST_OSDP_FILEXFER_WRAPUP;
    break;

  case OSDP_FTSTAT_FINISHING:
    // wavelynx sends status 3 at the end
    status = ST_OSDP_FILEXFER_FINISHING;
    ctx->xferctx.state = OSDP_XFER_STATE_FINISHING;
    osdp_test_set_status(OOC_SYMBOL_ftstat_dly_final, OCONFORM_EXERCISED);
    break;

  case OSDP_FTSTAT_PROCESSED:
    fprintf(ctx->log, "FTSTAT Detail: %02x (\"processed\")\n", filetransfer_status);
    ctx->xferctx.state = OSDP_XFER_STATE_TRANSFERRING;

    if (ctx->xferctx.total_sent EQUALS ctx->xferctx.total_length)
    {
      ctx->xferctx.state = OSDP_XFER_STATE_FINISHING;
      status = ST_OSDP_FILEXFER_WRAPUP;
    };
    break;

  case OSDP_FTSTAT_REBOOTING:
    // gritty 'cause compiler objected.

    delay_nsec = filetransfer_delay;
    delay_nsec = delay_nsec * 1000;
    delay_nsec = delay_nsec * 1000;
    delay_time.tv_sec = delay_sec;
    delay_time.tv_nsec = delay_nsec;
    fprintf(ctx->log, "  Filetransfer: FTSTAT is `Rebooting`, sleep delay %ld %ld\n", delay_time.tv_sec, delay_time.tv_nsec);
    fprintf(ctx->log, "PD is rebooting.\n");
    (void) nanosleep(&delay_time, NULL);
    status = ST_OSDP_FILEXFER_WRAPUP;
    if (ctx->post_command_action EQUALS OO_POSTCOMMAND_SINGLESTEP)
    {
      fprintf(ctx->log, "--> Polling disabled by request <---\n");
      ctx->enable_poll = OO_POLL_NEVER;
    };
    break;

  case OSDP_FTSTAT_UNRECOGNIZED:
    fprintf(ctx->log, "PD did not recognize file\n");
    // stop transfer if there is an error.
    status = ST_OSDP_FILEXFER_WRAPUP;
    break;

  default:
    fprintf(ctx->log, "Unknown FTSTAT Detail: %d\n", filetransfer_status);
    // stop transfer if there is an error.
    status = ST_OSDP_FILEXFER_WRAPUP;
    break;
  };

  // if we transitioned out of "finishing" declare it wrapped up.

  if (filetransfer_status != OSDP_FTSTAT_FINISHING)
    if (ctx->xferctx.state EQUALS OSDP_XFER_STATE_FINISHING)
      status = ST_OSDP_FILEXFER_WRAPUP;

  if (status EQUALS ST_OK)
  {
    // update fragment size to send.

    osdp_array_to_doubleByte(ftstat->FtUpdateMsgMax, &new_size);
    if (new_size != 0)
    {
      ctx->xferctx.current_send_length = new_size;
      if (ctx->verbosity > 3)
        fprintf(ctx->log,  "DEBUG: updated send to %d.\n", ctx->xferctx.current_send_length);
    };
  };
  return (status);

} /* osdp_ftstat_validate */


/*
  osdp_wrapup_filetransfer - conclude processing of a file transfer.

  Note:
    this can get called from the FTSTAT or the last FILETRANSFER so it
    has to be benign about multiple calls.
*/
void
  osdp_wrapup_filetransfer
    (OSDP_CONTEXT *ctx)

{ /* osdp_wrapup_filetransfer */

  fflush(ctx->log);
  if (ctx->verbosity > 3)
    fprintf(stderr, "DEBUG: osdp_wrapup_filetransfer xferf %lx\n", (unsigned long)(ctx->xferctx.xferf));
  if (ctx->xferctx.xferf != NULL)
  {
    fclose(ctx->xferctx.xferf);
    fprintf(ctx->log, "closing transferred file\n");
    ctx->xferctx.xferf = NULL;
  };
  fprintf(ctx->log, "  File transfer: finished, total length was %d.\n",
    ctx->xferctx.total_length);
  ctx->xferctx.current_offset = 0;
  ctx->xferctx.total_length = 0;

} /* osdp_wrapup_filetransfer */


int
  oo_load_parameters
    (OSDP_CONTEXT *ctx,
    char *filename)

{ /* oo_load_parameters */

  char new_key [1024];
  unsigned short new_key_length;
  json_t *saved_parameters_root;
  int status;
  json_error_t status_json;
  json_t *value;


  if (ctx->verbosity > 3)
    fprintf(ctx->log, "Loading parameters from %s\n", filename);
  saved_parameters_root = json_load_file(filename, 0, &status_json);

  value = json_object_get(saved_parameters_root, "key");
  if (json_is_string (value))
  {
    strcpy(new_key, json_string_value(value));
fprintf(ctx->log, "restoring key %s\n", new_key);
    new_key_length = sizeof(ctx->current_scbk);
    status = osdp_string_to_buffer(ctx,
      new_key, ctx->current_scbk, &new_key_length);
    if (status EQUALS ST_OK)
    {
      fprintf(ctx->log, "Saved key %s loaded.\n", new_key);
      ctx->secure_channel_use [OO_SCU_KEYED] = OO_SECPOL_KEYLOADED;
    }
    else
    {
      fprintf(ctx->log, "failed to load key from saved parameters\n");
    };
  };

  value = json_object_get(saved_parameters_root, "serial-speed");
  if (json_is_string(value))
  {
    if (ctx->verbosity > 3)
      fprintf(stderr, "DEBUG: restored speed would be %s\n", json_string_value(value));
  };
  value = json_object_get(saved_parameters_root, "pd-address");
  if (json_is_string(value))
  {
    if (ctx->verbosity > 3)
      fprintf(stderr, "DEBUG: restored PD address would be %s\n", json_string_value(value));
  };

  // also load saved credentials.
  saved_parameters_root = json_load_file("osdp-saved-credentials.json", 0, &status_json);

  value = json_object_get(saved_parameters_root, "bio-format");
  if (json_is_string (value))
  {
    int i;
    sscanf(json_string_value(value), "%x", &i);
    ctx->saved_bio_format = i;
  };

  value = json_object_get(saved_parameters_root, "bio-template");
  if (json_is_string (value))
  {
    strcpy(ctx->saved_bio_template, json_string_value(value));
  };

  value = json_object_get(saved_parameters_root, "bio-type");
  if (json_is_string (value))
  {
    int i;
    sscanf(json_string_value(value), "%x", &i);
    ctx->saved_bio_type = i;
  };

  value = json_object_get(saved_parameters_root, "bio-quality");
  if (json_is_string (value))
  {
    int i;
    sscanf(json_string_value(value), "%x", &i);
    ctx->saved_bio_quality = i;
  };

  return(ST_OK);

} /* oo_load_parameters */


/*
  oo_save_parameters -- saves parameters from PD's view

  saves current_scbk unless scbk is specified
*/

int
  oo_save_parameters
    (OSDP_CONTEXT *ctx,
    char *filename,
    unsigned char *scbk)

{ /* oo_save_parameters */

  int i;
  FILE *pf;
  unsigned char scbk_to_save [OSDP_KEY_OCTETS];


  if (scbk)
    memcpy(scbk_to_save, scbk, sizeof(scbk_to_save));
  else
    memcpy(scbk_to_save, ctx->current_scbk, sizeof(scbk_to_save));
  dump_buffer_log(ctx, (char *)"SCBK to be saved:",
   scbk_to_save, OSDP_KEY_OCTETS);
  pf = fopen(filename, "w");
  if (pf != NULL)
  {
    fprintf(pf, "{\n  \"#\" : \"saved OSDP parameters\",\n");

    fprintf(pf, "  \"key\" : \"");
    for (i=0; i<OSDP_KEY_OCTETS; i++)
    {
      fprintf(pf, "%02x", scbk_to_save [i]);
    };

    fprintf(pf, "\",\n  \"serial-speed\" : \"%s\",\n", ctx->serial_speed);
    fprintf(pf, "  \"pd-address\" : \"%X\",\n", ctx->pd_address);

    fprintf(pf, "\n  \"_#\" : \"-\"\n");
    fprintf(pf, "}\n");
    fclose(pf);
  };
  return(ST_OK);

} /* oo_save_parameters */


int
  osdp_send_filetransfer
    (OSDP_CONTEXT *ctx)

{ /* osdp_send_filetransfer */

  int current_length;
  OSDP_HDR_FILETRANSFER *ft;
  int size_to_read;
  int status;
  int status_io;
  int transfer_send_size;
  unsigned char xfer_buffer [OSDP_BUF_MAX];


  status = ST_OK;

  if (ctx->verbosity > 3)
    fprintf (stderr, "File Transfer Offset %d. Length %d Max %d\n",
      ctx->xferctx.current_offset, ctx->xferctx.current_send_length,
      ctx->xferctx.total_length);
  if (status EQUALS ST_OK)
  {
    memset (xfer_buffer, 0, sizeof(xfer_buffer));
    ft = (OSDP_HDR_FILETRANSFER *)xfer_buffer;

    // if we're finishing up send a benign message
    // L=0 Off=whole-size Tot=whole-size
    if (ctx->xferctx.state EQUALS OSDP_XFER_STATE_FINISHING)
    {
      transfer_send_size = 1 + sizeof(*ft); // just sending a header
      memset(ft, 0, sizeof(*ft));
      osdp_quadByte_to_array(ctx->xferctx.total_length, ft->FtSizeTotal);
      ft->FtType = ctx->xferctx.file_transfer_type;
      osdp_quadByte_to_array(ctx->xferctx.total_length, ft->FtOffset);
      current_length = 0;
      status = send_message (ctx,
        OSDP_FILETRANSFER, p_card.addr, &current_length,
        transfer_send_size, (unsigned char *)ft);
    }
    else
    {
      // load data from file starting at msg->FtData

      if (ctx->verbosity > 3)
      {
        fprintf(stderr, "DEBUG: osdp_send_filetransfer: current_send_length %d(%X) ctx->max_message %d.\n",
          ctx->xferctx.current_send_length, ctx->xferctx.current_send_length, ctx->max_message);
      };
      if (ctx->xferctx.current_send_length)
      {
        size_to_read = ctx->xferctx.current_send_length;
        //fprintf(stderr, "DEBUG: size to read %d.\n", ctx->xferctx.current_send_length);
      }
      else
      {
        size_to_read = ctx->max_message;
      };

if (0)
{
    // adjust for header, crc
    size_to_read = size_to_read - 6 - 2;
// if it's checksum use -1 not -2.

    if (ctx->secure_channel_use [OO_SCU_ENAB] EQUALS OO_SCS_OPERATIONAL)
      size_to_read = size_to_read - 2 - 4; //scs header, mac

    size_to_read = size_to_read + 1 - sizeof(OSDP_HDR_FILETRANSFER);
};
    status_io = fread (&(ft->FtData), sizeof (unsigned char), size_to_read,
      ctx->xferctx.xferf);
    if (status_io > 0)
      size_to_read = status_io;
    if (status_io <= 0)
      status = ST_OSDP_FILEXFER_READ;

    if (status EQUALS ST_OK)
    {

      // update what we've sent

      ctx->xferctx.total_sent = ctx->xferctx.total_sent + size_to_read;

      // load data length into FtSizeTotal (little-endian)
      osdp_quadByte_to_array(ctx->xferctx.total_length, ft->FtSizeTotal);

      ft->FtType = ctx->xferctx.file_transfer_type;

      osdp_doubleByte_to_array(size_to_read, ft->FtFragmentSize);
      osdp_quadByte_to_array(ctx->xferctx.current_offset, ft->FtOffset);

      transfer_send_size = size_to_read;
      transfer_send_size = transfer_send_size - 1 + sizeof (*ft);
      current_length = 0;
      if (ctx->verbosity > 3)
        fprintf(ctx->log, "osdp_FILETRANSFER: sending %d. bytes\n", transfer_send_size);
      status = send_message_ex(ctx, OSDP_FILETRANSFER, p_card.addr, &current_length,
        transfer_send_size, (unsigned char *)ft,
        OSDP_SEC_SCS_17, 0, NULL);

      // after the send update the current offset
      ctx->xferctx.current_offset = ctx->xferctx.current_offset + size_to_read;

      // we're transferring.  set the state to show that
      ctx->xferctx.state = OSDP_XFER_STATE_TRANSFERRING;
    };
    }; // end else real filetransfer
  };
  return (status);

} /* osdp_send_filetransfer */


int
  oo_write_status
    (OSDP_CONTEXT
      *ctx)

{ /* write_status */

  char current_date_string [1024];
  time_t current_time;
  int i;
  int j;
  extern OSDP_INTEROP_ASSESSMENT osdp_conformance;
  extern OSDP_BUFFER osdp_buf;
  FILE *sf;
  char statfile [3072];
  int status;
  char tag [1024];
  char val [1024];


  status = ST_OK;

  // clear logs if possible
  fflush(ctx->log);

  if (ctx->role EQUALS OSDP_ROLE_PD)
    strcpy (tag, "PD");
  if (ctx->role EQUALS OSDP_ROLE_ACU)
    strcpy (tag, "ACU");
  if (ctx->role EQUALS OSDP_ROLE_MONITOR)
    strcpy (tag, "MON");
  sprintf (statfile, OSDP_STAT_FILE);
  sf = fopen (statfile, "w");
  if (sf != NULL)
  {
    current_time = time (NULL);
    strcpy (current_date_string, asctime (localtime (&current_time)));
    current_date_string [strlen (current_date_string)-1] = 0;

    fprintf(sf, "{");
    fprintf(sf, "\"mmt\" : \"%d\",", osdp_conformance.conforming_messages);
    fprintf(sf, "\"retries\" : \"%d\",", ctx->retries);
    fprintf(sf, "\"role\" : \"%d\",", ctx->role);
    if (strlen (ctx->text) > 0)
      fprintf(sf,"\"text\" : \"%s\",", ctx->text);

    fprintf(sf, " \"key-slot\" : \"%d\", ", ctx->current_key_slot);
    fprintf(sf, " \"scbk\" : \"");
    for (i=0; i<OSDP_KEY_OCTETS; i++)
      fprintf(sf, "%02x", ctx->current_scbk [i]);
    fprintf(sf, "\",\n");
    fprintf (sf,
"\"serial-speed\" : \"%s\",",
      ctx->serial_speed);
    fprintf (sf,
"\"pd-address\" : \"%02x\",\n",
      p_card.addr);
    fprintf(sf,
"\"max_pd_send\" : \"%d\",\n",
      ctx->max_message);
    fprintf(sf,
"\"dropped\" : \"%d\",\"octets-received\":\"%d\",\"octets-sent\":\"%d\",",
      ctx->dropped_octets, ctx->bytes_received, ctx->bytes_sent);
    fprintf(sf, "\"seq-bad\" : \"%d\",", ctx->seq_bad);
    fprintf (sf,
"\"crc_errs\" : \"%d\",", ctx->crc_errs);
    fprintf (sf,
"\"checksum_errs\" : \"%d\",", ctx->checksum_errs);
    fprintf(sf,
"\"buffer-overflows\" : \"%d\",\n",
      osdp_buf.overflow);
    for (j=0; j<OSDP_MAX_LED; j++)
    {
      if (ctx->led [j].state EQUALS OSDP_LED_ACTIVATED)
        fprintf (sf,
                 "     \"led_color_%02d\" : \"#%06x\",\n",
        j, ctx->led [j].web_color);
    };
    fprintf(sf,  " \"Receive-BufferSize\" : \"%d\",\n",
      ctx->pd_cap.rec_max);
    for (j=0; j<OSDP_MAX_OUT; j++)
    {
      fprintf (sf,
        " \"out-%02d\" : \"%d\",",
        j, ctx->out [j].current);
    };
    fprintf(sf, "\n");
    fprintf (sf,
"\"verbosity\" : \"%d\", \"trace\" : \"%d\",  ",
      ctx->verbosity, ctx->trace);
    fprintf (sf, "\"power-report\" : \"%d\", ",
      ctx->power_report);
    fprintf (sf, "\"crc-mode\" : \"%d\", ",
      m_check);
    fprintf (sf,
"\"timeout\" : \"%ld\", ",
      ctx->timer[0].i_sec);
//    fprintf (sf, " \"poll\" : \"%d\",\n", p_card.poll);

    // copy in the keyboard "buffer"

    fprintf (sf,
"    \"keypad_last_8\" : \"%02x%02x-%02x%02x-%02x%02x-%02x%02x\",\n",
      ctx->last_keyboard_data [0], ctx->last_keyboard_data [1],
      ctx->last_keyboard_data [2], ctx->last_keyboard_data [3],
      ctx->last_keyboard_data [4], ctx->last_keyboard_data [5],
      ctx->last_keyboard_data [6], ctx->last_keyboard_data [7]);

    // copy in all the octets holding the bits.

    memset (val, 0, sizeof (val));
    fprintf (sf, "  \"raw_data_bits\" : \"%d\",\n",
      ctx->last_raw_read_bits);

    fprintf(sf, "\"current_offset\" : \"%d\",\n", ctx->xferctx.current_offset);
    fprintf(sf, "\"current_send_length\" : \"%d\",\n", ctx->xferctx.current_send_length);
    fprintf(sf, "\"last_update_timeT\" : \"%ld\",\n", current_time);
    for (i=0; i<(7+ctx->last_raw_read_bits)/8; i++)
    {
      sprintf (val+(2*i), "%02x", ctx->last_raw_read_data [i]);
    };
    fprintf(sf, "\"raw_data\" : \"%s\",\n", val);
    fprintf(sf, "\"serial_number\":\"%02X%02X%02X%02X\",\n",
      ctx->serial_number [0], ctx->serial_number [1], ctx->serial_number [2], ctx->serial_number [3]);
    fprintf(sf, "\"total_length\" : \"%d\",\n", ctx->xferctx.total_length);

    fprintf(sf,
" \"acu-polls\" : \"%d\",", ctx->acu_polls);
    fprintf(sf, 
" \"pd-acks\" : \"%d\",", ctx->pd_acks);
    fprintf(sf,
" \"pdus-received\" : \"%d\", \"pdus-sent\" : \"%d\",\n",
      ctx->pdus_received, ctx->pdus_sent);
    fprintf(sf,
" \"last_update\" : \"%s\",", current_date_string);
    fprintf(sf, "\n");
    fprintf(sf,
" \"pd-naks\" : \"%d\",", ctx->sent_naks);
    fprintf (sf,
"\"hash-ok\" : \"%d\", \"hash-bad\" : \"%d\",\n", ctx->hash_ok, ctx->hash_bad);
    fprintf(sf, "\"_#\" : \"_end\" ");
    fprintf(sf, "}\n");

    fclose (sf);
  }
  else
  {
    fprintf(ctx->log, "Error writing to %s\n", statfile);
  };
  return (status);

} /* oo_write_status */

