/*
  oosdp_files - osdp file io/

  (C)2017-2020 Smithee Solutions LLC
  (C)2016 Smithee Spelvin Agnew & Plinge, Inc.

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


#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>


extern OSDP_PARAMETERS p_card;


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

  unsigned short int filetransfer_delay;
  unsigned short int filetransfer_status;
  unsigned short int new_size;
  int status;


  status = ST_OK;

  // if FtAction bad set status

  osdp_array_to_doubleByte(ftstat->FtStatusDetail, &filetransfer_status);

  filetransfer_delay = 0;
  osdp_array_to_doubleByte(ftstat->FtDelay, &filetransfer_delay);

  /*
    per the spec, positive status numbers are advisory, negative mean
    the transfer should be terminated.  "finishing" state causes idle msgs.
  */
  switch (filetransfer_status)
  {
  case OSDP_FTSTAT_OK:
    // continue with transfer
    status = ST_OK;
    ctx->xferctx.state = OSDP_XFER_STATE_TRANSFERRING;
    break;

  case OSDP_FTSTAT_FINISHING:
// wavelynx sends status 3 at the end
    status = ST_OSDP_FILEXFER_FINISHING;
    ctx->xferctx.state = OSDP_XFER_STATE_FINISHING;
    break;

  case OSDP_FTSTAT_PROCESSED:
    fprintf(stderr, "FTSTAT Detail: %02x (\"processed\")\n", filetransfer_status);
    ctx->xferctx.state = OSDP_XFER_STATE_TRANSFERRING;
    break;

  default:
    status = ST_OSDP_FILEXFER_ERROR;
    fprintf(stderr, "FTSTAT Detail: %02x\n", filetransfer_status);
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
      ctx->xferctx.current_send_length = new_size;
  };
  return (status);

} /* osdp_ftstat_validate */


void
  osdp_wrapup_filetransfer
    (OSDP_CONTEXT *ctx)

{ /* osdp_wrapup_filetransfer */

  fclose(ctx->xferctx.xferf);
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
      ctx->secure_channel_use [OO_SCU_KEYED] = OO_SECPOL_KEYLOADED;
    else
    {
      fprintf(ctx->log, "failed to load key from saved parameters\n");
    };
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

    fprintf(pf, "\",\n  \"serial-speed\" : \"%s\",\n",
      ctx->serial_speed);

    fprintf(pf, "\n  \"_#\" : \"-\"\n");
    fprintf(pf, "}\n");
    fclose(pf);
  };
  return(ST_OK);

} /* oo_save_parameters */


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
  char statfile [2*1024];
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
  sprintf (statfile, "/opt/osdp-conformance/run/%s/osdp-status.json",
    tag);
  if (ctx->verbosity > 9)
  {
    fprintf(stderr, "Writing status to %s\n", statfile);
  };
  sf = fopen (statfile, "w");
  if (sf != NULL)
  {
    current_time = time (NULL);
    strcpy (current_date_string, asctime (localtime (&current_time)));
    current_date_string [strlen (current_date_string)-1] = 0;
    fprintf (sf, "{");
    fprintf (sf,
"\"last_update\" : \"%s\",\n",
      current_date_string);
    fprintf(sf, " \"mmt\" : \"%d\",", osdp_conformance.conforming_messages);
    if (strlen (ctx->text) > 0)
    fprintf (sf,
"\"text\" : \"%s\",",
        ctx->text);
    fprintf (sf,
"\"role\" : \"%d\",\n",
      ctx->role);
    fprintf(sf, " \"key-slot\" : \"%d\", ", ctx->current_key_slot);
    fprintf(sf, " \"scbk\" : \"");
    for (i=0; i<OSDP_KEY_OCTETS; i++)
      fprintf(sf, "%02x", ctx->current_scbk [i]);
    fprintf(sf, "\",\n");
    fprintf (sf,
"\"serial_speed\" : \"%s\",",
      ctx->serial_speed);
    fprintf (sf,
"\"pd_address\" : \"%02x\",\n",
      p_card.addr);
    fprintf(sf,
"\"max_pd_send\" : \"%d\",\n",
      ctx->max_message);
    fprintf(sf, "\"acu-polls\" : \"%d\",", ctx->acu_polls);
    fprintf(sf, " \"pd-acks\" : \"%d\",", ctx->pd_acks);
    fprintf(sf, " \"pdus-received\" : \"%d\", \"pdus-sent\" : \"%d\",\n",
      ctx->pdus_received, ctx->pdus_sent);
    fprintf(sf,
"\"pd-naks\" : \"%d\",", ctx->sent_naks);
    fprintf(sf,
"\"seq-bad\" : \"%d\",", ctx->seq_bad);
    fprintf (sf,
"\"hash-ok\" : \"%d\", \"hash-bad\" : \"%d\",\n", ctx->hash_ok, ctx->hash_bad);
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
    fprintf (sf,
" \"poll\" : \"%d\",\n",
      p_card.poll);

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
    for (i=0; i<(7+ctx->last_raw_read_bits)/8; i++)
    {
      sprintf (val+(2*i), "%02x", ctx->last_raw_read_data [i]);
    };
    fprintf (sf, "  \"raw_data\" : \"%s\",\n",
      val);

    fprintf(sf,
" \"current_offset\" : \"%d\", ",
      ctx->xferctx.current_offset);
    fprintf(sf,
"\"total_length\" : \"%d\", ",
      ctx->xferctx.total_length);
    fprintf(sf,
"\"current_send_length\" : \"%d\", ",
      ctx->xferctx.current_send_length);

    fprintf(sf,
"\"last_update_timeT\" : \"%ld\", ", current_time);

    fprintf(sf, "\"_#\" : \"_end\" ");
    fprintf (sf, "}\n");

    fclose (sf);
  }
  else
  {
    fprintf(ctx->log, "Error writing to %s\n", statfile);
  };
  return (status);

} /* oo_write_status */

