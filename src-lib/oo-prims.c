/*
  (C)Copyright 2017-2022 Smithee Solutions LLC
*/
#include <stdio.h>
#include <string.h>
//#include <time.h>

#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>
extern OSDP_INTEROP_ASSESSMENT osdp_conformance;
extern OSDP_PARAMETERS p_card;
extern OSDP_BUFFER osdp_buf;


void
  dump_buffer_stderr
    (char * tag, unsigned char *b, int l)

{
  int i;
  int l2;

  l2 = l;
  fprintf(stderr, "%s (L=%d.)", tag, l);
  if (l2 > 48) l2 = 48;
  for (i=0; i<l2; i++)
    fprintf(stderr, " %02x", b [i]);
  fprintf(stderr, "\n");
  fflush(stderr);
}


char *
  oo_lookup_nak_text
    (int nak_code)

{ /* oo_lookup_nak_text */

  char *nak_text;


  switch(nak_code)
  {
  default:
    nak_text = "Unknown code";
    break;
  case OO_NAK_CHECK_CRC:
    nak_text = "Message check";
    break;
  case OO_NAK_CMD_UNABLE:
    nak_text = "Unable to process command";
    break;
  case OO_NAK_ENC_REQ:
    nak_text = "Encrypted communications required";
    break;
  case OO_NAK_SEQUENCE:
    nak_text = "Unexpected sequence number";
    break;
  case OO_NAK_UNK_CMD:
    nak_text = "Unknown command";
    break;
  case OO_NAK_UNSUP_SECBLK:
    nak_text = "Unsupported security block";
    break;
//2 7 8
  };
  return(nak_text);

} /* oo_lookup_nak_text */


int oo_filetransfer_SDU_offer
  (OSDP_CONTEXT *ctx)

{ /* oo_filetransfer_SDU_offer */

  int offered_size;


  offered_size = ctx->max_message;
  if (ctx->verbosity > 3)
    fprintf(ctx->log, "FTMsgUpdateMax-1 %d.\n", offered_size);
  if (ctx->max_message > 0)
  {
    offered_size = offered_size - 14; // headers and footers, secure channel
    if (ctx->verbosity > 3)
      fprintf(ctx->log, "FTMsgUpdateMax-2 %d.\n", offered_size);
    offered_size = ((offered_size / OSDP_KEY_OCTETS) * OSDP_KEY_OCTETS) - 1; // fit in cipher blocks with minimal padding
    if (ctx->verbosity > 3)
      fprintf(ctx->log, "FTMsgUpdateMax-3 %d.\n", offered_size);
    offered_size = offered_size - 11; // less osdp_FILETRANSFER header
  };
  if (ctx->verbosity > 3)
    fprintf(ctx->log, "FTMsgUpdateMax offered: %d.\n", offered_size);

  return(offered_size);

} /* oo_filetransfer_SDU_offer */


unsigned char
  oo_response_address
    (OSDP_CONTEXT *ctx,
    unsigned char from_address)

{ /* oo_response_address */

  int ret_addr;

  ret_addr = 0;
  if (from_address != OSDP_CONFIGURATION_ADDRESS)
    ret_addr = from_address;
  else
  {
    ret_addr = OSDP_CONFIGURATION_ADDRESS;
  };
  return(ret_addr);

} /* oo_response_address */


void
  osdp_array_to_doubleByte
    (unsigned char a [2],
    unsigned short int *i)

{ /* osdp_array_to_doubleByte */

  *i = a[1];
  *i = (*i << 8) + a [0];

} /* osdp_array_to_doubleByte */


void
  osdp_array_to_quadByte
    (unsigned char a [4],
    unsigned int *i)

{ /* osdp_array_to_quadByte */

  *i = a[3];
  *i = (*i << 8) + a [2];
  *i = (*i << 8) + a [1];
  *i = (*i << 8) + a [0];

} /* osdp_array_to_quadByte */


int
  osdp_awaiting_response
    (OSDP_CONTEXT *ctx)

{ /* osdp_awaiting_response */

  int following_sequence;
  int ret;


  if (ctx->verbosity > 9)
  {
    fprintf(ctx->log, "awaiting: last sq %d lastproc %d\n", ctx->last_sequence_received, ctx->last_was_processed);
  };

  // assume it is awaiting a response

  ret = 1;

  following_sequence = ctx->last_sequence_received;
  if (following_sequence >= 0)
  {
    following_sequence = (ctx->last_sequence_received + 1) % 4;
    if (following_sequence EQUALS 0)
      following_sequence = 1;
  };

  // if we've processed the response, we're ok to proceed

  if (ctx->last_was_processed)
  {
    ret = 0;
  };

  // assuming we have not already decided it's ok to proceed, look at sequence numbers

  if (ret && (ctx->next_sequence != following_sequence))
  {
    if (ctx->verbosity > 9)
      fprintf(stderr, "DEBUG: waiting-ret %d following %d last %d next %d last-processed %d\n",
        ret, following_sequence, ctx->last_sequence_received, ctx->next_sequence, ctx->last_was_processed);

    if (following_sequence EQUALS -1)
    {
      ret = 0; // ok to proceed if nothing received
    }
    else
    {
      // if last was a zero and next is a zero then it's ok we are resetting seq nums
      if ((ctx->last_sequence_received EQUALS 0) && (ctx->next_sequence EQUALS 0))
      {
        ret = 0;
      }
      else
      {
        if (ctx->verbosity > 9)
        {
          fprintf(ctx->log,
"DEBUG: not actually ready n %d f %d bcount %d 0=%02x 1=%02x 2=%02x 5=%02x 6=%02x\n",
            ctx->next_sequence, following_sequence, osdp_buf.next,
            osdp_buf.buf [0], osdp_buf.buf [1], osdp_buf.buf [2],
            osdp_buf.buf [5], osdp_buf.buf [6]);
        };
        ret = 1; // not actually ready.
      };
    };
  };

  if (ctx->timer [OSDP_TIMER_RESPONSE].status EQUALS OSDP_TIMER_STOPPED)
  {
    if (ctx->verbosity > 9)
    {
      fprintf(ctx->log, "receive timeout, attempting transmission (%d)\n", ctx->last_sequence_received);
    };
    if (ctx->last_was_processed) // assuming the last was processed...
      ret = 0; // if no response but timeout, call it "not waiting"
  };
  fflush(ctx->log);

  return (ret);

} /* osdp_awaiting_response */


int
  osdp_command_match
    (OSDP_CONTEXT *ctx,
    json_t *root,
    char *command,
    int *command_id)

{ /* osdp_command_match */

  int ret_cmd;
  int status;
  json_t *value;


  status = ST_CMD_UNKNOWN;
  ret_cmd = OSDP_CMDB_NOOP; // no-op if not known
  value = json_object_get (root, "command");
  if (!json_is_string (value))
    status = ST_CMD_INVALID;
  else
  {
    status = ST_OK;
    strcpy (command, json_string_value (value));
  };

  if (status EQUALS ST_OK)
  {
    ret_cmd = OSDP_CMDB_NOOP;
    status = ST_CMD_UNKNOWN;
    if (0 EQUALS strcmp(command, "bioread"))
      ret_cmd = OSDP_CMDB_BIOREAD;
    if (0 EQUALS strcmp(command, "biomatch"))
      ret_cmd = OSDP_CMDB_BIOMATCH;
    if (0 EQUALS strcmp(command, "conform-070-17-01"))
      ret_cmd = OSDP_CMDB_CONFORM_070_17_01;
    if (0 EQUALS strcmp(command, "factory-default"))
      ret_cmd = OSDP_CMDB_FACTORY_DEFAULT;
    if (0 EQUALS strcmp(command, "identify"))
      ret_cmd = OSDP_CMDB_IDENT;
    if (0 EQUALS strcmp(command, "keyset"))
      ret_cmd = OSDP_CMDB_KEYSET;
    if (0 EQUALS strcmp(command, "ondemand-lstatr"))
      ret_cmd = OSDP_CMDB_ONDEMAND_LSTATR;
    if (0 EQUALS strcmp(command, "pivdata"))
      ret_cmd = OSDP_CMDB_PIVDATA;
    if (0 EQUALS strcmp(command, "polling"))
      ret_cmd = OSDP_CMDB_POLLING;
    if (0 EQUALS strcmp(command, "reset"))
      ret_cmd = OSDP_CMDB_RESET;
    if (0 EQUALS strcmp(command, "reset-statistics"))
      ret_cmd = OSDP_CMDB_RESET_STATS;
    if (0 EQUALS strcmp(command, "scbk-default"))
      ret_cmd = OSDP_CMDB_SCBK_DEFAULT;
    if (0 EQUALS strcmp(command, "send-explicit"))
      ret_cmd = OSDP_CMDB_SEND_EXPLICIT;
    if (0 EQUALS strcmp(command, "trace"))
      ret_cmd = OSDP_CMDB_TRACE;
    if (ret_cmd != -1)
      status = ST_OK;
  };

  *command_id = ret_cmd;
  return(status);

} /* osdp_command_match */


// direction is the CP/PD bit e.g. 0 or 128

char
  *osdp_command_reply_to_string
    (unsigned char cmdrep, int direction)

{ /* osdp_command_reply_to_string */

  static char cmd_rep_s [1024];

  cmd_rep_s [0] = 0;

  // nonzero if it's a PD

  if (direction != 0)
  {
    switch (cmdrep)
    {
    default:
      sprintf(cmd_rep_s, "???2(0x%2x)", cmdrep);
      break;
    case OSDP_ACK:    strcpy(cmd_rep_s, "osdp_ACK"); break;
    case OSDP_BIOMATCH: strcpy(cmd_rep_s, "osdp_BIOMATCH"); break;
    case OSDP_BIOMATCHR: strcpy(cmd_rep_s, "osdp_BIOMATCHR"); break;
    case OSDP_BIOREAD: strcpy(cmd_rep_s, "osdp_BIOREAD"); break;
    case OSDP_BIOREADR: strcpy(cmd_rep_s, "osdp_BIOREADR"); break;
    case OSDP_BUSY:   strcpy(cmd_rep_s, "osdp_BUSY"); break;
    case OSDP_CCRYPT: strcpy(cmd_rep_s, "osdp_CCRYPT"); break;
    case OSDP_CRAUTHR: strcpy(cmd_rep_s, "osdp_CRAUTHR"); break;
    case OSDP_COM:    strcpy(cmd_rep_s, "osdp_COM"); break;
    case OSDP_FTSTAT: strcpy(cmd_rep_s, "osdp_FTSTAT"); break;
    case OSDP_GENAUTHR: strcpy(cmd_rep_s, "osdp_GENAUTHR"); break;
    case OSDP_ISTATR: strcpy(cmd_rep_s, "osdp_ISTATR"); break;
    case OSDP_KEYPAD: strcpy(cmd_rep_s, "osdp_KEYPAD"); break;
    case OSDP_LSTATR: strcpy(cmd_rep_s, "osdp_LSTATR"); break;
    case OSDP_MFGERRR: strcpy(cmd_rep_s, "osdp_MFGERRR"); break;
    case OSDP_MFGREP:   strcpy(cmd_rep_s, "osdp_MFGREP"); break;
    case OSDP_NAK:      strcpy(cmd_rep_s, "osdp_NAK"); break;
    case OSDP_OSTATR:   strcpy(cmd_rep_s, "osdp_OSTATR"); break;
    case OSDP_PDCAP:    strcpy(cmd_rep_s, "osdp_PDCAP"); break;
    case OSDP_PDID:     strcpy(cmd_rep_s, "osdp_PDID"); break;
    case OSDP_PIVDATAR: strcpy(cmd_rep_s, "osdp_PIVDATAR"); break;
    case OSDP_RAW:      strcpy(cmd_rep_s, "osdp_RAW"); break;
    case OSDP_RMAC_I:   strcpy(cmd_rep_s, "osdp_RMAC_I"); break;
    case OSDP_RSTATR:   strcpy(cmd_rep_s, "osdp_RSTATR"); break;
    case OSDP_SCRYPT:   strcpy(cmd_rep_s, "osdp_SCRYPT"); break;
    case OSDP_XRD:      strcpy(cmd_rep_s, "osdp_XRD"); break;
    };
  };

  // zero if it's the CP

  if (direction EQUALS 0)
  {
    switch (cmdrep)
    {
    default: sprintf(cmd_rep_s, "???1(%02x)", cmdrep); break;
    case OSDP_ACURXSIZE:    strcpy(cmd_rep_s, "osdp_ACURXSIZE"); break;
    case OSDP_BIOREAD:      strcpy(cmd_rep_s, "osdp_BIOREAD"); break;
    case OSDP_BIOMATCH:     strcpy(cmd_rep_s, "osdp_BIOMATCH"); break;
    case OSDP_BUZ:          strcpy(cmd_rep_s, "osdp_BUZ"); break;
    case OSDP_CAP:          strcpy(cmd_rep_s, "osdp_CAP"); break;
    case OSDP_CHLNG:        strcpy(cmd_rep_s, "osdp_CHLNG"); break;
    case OSDP_COMSET:       strcpy(cmd_rep_s, "osdp_COMSET"); break;
    case OSDP_CRAUTH:       strcpy(cmd_rep_s, "osdp_CRAUTH"); break;
    case OSDP_DATA:         strcpy(cmd_rep_s, "osdp_DATA"); break;
    case OSDP_DIAG:         strcpy(cmd_rep_s, "osdp_DIAG"); break;
    case OSDP_FILETRANSFER: strcpy(cmd_rep_s, "osdp_FILETRANSFER"); break;
    case OSDP_GENAUTH:      strcpy(cmd_rep_s, "osdp_GENAUTH"); break;
    case OSDP_ID:           strcpy(cmd_rep_s, "osdp_ID"); break;
    case OSDP_ISTAT:        strcpy(cmd_rep_s, "osdp_ISTAT"); break;
    case OSDP_KEEPACTIVE:   strcpy(cmd_rep_s, "osdp_KEEPACTIVE"); break;
    case OSDP_KEYSET:       strcpy(cmd_rep_s, "osdp_KEYSET"); break;
    case OSDP_LED:          strcpy(cmd_rep_s, "osdp_LED"); break;
    case OSDP_LSTAT:        strcpy(cmd_rep_s, "osdp_LSTAT"); break;
    case OSDP_MFG:          strcpy(cmd_rep_s, "osdp_MFG"); break;
    case OSDP_OSTAT:     strcpy(cmd_rep_s, "osdp_OSTAT"); break;
    case OSDP_OUT:       strcpy(cmd_rep_s, "osdp_OUT"); break;
    case OSDP_PIVDATA:      strcpy(cmd_rep_s, "osdp_PIVDATA"); break;
    case OSDP_POLL:      strcpy(cmd_rep_s, "osdp_POLL"); break;
    case OSDP_RSTAT:     strcpy(cmd_rep_s, "osdp_RSTAT"); break;
    case OSDP_SCRYPT:    strcpy(cmd_rep_s, "osdp_SCRYPT"); break;
    case OSDP_TEXT:      strcpy(cmd_rep_s, "osdp_TEXT"); break;
    case OSDP_XWR:       strcpy(cmd_rep_s, "osdp_XWR"); break;
    };
  };
  return (cmd_rep_s);

} /* osdp_command_reply_to_string */


void
  osdp_doubleByte_to_array
    (unsigned short int i,
    unsigned char a [2])

{ /* osdp_doubleByte_to_array */

  a [0] = i & 0xff;
  a [1] = (i & 0xff00) >> 8;

} /* osdp_doubleByte_to_array */


void
  osdp_quadByte_to_array
    (unsigned int i,
    unsigned char a [4])

{ /* osdp_quadByte_to_array */

  a [0] = i & 0xff;
  a [1] = (i & 0xff00) >> 8;
  a [2] = (i & 0xff0000) >> 16;
  a [3] = (i & 0xff000000) >> 24;

} /* osdp_quadByte_to_array */


int
  osdp_send_ftstat
    (OSDP_CONTEXT *ctx,
    OSDP_HDR_FTSTAT *response)

{ /* osdp_send_ftstat */

  int current_length;
  int status;
  int to_send;


  status = ST_OK;
  osdp_test_set_status(OOC_SYMBOL_cmd_filetransfer, OCONFORM_EXERCISED);
  osdp_test_set_status(OOC_SYMBOL_resp_ftstat, OCONFORM_EXERCISED);

  to_send = sizeof(*response);
  current_length = 0;
  status = send_message (ctx, OSDP_FTSTAT, p_card.addr,
    &current_length, to_send, (unsigned char *)response);
  return(status);

} /* osdp_send_ftstat */


// osdp_timer_start - start a timer.  uses preset values

int osdp_timer_start
   (OSDP_CONTEXT *ctx,
   int timer_index)

{ /* osdp_timer_start */

  int status;


  status = ST_OK;
if (timer_index == OSDP_TIMER_RESPONSE)
{
  if (ctx->verbosity > 9)
  {
    fprintf(ctx->log, "DEBUG: osdp_timer_start: old s %ld ns %ld\n",
      ctx->timer[timer_index].i_sec,
      ctx->timer[timer_index].i_nsec);
  };
};
  if ((timer_index < 0) || (timer_index > OSDP_TIMER_MAX))
    status = ST_OSDP_BAD_TIMER;
  if (status EQUALS ST_OK)
  {
    if (ctx->timer [timer_index].i_sec > 0)
    {
      ctx->timer [timer_index].current_seconds = ctx->timer [timer_index].i_sec;
      ctx->timer [timer_index].status = OSDP_TIMER_RESTARTED;
    };
    if (ctx->timer [timer_index].i_nsec > 0)
    {
      ctx->timer [timer_index].current_nanoseconds = ctx->timer [timer_index].i_nsec;
      ctx->timer [timer_index].status = OSDP_TIMER_RESTARTED;
    };
if (timer_index == OSDP_TIMER_RESPONSE)
{
  if (ctx->verbosity > 9)
  {
    fprintf(ctx->log, "DEBUG: osdp_timer_start: restart s %ld ns %ld\n",
      ctx->timer[timer_index].i_sec,
      ctx->timer[timer_index].i_nsec);
  };
};
  };

  return (status);

} /* osdp_timer_start */


int osdp_validate_led_values
      (OSDP_RDR_LED_CTL *leds,
      unsigned char *errdeets,
      int *elth)

{ /* osdp_validate_led_values */

  int status;


  status = ST_OK;
  if (leds->reader != 0)
  {
    errdeets[0] = OO_NAK_CMD_UNABLE;
    *elth = 1;
  };
  return (status);

} /* osdp_validate_led_values */

