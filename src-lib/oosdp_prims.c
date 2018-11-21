#include <stdio.h>
#include <string.h>
//#include <time.h>

#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>
extern OSDP_INTEROP_ASSESSMENT
  osdp_conformance;
extern OSDP_PARAMETERS
  p_card;


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
    case OSDP_ACK: strcpy(cmd_rep_s, "osdp_ACK"); break;
    case OSDP_BUSY: strcpy(cmd_rep_s, "osdp_BUSY"); break;
    case OSDP_CCRYPT: strcpy(cmd_rep_s, "osdp_CCRYPT"); break;
    case OSDP_COM: strcpy(cmd_rep_s, "osdp_COM"); break;
    case OSDP_FTSTAT: strcpy(cmd_rep_s, "osdp_FTSTAT"); break;
    case OSDP_ISTATR: strcpy(cmd_rep_s, "osdp_ISTATR"); break;
    case OSDP_KEYPAD: strcpy(cmd_rep_s, "osdp_KEYPAD"); break;
    case OSDP_LSTATR: strcpy(cmd_rep_s, "osdp_LSTATR"); break;
    case OSDP_MFGREP: strcpy(cmd_rep_s, "osdp_MFGREP"); break;
    case OSDP_NAK: strcpy(cmd_rep_s, "osdp_NAK"); break;
    case OSDP_OSTATR: strcpy(cmd_rep_s, "osdp_OSTATR"); break;
    case OSDP_PDCAP: strcpy(cmd_rep_s, "osdp_PDCAP"); break;
    case OSDP_PDID: strcpy(cmd_rep_s, "osdp_PDID"); break;
    case OSDP_RAW: strcpy(cmd_rep_s, "osdp_RAW"); break;
    case OSDP_RMAC_I: strcpy(cmd_rep_s, "osdp_RMAC_I"); break;
    case OSDP_RSTATR: strcpy(cmd_rep_s, "osdp_RSTATR"); break;
    case OSDP_SCRYPT: strcpy(cmd_rep_s, "osdp_SCRYPT"); break;
    };
  };

  // zero if it's the CP

  if (direction EQUALS 0)
  {
    switch (cmdrep)
    {
    default: strcpy(cmd_rep_s, "???1"); break;
    case OSDP_ACURXSIZE: strcpy(cmd_rep_s, "osdp_ACURXSIZE"); break;
    case OSDP_BIOREAD: strcpy(cmd_rep_s, "osdp_BIOREAD"); break;
    case OSDP_BUZ: strcpy(cmd_rep_s, "osdp_BUZ"); break;
    case OSDP_CAP: strcpy(cmd_rep_s, "osdp_CAP"); break;
    case OSDP_CHLNG: strcpy(cmd_rep_s, "osdp_CHLNG"); break;
    case OSDP_COMSET: strcpy(cmd_rep_s, "osdp_COMSET"); break;
    case OSDP_DATA: strcpy(cmd_rep_s, "osdp_DATA"); break;
    case OSDP_DIAG: strcpy(cmd_rep_s, "osdp_DIAG"); break;
    case OSDP_FILETRANSFER: strcpy(cmd_rep_s, "osdp_FILETRANSFER"); break;
    case OSDP_ID: strcpy(cmd_rep_s, "osdp_ID"); break;
    case OSDP_ISTAT: strcpy(cmd_rep_s, "osdp_ISTAT"); break;
    case OSDP_KEYSET: strcpy(cmd_rep_s, "osdp_KEYSET"); break;
    case OSDP_LED: strcpy(cmd_rep_s, "osdp_LED"); break;
    case OSDP_LSTAT: strcpy(cmd_rep_s, "osdp_LSTAT"); break;
    case OSDP_MFG: strcpy(cmd_rep_s, "osdp_MFG"); break;
    case OSDP_OSTAT: strcpy(cmd_rep_s, "osdp_OSTAT"); break;
    case OSDP_OUT: strcpy(cmd_rep_s, "osdp_OUT"); break;
    case OSDP_POLL: strcpy(cmd_rep_s, "osdp_POLL"); break;
    case OSDP_PROMPT: strcpy(cmd_rep_s, "osdp_PROMPT"); break;
    case OSDP_RSTAT: strcpy(cmd_rep_s, "osdp_RSTAT"); break;
    case OSDP_SCRYPT: strcpy(cmd_rep_s, "osdp_SCRYPT"); break;
    case OSDP_TDSET: strcpy(cmd_rep_s, "osdp_TDSET"); break;
    case OSDP_TEXT: strcpy(cmd_rep_s, "osdp_TEXT"); break;
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
  osdp_send_filetransfer
    (OSDP_CONTEXT *ctx)

{ /* osdp_send_filetransfer */

  int current_length;
  OSDP_HDR_FILETRANSFER *ft;
  int size_to_read;
  int status;
  int status_io;
  int transfer_send_size;
  unsigned char xfer_buffer [MAX_BUF];


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
      transfer_send_size = 0;
      memset(ft, 0, sizeof(*ft));
      osdp_quadByte_to_array(ctx->xferctx.total_length, ft->FtSizeTotal);
      ft->FtType = OSDP_FILETRANSFER_TYPE_OPAQUE;
      osdp_quadByte_to_array(ctx->xferctx.total_length, ft->FtOffset);
      current_length = 0;
      status = send_message (ctx,
        OSDP_FILETRANSFER, p_card.addr, &current_length,
        transfer_send_size, (unsigned char *)ft);
    }
    else
    {
    // load data from file starting at msg->FtData

    if (ctx->xferctx.current_send_length)
      size_to_read = ctx->xferctx.current_send_length;
    else
      size_to_read = ctx->max_message;
    size_to_read = size_to_read + 1 - sizeof(OSDP_HDR_FILETRANSFER);
    status_io = fread (&(ft->FtData), sizeof (unsigned char), size_to_read,
      ctx->xferctx.xferf);
    if (status_io > 0)
      size_to_read = status_io;
    if (status_io <= 0)
      status = ST_OSDP_FILEXFER_READ;

    if (status EQUALS ST_OK)
    {
      // load data length into FtSizeTotal (little-endian)
      osdp_quadByte_to_array(ctx->xferctx.total_length, ft->FtSizeTotal);

      ft->FtType = OSDP_FILETRANSFER_TYPE_OPAQUE;

      osdp_doubleByte_to_array(size_to_read, ft->FtFragmentSize);
      osdp_quadByte_to_array(ctx->xferctx.current_offset, ft->FtOffset);

      transfer_send_size = size_to_read;
      transfer_send_size = transfer_send_size - 1 + sizeof (*ft);
      current_length = 0;
      status = send_message (ctx,
        OSDP_FILETRANSFER, p_card.addr, &current_length,
        transfer_send_size, (unsigned char *)ft);

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
  osdp_send_ftstat
    (OSDP_CONTEXT *ctx,
    OSDP_HDR_FTSTAT *response)

{ /* osdp_send_ftstat */

  int current_length;
  int status;
  int to_send;


  status = ST_OK;
  osdp_conformance.resp_ftstat.test_status = OCONFORM_EXERCISED;

  to_send = sizeof(*response);
  current_length = 0;
  status = send_message (ctx, OSDP_FTSTAT, p_card.addr,
    &current_length, to_send, (unsigned char *)response);
  return(status);

} /* osdp_send_ftstat */


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


void dump_buffer_log (OSDP_CONTEXT *ctx, char * tag, unsigned char *b, int l)
{
  int i;
  int l2;

  l2 = l;
  fprintf(ctx->log, "%s (L=%d.)", tag, l);
  if (l2 > 48) l2 = 48;
  for (i=0; i<l2; i++)
    fprintf(ctx->log, " %02x", b [i]);
  fprintf(ctx->log, "\n");
  fflush(ctx->log);
}


void dump_buffer_stderr (char * tag, unsigned char *b, int l)
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

int osdp_awaiting_response (OSDP_CONTEXT *ctx)
{
  int ret;

  ret = 1;

  if (ctx->last_was_processed)
  {
    ret = 0;
  }
  else
  {
    if (ctx->timer [OSDP_TIMER_RESPONSE].status EQUALS OSDP_TIMER_STOPPED)
      ret = 0; // if no response but timeout, call it "not waiting"
  };
  return (ret);
}


// osdp_timer_start - start a timer.  uses preset values

int osdp_timer_start
   (OSDP_CONTEXT *ctx,
   int timer_index)

{ /* osdp_timer_start */

  int status;


  status = ST_OK;
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
  };

  return (status);

} /* osdp_timer_start */
