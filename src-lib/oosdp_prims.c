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
    };
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

