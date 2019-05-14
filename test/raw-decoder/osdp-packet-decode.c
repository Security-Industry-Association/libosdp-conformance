// osdp-packet-decode

#include <string.h>
#include <ctype.h>

#include <open-osdp.h>
#include <osdp_conformance.h>
OSDP_CONTEXT context;
unsigned char creds_buffer_a [64*1024];
int creds_buffer_a_lth;
int creds_buffer_a_next;
int creds_buffer_a_remaining;
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

{ /* main for osdp-packet-decode */

  OSDP_CONTEXT *ctx;
  OSDP_MSG m;
  char osdp_message [1024];
  char osdp_message_bytes [1024];
  int osdp_message_length;
  char *p;
  OSDP_HDR returned_hdr;
  int status;


  p = getenv("QUERY_STRING");
  strcpy(osdp_message, p+4);
  printf("Content-type: text/html\n\n");
printf("<HTML><HEAD><TITLE>Dump</TITLE></HEAD><BODY>\n");
  printf("<PRE>\n");
  status = ST_OK;
  ctx = &context;
  memset(ctx, 0, sizeof(*ctx));
  ctx->verbosity = 9;
  ctx->log = stdout;
  ctx->role = OSDP_ROLE_MONITOR;
  memset(&m, 0, sizeof(m));
    status = -2; // gotta be at least one octet (2 hexits)
    if (strlen(osdp_message) > 1)
    {
      status = ST_OK;

      fprintf(ctx->log, "OSDP Raw Dump: %s\n", osdp_message);
      osdp_message_length = sizeof(osdp_message_bytes);
      bytes_from_string(osdp_message, osdp_message_bytes, &osdp_message_length);
      m.ptr = (unsigned char *)osdp_message_bytes;
      m.lth = osdp_message_length;
      status = osdp_parse_message (ctx, OSDP_ROLE_MONITOR, &m, &returned_hdr);
      if (status EQUALS ST_OK)
        (void)monitor_osdp_message (ctx, &m);
      else
        printf("osdp_parse_message returned %d.\n", status);
    };
  if (status != ST_OK)
    printf("dump-osdp: terminating with status %d.\n", status);
  printf("</BODY></HTML>\n");

  return (0);

} /* main for dump-osdp */


int
  send_osdp_data
    (OSDP_CONTEXT *context,
    unsigned char *buf,
    int lth)
{ return (-1); }


/*
  bytes_from_string - forgivingly decode hex bytes

  skips a leading FF
  skips blanks
*/

void
  bytes_from_string
    (char *string,
    char *bytes,
    int *bytes_length)

{ /* bytes_from_string */

  int byte;
  int done;
  int len;
  int max_length;
  char *pdest;
  char *psource;
  char ptemp [1024];
  int status;


  status = 0;
  done = 0;
  if (*bytes_length < 1)
    status = -1;
  if (!string)
    status = -2;

  // remove blanks and pluses (blanks manifest as '+' through http)
  if (status EQUALS ST_OK)
  {
    char *p;
    int i;

    p = string;
    i = 0;
    memset(ptemp, 0, sizeof(ptemp));
    while (!done)
    {
      if (*p EQUALS 0)
        done = 1;
      else
      {
        if ((*p != ' ') && (*p != '+'))
        {
          ptemp [i] = *p;
          i++;
        };
      };
      p++;
    };
    psource = ptemp;
  };

  done = 0;
  if (!done)
  {
    len = strlen(psource);
    if (0 != (len % 2))
      done = 1;
  };
  if (!done)
  {
    // if it starts with 0xff, eat that
    if (tolower(*psource) EQUALS 'f')
      psource = psource + 2;

printf("source %s\n", psource);
    pdest = bytes;
    max_length = *bytes_length;
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

} /* bytes_from_string */

