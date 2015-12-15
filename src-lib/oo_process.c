/*
  oo-process - process OSDP message input

  (C)Copyright 2014-2015 Smithee Spelvin Agnew & Plinge, Inc.

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


#include <gnutls/gnutls.h>


#include <osdp-tls.h>
#include <open-osdp.h>


// cut everything but old main for now

#if 0
#include <sys/select.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>
extern char *optarg;
extern int  optind;


#include <osdp_conformance.h>


OSDP_INTEROP_ASSESSMENT
  osdp_conformance;
unsigned char
  creds_buffer_a [64*1024];
int
  creds_buffer_a_lth;
int
  creds_buffer_a_next;
int
  creds_buffer_a_remaining;

char
  logmsg [1024];
unsigned char
  test_blk [1024];


int
  initialize
    (OSDP_CONTEXT
       *context,
    int
      argc,
    char
      *argv []);
int main
    (int
      argc,
    char
      *argv []);
int
  process_command
  (int
     command,
  OSDP_CONTEXT
     *context);
int
  usage
    (void);


int
  initialize
    (OSDP_CONTEXT
      *context,
    int
      argc,
    char
      *argv [])

{ /* initialize */

  int
    creds_f;
  int
    done;
  int
    longindex;
  struct option
    longopts [13] = {
      {"pd", 0, NULL, OSDP_OPT_PD},
      {"cp", 0, NULL, OSDP_OPT_CP},
      {"device", required_argument, NULL, OSDP_OPT_DEVICE},
      {"debug", optional_argument, NULL, OSDP_OPT_DEBUG},
      {"checksum", 0, NULL, OSDP_OPT_CHECKSUM},
      {"crc", 0, NULL, OSDP_OPT_CRC},
      {"?", 0, NULL, OSDP_OPT_HELP},
      {"pd-addr", required_argument, NULL, OSDP_OPT_PDADDR},
      {"no-poll", 0, NULL, OSDP_OPT_NOPOLL},
      {"init-command", optional_argument, NULL,OSDP_OPT_INIT},
      {"monitor", 0, NULL, OSDP_OPT_MONITOR},
      {"special", 0, NULL, OSDP_OPT_SPECIAL},
      {0, 0, 0, 0}
    };
  char
    optstring [1024];
  extern time_t
    previous_time;
  int
    status;
  int
    status_io;
  int
    status_opt;


  status = ST_OK;
  memset (context, 0, sizeof (*context));
  memset (&osdp_conformance, 0, sizeof (osdp_conformance));
  context->mmsgbuf = multipart_message_buffer_1;
  memset (&p_card, 0, sizeof (p_card));

  m_verbosity = 3;
  m_version_minor = OSDP_VERSION_MINOR;
  m_build = OSDP_VERSION_BUILD;
  context->model = 2;
  context->version = 1;
  context->fw_version [0] = OSDP_VERSION_MAJOR;
  context->fw_version [1] = m_version_minor;
  context->fw_version [2] = m_build;
  context->vendor_code [0] = 0x08;
  context->vendor_code [1] = 0x00;
  context->vendor_code [2] = 0x1b;
  m_idle_timeout = 30;
  m_check = OSDP_CRC;
  m_dump = 1;
  strcpy (p_card.filename, "/dev/ttyUSB0");
  context->next_sequence = 0;

  previous_time = 0;

  context->log = fopen ("open-osdp.log", "w");
  if (context->log EQUALS NULL)
    status = ST_LOG_OPEN_ERR;

//was ok here
  if (status EQUALS ST_OK)
  {
    /*
      try to get configuration from configuration file open_osdp.cfg
    */
    status = read_config (context);
    if (m_verbosity > 3)
      fprintf (stderr, "read_config returned %d\n", status);
    status = ST_OK; // doesn't matter if config reading failed
  };

  if (status EQUALS ST_OK)
  {
    strcpy (optstring, "");
    done = 0;
  }
  else
    done = 1;
  while (!done)
  {
    status_opt = getopt_long (argc, argv, optstring, longopts, &longindex);

    if (m_verbosity > 3)
    {
      fprintf (stderr, "Args:\n");
      fprintf (stderr,
        "optind %d optarg %s status %d. idx %d.\n", optind, optarg, status_opt, longindex);
    };
    if (status_opt != -1)
    {
      switch (status_opt)
      {
      default:
        fprintf (stderr, "Unknown argument %d\n", longindex);
        break;
      case OSDP_OPT_CHECKSUM:
        m_check = OSDP_CHECKSUM;
        break;
      case OSDP_OPT_CP:
        context->role = OSDP_CP;
        m_check = OSDP_CRC;
        break;
      case OSDP_OPT_CRC:
        m_check = OSDP_CRC;
        break;
      case OSDP_OPT_DEBUG:
        m_verbosity = 999;
        if (optarg != 0)
        {
          int i;
          sscanf (optarg, "%d", &i);
          m_verbosity = i;
        };
        break;
      case OSDP_OPT_DEVICE:
        strcpy (p_card.filename, optarg);
        break;
      case OSDP_OPT_HELP:
        status = usage ();
        break;
      case OSDP_OPT_INIT:
        strcpy (context->init_command, "./open-osdp-dev-init.sh %s");
        if (optarg != 0)
        {
          strcpy (context->init_command, optarg);
        };
        fprintf (stderr, "Init command specified: \"%s\"\n",
          context->init_command);
        break;
      case OSDP_OPT_MONITOR:
        context->role = OSDP_MONITOR;
        break;
      case OSDP_OPT_PD:
        context->role = OSDP_PD;
        m_check = OSDP_CHECKSUM;
        break;
      case OSDP_OPT_PDADDR:
        {
          int i;
          sscanf (optarg, "%d", &i);
          p_card.addr = 0x7f & i;
        };
        break;
      case OSDP_OPT_NOPOLL:
        context->idle_time = -1;
        break;
      case OSDP_OPT_SPECIAL:
        context->special_1 = 3;
        break;
      };
    };
    if (status_opt == -1)
      done = 1;
  };

  if (status EQUALS ST_OK)
  {
    sprintf (logmsg, "Open-OSDP - OSDP Tester Version %d.%d Build %d",
      context->fw_version [0], m_version_minor, m_build);
    fprintf (context->log, "%s\n", logmsg);
    printf ("%s\n", logmsg);
  };
  if (status EQUALS ST_OK)
  {
    time_t tmp_time;

    struct timespec
      current_time_fine;


    clock_gettime (CLOCK_REALTIME, &current_time_fine);
    tmp_time = time (NULL);
    sprintf (logmsg, "%08ld.%08ld %s(%ld)",
      (unsigned long int)current_time_fine.tv_sec, current_time_fine.tv_nsec,
      asctime (localtime (&tmp_time)), tmp_time);
    fprintf (context->log,
      "%s (Rcvd Frame %6d)", logmsg, context->packets_received);
  };

  fprintf (context->log, "Verbosity set to %d.\n",
    m_verbosity);
  if (context->special_1 != 0)
    fprintf (context->log, "SPECIAL Processing (%d) Enabled\n",
      context->special_1);
  {
    int idx;
    char logmsg [1024];
    char tlogmsg [1024];

    sprintf (logmsg, "Parameters:");
    fprintf (stderr, "%s\n", logmsg);
    fprintf (context->log, "%s\n", logmsg);
    sprintf (logmsg, "  Filename: %s", p_card.filename);
    fprintf (stderr, "%s\n", logmsg);
    fprintf (context->log, "%s\n", logmsg);
    sprintf (logmsg, "  Addr: %02x (%d.)", p_card.addr, p_card.addr);
    fprintf (stderr, "%s\n", logmsg);
    fprintf (context->log, "%s\n", logmsg);
    sprintf (logmsg, "  Bits: %d", p_card.bits);
    fprintf (stderr, "%s\n", logmsg);
    fprintf (context->log, "%s\n", logmsg);
    sprintf (logmsg, "  Value (%d. bytes): ", p_card.value_len);
    fprintf (stderr, "%s", logmsg);
    fprintf (context->log, "%s", logmsg);
    logmsg [0] = 0;
    for (idx=0; idx<p_card.value_len; idx++)
    {
      sprintf (tlogmsg, "%02x", p_card.value [idx]);
      strcat (logmsg, tlogmsg);
    };
    fprintf (stderr, "%s\n", logmsg);
    fprintf (context->log, "%s\n", logmsg);
  };

  if (status EQUALS ST_OK)
  {
    char
      creds_filename_a [1024];

    creds_buffer_a_next = 0;
    creds_buffer_a_remaining = 0;
    strcpy (creds_filename_a, "open-osdp-creds-a.dat");
    fprintf (context->log, "Credentials File A: %s\n", creds_filename_a);

    // initialize credentials buffer(s)

    creds_f = open (creds_filename_a, O_RDONLY);
    if (creds_f != -1)
    {
      status_io = read (creds_f, creds_buffer_a, sizeof (creds_buffer_a));
      if (status_io < 10000)
      {
        creds_buffer_a_lth = status_io;
        fprintf (context->log, "%d. bytes read from credentials file A\n", creds_buffer_a_lth);
        status = ST_OK;
      }
      else
        status = ST_ERR_INIT_CREDS;
    }
    else
    {
      // ignore error
      creds_buffer_a_lth = 0;
      status = ST_OK;
    };
  };
  
  memset (&osdp_buf, 0, sizeof (osdp_buf));
  context->current_menu = OSDP_MENU_TOP;
  return (status);

} /* intitialize */
#endif


extern OSDP_CONTEXT
  context;
char
  multipart_message_buffer_1 [64*1024];
extern OSDP_PARAMETERS
  p_card;

int
  process_osdp_input
    (OSDP_BUFFER
      *osdp_buf)

{ /* process_osdp_input */

  OSDP_MSG
    msg;
  OSDP_HDR
    parsed_msg;
  int
    status;
  OSDP_BUFFER
    temp_buffer;


  memset (&msg, 0, sizeof (msg));

  msg.lth = osdp_buf->next;
  msg.ptr = osdp_buf->buf;
  status = parse_message (&context, &msg, &parsed_msg);
  if (status EQUALS ST_MSG_TOO_SHORT)
    status = ST_SERIAL_IN;
  if (status EQUALS ST_OK)
  {
    status = process_osdp_message (&context, &msg);
  };

  // move the existing buffer up to the front if it was unknown, not mine,
  // monitor only, or processed

  if ((status EQUALS ST_PARSE_UNKNOWN_CMD) || \
    (status EQUALS ST_BAD_CRC) || \
    (status EQUALS ST_BAD_CHECKSUM) || \
    (status EQUALS ST_NOT_MY_ADDR) || \
    (status EQUALS ST_MONITOR_ONLY) || \
    (status EQUALS ST_OK))
  {
    int length;
    length = (parsed_msg.len_msb << 8) + parsed_msg.len_lsb;
    memcpy (temp_buffer.buf, osdp_buf->buf+length, osdp_buf->next-length);
    temp_buffer.next = osdp_buf->next-length;
    memcpy (osdp_buf->buf, temp_buffer.buf, temp_buffer.next);
    osdp_buf->next = temp_buffer.next;
    if (status != ST_OK)
      // if we experienced an error we just reset things and continue
      status = ST_SERIAL_IN;
  };
  return (status);

} /* process_osdp_input */

