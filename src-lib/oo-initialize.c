/*
  oo_initialize - init code for OSDP

  (C)Copyright 2017-2022 Smithee Solutions LLC

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
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/file.h>


#define _OO_INITIALIZE_
#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>


char multipart_message_buffer_1 [64*1024];
extern OSDP_INTEROP_ASSESSMENT osdp_conformance;
extern OSDP_PARAMETERS p_card;

OSDP_COMMAND_QUEUE osdp_command_queue [OSDP_COMMAND_QUEUE_SIZE];

int
  init_serial
    (OSDP_CONTEXT *ctx,
    char *device)

{ /* init_serial */

  char command [1024];
  int status;
  int status_io;


  if (ctx->verbosity > 3)
    printf ("init_serial: command %s\n",
      ctx->init_command);
  if (strlen (ctx->init_command) > 0)
  {
    fprintf (ctx->log, "Using init command \"%s\" for device %s\n",
      ctx->init_command, device);
    sprintf (command, ctx->init_command, device);
    system (command);
  };
  if (ctx->fd != -1)
  {
    if (ctx->verbosity > 3)
      fprintf (stderr, "Closing %s\n", device);
    close (ctx->fd);
  };
  ctx->fd = open (device, O_RDWR | O_NONBLOCK);
  fprintf (ctx->log, "Opening %s, fd=%d.\n", device, ctx->fd);
  if (ctx->fd EQUALS -1)
  {
    if (ctx->verbosity > 3)
      fprintf (stderr, "errno at device %s open %d\n", device, errno);
    status= ST_SERIAL_OPEN_ERR;
  }
  else
    status = ST_OK;
  if (status EQUALS ST_OK)
  {
    status_io = tcgetattr (ctx->fd, &(ctx->tio));
//fprintf (stderr, "tcgetattr returned %d\n", status_io);
    cfmakeraw (&(ctx->tio));
    status_io = tcsetattr (ctx->fd, TCSANOW, &(ctx->tio));
//fprintf (stderr, "tcsetattr raw returned %d\n", status_io);

{
  int serial_speed_cfg_value;
  int known_speed;

  known_speed = 1;
  serial_speed_cfg_value = B9600;
  // if speed wasn't set use the default of 9600
  if (strlen (ctx->serial_speed) EQUALS 0)
    strcpy (ctx->serial_speed, "9600");

  if (strcmp (ctx->serial_speed, "9600") EQUALS 0)
  {
    serial_speed_cfg_value = B9600;
    known_speed = 1;
  }
  if (strcmp (ctx->serial_speed, "19200") EQUALS 0)
  {
    serial_speed_cfg_value = B19200;
    known_speed = 1;
  }
  if (strcmp (ctx->serial_speed, "38400") EQUALS 0)
  {
    serial_speed_cfg_value = B38400;
    known_speed = 1;
  }
  if (strcmp (ctx->serial_speed, "57600") EQUALS 0)
  {
    serial_speed_cfg_value = B57600;
    known_speed = 1;
  }
  if (strcmp (ctx->serial_speed, "115200") EQUALS 0)
  {
    serial_speed_cfg_value = B115200;
    known_speed = 1;
  }
  if (strcmp (ctx->serial_speed, "230400") EQUALS 0)
  {
    serial_speed_cfg_value = B230400;
    known_speed = 1;
  }
  if (!known_speed)
  {
    serial_speed_cfg_value = B9600;
    fprintf (stderr, "Unknown speed (%s), using 9600 BPS\n",
      ctx->serial_speed);
  };
  status_io = cfsetispeed (&(ctx->tio), serial_speed_cfg_value);
  if (ctx->verbosity > 3)
    fprintf (stderr, "cfsetispeed returned %d\n", status_io);
  status_io = cfsetospeed (&(ctx->tio), serial_speed_cfg_value);
  if (ctx->verbosity > 3)
    fprintf (stderr, "cfsetospeed returned %d\n", status_io);
  status_io = tcsetattr (ctx->fd, TCSANOW, &(ctx->tio));
  if (ctx->verbosity > 3)
    fprintf (stderr, "tcsetattr returned %d\n", status_io);
  if (status_io != 0)
    status = ST_SERIAL_SET_ERR;
};
  };

  return (status);

} /* init_serial */


int
  initialize_osdp
    (OSDP_CONTEXT *context)

{ /* initialize */

  extern unsigned char *creds_buffer_a;
  extern int creds_buffer_a_lth;
  extern int creds_buffer_a_next;
  extern int creds_buffer_a_remaining;
  int creds_f;
  char logmsg [1024];
  extern int mfg_rep_sequence;
  char optstring [1024];
  extern OSDP_BUFFER *osdp_buf;
  extern time_t previous_time;
  int status;
  int status_io;


  status = ST_OK;
  memset (&osdp_conformance, 0, sizeof (osdp_conformance));

  // logging set-up

  context->log = fopen (context->log_path, "w");
  if (context->log EQUALS NULL)
    status = ST_LOG_OPEN_ERR;
  if (status EQUALS ST_OK)
  {
    mfg_rep_sequence = 0;

    // create the lock, exclusively, for just this user
    context->process_lock = open(OSDP_EXCLUSIVITY_LOCK,
      O_CREAT | O_WRONLY, S_IRWXU);
    if (context->process_lock < 0)
      status = -1;
  };
  if (status EQUALS ST_OK)
  {
    status_io = flock(context->process_lock, LOCK_EX | LOCK_NB);
    if (status_io EQUALS -1)
      status = ST_OSDP_EXCLUSIVITY_FAILED;
  };

  // initialize the trace file to empty

  {
    FILE *tf;
    tf = fopen(OSDP_TRACE_FILE, "w");
    if (tf)
      fclose(tf);
  };


  if (status EQUALS ST_OK)
  {
    osdp_conformance.last_unknown_command = OSDP_POLL;
    context->mmsgbuf = multipart_message_buffer_1;
    memset (&p_card, 0, sizeof (p_card));

    context->verbosity = 3;

    context->q = osdp_command_queue;
    context->enable_poll = OO_POLL_ENABLED;

    context->current_key_slot = -1;
    memcpy(context->current_default_scbk, OSDP_SCBK_DEFAULT, sizeof(context->current_default_scbk));

    m_version_minor = OSDP_VERSION_MINOR;
    m_build = OSDP_VERSION_BUILD;
    context->model = 2;
    context->version = 2;
    context->fw_version [0] = OSDP_VERSION_MAJOR;
    context->fw_version [1] = m_version_minor;
    context->fw_version [2] = m_build;
    context->vendor_code [0] = 0x0A;
    context->vendor_code [1] = 0x00;
    context->vendor_code [2] = 0x17; //yellow pig
    context->serial_number [0] = 0xca;
    context->serial_number [1] = 0xfe;
    context->serial_number [2] = 0xde;
    context->serial_number [3] = 0xed;
    context->capability_configured_sounder = 1; // it's got a beeper

  strcpy (context->fqdn, "perim-0000.example.com");
  context->xferctx.state = OSDP_XFER_STATE_IDLE;
  p_card.value [0] = 0x00; // fc=1 card=1 in 26 bit wiegand
  p_card.value [1] = 0x80; // fc=1 card=1 in 26 bit wiegand
  p_card.value [2] = 0x00; // fc=1 card=1 in 26 bit wiegand
  p_card.value [3] = 0x80; // fc=1 card=1 in 26 bit wiegand
  p_card.value_len = 4;
  p_card.bits = 26;

    context->configured_inputs = OOSDP_DEFAULT_INPUTS;
    context->configured_outputs = OOSDP_DEFAULT_OUTPUTS;

  m_check = OSDP_CRC;
  // to force checksum-only set m_check to OSDP_CHECKSUM here.

  m_dump = 0;
  strcpy (p_card.filename, "/dev/ttyUSB0");
  context->next_sequence = 0;

  // timer set-up

  previous_time = 0;
  context->timer_count = 3;
  context->timer [OSDP_TIMER_STATISTICS].timeout_action = OSDP_TIMER_RESTART_ALWAYS;
  context->timer [OSDP_TIMER_STATISTICS].i_sec = 3;
  context->timer [OSDP_TIMER_STATISTICS].i_nsec = 0;
  context->timer [OSDP_TIMER_RESPONSE].timeout_action = OSDP_TIMER_RESTART_NONE;
  context->timer [OSDP_TIMER_RESPONSE].i_sec = 0;
  context->timer [OSDP_TIMER_RESPONSE].i_nsec = 100000000l;
  fprintf(context->log, "Inter-command poll timeout %ld.\n", context->timer [OSDP_TIMER_RESPONSE].i_nsec);
  context->timer [OSDP_TIMER_SUMMARY].timeout_action = OSDP_TIMER_RESTART_ALWAYS;
  context->timer [OSDP_TIMER_SUMMARY].i_sec = 60;
  context->timer [OSDP_TIMER_SERIAL_READ].status = OSDP_TIMER_STOPPED;
  context->timer [OSDP_TIMER_SERIAL_READ].i_nsec = 100000000;
  fprintf(context->log, "Serial read timeout %ld.\n", context->timer [OSDP_TIMER_SERIAL_READ].i_nsec);
  { 
    struct timespec resolution;

    clock_getres (CLOCK_REALTIME, &resolution);
    if (context->verbosity > 3)
      fprintf (stderr, "Clock resolution is %ld seconds/%ld nanoseconds\n",
        resolution.tv_sec, resolution.tv_nsec);
  };
  }; // status ok after lock 

  if (status EQUALS ST_OK)
  {
    /*
      try to get configuration from configuration file open_osdp.cfg
    */
    status = read_config (context);
    if (!(context->keep_results))
      system("rm -f /opt/osdp-conformance/results/*");

    if (context->verbosity > 4)
    {
      m_dump = 1;
      fprintf (stderr, "read_config returned %d\n", status);
    };
    status = ST_OK; // doesn't matter if config reading failed
  };

  if (status EQUALS ST_OK)
  {
    char *current_role;
    FILE *f;

    strcpy (optstring, "");

    // record our current role

    current_role = "";
    if (context->role EQUALS OSDP_ROLE_CP)
      current_role = "ACU";
    if (context->role EQUALS OSDP_ROLE_PD)
      current_role = "PD";
    {
      f = fopen(OO_OSDP_ROLE_FILENAME, "w");
      if (f != NULL)
      {
        fprintf(f, "%s", current_role);
        fclose(f);
      };
    };    
  }

  if (status EQUALS ST_OK)
  {
    // and... we're powering on so send an LSTATR when we get a chance.

    context->power_report = 1;

    sprintf (logmsg, "Open-OSDP - OSDP Tester Version %d.%d Build %d",
      context->fw_version [0], m_version_minor, m_build);
    fprintf (context->log, "%s\n", logmsg);
    printf ("%s\n", logmsg);

    if (context->role EQUALS OSDP_ROLE_CP)
    {
      // all these are for the PD we're talking to
      context->model = 0;
      context->version = 0;
      context->fw_version [0] = 0;
      context->fw_version [1] = 0;
      context->fw_version [2] = 0;
      context->vendor_code [0] = 0;
      context->vendor_code [1] = 0;
      context->vendor_code [2] = 0;
    };
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

    fprintf (context->log, "Verbosity %d. Device %s Address %2d Speed %s\n",
      context->verbosity, p_card.filename, p_card.addr, context->serial_speed);
  };

  if ((status EQUALS ST_OK) && (context->role != OSDP_ROLE_MONITOR))
  {
    int idx;
    char logmsg [2*1024]; // 'cause filename could be that long...
    char tlogmsg [1024];

    sprintf (logmsg, "Parameters:");
    fprintf (context->log, "%s\n", logmsg);
    sprintf (logmsg, "  Filename: %s", p_card.filename);
    fprintf (context->log, "%s\n", logmsg);
    sprintf (logmsg, "  Addr: %02x (%d.)", p_card.addr, p_card.addr);
    fprintf (context->log, "%s\n", logmsg);
    sprintf (logmsg, "  Bits: %d", p_card.bits);
    fprintf (context->log, "%s\n", logmsg);
    sprintf (logmsg, "  Value (%d. bytes): ", p_card.value_len);
    fprintf (context->log, "%s", logmsg);
    logmsg [0] = 0;
    for (idx=0; idx<p_card.value_len; idx++)
    {
      sprintf (tlogmsg, "%02x", p_card.value [idx]);
      strcat (logmsg, tlogmsg);
    };
    fprintf (context->log, "%s\n", logmsg);

    memset (&osdp_buf, 0, sizeof (osdp_buf));
    context->current_menu = OSDP_MENU_TOP;

    if (status EQUALS ST_OK)
    {
      char creds_filename_a [1024];

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

    status = oo_load_parameters(context, OSDP_SAVED_PARAMETERS);
    if (status != ST_OK)
    {
      fprintf(context->log, "Problem loading saved parameters (%d)\n", status);
      status = 0;
    }
    else
    {
      fprintf(context->log, "Saved parameters loaded.\n");
    };
  }; // NOT monitor mode

  // we are ready to party.  "last was processed"
  if (status EQUALS ST_OK)
    context->last_was_processed = 1;

  if (status EQUALS ST_OK)
    status = oo_write_status (context);
  if (status != ST_OK)
    fprintf(stderr, "OSDP initialization failed (%d.)\n", status);
  return (status);

} /* initialize_osdp */

