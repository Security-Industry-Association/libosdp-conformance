/*
  open-osdp - RS-485 implementation of OSDP protocol

  (C)Copyright 2017-2018 Smithee Solutions LLC
  (C)Copyright 2015-2016 Smithee,Spelvin,Agnew & Plinge, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Support provided by the Security Industry Association
  http://www.securityindustry.org
*/


#include <stdio.h>
#include <sys/select.h>
#include <memory.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <termios.h>


#include <open-osdp.h>
#include <osdp_conformance.h>
#include <osdp-local-config.h>


int
  check_for_command;
OSDP_CONTEXT
  context;
struct timespec
  last_time_check_ex;
OSDP_BUFFER
  osdp_buf;
OSDP_INTEROP_ASSESSMENT
  osdp_conformance;
OSDP_OUT_CMD
  current_output_command [16];
OSDP_PARAMETERS
  p_card;
char tag [1024]; // PD or CP as a string
char trace_in_buffer [1024];
char trace_out_buffer [1024];


unsigned char
  creds_buffer_a [64*1024];
int
  creds_buffer_a_lth;
int
  creds_buffer_a_next;
int
  creds_buffer_a_remaining;


void
  check_serial
    (OSDP_CONTEXT
      *ctx)
{
  struct termios
    serial_termios;
  speed_t
    speed;
  int
    status_io;


  status_io = tcgetattr (ctx->fd, &serial_termios);
  fprintf (stderr, "tcgetattr returned %d\n", status_io);
  speed = cfgetispeed (&serial_termios);
  fprintf (stderr, "input speed %d\n", speed);
  speed = cfgetospeed (&serial_termios);
  fprintf (stderr, "output speed %d\n", speed);

}

int
  initialize
    (int
      argc,
    char
      *argv [])

{ /* initialize */

  char
    command [1024];
  pid_t
    my_pid;
  int
    status;


  status = ST_OK;
  trace_in_buffer [0] = 0;
  trace_out_buffer [0] = 0;
  check_for_command = 0;

  if (status EQUALS ST_OK)
  {
    memset (&context, 0, sizeof (context));
    context.current_menu = OSDP_MENU_TOP;
    strcpy (context.init_parameters_path, "open-osdp-params.json");
    strcpy (context.log_path, "osdp.log");

    // if there's an argument it is the config file path
    if (argc > 1)
    {
      strcpy (context.init_parameters_path, argv [1]);
    };
    status = initialize_osdp (&context);
  };

  if (status EQUALS ST_OK)
  {
    // set things up depending on role.

    strcpy (tag, "PD");
    if (context.role EQUALS OSDP_ROLE_CP)
      strcpy (tag, "CP");
    if (context.role EQUALS OSDP_ROLE_MONITOR)
      strcpy (tag, "MON");
    sprintf (context.command_path,
      "/opt/osdp-conformance/run/%s/open_osdp_command.json", tag);
    // initialize my current pid
    my_pid = getpid ();
    sprintf (command, OSPD_LCL_SET_PID_TEMPLATE,
      tag, my_pid);
    system (command);
  };

  if (status EQUALS ST_OK)
  {
    status = init_serial (&context, p_card.filename);
  };
  if (status EQUALS ST_OK)
  {
    if (context.role EQUALS OSDP_ROLE_CP)
      fprintf (stderr, "Role: CP\n");
    if (context.role EQUALS OSDP_ROLE_PD)
      fprintf (stderr, "Role: PD\n");
  };

  return (status);

} /* initialize */


int
  main
    (int
      argc,
    char
      *argv [])

{ /* main for open-osdp */

  int c1;
  int done;
  fd_set exceptfds;
  char octet [3]; // used for text version of byte in tracing
  fd_set readfds;
  int scount;
  const sigset_t sigmask;
  int status;
  int status_io;
  int status_select;
  struct timespec timeout;
  int ufd;
  fd_set writefds;


  status = ST_OK;
  status = initialize (argc, argv);
  if (status EQUALS ST_OK)
  {
    memset (&last_time_check_ex, 0, sizeof (last_time_check_ex));
    done = 0;
    fprintf (stderr, "role %02x\n",
      context.role);
  };
  if (status != ST_OK)
    done = 1;

  // set up a unix socket so commands can be injected

  if (!done)
  {
    char
      sn [1024];
    int
      status_socket;
    struct sockaddr_un
      usock;


    memset (sn, 0, sizeof (1024));
    sprintf (sn, OSDP_LCL_UNIX_SOCKET, tag);

    ufd = socket (AF_UNIX, SOCK_STREAM, 0);
    if (ufd != -1)
    {
      memset (&usock, 0, sizeof (usock));
      usock.sun_family = AF_UNIX;
      unlink (sn);
      strcpy (usock.sun_path, sn);
      if (context.verbosity > 3)
        fprintf (stderr, "unix socket path %s\n",
          usock.sun_path);
      status_socket = bind (ufd, (struct sockaddr *)&usock, sizeof (usock));
      if (status_socket != -1)
      {
        status_socket = fcntl (ufd, F_SETFL,
          fcntl (ufd, F_GETFL, 0) | O_NONBLOCK);
        if (status_socket != -1)
          status_socket = listen (ufd, 0);
      };
    };
    check_serial (&context);
  };
  while (!done)
  {
    fflush (context.log);

    // do a select waiting for RS-485 serial input (or a HUP)

    FD_ZERO (&readfds);
    FD_SET (ufd, &readfds);
    FD_SET (context.fd, &readfds);
    if (ufd > context.fd)
      scount = ufd+1;
    else
      scount = context.fd+1;
    FD_ZERO (&writefds);
    FD_ZERO (&exceptfds);
    timeout.tv_sec = 0;
    timeout.tv_nsec = 100000000;
    status_select = pselect (scount, &readfds, &writefds, &exceptfds,
      &timeout, &sigmask);

    if (status_select EQUALS -1)
    {
      status = ST_SELECT_ERROR;

      // if it's an interrupt, fake it's ok.  assume a legitimate HUP
      // interrupted it and we'll recover.

      if (errno EQUALS EINTR)
      {
        status = ST_OK;
        status_select = 0;
      }
      else
      {
        fprintf (stderr, "errno at select error %d\n", errno);
      };
    };
    if (status_select EQUALS 0)
    {
      status = ST_OK;
      if (osdp_timeout (&context, &last_time_check_ex))
      {
        // if timer 0 expired dump the status
        if (context.timer[OSDP_TIMER_STATISTICS].status EQUALS
          OSDP_TIMER_RESTARTED)
        {
          status = write_status (&context);
        };

        // if "the timer" went off, do the background process.
        // It'll figure out if there figure out if there  was a send timeout.

        status = background (&context);

        if (context.timer[OSDP_TIMER_SUMMARY].status EQUALS
          OSDP_TIMER_RESTARTED)
        {
          status = osdp_log_summary(&context);
        };
      };
    };

    // if there was data at the 485 file descriptor, process it.
    // if we got kicked in the unix socket, process the waiting command

    if (status_select > 0)
    {
      if (context.verbosity > 9)
        fprintf (stderr, "%d descriptors from pselect\n",
          status_select);

      // check for command input (unix socket activity pokes us to check)

      if (FD_ISSET (ufd, &readfds))
      {
        char cmdbuf [2];
        c1 = accept (ufd, NULL, NULL);
        if (context.verbosity > 5)
          fprintf (stderr, "ufd socket(%d) was selected in READ (new fd %d)\n",
            ufd, c1);
        if (c1 != -1)
        {
          status_io = read (c1, cmdbuf, sizeof (cmdbuf));
          if (status_io > 0)
          {
            close (c1);

            status = process_current_command ();
            if (status EQUALS ST_OK)
              preserve_current_command ();
            check_for_command = 0;
            status = ST_OK;
          };
        };       
      };

      if (FD_ISSET (context.fd, &readfds))
      {
        unsigned char buffer [2];
        status_io = read (context.fd, buffer, 1);
        if (status_io < 1)
        {
          // continue if it was a serial error
          status = ST_OK;
        }
        else
        {
          if (context.verbosity > 8)
          {
//            fprintf(context.log, "RAW SERIAL: %02x\n", buffer [0]);
            sprintf(octet, " %02x", buffer [0]);
            strcat(trace_in_buffer, octet);
          };
          if (context.verbosity > 9)
            fprintf (stderr, "485 read returned %d bytes\n",
              status_io);

          status = ST_SERIAL_IN;
          if (osdp_buf.next < sizeof (osdp_buf.buf))
          {
            osdp_buf.buf [osdp_buf.next] = buffer [0];
            osdp_buf.next ++;

          // if we're reading noise dump bytes until a clean header starts

          // messages start with SOM, anything else is noise.
          // (checksum mechanism copes with SOM's in the middle of a msg.)

          if (osdp_buf.next EQUALS 1)
          {
            if (!(osdp_buf.buf [0] EQUALS C_SOM))
              osdp_buf.next = 0;
// zzz move up one byte
          };
        }
        else
        {
          fprintf(context.log, "Serial Overflow, resetting input buffer\n");
          osdp_buf.overflow ++;
          osdp_buf.next = 0; 
        };
      };
    };
    }; // select returned nonzero number of fd's

    // if there was input, process the message
    if (status EQUALS ST_SERIAL_IN)
    {
      status = process_osdp_input (&osdp_buf);
      // if it's too short so far it'll be 'serial_in' so ignore that
      if (status EQUALS ST_SERIAL_IN)
        status = ST_OK;
    };

    if (status != ST_OK)
      done = 1;
  };
  if (status != ST_OK)
    fprintf (stderr, "open-osdp return status %d\n",
      status);

  return (status);

} /* main for open-osdp */


int
  send_osdp_data
    (OSDP_CONTEXT
      *context,
    unsigned char
      *buf,
    int
      lth)

{ /* send_osdp_data */

  if (context->verbosity > 9)
  {
    int idx;
   
    fprintf (stderr, "\nRaw:");
    for (idx=0; idx<lth; idx++)
    {
      fprintf (stderr, " %02x", buf[idx]);
    };
    fprintf (stderr, "\n");
  };
  write (context->fd, buf, lth);
  
  return (ST_OK);

} /* send_osdp_data */

