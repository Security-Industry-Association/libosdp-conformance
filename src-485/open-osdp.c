/*
  open-osdp - RS-485 implementation of OSDP protocol

  (C)Copyright 2015 Smithee,Spelvin,Agnew & Plinge, Inc.

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
#include <sys/select.h>
#include <memory.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <errno.h>


#include <open-osdp.h>
#include <osdp_conformance.h>


OSDP_CONTEXT
  context;
long int
  last_time_check;
OSDP_BUFFER
  osdp_buf;
OSDP_INTEROP_ASSESSMENT
  osdp_conformance;
OSDP_PARAMETERS
  p_card;


unsigned char
  creds_buffer_a [64*1024];
int
  creds_buffer_a_lth;
int
  creds_buffer_a_next;
int
  creds_buffer_a_remaining;


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
  char
    tag [1024];


  status = ST_OK;

m_idle_timeout = 30;

{
  int status_signal;
  static struct sigaction signal_action;
  //signal (SIGHUP, signal_callback_handler);
  memset (&signal_action, 0, sizeof (signal_action));
  signal_action.sa_handler = signal_callback_handler;
  status_signal = sigaction (SIGHUP,
    &signal_action, NULL);
};

  last_time_check = time (NULL);
  if (status EQUALS ST_OK)
  {
    memset (&context, 0, sizeof (context));
    strcpy (context.init_parameters_path, "open_osdp_params.json");
    strcpy (context.log_path, "open_osdp.log");

    // if there's an argument it is the config file path
    if (argc > 1)
    {
      strcpy (context.init_parameters_path, argv [1]);
    };
    status = initialize_osdp (&context);
    context.current_menu = OSDP_MENU_TOP;
  };

  // set things up depending on role.

  strcpy (tag, "PD");
  if (context.role EQUALS OSDP_ROLE_CP)
    strcpy (tag, "CP");
  sprintf (context.command_path,
    "/opt/open-osdp/run/%s/open_osdp_command.json", tag);
  // initialize my current pid
  my_pid = getpid ();
  sprintf (command, "sudo -n /opt/open-osdp/bin/set-%s-pid %d",
    tag, my_pid);
  system (command);

  if (status EQUALS ST_OK)
  {
    status = init_serial (&context, p_card.filename);
  };
  if (status EQUALS ST_OK)
  {
    fprintf (stderr, "open-osdp version %s\n",
      "TEMP 1.0-build 3");
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

  int
    done;
  fd_set
    exceptfds;
  fd_set
    readfds;
  int
    nfds;
  const sigset_t
    sigmask;
  int
    status;
  int
    status_io;
  int
    status_select;
  struct timespec
    timeout;
  fd_set
    writefds;


  status = ST_OK;
  status = initialize (argc, argv);
  done = 0;
  fprintf (stderr, "role %02x\n",
    context.role);
  if (status != ST_OK)
    done = 1;
  while (!done)
  {
    fflush (context.log);

    // do a select waiting for RS-485 serial input (or a HUP)

    nfds = 0;
    FD_ZERO (&readfds);
    FD_SET (context.fd, &readfds);
    FD_ZERO (&writefds);
    FD_ZERO (&exceptfds);
    timeout.tv_sec = 0;
    timeout.tv_nsec = 100000000;
    status_select = pselect (1+context.fd, &readfds, &writefds, &exceptfds,
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
      if (osdp_timeout (&context, &last_time_check))
        status = background (&context);
    };

    // if there was data at the 485 file descriptor, process it

    if (FD_ISSET (context.fd, &readfds))
    {
      unsigned char buffer [2];
      status_io = read (context.fd, buffer, 1);
      if (status_io < 1)
      {
        //status = ST_SERIAL_READ_ERR;
        // continue if it was a serial error
        status = ST_OK;
      }
      else
      {
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
          status = ST_SERIAL_OVERFLOW;
          osdp_buf.overflow ++;
        };
      };
    };

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
#if 0
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>




int
  passphrase_length;
int
  plmax = 16;
char
  current_passphrase [17];
char
  specified_passphrase [17];
char
  buffer [MAX_BUF + 1];
gnutls_dh_params_t
  dh_params;
struct sockaddr_in
  sa_serv;
//gnutls_session_t session;


void
  signal_callback_handler
    (int
      signum);


int
  generate_dh_params
    (void)

{ /* generate_dh_params */

  unsigned int bits = gnutls_sec_param_to_pk_bits(GNUTLS_PK_DH,
    GNUTLS_SEC_PARAM_LEGACY);
  /* Generate Diffie-Hellman parameters - for use with DHE
   * kx algorithms. These should be discarded and regenerated
   * once a day, once a week or once a month. Depending on the
   * security requirements.
   */
  gnutls_dh_params_init(&dh_params);
  gnutls_dh_params_generate2(dh_params, bits);

  return 0;

} /* generate_dh_params */


// MAIN


//merged
//  next
//    next
//      next
            if (status_sock EQUALS 0)
            {
              status = ST_OK;
            };
          }
          else
          {
            status = ST_OK; // assume tls read was ok for starters
            tls_current_length = status_tls;
            if (status_tls EQUALS 0)
              status = ST_OSDP_TLS_CLOSED;
            if (status_tls < 0)
              status = ST_OSDP_TLS_ERROR;
            if (status EQUALS ST_OK)
            {
              // if we have enough data look for the passphrase
              if (!context.authenticated)
              {
                if (passphrase_length < plmax)
                {
                  int lth;
                  lth = tls_current_length;
                  if ((passphrase_length + lth) > plmax)
                    lth = plmax - passphrase_length;
                  memcpy (current_passphrase+passphrase_length, buffer, lth);
                  if (0 EQUALS
                    memcmp (current_passphrase, specified_passphrase, plmax))
                    context.authenticated = 1;
                };
              };

              // append buffer to osdp buffer
              if (context.authenticated)
              {
                // while first not SOM skip until SOM

                int i;
                int done;
                int current_length;

                i = 0;
                current_length = tls_current_length;
                done = 0;
                while (!done)
                {
                  if (buffer [i] != C_SOM)
                  {
                    i++;
                    current_length --;
                  }
                  else
                  {
                    memcpy (osdp_buf.buf + osdp_buf.next,
                      buffer+i, current_length);
                    osdp_buf.next = osdp_buf.next + current_length;
                    status = ST_NET_INPUT_READY;
                    done = 1;
                  };
                  if (i EQUALS tls_current_length)
                    done = 1;
                }
              };
            }
          };
          if (status != ST_OK)
          {
            if (status != ST_NET_INPUT_READY)
            {
              fprintf (stderr, "status %d\n", status);
              done_tls = 1;
            };
          };
          if (status != ST_OK)
          {
            done_tls = 1;
          };
#endif
//merged
//  next
//    next
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

  write (context->fd, buf, lth);
  return (ST_OK);

} /* send_osdp_data */


