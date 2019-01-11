/*
  osdp-tcp-client - TCP-only version of osdp-net-client

  (C)Copyright 2017-2018 Smithee Solutions LLC
  (C)Copyright 2015-2017 Smithee,Spelvin,Agnew & Plinge, Inc.

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
#include <memory.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/un.h>


#include <gnutls/gnutls.h>
#include <gnutls/x509.h>


#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>
#include <osdp-local-config.h>
char trace_in_buffer [1024];
char trace_out_buffer [1024];


int
  read_tcp_stream
    (OSDP_CONTEXT
      *ctx,
    int
      net_fd,
    int
      *poll);
int tcp_connect (void);


char
  buffer [MAX_BUF + 1];
OSDP_TLS_CONFIG
  config;
OSDP_CONTEXT
  context;
OSDP_OUT_CMD
  current_output_command [16];
int
  current_sd; // current socket for tcp connection
struct timespec
  last_time_check_ex;
OSDP_BUFFER
  osdp_buf;
OSDP_INTEROP_ASSESSMENT
  osdp_conformance;
OSDP_PARAMETERS
  p_card;
time_t
  previous_time;
int
  request_immediate_poll;
struct sockaddr_in
  sa_serv;
char
  *tag;

// cardholder number kludge

unsigned char
  creds_buffer_a [64*1024];
int
  creds_buffer_a_lth;
int
  creds_buffer_a_next;
int
  creds_buffer_a_remaining;

// passphrase kludge

int
  passphrase_length;
int
  plmax = 16;
char
  current_passphrase [17];
char
  specified_passphrase [17];


int
  initialize
    (OSDP_TLS_CONFIG
      *config,
    int
      argc,
    char
      *argv [])

{ /* initialize */

  char
    command [1024];
  char
    current_network_address [1024];
  int
    status;


  status = ST_OK;
  memset (config, 0, sizeof (*config));
  current_network_address [0] = 0;

  memset (&context, 0, sizeof (context));
  strcpy (context.init_parameters_path, "open-osdp-params.json");
  strcpy (context.log_path, "osdp.log");

  // if there's an argument it is the config file path
  if (argc > 1)
  {
    strcpy (context.init_parameters_path, argv [1]);

    // a second argument is the network address of the destination
    if (argc > 2)
      strcpy (current_network_address, argv [2]);
  };

  sprintf (config->version, "v%d.%d-Build%d",
    OSDP_VERSION_MAJOR, OSDP_VERSION_MINOR, OSDP_VERSION_BUILD);
  strcpy (config->ca_file, OSDP_LCL_CA_KEYS);
// sets port
config->listen_sap = 10001;

  //strcpy (specified_passphrase, "speakFriend&3ntr");
  strcpy (specified_passphrase, OSDP_LCL_DEFAULT_PSK);

  if (status EQUALS ST_OK)
    status = initialize_osdp (&context);
  if (context.role EQUALS OSDP_ROLE_CP)
    tag = "CP";
  else
    tag = "PD";

  // initialize my current pid
  if (status EQUALS ST_OK)
  {
    pid_t
      my_pid;

    my_pid = getpid ();
    context.current_pid = my_pid;
    sprintf (command, OSPD_LCL_SET_PID_TEMPLATE,
      tag, my_pid);
    system (command);
  };

  // init timer
  memset (&last_time_check_ex, 0, sizeof (last_time_check_ex));

  if (strlen (current_network_address) > 0)
    strcpy (context.network_address, current_network_address);

  sprintf (context.command_path, 
    OSDP_LCL_COMMAND_PATH, tag);

  context.authenticated = 1; // for now just say we're authenticated.

  if (status EQUALS ST_OK)
  {
    fprintf (stderr, "osdp-tcp-client version %s\n",
      config->version);
    if (context.role EQUALS OSDP_ROLE_CP)
    {
      fprintf (stderr, "Role: CP\n");
    };
    if (context.role EQUALS OSDP_ROLE_PD)
    {
      fprintf (stderr, "Role: PD\n");
    };
  };

  return (status);

} /* initialize */

int
  init_tls_client
    (void)

{ /* init_tls_client */

  int
    status;
  int
    status_sock;


  status = ST_OK;
  if (status EQUALS ST_OK)
  {
    /* connect to the peer
     */
    current_sd = tcp_connect();
  };
  if (status EQUALS ST_OK)
  {
    status_sock = fcntl (current_sd, F_SETFL,
    fcntl (current_sd, F_GETFL, 0) | O_NONBLOCK);
    if (status_sock EQUALS -1)
    {
      status = ST_OSDP_TCP_NONBLOCK;;
    };
  };
  return (status);

} /* init_tls_client */


int
  local_socket_setup
  (int
    *lcl_sock_fd)

{ /* local_socket_setup */

  struct sockaddr_un usock;
  char sn [1024];
  int
    status;
  int
    status_socket;
  char
    *tag;
  int
    ufd;


  status = ST_OK;
  memset (sn, 0, sizeof (1024));
  if (context.role EQUALS OSDP_ROLE_CP)
    tag = "CP";
  else
    tag = "PD";
  sprintf (sn, "/opt/osdp-conformance/run/%s/open-osdp-control", tag);

  ufd = socket (AF_UNIX, SOCK_STREAM, 0);
  if (ufd != -1)
  {
    memset (&usock, 0, sizeof (usock));
    usock.sun_family = AF_UNIX;
    unlink (sn);
    strcpy (usock.sun_path, sn);
    fprintf (stderr, "unix socket path %s\n",
      usock.sun_path);
    status_socket = bind (ufd, (struct sockaddr *)&usock, sizeof (usock));
    if (status_socket != -1)
    {
      status_socket = fcntl (ufd, F_SETFL,
        fcntl (ufd, F_GETFL, 0) | O_NONBLOCK);
      if (status_socket != -1)
      {
        status_socket = listen (ufd, 0);
      }
      else
      {
        status = -5;
      };
    }
    else
    {
      status = -4;
    };
  }
  else
  {
    status = -3;
  };

  if (status EQUALS ST_OK)
    *lcl_sock_fd = ufd;
  return (status);

} /* local_socket_setup */


int
  main
    (int
      argc,
    char
      *argv [])

{ /* main for osdp-tcp-client */

  int c1;
  int do_net_read;
  int done_tls;
  fd_set exceptfds;
  fd_set readfds;
  int nfds;
  const sigset_t sigmask;
  int status;
  int status_io;
  int status_sock;
  struct timespec timeout;
  fd_set writefds;
  int ufd;


  status = initialize (&config, argc, argv);
  if (status EQUALS ST_OK)
  {
    status = local_socket_setup (&ufd);
  };
  if (status EQUALS ST_OK)
  {
    trace_in_buffer [0] = 0;
    trace_out_buffer [0] = 0;
    memset (&last_time_check_ex, 0, sizeof (last_time_check_ex));

    done_tls = 0; // assume not done unless some bad status

    status = init_tls_client ();
    if (status != ST_OK)
      done_tls = 1;
  };
  request_immediate_poll = 0;
  while (!done_tls)
  {
    do_net_read = 1; // assume we should do some reading

    fflush (stdout); fflush (stderr); fflush (context.log);
    
    // if we already have buffer contents try to process it before reading more.
    if (osdp_buf.next > 0)
    {
      int skip_done;
      char tmp1 [8192];

      skip_done = 1; 

      if (osdp_buf.next > 1)
        if (osdp_buf.buf [0] != C_SOM)
          skip_done = 0;

      while (!skip_done)
      {
        if (osdp_buf.buf [0] != C_SOM)
        {
          memcpy(tmp1, osdp_buf.buf+1, osdp_buf.next-1);
          memcpy(osdp_buf.buf, tmp1, osdp_buf.next-1);
          osdp_buf.next --;
        }
        else
        {
          skip_done = 1;
        };
        if (!osdp_buf.next)
          skip_done = 1;
      };

      status = process_osdp_input (&osdp_buf);
      if (context.verbosity > 9)
        dump_buffer_log(&context, "After process_osdp_input",
          osdp_buf.buf, osdp_buf.next);

      // if it's too short so far it'll be 'serial_in' so ignore that
      if (status EQUALS ST_SERIAL_IN)
      {
        status = ST_OK;
        do_net_read = 1;
      }
      else
      {
        do_net_read = 0;
      };
    };

    // if there was too little to process get some more from the net
    // otherwise we'll loop around and process more buffer.

    if (do_net_read)
    {
      // look for file descriptor activity

      nfds = 0;
      FD_ZERO (&readfds);
      FD_ZERO (&writefds);
      FD_ZERO (&exceptfds);
      FD_SET (ufd, &readfds);

      FD_SET (current_sd, &readfds);
      nfds = ufd+1;
      if (current_sd > ufd)
        nfds = current_sd + 1;
      timeout.tv_sec = 0;
      timeout.tv_nsec = 100000000;
      status_sock = pselect (nfds, &readfds, &writefds, &exceptfds,
        &timeout, &sigmask);

      if (status_sock > 0)
      {
        // check for command input (unix socket activity pokes us to check)
        if (FD_ISSET (ufd, &readfds))
        {
          char cmdbuf [2];
          char gratuitous_data [2] = {C_OSDP_MARK, 0x00};;

          /*
            send a benign "message" up the line so that the other knows
            we're active.
            If the othere end is the CP this will motivate it to generate
            an osdp_POLL.
          */
          status = send_osdp_data (&context, (unsigned char *)gratuitous_data, 1);
          if (status != ST_OK)
            done_tls = 1;

          c1 = accept (ufd, NULL, NULL);
          if (c1 != -1)
          {
            status_io = read (c1, cmdbuf, sizeof (cmdbuf));
            if (status_io > 0)
            {
              close (c1);

              status = process_current_command (&context);
              if (status EQUALS ST_OK)
                preserve_current_command ();
              status = ST_OK;
            };
          };
        };

        if (FD_ISSET (current_sd, &readfds))
        {
          status = read_tcp_stream (&context, current_sd,
            &request_immediate_poll);
          if (context.verbosity > 8)
          {
            if (context.verbosity > 8)
            {
              char octet [3];
              sprintf(octet, " %02x", buffer [0]);
              strcat(trace_in_buffer, octet);
              dump_buffer_log(&context, "TCP Input:", osdp_buf.buf, osdp_buf.next);
            };
          };
        };
      };

      // idle processing

      if (status_sock EQUALS 0)
      {
        if ((context.role EQUALS OSDP_ROLE_CP) && context.authenticated)
        {
          if (osdp_timeout (&context, &last_time_check_ex) ||
            request_immediate_poll)
          {
            // if timer 0 expired dump the status
            if (context.timer[OSDP_TIMER_STATISTICS].status EQUALS OSDP_TIMER_RESTARTED)
              status = write_status (&context);

            // if "the timer" went off, do the background process

            if (context.timer[OSDP_TIMER_RESPONSE].status EQUALS OSDP_TIMER_RESTARTED)
              status = background (&context);

            if (context.timer[OSDP_TIMER_SUMMARY].status EQUALS OSDP_TIMER_RESTARTED)
              status = osdp_log_summary(&context);

            request_immediate_poll = 0;
          };
        };
      };
    }

    if (status != ST_OK)
    {
      if (status != ST_NET_INPUT_READY)
      {
        fprintf (stderr, "status %d\n", status);
          done_tls = 1;
      }
      else
      {
        status = ST_OK; // net input ready is OK
      };
    };
#if 0
    // if there was input, process the message
    if (status EQUALS ST_NET_INPUT_READY)
    {
      if (status != ST_OK)
        status = process_osdp_input (&osdp_buf);
      // if it's too short so far it'll be 'serial_in' so ignore that
      if (status EQUALS ST_SERIAL_IN)
        status = ST_OK;
    };
#endif
    if (status != ST_OK)
    {
      done_tls = 1;
    };
  } /* not done tls */;

  if (status != ST_OK)
    fprintf (stderr, "osdp-tls return status %d\n",
      status);

  return (status);

} /* main for osdp-net-client */


int tcp_connect(void)
{
  const char *PORT = "10001";
  int err, sd;
  struct sockaddr_in sa;


fprintf(stderr, "Connecting to %s Port %s\n",
  context.network_address, PORT);
fprintf(context.log, "Connecting to %s Port %s\n",
  context.network_address,
  PORT);
        /* connects to server
         */
        sd = socket(AF_INET, SOCK_STREAM, 0);

        memset(&sa, '\0', sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(atoi(PORT));
        inet_pton(AF_INET, context.network_address, &sa.sin_addr);

        err = connect(sd, (struct sockaddr *) &sa, sizeof(sa));
        if (err < 0) {
                fprintf(stderr, "Connect error\n");
                exit(1);
        }

        return sd;
}


int
  read_tcp_stream
    (OSDP_CONTEXT *ctx,
    int net_fd,
    int *poll)

{ /* read_tcp_stream */

  char buffer [1024];
  int current_length;
  int status;
  int status_io;


  status = ST_OK;
  status_io = read (net_fd, buffer, sizeof (buffer));
  if (status_io EQUALS 0)
    status = ST_OSDP_NET_CLOSED;
  if (status_io < 0)
    status = ST_OSDP_NET_ERROR;
  if (status EQUALS ST_OK)
  {
//    if (ctx->verbosity > 8)
    {
      int i;
      char octet [3];

      for(i=0; i<status_io; i++)
      {
        sprintf(octet, " %02x", (unsigned char) buffer [i]);
        strcat(trace_in_buffer, octet);
      };
    }
    ctx->bytes_received = ctx->bytes_received + status_io;

    // append buffer to osdp buffer
    if (ctx->authenticated)
    {
      current_length = status_io;
      request_immediate_poll = 0; 
      memcpy (osdp_buf.buf + osdp_buf.next, buffer, current_length);
      osdp_buf.next = osdp_buf.next + current_length;

      status = ST_NET_INPUT_READY;
    };
  };
  return (status);

} /* read_tcp_stream */


int
  send_osdp_data
    (OSDP_CONTEXT *ctx,
    unsigned char *buf,
    int lth)

{ /* send_osdp_data */

  int status;
  int status_io;


  status = ST_OK;
//  if (ctx->verbosity > 8)
  {
    int i;
    char octet [3];

    for(i=0; i<lth; i++)
    {
      sprintf(octet, " %02x", buf [i]);
      strcat(trace_out_buffer, octet);
    };
  }
  status_io = write (current_sd, buf, lth);

  ctx->bytes_sent = ctx->bytes_sent + lth;
  if (status_io != lth)
    status = -3;
  return (status);

} /* send_osdp_data */

