/*
  osdp-tcp-server - TCP-only version of osdp-net-server

  (C)Copyright 2015-2016 Smithee,Spelvin,Agnew & Plinge, Inc.

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
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <memory.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/un.h>


#include <gnutls/gnutls.h>
#include <gnutls/x509.h>


#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>
#include <osdp-local-config.h>


int
  read_tcp_stream
    (OSDP_CONTEXT
      *ctx,
    int
      net_fd,
    int
      *poll);


int
  current_sd; // current socket for tcp connection
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
OSDP_TLS_CONFIG
  config;
OSDP_CONTEXT
  context;
unsigned char
  creds_buffer_a [64*1024];
int
  creds_buffer_a_lth;
int
  creds_buffer_a_next;
int
  creds_buffer_a_remaining;
OSDP_OUT_CMD
  current_output_command [16];
gnutls_dh_params_t
  dh_params;
long int
  last_time_check;
int
  listen_sd;
OSDP_BUFFER
  osdp_buf;
OSDP_INTEROP_ASSESSMENT
  osdp_conformance;
OSDP_PARAMETERS
  p_card;
struct sockaddr_in
  sa_serv;
char
  *tag;
gnutls_session_t
  tls_session;


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
  int
    status;


  status = ST_OK;
  memset (config, 0, sizeof (*config));

  memset (&context, 0, sizeof (context));
  strcpy (context.init_parameters_path, "open-osdp-params.json");
  strcpy (context.log_path, "open_osdp.log");

  // if there's an argument it is the config file path
  if (argc > 1)
  {
    strcpy (context.init_parameters_path, argv [1]);
  };
  sprintf (config->version, "v%d.%d-Build%d",
    OSDP_VERSION_MAJOR, OSDP_VERSION_MINOR, OSDP_VERSION_BUILD);
  // sets port
  config->listen_sap = 10001;

  m_idle_timeout = 30;

  strcpy (specified_passphrase, OSDP_LCL_DEFAULT_PSK);

  if (status EQUALS ST_OK)
    status = initialize_osdp (&context);
  if (context.role EQUALS OSDP_ROLE_CP)
    tag = "CP";
  else
    tag = "PD";

  // initialize my current pid
  {
    pid_t
      my_pid;

    my_pid = getpid ();
    context.current_pid = my_pid;
    sprintf (command, OSPD_LCL_SET_PID_TEMPLATE,
      tag, my_pid);
    system (command);
  };

  last_time_check = time (NULL);
sprintf (context.command_path, 
  OSDP_LCL_COMMAND_PATH, tag);
context.current_menu = OSDP_MENU_TOP;

  if (status EQUALS ST_OK)
  {
    fprintf (stderr, "osdp-tcp version %s\n",
      config->version);
    if (context.role EQUALS OSDP_ROLE_CP)
      fprintf (stderr, "Role: CP\n");
    if (context.role EQUALS OSDP_ROLE_PD)
      fprintf (stderr, "Role: PD\n");
  };

  return (status);

} /* initialize */


int
  init_tcp_server
    (void)

{ /* init_tcp_server */

  struct sockaddr_in
    sa_cli;
  socklen_t
    client_len;
  int
    optval;
  int
    sd;
  int
    status;
  int
    status_sock;
  char
    topbuf [1024];


  status = ST_OK;
  sd = 0;
  if (status EQUALS ST_OK)
  {
    listen_sd = socket (AF_INET, SOCK_STREAM, 0);
    if (listen_sd EQUALS -1)
      status = ST_OSDP_TLS_SOCKET_ERR;;
  };
  if (status EQUALS ST_OK)
  {
    optval = 1;
    memset (&sa_serv, '\0', sizeof(sa_serv));
    sa_serv.sin_family = AF_INET;
    sa_serv.sin_addr.s_addr = INADDR_ANY;
    sa_serv.sin_port = htons(config.listen_sap);
    setsockopt (listen_sd, SOL_SOCKET, SO_REUSEADDR, (void *) &optval,
      sizeof(int));
    status_sock = bind (listen_sd, (struct sockaddr *) &sa_serv,
      sizeof(sa_serv));
    if (status_sock EQUALS -1)
      status = ST_OSDP_TLS_BIND_ERR;
  };
  if (status EQUALS ST_OK)
  {
    status_sock = listen (listen_sd, 1024);
    if (status_sock EQUALS -1)
      status = ST_OSDP_TLS_LISTEN_ERR;;
  };
  if (status EQUALS ST_OK)
  {
    fprintf (stderr,
      "Server ready. Listening to port '%d'.\n\n", config.listen_sap);

    client_len = sizeof (sa_cli);
  };
  if (status EQUALS ST_OK)
  {
    sd = accept (listen_sd, (struct sockaddr *) &sa_cli, &client_len);
    fprintf (stderr, "- connection from %s, port %d\n",
      inet_ntop (AF_INET, &sa_cli.sin_addr, topbuf, sizeof (topbuf)),
      ntohs (sa_cli.sin_port));
  };
  if (status EQUALS ST_OK)
  {
    fprintf (stderr, "- TCP connection active.\n");

    status_sock = fcntl (sd, F_SETFL,
    fcntl (sd, F_GETFL, 0) | O_NONBLOCK);
    if (status_sock EQUALS -1)
    {
      status = ST_OSDP_TLS_NONBLOCK;;
    };
  };
  current_sd = sd;
  return (status);

} /* init_tcp_server */


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
  int
    ufd;


  status = ST_OK;
  memset (sn, 0, sizeof (1024));
  sprintf (sn, "/opt/open-osdp/run/%s/open-osdp-control", tag);

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

{ /* main for osdp-net-server */

  int
    c1;
  int
    done_tls;
  fd_set
    exceptfds;
  char
    gratuitous_data [2] = {C_OSDP_MARK, 0x00};
  fd_set
    readfds;
  int
    nfds;
  int
    request_immediate_poll;
  const sigset_t
    sigmask;
  int
    status;
  int
    status_io;
  int
    status_sock;
  struct timespec
    timeout;
  int
    ufd;
  fd_set
    writefds;


  status = ST_OK;
  request_immediate_poll = 0;
  status = initialize (&config, argc, argv);
  if (status EQUALS ST_OK)
  {
    status = local_socket_setup (&ufd);
  };
  if (status EQUALS ST_OK)
  {
    status = init_tcp_server ();
    if (status EQUALS ST_OK)
    {
      fprintf (stderr, "Specified passphrase: %s(%d)\n",
        specified_passphrase, plmax);
      done_tls = 0;
      request_immediate_poll = 0;
      while (!done_tls)
      {
        fflush (stdout); fflush (stderr);
        fflush (context.log);
        {
        nfds = 0;
        nfds = ufd+1;
        if (current_sd > ufd)
          nfds = current_sd + 1;
        FD_ZERO (&readfds);
        FD_SET (current_sd, &readfds);
        FD_ZERO (&writefds);
        FD_ZERO (&exceptfds);
        FD_SET (ufd, &readfds);
        timeout.tv_sec = 0;
        timeout.tv_nsec = 100000000;
        status_sock = pselect (nfds, &readfds, &writefds, &exceptfds,
          &timeout, &sigmask);

        if (context.verbosity > 9)
          if (context.verbosity > 9) if (status_sock > 0)
          {
            fprintf (stderr, "pselect %d\n",
              status_sock);
            if (FD_ISSET (current_sd, &readfds))
              fprintf (stderr, "TCP FD ready\n");
          };
        if (status_sock EQUALS 0)
        {
              status = ST_OK;

              if (context.role EQUALS OSDP_ROLE_CP)
              {
                /*
                  if timed out due to inactivity or requested,
                  run the background poller.
                */
                if ((osdp_timeout (&context, &last_time_check)) ||
                  (request_immediate_poll))
                {
                  if (context.authenticated)
                    status = background (&context);
                  request_immediate_poll = 0;
                };
              };
            };
            if (status_sock > 0)
            {
              // chk for cmd (unix socket activity pokes us to check)

              if (FD_ISSET (ufd, &readfds))
              {
                char cmdbuf [2];
                fprintf (stderr, "ufd socket was selected in READ (%d)\n",
                  ufd);
                c1 = accept (ufd, NULL, NULL);
                if (c1 != -1)
                {
                  status_io = read (c1, cmdbuf, sizeof (cmdbuf));
                  if (status_io > 0)
                  {
                    fprintf (stderr, "cmd buf %02x%02x\n",
                      cmdbuf [0], cmdbuf [1]);
                    close (c1);

                    status = process_current_command ();
                    if (status EQUALS ST_OK)
                      preserve_current_command ();
                    status = ST_OK;
                    /*
                      send a benign "message" up the line so that the CP knows we're
                      active.
                    */
                    if (context.role EQUALS OSDP_ROLE_PD)
                    {
                      status = send_osdp_data (&context,
                       (unsigned char *)gratuitous_data, 1);
                    };
                  };
                };
              };

              if (FD_ISSET (current_sd, &readfds))
              {
                status = read_tcp_stream (&context, current_sd, &request_immediate_poll);
              };

            };
          }
          if (status != ST_OK)
          {
            if (status != ST_NET_INPUT_READY)
            {
              fprintf (stderr, "status %d\n", status);
              done_tls = 1;
            };
          };
        // if there was input, process the message
        if (status EQUALS ST_NET_INPUT_READY)
        {
          status = process_osdp_input (&osdp_buf);
        };
        if (status != ST_OK)
        {
          done_tls = 1;
        };
      };
    };
  };
  if (status != ST_OK)
    fprintf (stderr, "osdp-tls return status %d\n",
      status);

  return (status);

} /* main for osdp-tls */


int
  read_tcp_stream
    (OSDP_CONTEXT
      *ctx,
    int
      net_fd,
    int
      *poll)

{ /* read_tcp_stream */

  char
    buffer [1024];
  int
    current_length;
  int
    done;
  int
    i;
  int
    lth;
  int
    request_immediate_poll;
  int
    status;
  int
    status_io;
//current_passphrase
//passphrase_length
///plmax
//specified_passphrase


  status = ST_OK;
  request_immediate_poll = 0;
  status_io = read (net_fd, buffer, sizeof (buffer));
  if (status_io EQUALS 0)
    status = ST_OSDP_NET_CLOSED;
  if (status_io < 0)
    status = ST_OSDP_NET_ERROR;
  if (status EQUALS ST_OK)
  {
    ctx->bytes_received = ctx->bytes_received + status_io;

    // if we have enough data look for the passphrase
    if (!ctx->authenticated)
    {
      if (passphrase_length < plmax)
      {
        lth = status_io;
        if ((passphrase_length + lth) > plmax)
          lth = plmax - passphrase_length;
        memcpy (current_passphrase+passphrase_length, buffer, lth);
        if (0 EQUALS
          memcmp (current_passphrase, specified_passphrase, plmax))
            ctx->authenticated = 1;
      };
    };

    // append buffer to osdp buffer
    if (ctx->authenticated)
    {
      // while first not SOM skip until SOM
      i = 0;
      current_length = status_io;
      done = 0;
      while (!done)
      {
        if (buffer [i] != C_SOM)
        {
          if (ctx->slow_timer)
          {
            fprintf (stderr, "!SOM %02x\n",
              buffer [i]);
            request_immediate_poll = 1;
          };
          i++;
          current_length --;
        }
        else
        {
          // saw an SOM, so normal incoming message
          request_immediate_poll = 0; 
          memcpy (osdp_buf.buf + osdp_buf.next,
            buffer+i, current_length);
          osdp_buf.next = osdp_buf.next + current_length;
          status = ST_NET_INPUT_READY;
          done = 1;
        };
        if (i EQUALS status_io)
          done = 1;
      }
    };
  };
  *poll = request_immediate_poll;
  return (status);

} /* read_tcp_stream */


int
  send_osdp_data
    (OSDP_CONTEXT
      *context,
    unsigned char
      *buf,
    int
      lth)

{ /* send_osdp_data */

  int
    status;
  int
    status_io;

  status = ST_OK;
  status_io = write (current_sd, buf, lth);

  context->bytes_sent = context->bytes_sent + lth;
  if (status_io != lth)
    status = -3;
  return (status);

} /* send_osdp_data */

