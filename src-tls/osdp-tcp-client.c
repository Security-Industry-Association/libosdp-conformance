/*
  osdp-net-client - network (TLS) client implementation of OSDP protocol

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
  strcpy (context.log_path, "open_osdp.log");

  // if there's an argument it is the config file path
  if (argc > 1)
  {
    strcpy (context.init_parameters_path, argv [1]);

    // a second argument is the network address of the destination
    if (argc > 2)
      strcpy (current_network_address, argv [2]);
  };

  strcpy (config->version, "v0.00-EP02");
  strcpy (config->ca_file, OSDP_LCL_CA_KEYS);
// sets port
config->listen_sap = 10443;


  m_idle_timeout = 30;

  //strcpy (specified_passphrase, "speakFriend&3ntr");
  strcpy (specified_passphrase, "1234"); // OSDP_LCL_DEFAULT_PSK);
  plmax = 4;


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
  int snl;
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
  sprintf (sn, "/opt/open-osdp/run/%s/open-osdp-control", tag);
  snl = strlen (sn);

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

  int
    c1;
  int
    done_tls;
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
    status_sock;
  int
    status_tls;
  struct timespec
    timeout;
  int
    tls_current_length;
  fd_set
    writefds;
  int
    ufd;


  status = ST_OK;
  status = initialize (&config, argc, argv);
  if (status EQUALS ST_OK)
  {
    status = local_socket_setup (&ufd);
  };
  if (status EQUALS ST_OK)
  {
    done_tls = 0; // assume not done unless some bad status

    status = init_tls_client ();

    // for "phase 1" authentication, kludge it by sending a passphrase
    // send the passphrase to authenticate
    status = send_osdp_data (&context,
      (unsigned char *)specified_passphrase, plmax);
    if (status != ST_OK)
      done_tls = 1;

    if (status EQUALS 0)
    {
      while (!done_tls)
      {
        fflush (stdout); fflush (stderr); fflush (context.log);
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
                send a benign "message" up the line so that the other knows we're active.
                If the othere end is the CP this will motivate it to generate an osdp_POLL.
              */
              status = send_osdp_data (&context,
//                (unsigned char *)"!!!!!!!!!!!!!!!!!!!!!!!", 8);
(unsigned char *)gratuitous_data, 1);
              if (status != ST_OK)
                done_tls = 1;

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
                };
              };

              if (FD_ISSET (current_sd, &readfds))
              {
                status = read_tcp_stream (&context, current_sd,
                  &request_immediate_poll);
              };
            };
          };
        }

        if (0) {
          status = ST_OK; // assume tls read was ok for starters
          tls_current_length = status_tls;
          if (status_tls EQUALS 0)
            status = ST_OSDP_TLS_CLOSED;
          if (status_tls < 0)
            status = ST_OSDP_TLS_ERROR;
          if (status EQUALS ST_OK)
          {
            if (context.verbosity > 4)
              fprintf (stderr, "%d bytes received via TLS:\n",
                status_tls);

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
        // if there was input, process the message
        if (status EQUALS ST_NET_INPUT_READY)
        {

          if (status != ST_OK)
            status = process_osdp_input (&osdp_buf);
        };
        if (status != ST_OK)
        {
          done_tls = 1;
        };
      } /* not done dls */;
    } /* tls initialized */;
  };

  if (status != ST_OK)
    fprintf (stderr, "osdp-tls return status %d\n",
      status);

  return (status);

} /* main for osdp-net-client */


int tcp_connect(void)
{
        const char *PORT =
"10443";
// "5556";
//        const char *SERVER = "127.0.0.1";
        int err, sd;
        struct sockaddr_in sa;


fprintf (context.log, "Connecting to %s Port %s\n",
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

