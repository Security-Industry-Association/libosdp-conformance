/*
  osdp-tls - TLS implementation of OSDP protocol

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


#include <gnutls/gnutls.h>


#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>


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
gnutls_dh_params_t
  dh_params;
long int
  last_time_check;
OSDP_BUFFER
  osdp_buf;
OSDP_INTEROP_ASSESSMENT
  osdp_conformance;
OSDP_PARAMETERS
  p_card;
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


int
  initialize
    (OSDP_TLS_CONFIG
      *config)

{ /* initialize */

  char
    command [1024];
  int
    status;


  status = ST_OK;
  memset (config, 0, sizeof (*config));
  strcpy (config->version, "v0.00-EP02");
  strcpy (config->cert_file, "/tester/current/etc/osdp_tls_server_cert.pem");
  strcpy (config->key_file, "/tester/current/etc/osdp_tls_server_key.pem");
// read json config file
// sets role
context.role = OSDP_ROLE_CP;
// sets port
config->listen_sap = 10443;
  m_idle_timeout = 30;
strcpy (config->cmd_dir, "/tester/current/results");
sprintf (command, "mkdir -p %s/history",
  config->cmd_dir);
system (command);

  strcpy (specified_passphrase, "speakFriend&3ntr");

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
    status = initialize_osdp (&context);
m_verbosity=9;

  if (status EQUALS ST_OK)
  {
    fprintf (stderr, "osdp-tls version %s\n",
      config->version);
    if (context.role EQUALS OSDP_ROLE_CP)
      fprintf (stderr, "Role: CP\n");
    if (context.role EQUALS OSDP_ROLE_PD)
      fprintf (stderr, "Role: PD\n");
    fprintf (stderr, "Server certificate: %s\n",
      config->cert_file);
    fprintf (stderr, "        Server key: %s\n",
      config->key_file);
  };

  return (status);

} /* initialize */

int
  init_tls_server
    (void)

{ /* init_tls_server */

  struct sockaddr_in
    sa_cli;
  socklen_t
    client_len;
  int
    listen_sd;
  int
    optval;
  gnutls_priority_t
    priority_cache;
  int
    sd;
  int
    status;
  int
    status_sock;
  int
    status_tls;
  char
    topbuf [1024];
  gnutls_certificate_credentials_t
    x509_cred;


  status = ST_OK;
  if (gnutls_check_version ("3.1.4") == NULL)
  {
    fprintf (stderr,
      "GnuTLS 3.1.4 or later is required\n");
      status = ST_OSDP_TLS_ERR;
  }
  if (status EQUALS ST_OK)
  {
    /* for backwards compatibility with gnutls < 3.3.0 */

    gnutls_global_init ();
    gnutls_certificate_allocate_credentials (&x509_cred);

    status_tls =
      gnutls_certificate_set_x509_key_file(x509_cred, config.cert_file,
      config.key_file, GNUTLS_X509_FMT_PEM);
    if (status_tls < 0)
      status = ST_OSDP_TLS_NOCERT;
  };
  if (status EQUALS ST_OK)
  {
    generate_dh_params ();
    gnutls_priority_init (&priority_cache,
      "PERFORMANCE:%SERVER_PRECEDENCE", NULL);
    gnutls_certificate_set_dh_params(x509_cred, dh_params);
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
    status_sock = bind (listen_sd, (struct sockaddr *) &sa_serv, sizeof(sa_serv));
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
    gnutls_init (&(context.tls_session), GNUTLS_SERVER);
    gnutls_priority_set(context.tls_session, priority_cache);
    gnutls_credentials_set(context.tls_session, GNUTLS_CRD_CERTIFICATE, x509_cred);
    sd = accept (listen_sd, (struct sockaddr *) &sa_cli, &client_len);
    fprintf (stderr, "- connection from %s, port %d\n",
      inet_ntop (AF_INET, &sa_cli.sin_addr, topbuf, sizeof (topbuf)),
      ntohs (sa_cli.sin_port));
    gnutls_transport_set_int (context.tls_session, sd);
    do {
      status_tls = gnutls_handshake (context.tls_session);
    } while (status_tls < 0 && gnutls_error_is_fatal (status_tls) == 0);
    if (status_tls < 0)
    {
      close (sd);
      gnutls_deinit (context.tls_session);
      fprintf (stderr, "*** Handshake has failed (%s)\n\n",
        gnutls_strerror (status_tls));
      status = ST_OSDP_TLS_HANDSHAKE;
      context.tls_session = NULL;
    }
  };
  if (status EQUALS ST_OK)
  {
    fprintf (stderr, "- Handshake was completed\n");

    status_sock = fcntl (sd, F_SETFL,
    fcntl (sd, F_GETFL, 0) | O_NONBLOCK);
    if (status_sock EQUALS -1)
    {
      status = ST_OSDP_TLS_NONBLOCK;;
    };
  };
  return (status);

} /* init_tls_server */


int
  main
    (int
      argc,
    char
      *argv [])

{ /* main for osdp-tls */

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
    status_sock;
  int
    status_tls;
  struct timespec
    timeout;
  int
    tls_current_length;
  fd_set
    writefds;


  status = ST_OK;
  status = initialize (&config);
  if (status EQUALS ST_OK)
  {
    if (context.role EQUALS OSDP_ROLE_CP)
    {
      status = init_tls_server ();
      if (status EQUALS 0)
      {
        done_tls = 0;
        while (!done_tls)
        {
          fflush (stdout); fflush (stderr);
          fflush (context.log);
          /*
            try reading TLS data.  If there isn't any there it will
            return the moral equivalent of E_AGAIN since we've set the FD
            to nonblocking.
          */
          status_tls = gnutls_record_recv (context.tls_session, buffer, MAX_BUF);
          if (status_tls EQUALS GNUTLS_E_AGAIN)
          {
            // look for HUP signal

            nfds = 0;
            FD_ZERO (&readfds);
            FD_ZERO (&writefds);
            FD_ZERO (&exceptfds);
            timeout.tv_sec = 0;
            timeout.tv_nsec = 100000000;
            status_sock = pselect (nfds, &readfds, &writefds, &exceptfds,
              &timeout, &sigmask);

            if (status_sock EQUALS 0)
            {
              status = ST_OK;
              if (osdp_timeout (&context, &last_time_check))
              {
                status = background (&context);
              };
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
      if (context.role EQUALS OSDP_ROLE_PD)
      {
        fprintf (stderr, "PD\n");
        status = -2;
      };
    };
  };
  if (status != ST_OK)
    fprintf (stderr, "osdp-tls return status %d\n",
      status);

  return (status);

} /* main for osdp-tls */

