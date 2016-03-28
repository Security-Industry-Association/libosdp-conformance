/*
  osdp-tls - TLS implementation of OSDP protocol

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


int _verify_certificate_callback(gnutls_session_t session);


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
  sprintf (config->version, "v1.00-Build%d", OSDP_VERSION_BUILD);
  strcpy (config->cert_file, OSDP_LCL_SERVER_CERT);
  strcpy (config->key_file, OSDP_LCL_SERVER_KEY);
// sets port
config->listen_sap = 10443;

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

    // set trusted CA's, set up verify callback

    gnutls_certificate_set_x509_trust_file (x509_cred,
      "/opt/open-osdp/etc/ca_keys.pem", GNUTLS_X509_FMT_PEM);
    gnutls_certificate_set_verify_function (x509_cred,
      _verify_certificate_callback);

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
//      "PERFORMANCE:%SERVER_PRECEDENCE", NULL);
//"SERVER128:+PSK:+DHE_PSK:+SHA:+AES128_CBC",
"PERFORMANCE:%SERVER_PRECEDENCE:+PSK",
      NULL);

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
    gnutls_init (&(tls_session), GNUTLS_SERVER);
    gnutls_priority_set(tls_session, priority_cache);
    gnutls_credentials_set(tls_session, GNUTLS_CRD_CERTIFICATE, x509_cred);

    if (!context.disable_certificate_checking)
      gnutls_certificate_server_set_request (tls_session, GNUTLS_CERT_REQUIRE);
    sd = accept (listen_sd, (struct sockaddr *) &sa_cli, &client_len);
    fprintf (stderr, "- connection from %s, port %d\n",
      inet_ntop (AF_INET, &sa_cli.sin_addr, topbuf, sizeof (topbuf)),
      ntohs (sa_cli.sin_port));
    gnutls_transport_set_int (tls_session, sd);
    do {
      status_tls = gnutls_handshake (tls_session);
    } while (status_tls < 0 && gnutls_error_is_fatal (status_tls) == 0);
    if (status_tls < 0)
    {
      close (sd);
      gnutls_deinit (tls_session);
      fprintf (stderr, "*** Handshake has failed (%s)\n\n",
        gnutls_strerror (status_tls));
      status = ST_OSDP_TLS_HANDSHAKE;
      tls_session = NULL;
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
  int
    ufd;


  status = ST_OK;
  memset (sn, 0, sizeof (1024));
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

{ /* main for osdp-net-server */

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
  int
    status_tls;
  struct timespec
    timeout;
  int
    tls_current_length;
  int
    ufd;
  fd_set
    writefds;


  status = ST_OK;
  status = initialize (&config, argc, argv);
  if (status EQUALS ST_OK)
  {

    if (context.disable_certificate_checking)
      fprintf (stderr, "WARNING: Certificate checking disabled.\n");
    status = local_socket_setup (&ufd);
  };
  if (status EQUALS ST_OK)
  {
      status = init_tls_server ();
      if (status EQUALS 0)
      {
        done_tls = 0;
        request_immediate_poll = 0;
        while (!done_tls)
        {
          fflush (stdout); fflush (stderr);
          fflush (context.log);
          /*
            try reading TLS data.  If there isn't any there it will
            return the moral equivalent of E_AGAIN since we've set the FD
            to nonblocking.
          */
          status_tls = gnutls_record_recv (tls_session, buffer, MAX_BUF);
          if (status_tls EQUALS GNUTLS_E_AGAIN)
          {
            nfds = 0;
            FD_ZERO (&readfds);
            FD_ZERO (&writefds);
            FD_ZERO (&exceptfds);
            FD_SET (ufd, &readfds);
            nfds = ufd+1;
            timeout.tv_sec = 0;
            timeout.tv_nsec = 100000000;
            status_sock = pselect (nfds, &readfds, &writefds, &exceptfds,
              &timeout, &sigmask);

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
                  };
                };
              };
            };
          }
          else
          {
if(0)
{
  unsigned char raw_tls [8];
  memcpy (raw_tls, buffer, 8);
fprintf (stderr, "tls buf (%d) %2x %2x %2x\n",
  status_tls, raw_tls [0], raw_tls [1], raw_tls [2]);
};
            status = ST_OK; // assume tls read was ok for starters
            tls_current_length = status_tls;
            if (status_tls EQUALS 0)
              status = ST_OSDP_TLS_CLOSED;
            if (status_tls < 0)
              status = ST_OSDP_TLS_ERROR;
            if (status EQUALS ST_OK)
            {
              context.bytes_received = context.bytes_received + status_tls;

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
                    if (context.slow_timer)
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
request_immediate_poll = 0; // saw an SOM, so normal incoming message
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
          char gratuitous_data [2] = {C_OSDP_MARK, 0x00};;
          /*
            send a benign "message" up the line so that the CP knows we're
            active.
          */
          if (context.role EQUALS OSDP_ROLE_PD)
          {
            status = send_osdp_data (&context,
              (unsigned char *)gratuitous_data, 1);
            if (status != ST_OK)
              done_tls = 1;
          };
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
  send_osdp_data
    (OSDP_CONTEXT
      *context,
    unsigned char
      *buf,
    int
      lth)

{ /* send_osdp_data */

  gnutls_record_send (tls_session, buf, lth);
  context->bytes_sent = context->bytes_sent + lth;
  return (ST_OK);

} /* send_osdp_data */

/* This function will verify the peer's certificate, and check
 * if the hostname matches, as well as the activation, expiration dates.
 */
int _verify_certificate_callback(gnutls_session_t session)
{
        unsigned int status;
        int ret, type;
        const char *hostname;
        gnutls_datum_t out;


        /* read hostname */
        hostname = gnutls_session_get_ptr(session);

        /* This verification function uses the trusted CAs in the credentials
         * structure. So you must have installed one or more CA certificates.
         */

         /* The following demonstrate two different verification functions,
          * the more flexible gnutls_certificate_verify_peers(), as well
          * as the old gnutls_certificate_verify_peers3(). */
#if 1
        {
        gnutls_typed_vdata_st data[2];

        memset(data, 0, sizeof(data));

        data[0].type = GNUTLS_DT_DNS_HOSTNAME;
        data[0].data = (void*)hostname;

        data[1].type = GNUTLS_DT_KEY_PURPOSE_OID;
        data[1].data = (void*)GNUTLS_KP_TLS_WWW_SERVER;

        ret = gnutls_certificate_verify_peers(session, data, 2,
					      &status);
        }
#else
        ret = gnutls_certificate_verify_peers3(session, hostname,
					       &status);
#endif
        if (ret < 0) {
                printf("Error\n");
                return GNUTLS_E_CERTIFICATE_ERROR;
        }

        type = gnutls_certificate_type_get(session);

        ret =
            gnutls_certificate_verification_status_print(status, type,
                                                         &out, 0);
        if (ret < 0) {
                printf("Error\n");
                return GNUTLS_E_CERTIFICATE_ERROR;
        }

        printf("%s", out.data);

        gnutls_free(out.data);

        if (context.disable_certificate_checking)
          return 0;

        if (status != 0)        /* Certificate is not trusted */
          return GNUTLS_E_CERTIFICATE_ERROR;

        /* notify gnutls to continue handshake normally */
        return 0;
}

