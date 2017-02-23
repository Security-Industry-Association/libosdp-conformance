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
#include <netdb.h>


#include <gnutls/gnutls.h>
#include <gnutls/x509.h>


#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>
#include <osdp-local-config.h>


int tcp_connect (void);
int _verify_certificate_callback(gnutls_session_t session);


char
  buffer [MAX_BUF + 1];
OSDP_TLS_CONFIG
  config;
OSDP_CONTEXT
  context;
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
time_t
  previous_time;
int
  request_immediate_poll;
char
  *tag;
gnutls_session_t
  tls_session;
gnutls_certificate_credentials_t
  xcred;

// cardholder nmber kludge

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
  char
    current_network_address [1024];
  int
    status;


  status = ST_OK;
  memset (config, 0, sizeof (*config));
  current_network_address [0] = 0;

  memset (&context, 0, sizeof (context));
  strcpy (context.init_parameters_path, "open-osdp-params.json");
  strcpy (context.log_path, "open-osdp.log");

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
config->listen_sap = 10443;


  m_idle_timeout = 30;

  strcpy (specified_passphrase, "speakFriend&3ntr");

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
  last_time_check = time (NULL);

  if (strlen (current_network_address) > 0)
    strcpy (context.network_address, current_network_address);

  sprintf (context.command_path, 
    OSDP_LCL_COMMAND_PATH, tag);

  context.authenticated = 1; // for now just say we're authenticated.

  if (status EQUALS ST_OK)
  {
    fprintf (stderr, "osdp-net-server(TLS version) %s\n",
      config->version);
    if (context.role EQUALS OSDP_ROLE_CP)
    {
      fprintf (stderr, "Role: CP\n");
      fprintf (stderr, "Server certificate: %s\n",
        config->cert_file);
      fprintf (stderr, "        Server key: %s\n",
        config->key_file);
    };
    if (context.role EQUALS OSDP_ROLE_PD)
    {
      fprintf (stderr, "Role: PD\n");
      fprintf (stderr, "CA list: %s\n",
        config->ca_file);
    };
  };

  return (status);

} /* initialize */

 
int
  init_tls_client
    (void)

{ /* init_tls_client */

  int
    ret;
  int
    sd;
  int
    status;
  int
    status_sock;


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
    gnutls_certificate_allocate_credentials (&xcred);

    /* sets the trusted cas file
     */
    gnutls_certificate_set_x509_trust_file(xcred, config.ca_file,
      GNUTLS_X509_FMT_PEM);
    gnutls_certificate_set_verify_function(xcred,
      _verify_certificate_callback);

    // specify my cert to send as a client

    if (!context.disable_certificate_checking)
      gnutls_certificate_set_x509_key_file (xcred, 
        "/opt/open-osdp/etc/client_cert.pem",
        "/opt/open-osdp/etc/client_key.pem",
        GNUTLS_X509_FMT_PEM); 

    /* Initialize TLS session 
     */
    gnutls_init(&tls_session, GNUTLS_CLIENT);

    fprintf (stderr, "fqdn is %s\n",
      context.fqdn);
    gnutls_session_set_ptr(tls_session, (void *) context.fqdn);

    gnutls_server_name_set(tls_session, GNUTLS_NAME_DNS, "my_host_name",
      strlen("my_host_name"));

    /* use default priorities */
    gnutls_set_default_priority (tls_session);

    /* put the x509 credentials to the current session
     */
    gnutls_credentials_set (tls_session, GNUTLS_CRD_CERTIFICATE, xcred);

    /* connect to the peer
     */
    sd = tcp_connect();

    gnutls_transport_set_int(tls_session, sd);
    gnutls_handshake_set_timeout(tls_session,
      GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

    /* Perform the TLS handshake
     */
    do {
      ret = gnutls_handshake (tls_session);
    }
    while (ret < 0 && gnutls_error_is_fatal(ret) == 0);

    if (ret < 0)
    {
      fprintf (stderr, "*** Handshake failed\n");
      gnutls_perror (ret);
      status = ST_OSDP_TLS_CLIENT_HANDSHAKE;
    }
    else
    {
      char *desc;

      desc = gnutls_session_get_desc (tls_session);
      printf("- Session info: %s\n", desc);
      gnutls_free(desc);
    }
  };
  if (status EQUALS ST_OK)
  {
    status_sock = fcntl (sd, F_SETFL,
    fcntl (sd, F_GETFL, 0) | O_NONBLOCK);
    if (status_sock EQUALS -1)
    {
      status = ST_OSDP_TLS_NONBLOCK;;
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

{ /* main for osdp-net-client */

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
  fd_set
    writefds;
  int
    ufd;


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
    done_tls = 0; // assume not done unless some bad status
    request_immediate_poll = 0;

    status = init_tls_client ();

#if TEMP_PASSPHRASE
    // for "phase 1" authentication, kludge it by sending a passphrase
    // send the passphrase to authenticate
    status = send_osdp_data (&context,
      (unsigned char *)specified_passphrase, plmax);
    if (status != ST_OK)
      done_tls = 1;
#endif

    if (status EQUALS 0)
    {
      request_immediate_poll = 0;
      while (!done_tls)
      {
        fflush (stdout); fflush (stderr); fflush (context.log);
        /*
          try reading TLS data.  If there isn't any there it will
          return the moral equivalent of E_AGAIN since we've set the FD
          to nonblocking.
        */
        status_tls = gnutls_record_recv (tls_session, buffer, MAX_BUF);
        if (status_tls EQUALS GNUTLS_E_AGAIN)
        {
          // look for file descriptor activity

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
            };
          }
          else
          {
            // pselect returned no fd's
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

          // idle processing

          if (status_sock EQUALS 0)
          {
            if ((context.role EQUALS OSDP_ROLE_CP) && context.authenticated)
            {
              if (osdp_timeout (&context, &last_time_check) ||
                request_immediate_poll)
              {
                status = background (&context);
                request_immediate_poll = 0;
              };
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
            if (context.verbosity > 8)
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
                  // saw an SOM, so normal incoming message
                  request_immediate_poll = 0; 

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
  return (ST_OK);

} /* send_osdp_data */


int
  tcp_connect
    (void)

{ /* tcp_connect */

  struct addrinfo
    *addr;
  const char *PORT =
    "10443";
  int err;
  int
    sd;
  struct sockaddr_in6
    *socket_address;
  int
    status_getaddr;


  fprintf (context.log, "Connecting to %s Port %s\n",
    context.network_address,
    PORT);

  // fill in address from FQDN.  Use the v4/v6 generic getaddrinfo call.
  status_getaddr = getaddrinfo (context.fqdn, PORT, NULL, &addr); 
  if (status_getaddr)
  {
    err = -1;
    fprintf (stderr, "getaddrinfo returned %s for %s\n",
      gai_strerror (status_getaddr), context.fqdn);
  }
  else
  {
    // now set up the socket.  "addr" had info from the address resolution
    // note tha getaddrinfo set up the port number ("service")
    sd = socket (addr->ai_family, addr->ai_socktype, addr->ai_protocol);

    socket_address = (struct sockaddr_in6 *)addr->ai_addr; 
    err = connect (sd, (struct sockaddr *)socket_address, addr->ai_addrlen);
  };
  if (err < 0) {
    fprintf(stderr, "Connect error\n");
    exit(1);
  }

  return sd;

} /* tcp_connect */


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

  if (context.disable_certificate_checking)
    return 0;
        if (status != 0)        /* Certificate is not trusted */
                return GNUTLS_E_CERTIFICATE_ERROR;

        /* notify gnutls to continue handshake normally */
        return 0;
}

