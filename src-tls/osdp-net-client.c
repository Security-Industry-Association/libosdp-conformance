/*
  osdp-net-client - network (TLS) client implementation of OSDP protocol

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
#include <memory.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>


#include <gnutls/gnutls.h>
#include <gnutls/x509.h>


#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>


int tcp_connect (void);
int _verify_certificate_callback(gnutls_session_t session);


char
  buffer [MAX_BUF + 1];
OSDP_TLS_CONFIG
  config;
OSDP_CONTEXT
  context;
gnutls_dh_params_t
  dh_params;
OSDP_BUFFER
  osdp_buf;
OSDP_INTEROP_ASSESSMENT
  osdp_conformance;
OSDP_PARAMETERS
  p_card;
time_t
  previous_time;
struct sockaddr_in
  sa_serv;
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
  strcpy (config->ca_file, "/tester/current/etc/osdp_tls_ca_keys.pem");
// read json config file
// sets role
context.role = OSDP_ROLE_PD;
// sets port
config->listen_sap = 10443;
  m_idle_timeout = 30;
strcpy (config->cmd_dir, "/tester/current/results");
sprintf (command, "mkdir -p %s/history",
  config->cmd_dir);
system (command);
m_verbosity = 9;

  strcpy (specified_passphrase, "speakFriend&3ntr");

  signal (SIGHUP, signal_callback_handler);

  if (status EQUALS ST_OK)
    status = initialize_osdp (&context);
  context.role = OSDP_ROLE_PD;
  m_verbosity = 9;

  context.authenticated = 1; // for now just say we're authenticated.

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
    /* If client holds a certificate it can be set using the following:
     *
       gnutls_certificate_set_x509_key_file (xcred, 
         "cert.pem", "key.pem", 
         GNUTLS_X509_FMT_PEM); 
    */
    /* Initialize TLS session 
     */
    gnutls_init(&context.tls_session, GNUTLS_CLIENT);

    gnutls_session_set_ptr(context.tls_session, (void *) "perim-0000.example.com");

    gnutls_server_name_set(context.tls_session, GNUTLS_NAME_DNS, "my_host_name",
      strlen("my_host_name"));

    /* use default priorities */
    gnutls_set_default_priority (context.tls_session);

    /* put the x509 credentials to the current session
     */
    gnutls_credentials_set (context.tls_session, GNUTLS_CRD_CERTIFICATE, xcred);

    /* connect to the peer
     */
    sd = tcp_connect();

    gnutls_transport_set_int(context.tls_session, sd);
    gnutls_handshake_set_timeout(context.tls_session,
      GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

    /* Perform the TLS handshake
     */
    do {
      ret = gnutls_handshake (context.tls_session);
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

      desc = gnutls_session_get_desc (context.tls_session);
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
  main
    (int
      argc,
    char
      *argv [])

{ /* main for osdp-net-server */

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
    if (context.role EQUALS OSDP_ROLE_PD)
    {
      status = init_tls_client ();
      // send the passphrase to authenticate
      status = send_osdp_data (&context,
        (unsigned char *)specified_passphrase, plmax);
      if (status != ST_OK)
        done_tls = 1;
      if (status EQUALS 0)
      {
        done_tls = 0;
        while (!done_tls)
        {
          fflush (stdout); fflush (stderr); fflush (context.log);
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
            status = process_osdp_input (&osdp_buf);
          };
          if (status != ST_OK)
          {
            done_tls = 1;
          };
        } /* not done dls */;
      } /* tls initialized */;
    } /* role PD */;
  } /* ok initialize */;

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
        const char *SERVER = "127.0.0.1";
        int err, sd;
        struct sockaddr_in sa;

        /* connects to server
         */
        sd = socket(AF_INET, SOCK_STREAM, 0);

        memset(&sa, '\0', sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(atoi(PORT));
        inet_pton(AF_INET, SERVER, &sa.sin_addr);

        err = connect(sd, (struct sockaddr *) &sa, sizeof(sa));
        if (err < 0) {
                fprintf(stderr, "Connect error\n");
                exit(1);
        }

        return sd;
}




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

        if (status != 0)        /* Certificate is not trusted */
                return GNUTLS_E_CERTIFICATE_ERROR;

        /* notify gnutls to continue handshake normally */
        return 0;
}

