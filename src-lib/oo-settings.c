/*
  oo-settings - json init file processing

  (C)Copyright 2017-2024 Smithee Solutions LLC

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
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>


#include <jansson.h>


#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>


extern OSDP_PARAMETERS p_card;


int
  oo_parse_config_parameters
    (OSDP_CONTEXT *ctx)

{ /* oo_parse_config_parameters */

  FILE *cmdf;
  char field [1024];
  int found_field;
  int i;
  char json_string [4096];
  json_t *root;
  int status;
  int status_io;
  extern unsigned char special_pdcap_list [];
  json_error_t status_json;
  char *test_command;
  char this_command [1024];
  char this_value [1024];
  json_t *value;
  int was_valid;


  status = -1;
  found_field = 0;
  cmdf = fopen (ctx->init_parameters_path, "r");
  if (cmdf != NULL)
  {
    status = ST_OK;
    memset (json_string, 0, sizeof (json_string));
    status_io = fread (json_string,
      sizeof (json_string [0]), sizeof (json_string), cmdf);
    if (status_io >= sizeof (json_string))
      status = ST_CMD_OVERFLOW;
    if (status_io <= 0)
      status = ST_CMD_UNDERFLOW;
  };
  if (status EQUALS ST_OK)
  {
    root = json_loads (json_string, 0, &status_json);
    if (!root)
    {
      fprintf (stderr, "JSON parser failed.  String was ->\n%s<-\n",
        json_string);
      status = ST_CMD_ERROR;
    };
  }; 

  // parameter "address"
  // this is the PD address in DECIMAL.

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    strcpy (field, "address");
    value = json_object_get (root, field);
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    char vstr [1024];
    int i;
    strcpy (vstr, json_string_value (value));
    sscanf (vstr, "%d", &i);
    p_card.addr = i;
    ctx->pd_address = i;
  };

  // parameter "bits"

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    strcpy (field, "bits");
    value = json_object_get (root, field);
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    char vstr [1024];
    int i;
    strcpy (vstr, json_string_value (value));
    sscanf (vstr, "%d", &i);
    p_card.bits = i;
  }; 

  // parameter "capability-custom"
  if (status EQUALS ST_OK)
  {
    value = json_object_get (root, "capability-custom");
    if (json_is_string (value))
    {
      unsigned short int i;
      status = osdp_string_to_buffer(ctx, (char *)json_string_value(value), special_pdcap_list, &i);
      ctx->special_pdcap = i/3;
    };
  };

  // parameter "capability-led"
  // value is 0 for not supported, 1 for supported

  if (status EQUALS ST_OK)
  {
    value = json_object_get (root, "capability-led");
    if (json_is_string (value))
    {
      sscanf (json_string_value(value), "%d", &i);
      ctx->configured_led = i;
    };
  };

  // parameter "capability-scbk-d"
  // value is 0 for not-supported, 1 for supported.

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    value = json_object_get (root, "capability-scbk-d");
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    char vstr [1024];
    int i;
    strcpy (vstr, json_string_value (value));
    sscanf (vstr, "%d", &i);
    if ((i EQUALS 1) || (i EQUALS 0))
    {
      ctx->configured_scbk_d = i;
    };
  };

  // parameter "capability-sounder"
  // value is 0 for none, 1 for on/off.  2 (timed) is not supported.

  // our default is that we DO have a sounder.

  if (ctx->role EQUALS OSDP_ROLE_PD)
  {
    if (ctx->verbosity > 3)
      fprintf(ctx->log, "Enabling sounder.\n");
    ctx->configured_sounder = 1;
  };

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    value = json_object_get (root, "capability-sounder");
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    char vstr [1024];
    int i;
    strcpy (vstr, json_string_value (value));
    sscanf (vstr, "%d", &i);
    if ((i EQUALS 1) || (i EQUALS 0))
    {
      ctx->configured_sounder = i;
    };
  };

  // parameter "capability-text"
  // value is 0 for none, 1 for 1 line of 16 characters.
  if (status EQUALS ST_OK)
  {
    found_field = 1;
    value = json_object_get (root, "capability-text");
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    char vstr [1024];
    int i;
    strcpy (vstr, json_string_value (value));
    sscanf (vstr, "%d", &i);
    if ((i EQUALS 1) || (i EQUALS 0))
    {
      ctx->configured_text = i;
    };
  };

  // parameter "check"
  // value is "CRC" or "CHECKSUM"
  if (status EQUALS ST_OK)
  {
    found_field = 1;
    value = json_object_get (root, "check");
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    char vstr [1024];
    strcpy (vstr, json_string_value (value));
    if (0 EQUALS strcmp(vstr, "CHECKSUM"))
      m_check = OSDP_CHECKSUM;
    else
      m_check = OSDP_CRC;
  }; 

  // parameter "disable_checking"

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    strcpy (field, "disable-checking");
    value = json_object_get (root, field);
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    char vstr [1024];
    int i;
    strcpy (vstr, json_string_value (value));
    sscanf (vstr, "%d", &i);
    if (i != 0)
      ctx->disable_certificate_checking = i;
  }; 

  // parameter "enable-biometrics"

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    strcpy (field, "enable-biometrics");
    value = json_object_get (root, field);
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    char vstr [1024];
    int i;
    strcpy (vstr, json_string_value (value));
    sscanf (vstr, "%d", &i);
    if ((i >= 0) && (i <= 2))
      ctx->pd_cap.enable_biometrics = i;
  }; 

  // parameter "enable-install"

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    strcpy (field, "enable-install");
    value = json_object_get (root, field);
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    ctx->secure_channel_use [OO_SCU_INST] = OO_SECURE_INSTALL;
  }; 

  // parameter "enable-poll"

  // set to 0 to start ACU but not start polling.
  if (status EQUALS ST_OK)
  {
    int poll_value;

    value = json_object_get (root, "enable-poll");
    if (value != NULL)
    {
      poll_value = -1;
      sscanf(json_string_value(value), "%d", &poll_value);
      if (poll_value EQUALS 0)
      {
        ctx->enable_poll = OO_POLL_NEVER;
        fprintf(ctx->log, "Initial polling disabled.\n");
      };
    };
  };

  // parameter "enable-secure-channel"

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    strcpy (field, "enable-secure-channel");
    value = json_object_get (root, field);
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    const char *vstring;

    ctx->enable_secure_channel = 1;
    ctx->secure_channel_use [OO_SCU_ENAB] = OO_SCS_USE_ENABLED;

    vstring = json_string_value(value);
    if (vstring)
    {
      if (0 EQUALS strcmp (vstring, "DEFAULT"))
      {
        ctx->enable_secure_channel = 2;
      };
    };
  }; 

  // parameter "enable-trace"
  if ((status EQUALS ST_OK) || (status EQUALS ST_CMD_INVALID))
  {
    found_field = 1;
    value = json_object_get (root, "enable-trace");
    if (!json_is_string (value))
      found_field = 0;
  };
  if ((ctx->verbosity > 0) && (found_field))
  {
    fprintf(ctx->log, "enabling protocol tracing\n");
    ctx->trace = 1;
  }; 

//firmware-version goes here

  // parameter "fqdn"

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    strcpy (field, "fqdn");
    value = json_object_get (root, field);
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    strcpy (ctx->fqdn, json_string_value (value));
  }; 

  // parameter "init-command"

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    strcpy (field, "init-command");
    value = json_object_get (root, field);
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    strcpy (ctx->init_command, json_string_value (value));
  }; 

  // parameter "inputs" (value must be in range 0 - OOSDP_DEFAULT_INPUTS)
  if (status EQUALS ST_OK)
  {
    found_field = 1;
    value = json_object_get (root, "inputs");
    if (!json_is_string (value))
      found_field = 0;
    if (found_field)
    {
      int count;
      char count_string [1024];
      strcpy (count_string, json_string_value (value));
      sscanf (count_string, "%x", &count);
      if ((count >=0) && (count <= OOSDP_DEFAULT_INPUTS))
        ctx->configured_inputs = count;
    }; 
  };

  // parameter "max-send"

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    strcpy (field, "max-send");
    value = json_object_get (root, field);
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    char vstr [1024];
    int i;
    strcpy (vstr, json_string_value (value));
    sscanf (vstr, "%d", &i);
    ctx->max_message = i;
  };

  // parameter "model-version"
  if (status EQUALS ST_OK)
  {
    value = json_object_get (root, "model-version");
    if (json_is_string (value))
    {
      int byte;
      char octetstring [3];

      memcpy (octetstring, json_string_value(value), 2);
      octetstring [2] = 0;
      sscanf (octetstring, "%x", &byte);
      ctx->model = byte;
      memcpy (octetstring, 2+json_string_value(value), 2);
      octetstring [2] = 0;
      sscanf (octetstring, "%x", &byte);
      ctx->version = byte;
    };
  };


  // parameter "network_address"
  // this is the other end of the TLS connection

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    strcpy (field, "network-address");
    value = json_object_get (root, field);
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    strcpy (ctx->network_address, json_string_value (value));
  };

  // parameter "oui"
  // this is the vendor id we send in MFG requests as a CP.
  // this is the vendor id we claim as a PD.

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    value = json_object_get (root, "oui");
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    char vstr [1024];
    int i;
    strcpy (vstr, json_string_value (value));

    // expected to be 6 characters, hexits.

    if (strlen(vstr) EQUALS 6)
    {
      char hexbyte [3];
      hexbyte[2] = 0;

      memcpy(hexbyte, vstr, 2); sscanf(hexbyte, "%2x", &i); ctx->vendor_code [0] = 0xff & i;
      memcpy(hexbyte, vstr+2, 2); sscanf(hexbyte, "%2x", &i); ctx->vendor_code [1] = 0xff & i;
      memcpy(hexbyte, vstr+4, 2); sscanf(hexbyte, "%2x", &i); ctx->vendor_code [2] = 0xff & i;
    };
  };

  // parameter "outputs" (value must be in range 0 - OOSDP_DEFAULT_OUTPUTS)

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    value = json_object_get (root, "outputs");
    if (!json_is_string (value))
      found_field = 0;
    if (found_field)
    {
      int count;
      char count_string [1024];
      strcpy (count_string, json_string_value (value));
      sscanf (count_string, "%x", &count);
      if ((count >=0) && (count <= OOSDP_DEFAULT_OUTPUTS))
        ctx->configured_outputs = count;
    }; 
  };

  // parameter "pd-filetransfer-recsize" is bytes to ask for in osdp_FTSTAT response (for a PD)

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    value = json_object_get (root, "pd-filetransfer-recsize");
    if (!json_is_string (value))
      found_field = 0;
    if (found_field)
    {
      int i;
      sscanf(json_string_value (value), "%d", &i);
      ctx->pd_filetransfer_payload = i;
    }; 
  };

  // port - port number at the other end of tls or tcp connection

  if (status EQUALS ST_OK)
  {
    value = json_object_get (root, "port");
    if (json_is_string (value))
    {
      int i;
      found_field = 1;
      sscanf(json_string_value(value), "%d", &i);
      ctx->listen_sap = i;
      fprintf(ctx->log, "Listen Service Access Point set to %d.\n", ctx->listen_sap);
    };
  };

  // privacy - 1 to not dump PII

  if (status EQUALS ST_OK)
  {
    value = json_object_get (root, "privacy");
    if (json_is_string (value))
    {
      int i;
      found_field = 1;
      sscanf(json_string_value(value), "%d", &i);
      ctx->privacy = i;
    };
  };

  // results - "keep" or "new", default is "new"

  if (status EQUALS ST_OK)
  {
    char v_string [1024];

    found_field = 1;
    value = json_object_get (root, "results");
    if (json_is_string (value))
    {
      strcpy(v_string, json_string_value(value));
      if (0 EQUALS strcmp(v_string, "keep"))
        ctx->keep_results = 1;
    };
  };

  // RND.A - value to use for my RND.A for the PD

  if (status EQUALS ST_OK)
  {
    value = json_object_get (root, "RND.A");
    if (json_is_string (value))
    {
      char rnd_string [1024];

      strcpy (rnd_string, json_string_value (value));
      if (strlen (rnd_string) EQUALS 16)
      {
        int byte;
        int i;
        char octetstring [3];
        for (i=0; i<16; i++)
        {
          memcpy (octetstring, rnd_string+(2*i), 2);
          octetstring [2] = 0;
          sscanf (octetstring, "%x", &byte);
          ctx->rnd_a [i] = byte;
        };
        fprintf(ctx->log, "RND.A configured: %s\n", rnd_string);
      };
    };
  };

  // RND.B - value to use for my RND.B for the PD

  if (status EQUALS ST_OK)
  {
    value = json_object_get (root, "RND.B");
    if (json_is_string (value))
    {
      {
        char rnd_b_string [1024];

        strcpy (rnd_b_string, json_string_value (value));
        if (strlen (rnd_b_string) EQUALS 16)
        {
          int byte;
          int i;
          char octetstring [3];
          for (i=0; i<16; i++)
          {
            memcpy (octetstring, rnd_b_string+(2*i), 2);
            octetstring [2] = 0;
            sscanf (octetstring, "%x", &byte);
            ctx->rnd_b [i] = byte;
          };
          fprintf(ctx->log, "RND.B configured: %s\n", rnd_b_string);
        };
      };
    };
  };

  // secure_channel (enabled or disabled)
  // secure_install (normal or install)
  // secure_transmit (relaxed or strict)

  // parameter "serial-number"
  // argument is a four byte hex value.

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    value = json_object_get (root, "serial-number");
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    unsigned char serial_number [4];
    unsigned short int serial_number_length;

    serial_number_length = sizeof(serial_number);
    status = osdp_string_to_buffer(ctx, (char *)json_string_value(value), serial_number, &serial_number_length);
    if (status EQUALS ST_OK)
      memcpy(ctx->serial_number, serial_number, sizeof(ctx->serial_number));
fprintf(stderr, "DEBUG: serial_number in context is now %02X %02X %02X %02X\n",
  ctx->serial_number [0], ctx->serial_number [1], ctx->serial_number [2], ctx->serial_number [3]);
  };

  // parameter "firmware-version"
  // argument is a three byte hex value.

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    value = json_object_get (root, "firmware-version");
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    unsigned char firmware_version [6];
    unsigned short int firmware_version_length;

    firmware_version_length = sizeof(firmware_version);
    status = osdp_string_to_buffer(ctx, (char *)json_string_value(value), firmware_version, &firmware_version_length);
    if (status EQUALS ST_OK)
      memcpy(ctx->fw_version, firmware_version, sizeof(ctx->fw_version));
  };

  // parameter "service-root" - where libosdp-conformance runs from
  // typically this is /opt/osdp-conformance.

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    value = json_object_get (root, "service-root");
    if (json_is_string (value))
      strcpy(ctx->service_root, json_string_value(value));
  };

  // parameter "timeout"
  // note this is timer 0 (zero)

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    strcpy (field, "timeout");
    value = json_object_get (root, field);
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    char vstr [1024];
    int i;
    strcpy (vstr, json_string_value (value));
    sscanf (vstr, "%d", &i);
    // inter-poll delay time is by convention "timer 0", in seconds.
    ctx->timer [0].i_sec = i;
  }; 

  // parameter "timeout-nsec" - timeout in nanoseconds.
  // note this is OSDP_TIMER_RESPONSE, the poll timer.

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    strcpy (field, "timeout-nsec");
    value = json_object_get (root, field);
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    char vstr [1024];
    long i;
    strcpy (vstr, json_string_value (value));
    sscanf (vstr, "%ld", &i);
    // inter-poll delay time is timer OSDP_TIMER_INTERPOLL (a/k/a "timer 0"), in seconds.
    ctx->timer [OSDP_TIMER_RESPONSE].i_nsec = i;
    ctx->timer [OSDP_TIMER_RESPONSE].i_sec = 0;
    fprintf(ctx->log, "inter-poll response timer set to %ld. nanoseconds\n", ctx->timer [OSDP_TIMER_RESPONSE].i_nsec);
  }; 

  // parameter "serial-read-timeout" - nanoseconds.
  // note this is the pselect timeout waiting for rs485 serial reads

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    strcpy (field, "serial-read-timeout");
    value = json_object_get (root, field);
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    char vstr [1024];
    long i;
    strcpy (vstr, json_string_value (value));
    sscanf (vstr, "%ld", &i);
    ctx->timer [OSDP_TIMER_SERIAL_READ].i_nsec = i;
    ctx->timer [OSDP_TIMER_RESPONSE].i_sec = 0;
  }; 

  // parameter "verbosity"

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    strcpy (field, "verbosity");
//fprintf (stderr, "look for %s\n", field);
    value = json_object_get (root, field);
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    char vstr [1024];
    int i;
    strcpy (vstr, json_string_value (value));
    sscanf (vstr, "%d", &i);
//fprintf (stderr, "processing value %s\n", vstr);
    ctx->verbosity = i;
  };

  // parameter "role"

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    strcpy (field, "role");
    value = json_object_get (root, field);
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    was_valid = 0;
    strcpy (this_command, json_string_value (value));
    test_command = "ACU";
    if (0 EQUALS strncmp (this_command, test_command, strlen (test_command)))
    {
      was_valid = 1;
      ctx->role = OSDP_ROLE_ACU;
    };
    test_command = "MON";
    if (0 EQUALS strncmp (this_command, test_command, strlen (test_command)))
    {
      was_valid = 1;
      ctx->role = OSDP_ROLE_MONITOR;
    };
    test_command = "PD";
    if (0 EQUALS strncmp (this_command, test_command, strlen (test_command)))
    {
      was_valid = 1;
      ctx->role = OSDP_ROLE_PD;
    };
    if (!was_valid)
    {
      fprintf (stderr, "Parse error: field %s\n",
        field);
      status = ST_PARSE_ERROR;
    };
  }; 

  // parameter "serial_device"

  if ((status EQUALS ST_OK) || (status EQUALS ST_CMD_INVALID))
  {
    strcpy (field, "serial-device");
    found_field = 1;
    value = json_object_get (root, field);
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    strcpy (this_value, json_string_value (value));
    strcpy (p_card.filename, this_value);
  }; 

  // parameter "serial_speed"
  if ((status EQUALS ST_OK) || (status EQUALS ST_CMD_INVALID))
  {
    strcpy (field, "serial-speed");
    found_field = 1;
    value = json_object_get (root, field);
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    strcpy (this_value, json_string_value (value));
    strcpy (ctx->serial_speed, this_value);
  }; 

  // parameter "raw_value"

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    strcpy (field, "raw-value");
    value = json_object_get (root, field);
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    strcpy (this_value, json_string_value (value));
    /*
      accumulate the "value" field into p_card.value
    */
    int i;
    int idata;
    int idx;
    int rem;
    char tmps [3];

    ctx->card_format = 1; // default to P/Data/P

    p_card.value_len = 0;
    idx=0;
    idata = 0;
    rem = strlen (this_value);
    while (rem > 0)
    {
      strncpy (tmps, this_value+idx, 2);
      idx = idx + 2;
      rem = rem - 2;
      tmps [2] = 0;
      sscanf (tmps, "%x", &i);
      p_card.value [idata] = i;
      idata ++;
      p_card.value_len ++;
    };
  }; 

  // parameter "pdcap-format"
  if ((status EQUALS ST_OK) || (status EQUALS ST_CMD_INVALID))
  {
    found_field = 1;
    value = json_object_get (root, "pdcap-format");
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    char vstr [1024];
    int i;
    strcpy (vstr, json_string_value (value));
    sscanf (vstr, "%d", &i);
    ctx->pdcap_select = i;
  }; 

  // parameter "version"

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    strcpy (field, "version");
    value = json_object_get (root, field);
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    char vstr [1024];
    int i;
    strcpy (vstr, json_string_value (value));
    sscanf (vstr, "%d", &i);
    ctx->capability_version = i;
  };

  // if checksum only don't do secure channel
  if (m_check EQUALS OSDP_CHECKSUM)
  {
    ctx->enable_secure_channel = OO_SCS_USE_DISABLED;
    ctx->secure_channel_use [OO_SCU_ENAB] = 0;
  };

  return (status);

} /* oo_parse_config_parameters */


int
  read_config
    (OSDP_CONTEXT
      *ctx)

{ /* read_config */

  int
    status;


  status = 0;
  ctx->cparm = PARAMETER_NONE;
  ctx->cparm_v = PARMV_NONE;

  status = oo_parse_config_parameters(ctx);

  if (p_card.value_len EQUALS 26)
  {
    // 26 bits is [0] p+f1 [1] f4 f3+c1 [2] c4 c4 [3] c4 c3+p
    //               1+1      8           3+5         7 1
    unsigned short int
      cardholder;
    unsigned short int
      facility;
    unsigned short int
      parity1;
    unsigned short int
      parity2;
    unsigned int
      value;
 
    facility = 0;
    facility = (0x01 & p_card.value [0]);
    facility = (facility << 7) | ((0xfe & p_card.value [1]) >> 1);
    value = (0x01 & p_card.value [0]);
    value = (value << 1) | p_card.value [1];
    value = (value << 3) | ((0xe0 & p_card.value [2]) >> 5);
    parity1 = calc_parity (value, 12, 0);

    cardholder = 0x01 & p_card.value [1];
    cardholder = (cardholder << 8) | p_card.value [2];
    cardholder = (cardholder << 7) | ((0xfe & p_card.value [3]) >> 1);
    value = (0x1f & p_card.value [2]);
    value = (value << 5) | ((0xfe & p_card.value [3]) >> 1);
    parity2 = calc_parity (value, 12, 1);
    
    fprintf (stderr, "Facility(%d) %03d:Cardholder(%d) %05d\n",
      parity1, facility, parity2, cardholder);
  };

  ctx->m_check = m_check;  // context field mimics old "m_check" global

  return (status);

} /* read_config */

