/*
  oo_util2 - more open-osdp util routines

  (C)Copyright 2017-2020 Smithee Solutions LLC
  (C)Copyright 2014-2017 Smithee,Spelvin,Agnew & Plinge, Inc.

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


extern OSDP_INTEROP_ASSESSMENT osdp_conformance;
extern OSDP_CONTEXT context;
extern OSDP_PARAMETERS p_card;
char tlogmsg [1024];


void start_element (void *data, const char *element, const char **attribute);


int
  background
    (OSDP_CONTEXT *context)

{ /* background */

  int current_length;
  int send_secure_poll;
  int send_poll;
  int status;
  unsigned char sec_blk [1];


  status = ST_OK;
//  send_poll = 1;  // assume we're supposed to poll
  send_poll = 0;
  send_secure_poll = 0;

  // if we're not in a file transfer...
  // if we're not set up with an operational secure channel
  // if we're not enabled for secure channel
  // yeah, poll

  if (context->role EQUALS OSDP_ROLE_ACU)
    if (context->xferctx.total_length EQUALS 0)
      if (context->secure_channel_use [OO_SCU_ENAB] != OO_SCS_OPERATIONAL)
        if (!(context->secure_channel_use [OO_SCU_ENAB] & 0x80))
          send_poll = 1;

  // if we're in secure channel and the other conditions, do a secure poll

  if (context->role EQUALS OSDP_ROLE_ACU)
  {
    if (context->xferctx.total_length EQUALS 0)
    {
      if (context->secure_channel_use [OO_SCU_ENAB] EQUALS OO_SCS_OPERATIONAL)
      {
        send_secure_poll = 1;
      };
    };
  };

  // if waiting for response to last message then do NOT poll

  if (send_poll)
    if (osdp_awaiting_response(context))
    {
      send_poll = 0;
    };

    // if polling is not enabled do not send one
    // (resume is used to start at a given command)

    if ((OO_POLL_NEVER EQUALS (context->enable_poll)) ||
      (OO_POLL_RESUME EQUALS (context->enable_poll)))
      send_poll = 0;
  if (send_poll)
  {
    current_length = 0;
    status = send_message (context,
      OSDP_POLL, p_card.addr, &current_length, 0, NULL); 
  };
  if (send_secure_poll)
  {
    status = send_secure_message(context, OSDP_POLL, p_card.addr,
      &current_length, 0, NULL, OSDP_SEC_SCS_15, 0, sec_blk);
  };

  return (status);

} /* background */


int
  calc_parity
    (unsigned short
      value,
     int
       length,
     int
       sense)

{
  int
    i;
  unsigned short int
    mask_bit;
  int
    results;

  results = 0;
  mask_bit = 1;
  for (i=0; i<length; i++)
  {
    if (mask_bit & value)
      results++;
    mask_bit = mask_bit * 2;
  };
  results= results & 1;
  if (!sense)
  {
    if (!results)
      results = 1;
  }
  else
  {
    if (results)
      results = 1;
  };
  return (results);
}


unsigned char
  checksum
    (unsigned char
      *msg,
    int
      length)
{
  unsigned char
    checksum;
  int
    i;
  int
    whole_checksum;


  whole_checksum = 0;
  for (i=0; i<length; i++)
  {
    whole_checksum = whole_checksum + msg [i];
    checksum = ~(0xff & whole_checksum)+1;
  };
  return (checksum);

} /* checksum */


int
  fasc_n_75_to_string
    (char * s, long int *sample_1)

{ /* fasc_n_75_to_string */

  int
    status;
   char
    ret_string [1024];


  status = 0;
  {
    unsigned long long tmp1_64;
    unsigned long long tmp3_64;

{
  int j;
  char * p;
unsigned long long int z64;
  p = (char *)sample_1;
  tmp1_64 = 0;
  for (j=0; j<8; j++)
  {
    tmp1_64 = tmp1_64 << 8;
    tmp1_64 = tmp1_64 | (0xff & ((unsigned int)*(p+j)));
    tmp1_64 = tmp1_64 | (0xff & ((unsigned int)*(p+j)));
  };
  tmp3_64 = 0xff & (unsigned int)*(p+8);
  tmp3_64 = tmp3_64 <<(32+24);
z64 = (0xff & (unsigned int)*(p+9));
  tmp3_64 = tmp3_64 | (z64 << (32+16));
};

    long long v1,v2,v3,v4;

    v1 = (0x7ffe000000000000ll & tmp1_64) >> 49;
    v2 = (0x0001fff800000000ll & tmp1_64) >> 35;
    v3 = (0x00000007ffff8000ll & tmp1_64) >> 15;
    v4 = (0x0000000000007fffll & tmp1_64) << 10;
    v4 = v4 | ((0xffc0000000000000ll & tmp3_64) >> 54);

    sprintf (ret_string,
"Agency Code: %lld System Code: %lld Card Number: %lld Expiration: %lld",
      v1, v2, v3, v4);
  };

  strcpy (s, ret_string);
  return (status);

} /* fasc_n_75_to_string */


int
  next_sequence
    (OSDP_CONTEXT
      *ctx)

{ /* next_sequence */

  static int
    current_sequence;
  int
    do_increment;


  do_increment = 1;
  if (ctx->last_response_received != OSDP_NAK)
    do_increment = 1;
  else
  {
    // 20181213 clarification: if it was a NAK and we were to RETRY then don't increment the sequence number.

    // this is not a retry this will be for a new message

    // if the last thing was a NAK and a CRC error don't increment
    if (0) // (ctx->last_nak_error EQUALS OO_NAK_CHECK_CRC)
      do_increment = 0;

    // if the last thing was a NAK for sequence error reset sequence to 0
    if (ctx->last_nak_error EQUALS OO_NAK_SEQUENCE)
      ctx->next_sequence = 0;
  };
  
  if (do_increment)
  {
    // the current value is returned. might be 0 (if this is the first message)

    current_sequence = ctx->next_sequence;

    // increment sequence, skipping 1 (per spec)

    ctx->next_sequence++;
    if (ctx->next_sequence > 3)
      ctx->next_sequence = 1;

    // if polling is to resume enable it now
    if (OO_POLL_RESUME EQUALS (ctx->enable_poll))
      ctx->enable_poll = OO_POLL_ENABLED;
    if (OO_POLL_NEVER EQUALS (ctx->enable_poll))
      ctx->next_sequence = 0;

    // if they disabled polling don't increment the sequence number
    if (OO_POLL_NEVER EQUALS (ctx->enable_poll))
      ctx->next_sequence = 0;
  }
  else
  {
    if (ctx->verbosity > 2)
      fprintf (ctx->log, "Last in was NAK (E=%d) Seq now %d\n",
        ctx->last_nak_error, ctx->next_sequence);
  };
  return (current_sequence);

} /* next_sequence */


int
  osdp_timeout
    (OSDP_CONTEXT *ctx,
    struct timespec *last_time_ex)

{ /* osdp_timeout */

  long delta_nanotime;
  int delta_time;
  int i;
  int return_value;
  int status_posix;
  struct timespec time_spec;


  return_value = 0;
  status_posix = clock_gettime (CLOCK_REALTIME, &time_spec);
  if (status_posix == -1)
    ctx->last_errno = errno;

  // update timers (new style)


  for (i=0; i<ctx->timer_count; i++)
  {
    if (ctx->timer [i].status != OSDP_TIMER_STOPPED)
    {
      ctx->timer [i].status = OSDP_TIMER_RUNNING;
      if (ctx->timer [i].i_sec > 0)
      {
        // it's a 1-second resolution timer

        delta_time = time_spec.tv_sec - last_time_ex->tv_sec;
        if (delta_time > 0)
        {
          if (ctx->timer [i].current_seconds >= delta_time)
            ctx->timer [i].current_seconds =
              ctx->timer [i].current_seconds - delta_time;
          else
            ctx->timer [i].current_seconds =  0;
        };
        if (ctx->timer [i].current_seconds == 0)
        {
          ctx->timer [i].status = OSDP_TIMER_STOPPED;
          return_value = 1;
          if (ctx->timer [i].timeout_action EQUALS OSDP_TIMER_RESTART_ALWAYS)
          {
            ctx->timer [i].current_seconds = ctx->timer [i].i_sec;
            ctx->timer [i].status = OSDP_TIMER_RESTARTED;
          };
        };
      };
      if (ctx->timer [i].i_nsec > 0)
      {
        // it's a nanosecond resolution timer

        delta_nanotime = time_spec.tv_nsec - last_time_ex->tv_nsec;
        if (delta_nanotime > 0)
        {
          if (ctx->timer [i].current_nanoseconds >= delta_nanotime)
            ctx->timer [i].current_nanoseconds =
              ctx->timer [i].current_nanoseconds - delta_nanotime;
          else
            ctx->timer [i].current_nanoseconds =  0;
        };
        if (ctx->timer [i].current_nanoseconds == 0)
        {
if (i != OSDP_TIMER_RESPONSE)
  fprintf(stderr, "%d (n) stopped not %d\n", i, OSDP_TIMER_RESPONSE);
          ctx->timer [i].status = OSDP_TIMER_STOPPED;
          return_value = 1;
          if (ctx->timer [i].timeout_action EQUALS OSDP_TIMER_RESTART_ALWAYS)
          {
            ctx->timer [i].current_nanoseconds = ctx->timer [i].i_nsec;
            ctx->timer [i].status = OSDP_TIMER_RESTARTED;
          };
        };
      };
    }; // timer not stopped
  };
  last_time_ex->tv_sec = time_spec.tv_sec;;
  last_time_ex->tv_nsec = time_spec.tv_nsec;;
  return (return_value);

} /* osdp_timeout */
   

int
  oo_parse_config_parameters
    (OSDP_CONTEXT
      *ctx)

{ /* oo_parse_config_parameters */

  FILE *cmdf;
  char field [1024];
  int found_field;
  char json_string [4096];
  json_t *root;
  int status;
  int status_io;
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
  // this is the PD address.

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
    strcpy (field, "disable_checking");
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

  // parameter "init_command"

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    strcpy (field, "init_command");
    value = json_object_get (root, field);
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    strcpy (ctx->init_command, json_string_value (value));
  }; 

  // parameter  "key" ("DEFAULT" or a 16-byte hex value)

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    strcpy (field, "key");
    value = json_object_get (root, field);
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    char key_value [1024];

    strcpy (key_value, json_string_value (value));
    ctx->enable_secure_channel = 1;
    if (0 EQUALS strcmp (key_value, "DEFAULT"))
      ctx->enable_secure_channel = 2;
    if (strlen (key_value) EQUALS 32)
    {
      int byte;
      int i;
      char octetstring [3];
      for (i=0; i<16; i++)
      {
        memcpy (octetstring, key_value+(2*i), 2);
        octetstring [2] = 0;
        sscanf (octetstring, "%x", &byte);
        ctx->current_scbk [i] = byte;
      };
      fprintf(ctx->log, "Key configured: %s\n", key_value);
      ctx->secure_channel_use [OO_SCU_KEYED] = OO_SECPOL_KEYLOADED;
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

  // parameter "network_address"
  // this is the other end of the TLS connection

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    strcpy (field, "network_address");
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
      memcpy(ctx->MFG_oui, ctx->vendor_code, sizeof(ctx->MFG_oui));
    };
  };

  // poll

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    strcpy (field, "poll");
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
    p_card.poll = i;
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
    context.timer [0].i_sec = i;
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
    context.timer [OSDP_TIMER_RESPONSE].i_nsec = i;
    context.timer [OSDP_TIMER_RESPONSE].i_sec = 0;
fprintf(stderr, "inter-poll response timer set to %ld. nanoseconds\n",
  context.timer [OSDP_TIMER_RESPONSE].i_nsec);
  }; 

  // parameter "verbosity"

  if (status EQUALS ST_OK)
  {
    found_field = 1;
    strcpy (field, "verbosity");
fprintf (stderr, "look for %s\n",
  field);
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
fprintf (stderr, "processing value %s\n",
  vstr);
    context.verbosity = i;
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
      context.role = OSDP_ROLE_ACU;
    };
    test_command = "MON";
    if (0 EQUALS strncmp (this_command, test_command, strlen (test_command)))
    {
      was_valid = 1;
      context.role = OSDP_ROLE_MONITOR;
    };
    test_command = "PD";
    if (0 EQUALS strncmp (this_command, test_command, strlen (test_command)))
    {
      was_valid = 1;
      context.role = OSDP_ROLE_PD;
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
    strcpy (field, "serial_device");
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
    strcpy (field, "serial_speed");
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
    strcpy (field, "raw_value");
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

  // parameter "enable-trace"
  if ((status EQUALS ST_OK) || (status EQUALS ST_CMD_INVALID))
  {
    found_field = 1;
    value = json_object_get (root, "enable-trace");
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    fprintf(ctx->log, "enabling protocol tracing\n");
    ctx->trace = 1;
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
    context.pdcap_select = i;
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
//  status = parse_xml (test_buffer, sizeof (test_buffer));

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

  return (status);

} /* read_config */


int
  send_bio_read_template
    (OSDP_CONTEXT
      *ctx)

{ /* send_bio_read_template */

  int
    current_length;
  unsigned char
    param [4];
  int
    status;


  param [0] = 0; // reader 0
  param [1] = 0; // default bio type
  param [2] = 2; // ANSI/INCITS 378 Fingerprint template "49"
  param [3] = 0xFF;

  current_length = 0;
  status = send_message (ctx,
    OSDP_BIOREAD, p_card.addr, &current_length, sizeof (param), param);
  if (ctx->verbosity > 2)
    fprintf (stderr, "Request bio read\n");
  return (status);

} /* send_bio_read_template */


int
  send_comset
    (OSDP_CONTEXT
      *ctx,
    unsigned char
      pd_address,
    unsigned char
      new_address,
    char
      *speed_string)

{ /* send_comset */

  int
    current_length;
  int
    new_speed;
  unsigned char
    param [5];
  int
    status;


  sscanf (speed_string, "%d", &new_speed);
  param [0] = new_address; // byte 0: new address
  param [1] =        new_speed & 0xff;
  param [2] =     (new_speed & 0xff00) >> 8;
  param [3] =   (new_speed & 0xff0000) >> 16;
  param [4] = (new_speed & 0xff000000) >> 24;
  current_length = 0;
  osdp_conformance.cmd_comset.test_status = OCONFORM_EXERCISED;
  status = send_message_ex(ctx, OSDP_COMSET, pd_address, &current_length,
    sizeof(param), param, OSDP_SEC_SCS_17, 0, NULL);

  sprintf (ctx->serial_speed, "%d", new_speed);
  if (ctx->verbosity > 2)
    fprintf (stderr, "Diag - set com: addr to %02x speed to %s.\n",
      param [0], ctx->serial_speed);
  ctx->new_address = param [0];
  p_card.addr = ctx->new_address;
  status = init_serial (ctx, p_card.filename);
  return (status);

} /* send_comset */


/*
  send_message - send an OSDP message

  assumes command is a valid value.
*/

int
  send_message
    (OSDP_CONTEXT *context,
    int command,
    int dest_addr,
    int *current_length,
    int data_length,
    unsigned char *data)

{ /* send_message */

  unsigned char buf [2];
  int status;
  unsigned char test_blk [1024];
  int true_dest;


  context->last_was_processed = 0; //starting fresh on the processing

  if (context->verbosity > 9)
  {
    fprintf (context->log, "Top of send_message cmd=%02x:\n", command);
    fflush (context->log);
  };
  status = ST_OK;
  true_dest = dest_addr;
  *current_length = 0;

  if (context->verbosity > 3)
  {
    osdp_test_set_status(OOC_SYMBOL_rep_nak, OCONFORM_EXERCISED);
    if (command EQUALS OSDP_NAK)
      fprintf (stderr, "NAK being sent...%02x\n", *data);
  };
  status = osdp_build_message
    (test_blk, // message itself
    current_length, // returned message length in bytes
    command,
    true_dest,
    next_sequence (context),
    data_length, // data length to use
    data,
    0); // no security
  if (status EQUALS ST_OK)
  {

    // if (context->verbosity > 3)
    {
      OSDP_MSG m;
      int parse_role;
      OSDP_HDR returned_hdr;
      int status_monitor;

      memset (&m, 0, sizeof (m));

      m.ptr = test_blk; // marshalled outbound message
      m.lth = *current_length;

      // parse the message for display.  role to parse is the OTHER guy
      parse_role = OSDP_ROLE_ACU;
      if (context->role EQUALS OSDP_ROLE_ACU)
        parse_role = OSDP_ROLE_PD;
      status_monitor = osdp_parse_message (context, parse_role,
        &m, &returned_hdr);
      if (status_monitor != ST_OK)
      {
        if (context->verbosity > 3)
          fprintf(stderr, "DEBUG: ignoring osdp_parse_message status %d.\n", status);
        status_monitor = ST_OK;
      };
      if (context->verbosity > 8)
        if (status_monitor != ST_OK)
        {
          sprintf (tlogmsg,"parse_message for monitoring returned %d.\n",
            status_monitor);
          status = oosdp_log (context, OSDP_LOG_STRING_CP, 1, tlogmsg);
        };
      (void)monitor_osdp_message (context, &m);
    };

    buf [0] = 0xff;
    // send start-of-message marker (0xff)
    status = send_osdp_data (context, buf, 1);

    if (status EQUALS ST_OK)
    {
      status = send_osdp_data (context, test_blk, *current_length);

      // and after we sent the whole PDU bump the counter
      context->pdus_sent++;
    };

    if (context->verbosity > 4)
    {
      osdp_trace_dump(context, 1);
    };
  };
  if (status EQUALS ST_OK)
  {
    context->timer [OSDP_TIMER_RESPONSE].current_nanoseconds = context->timer [OSDP_TIMER_RESPONSE].i_nsec;
    context->timer [OSDP_TIMER_RESPONSE].status = OSDP_TIMER_RUNNING;
    context->last_command_sent = command;
  };

  return (status);

} /* send_message */


/*
  send_message_ex - send an OSDP message (extended features)

  sends a message in cleartext or secure channel.
*/

int
  send_message_ex
    (OSDP_CONTEXT *ctx,
    int command,
    int dest_addr,
    int *current_length,
    int data_length,
    unsigned char *data,
    int sec_block_type,
    int sec_block_length,
    unsigned char *sec_block)

{ /* send_message_ex */

  unsigned char current_sec_block [3];
  int current_sec_block_length;
  int current_sec_block_type;
  int status;


  status = ST_OK;
  if (ctx->role != OSDP_ROLE_MONITOR)
  {
  current_sec_block_type = sec_block_type;
  current_sec_block_length = sec_block_length;
  memset(current_sec_block, 0, sizeof(current_sec_block));
  if (sec_block != NULL)
    memcpy(current_sec_block, sec_block, sizeof(current_sec_block));

  // if we're not in secure channel it's all cleartext

  if (ctx->secure_channel_use [OO_SCU_ENAB] != OO_SCS_OPERATIONAL)
    current_sec_block_type = OSDP_SEC_NOT_SCS;

  // if we're in secure channel and it's not a known block it's an SCS_15/16
  // unless there's data in which case it's a 17/18

  current_sec_block_length = 0;

  if (current_sec_block_type EQUALS OSDP_SEC_NOT_SCS)
  {
    if (ctx->secure_channel_use [OO_SCU_ENAB] EQUALS OO_SCS_OPERATIONAL)
    {
      if (ctx->verbosity > 3)
      {
        fprintf(ctx->log, "send: SC; dlth %d\n", data_length);
      };
      if (data_length > 0)
      {
        if (ctx->role EQUALS OSDP_ROLE_ACU)
          current_sec_block_type = OSDP_SEC_SCS_17;
        else
          current_sec_block_type = OSDP_SEC_SCS_18;
      };
      if (data_length EQUALS 0)
      {
        if (ctx->role EQUALS OSDP_ROLE_ACU)
          current_sec_block_type = OSDP_SEC_SCS_15;
        else
          current_sec_block_type = OSDP_SEC_SCS_16;
      };
    };
  };

  // the caller asked us to chillax even if it's in secure mode.

  if (current_sec_block_type EQUALS OSDP_SEC_STAND_DOWN)
    current_sec_block_type = OSDP_SEC_NOT_SCS;

  if (current_sec_block_type != OSDP_SEC_NOT_SCS)
  {
    if (ctx->verbosity > 9)
    {
      fprintf(ctx->log, "send: SC-%x\n", current_sec_block_type);
    };
    status = send_secure_message(ctx, command, dest_addr,
      current_length, data_length, data,
      current_sec_block_type, current_sec_block_length, current_sec_block);
  }
  else
  {
    status = send_message (ctx, command, dest_addr, current_length,
      data_length, data);
  };
  }; // not monitor
  return(status);

} /* osdp_send_message_ex */

