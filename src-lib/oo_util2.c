/*
  oo_util2 - more open-osdp util routines

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


extern OSDP_INTEROP_ASSESSMENT
  osdp_conformance;
extern OSDP_CONTEXT
  context;
extern OSDP_PARAMETERS
  p_card;
char
  tlogmsg [1024];


void start_element (void *data, const char *element, const char **attribute);


int
  background
    (OSDP_CONTEXT
      *context)

{ /* background */

  int
    current_length;
  int
    status;


  status = ST_OK;
  if (context->role EQUALS OSDP_ROLE_CP)
  {
    current_length = 0;
    status = send_message (context,
      OSDP_POLL, p_card.addr, &current_length, 0, NULL); 
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


static int
  depth = 0;
static char
  *last_content;
/*
  end_element - end xml parsing element.  parses parameters

  this is a libexpat callback
*/
void
  end_element
    (void
      *data,
    const char
      *el)

{ /* end_element */

  int
    i;


  switch (context.cparm)
  {
  case PARAMETER_PARAMS:
    switch (context.cparm_v)
    {
    default:
      context.cparm = PARAMETER_NONE;
      break;
    case PARMV_ADDR:
      sscanf (last_content, "%d", &i);
      p_card.addr = i;
      context.cparm_v = PARMV_NONE;
      break;
    case PARMV_CARD_BITS:
      sscanf (last_content, "%d", &i);
      p_card.bits = i;
      context.cparm_v = PARMV_NONE;
      break;
    case PARMV_FILENAME:
      strcpy (p_card.filename, last_content);
      context.cparm_v = PARMV_NONE;
      break;
    case PARMV_CP_POLL:
      sscanf (last_content, "%d", &i);
      p_card.poll = i;
      context.cparm_v = PARMV_NONE;
      break;
    case PARMV_CARD_VALUE:
      {
        /*
          accumulate the "value" field into p_card.value
        */
        int
          idata;
        int
          idx;
        int
          rem;
        char
          tmps [3];

        idx=0;
        idata = 0;
        rem = strlen (last_content);
        while (rem > 0)
        {
          strncpy (tmps, last_content+idx, 2);
          idx = idx + 2;
          rem = rem - 2;
          tmps [2] = 0;
          sscanf (tmps, "%x", &i);
          p_card.value [idata] = i;
          idata ++;
          p_card.value_len ++;
        };
      };
      context.cparm_v = PARMV_NONE;
      break;
    case PARMV_ROLE:
      if (strcmp (last_content, "CP") == 0)
      if (strcmp (last_content, "PD") == 0)
        context.role = OSDP_ROLE_PD;
      if (strncmp (last_content, "MONITOR", 7) == 0)
        context.role = OSDP_ROLE_MONITOR;
      break;
    };
    break;
  };
  depth--;

} /* end_element */


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


void
  handle_data
    (void
      *data,
    const char
      *content,
    int
      length)
{
  char *tmp = malloc (length);

  strncpy (tmp, content, length);
  tmp [length] = 0;
  data = (void *)tmp;
  last_content = tmp;

} /* handle_data */


int
  next_sequence
    (OSDP_CONTEXT
      *ctx)

{ /* next_sequence */

  static int
    current_sequence;


  /*
    if the last thing we got was a NAK we do not increment the sequence number.
    (TODO: confirm this is true for all NAK types.)
  */
  if (ctx->last_response_received != OSDP_NAK)
  {
    // the current value is returned. might be 0 (if this is the first message)

    current_sequence = ctx->next_sequence;

    // increment sequence, skipping 1 (per spec)

    ctx->next_sequence++;
    if (ctx->next_sequence > 3)
      ctx->next_sequence = 1;
  }
  else
  {
    if (ctx->verbosity > 2)
      fprintf (ctx->log, "Last in was NAK, sequence stays at %d\n",
        ctx->next_sequence);
  };
  return (current_sequence);

} /* next_sequence */


int
  osdp_timeout
    (OSDP_CONTEXT
      *ctx,
    struct timespec
      *last_time_ex)

{ /* osdp_timeout */

  long
    delta_nanotime;
  int
    delta_time;
  int
    i;
  int
    return_value;
  int
    status_posix;
  struct timespec
    time_spec;


  return_value = 0;
  status_posix = clock_gettime (CLOCK_REALTIME, &time_spec);
  if (status_posix == -1)
    ctx->last_errno = errno;

#if 0
  time_t
    current_time;
  current_time = time (NULL);
  if (*last_time_check != current_time)
  {
    delta_time = current_time - *last_time_check;
    *last_time_check = current_time;
    if (delta_time > 0)
    {
      ctx->idle_time = ctx->idle_time + delta_time;
      if (ctx->idle_time > m_idle_timeout)
      {
        osdp_reset_background_timer (ctx);
        return_value = 1;
      };
    };
  };
#endif

  // update timers (new style)

  for (i=0; i<ctx->timer_count; i++)
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
        return_value = 1;
        ctx->timer [i].current_seconds = ctx->timer [i].i_sec;
        ctx->timer [i].status = OSDP_TIMER_RESTARTED;
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
        return_value = 1;
        ctx->timer [i].current_nanoseconds = ctx->timer [i].i_nsec;
        ctx->timer [i].status = OSDP_TIMER_RESTARTED;
      };
    };
  };
  last_time_ex->tv_sec = time_spec.tv_sec;;
  last_time_ex->tv_nsec = time_spec.tv_nsec;;
  return (return_value);

} /* osdp_timeout */
   

int
  parse_json
    (OSDP_CONTEXT
      *ctx)

{ /* parse_json */

  FILE
    *cmdf;
  char
    field [1024];
  int
    found_field;
  char
    json_string [4096];
  json_t
    *root;
  int
    status;
  int
    status_io;
  json_error_t
    status_json;
  char
    *test_command;
  char
    this_command [1024];
  char
    this_value [1024];
  json_t
    *value;
  int
    was_valid;


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

  // parameter "timeout"

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
    test_command = "CP";
    if (0 EQUALS strncmp (this_command, test_command, strlen (test_command)))
    {
      was_valid = 1;
      context.role = OSDP_ROLE_CP;
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
    int
      i;
    int
      idata;
    int
      idx;
    int
      rem;
    char
      tmps [3];

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

  return (status);

} /* parse_json */


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

  status = parse_json (ctx);
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
  status = send_message (ctx,
    OSDP_COMSET, pd_address, &current_length, sizeof (param), param);
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
    (OSDP_CONTEXT
      *context,
    int
      command,
    int
      dest_addr,
    int
      *current_length,
    int
      data_length,
    unsigned char
      *data)

{ /* send_message */

  unsigned char
    buf [2];
  int
    status;
  unsigned char
    test_blk [1024];
  int
    true_dest;


  status = ST_OK;
  true_dest = dest_addr;
  *current_length = 0;

  if (context->verbosity > 3)
  {
    osdp_conformance.rep_nak.test_status = OCONFORM_EXERCISED;
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
      OSDP_MSG
        m;
      OSDP_HDR
        returned_hdr;
      int
        status_monitor;

      memset (&m, 0, sizeof (m));

      m.ptr = test_blk; // marshalled outbound message
      m.lth = *current_length;

      status_monitor = parse_message (context, &m, &returned_hdr);
      if (context->verbosity > 8)
        if (status_monitor != ST_OK)
        {
          sprintf (tlogmsg,"parse_message for monitoring returned %d.\n",
            status_monitor);
          status = oosdp_log (context, OSDP_LOG_STRING_CP, 1, tlogmsg);
        };
      (void)monitor_osdp_message (context, &m);
    };
    if (context->verbosity > 4)
    {
      int
        i;

       fprintf (context->log, "Sending lth %d.=", *current_length);
       for (i=0; i<*current_length; i++)
         fprintf (context->log, " %02x", test_blk [i]);
       fprintf (context->log, "\n");
    };

    // update statistics

    if (command EQUALS OSDP_POLL)
      context->cp_polls ++;

    buf [0] = 0xff;
    // send start-of-message marker (0xff)
    status = send_osdp_data (context, buf, 1);

    if (status EQUALS ST_OK)
      status = send_osdp_data (context, test_blk, *current_length);
  };
  if (status EQUALS ST_OK)
    context->last_command_sent = command;

  return (status);

} /* send_message */

