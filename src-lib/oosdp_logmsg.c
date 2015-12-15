/*
  oosdp-logmsg - open osdp log message routines

  (C)Copyright 2014-2015 Smithee,Spelvin,Agnew & Plinge, Inc.

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
#include <time.h>
#include <string.h>


#include <gnutls/gnutls.h>


#include <osdp-tls.h>
#include <open-osdp.h>

extern OSDP_CONTEXT context;

char
  *osdp_pdcap_function
    (int func)
{
  static char funcname [1024];
  switch (func)
  {
  default:
    sprintf (funcname, "Unknown(0x%2x)", func);
    break;
  case 1:
    strcpy (funcname, "Contact Status Monitoring");
    break;
  case 2:
    strcpy (funcname, "Output Control");
    break;
  case 3:
    strcpy (funcname, "Card Data Format");
    break;
  case 4:
    strcpy (funcname, "Reader LED Control");
    break;
  case 5:
    strcpy (funcname, "Reader Audible Output");
    break;

  case 10:
    strcpy (funcname, "Receive Buffer Size");
    break;
  case 11:
    strcpy (funcname, "Max Multi-Part Size");
    break;
  };
  return (funcname);
};

int
  oosdp_make_message
    (int
       msgtype,
    char
      *logmsg,
    void
      *aux)
    
{
  OSDP_MSG
    *msg;
  char
    tlogmsg [1024];
  int
    status;

  status = ST_OK;
  switch (msgtype)
  {
  case OOSDP_MSG_KEYPAD:
    {
      char character;
      char *keypad_map [] =
      {"A", "B", "C", "D", "F1+F2", "F2+F3", "F3+F4", "F1+F4"};
      char *keypad_string;
      char tmpstr [1024];

      msg = (OSDP_MSG *) aux;
      character = *(msg->data_payload+2);
      tmpstr [1] = 0;
      tmpstr [0] = character;
      keypad_string = tmpstr;
      if (character == 0x7f)
        keypad_string = "*";
      else
        if (character == 0x0d)
          keypad_string = "#";
        else
          if ((character >= 0x41) && (character <= 0x48))
            keypad_string = keypad_map [character-0x41];
      sprintf (tlogmsg,
"Keypad Input Rdr %d Digit %s (%d digits.)",
        *(msg->data_payload+0),
        keypad_string,
        *(msg->data_payload+1));
    };
    break;

  case OOSDP_MSG_PD_CAPAS:
    {
      int
        count;
      int
        i;
      OSDP_HDR
        *oh;
      char
        tstr [1024];
      int
        value;

      msg = (OSDP_MSG *) aux;
      oh = (OSDP_HDR *)(msg->ptr);
      count = oh->len_lsb + (oh->len_msb << 8);
      count = count - 8;
      sprintf (tstr, "PD Capabilities (%d)\n", count/3);
      strcpy (tlogmsg, tstr);

      for (i=0; i<count; i=i+3)
      {
        switch (*(i+0+msg->data_payload))
        {
        case 4:
          {
            int compliance;
            char tstr2 [1024];
            compliance = *(i+1+msg->data_payload);
            strcpy (tstr2, "Compliance=?");
            if (compliance == 1) strcpy (tstr2, "On/Off Only");
            if (compliance == 2) strcpy (tstr2, "Timed");
            if (compliance == 3) strcpy (tstr2, "Timed, Bi-color");
            if (compliance == 4) strcpy (tstr2, "Timed, Tri-color");
          sprintf (tstr, "  [%02d] %s %d LED's Compliance:%s;\n",
            1+i/3, osdp_pdcap_function (*(i+0+msg->data_payload)), 
            *(i+2+msg->data_payload),
            tstr2);
          };
          break;
        case 10:
          value = *(i+1+msg->data_payload) + 256 * (*(i+2+msg->data_payload));
          sprintf (tstr, "  [%02d] %s %d;\n",
            1+i/3, osdp_pdcap_function (*(i+0+msg->data_payload)), value);
          break;
        case 11:
          value = *(i+1+msg->data_payload) + 256 * (*(i+2+msg->data_payload));
          sprintf (tstr, "  [%02d] %s %d;\n",
            1+i/3, osdp_pdcap_function (*(i+0+msg->data_payload)), value);
          break;
        default:
          sprintf (tstr, "  [%02d] %s %02x %02x;\n",
            1+i/3, osdp_pdcap_function (*(i+0+msg->data_payload)), *(i+1+msg->data_payload), *(i+2+msg->data_payload));
          break;
        };
        strcat (tlogmsg, tstr);
      };
    };
    break;

  case OOSDP_MSG_PD_IDENT:
    msg = (OSDP_MSG *) aux;
    sprintf (tlogmsg, 
"PD Identification\n OUI %02x-%02x-%02x Model %d Ver %d SN %02x%02x%02x%02x FW %d.%d Build %d\n",
        *(msg->data_payload + 0), *(msg->data_payload + 1),
        *(msg->data_payload + 2), *(msg->data_payload + 3),
        *(msg->data_payload + 4), *(msg->data_payload + 5),
        *(msg->data_payload + 6), *(msg->data_payload + 7),
        *(msg->data_payload + 8), *(msg->data_payload + 9),
        *(msg->data_payload + 10), *(msg->data_payload + 11));
    break;

  case OOSDP_MSG_PKT_STATS:
    sprintf (tlogmsg, " CP Polls %6d PD Acks %6d Sent NAKs %6d CkSumErr %6d\n",
      context.cp_polls, context.pd_acks, context.sent_naks,
      context.checksum_errs);
    break;
  default:
    sprintf (tlogmsg, "Unknown message type %d", msgtype);
    break;
  };
  strcpy (logmsg, tlogmsg);
  return (status);
}


int
  oosdp_log
    (OSDP_CONTEXT
      *context,
    int
      logtype,
    int
      level,
    char
      *message)

{ /* oosdp_log */

  time_t
    current_raw_time;
  char
    logmsg [1024];
  char
    prefix [1024];
  int
    status;
  char
    timestamp [1024];


  status = ST_OK;
  prefix [0] = 0;
  if (logtype == OSDP_LOG_STRING)
  {
    struct timespec
      current_time_fine;

    clock_gettime (CLOCK_REALTIME, &current_time_fine);
    (void) time (&current_raw_time);
    strcpy (timestamp, ctime (&current_raw_time));
    sprintf (timestamp, "%09ld.%09ld %s",
      (unsigned long int)current_time_fine.tv_sec, current_time_fine.tv_nsec,
      asctime (localtime (&current_raw_time)));
    timestamp [strlen (timestamp)-1] = 0; // trim trailing newline

    sprintf (prefix, "%s (Rcvd Frame %6d)\n", timestamp,
      context->packets_received);
  };
  strcpy (logmsg, message);
  if (context->role == OSDP_ROLE_MONITOR)
  {
    fprintf (context->log, "%s%s", prefix, logmsg);
  }
  else
    if (m_verbosity >= level)
      fprintf (context->log, "%s%s", prefix, logmsg);
  
  return (status);

} /* oosdp_log */

