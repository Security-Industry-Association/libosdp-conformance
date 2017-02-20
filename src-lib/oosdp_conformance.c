/*
  oosdp_conformance - conformance reporting routines

  (C)2014-2017 Smithee Spelvin Agnew & Plinge, Inc.

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
#include <string.h>
//#include <time.h>
//#include <arpa/inet.h>


//#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>


extern OSDP_INTEROP_ASSESSMENT
  osdp_conformance;
char
  log_string [1024];


char
  *conformance_status
    (unsigned char
      cstat)

{ /* conformance_status */

  static char
    response [1024];

  switch (cstat)
  {
  case OCONFORM_UNTESTED:
    strcpy (response, "Untested");
    osdp_conformance.untested ++;
    break;
  case OCONFORM_EXERCISED:
    strcpy (response, "Exercised");
    osdp_conformance.pass ++;
    break;
  case OCONFORM_EX_GOOD_ONLY:
    strcpy (response, "Exercised (no edge case tests)");
    osdp_conformance.pass ++;
    break;
  case OCONFORM_FAIL:
    strcpy (response, "Failed)");
    osdp_conformance.fail ++;
    break;
  default:
    sprintf (response, "conformance status unknown(%d)", cstat);
    break;
  };
  return (response);

} /* conformance_status */


void
  dump_conformance
    (OSDP_CONTEXT *ctx,
    OSDP_INTEROP_ASSESSMENT *oconf)

{ /* dump_conformance */

  oconf->pass = 0;
  oconf->fail = 0;
  oconf->untested = 0;

  // fill in results for "minimal message threshhold" case

  if (oconf->conforming_messages >= PARAM_MMT)
  {
    oconf->physical_interface.test_status =
      OCONFORM_EXERCISED;
    oconf->signalling.test_status =
      OCONFORM_EXERCISED;
    oconf->character_encoding.test_status =
      OCONFORM_EXERCISED;
    oconf->channel_access.test_status =
      OCONFORM_EXERCISED;
    oconf->packet_format.test_status =
      OCONFORM_EXERCISED;
    oconf->SOM.test_status =
      OCONFORM_EXERCISED;
    oconf->LEN.test_status =
      OCONFORM_EXERCISED;
    oconf->CTRL.test_status =
      OCONFORM_EXERCISED;
    oconf->CTRL.test_status =
      OCONFORM_EXERCISED;
    oconf->security_block.test_status =
      OCONFORM_EXERCISED;
    oconf->CHKSUM_CRC16.test_status =
      OCONFORM_EXERCISED;
    if (oconf->last_unknown_command EQUALS OSDP_POLL)
      oconf->CMND_REPLY.test_status =
        OCONFORM_EXERCISED;
    else
      oconf->CMND_REPLY.test_status =
        OCONFORM_FAIL;
  };

#define LOG_REPORT(lfargs) {\
  sprintf lfargs; \
  fprintf (ctx->log, "%s\n", log_string); fflush (ctx->log); \
  fprintf (ctx->report, "%s\n", log_string); fflush (ctx->report);\
}; 
  LOG_REPORT ((log_string, "Conformance Report:"));

  LOG_REPORT ((log_string, "2.1  Physical Interface                 %s",
    conformance_status (oconf->physical_interface.test_status)));
  LOG_REPORT ((log_string, "2.2  Signalling                         %s",
    conformance_status (oconf->signalling.test_status)));
  LOG_REPORT ((log_string, "2.3  Character Encoding                 %s",
    conformance_status (oconf->character_encoding.test_status)));
  LOG_REPORT ((log_string, "2.4  Channel Access                     %s",
    conformance_status (oconf->channel_access.test_status)));
  LOG_REPORT ((log_string, "2.5  Multi-byte Data Encoding           %s",
    conformance_status (oconf->multibyte_data_encoding.test_status)));
  LOG_REPORT ((log_string, "2.6  Packet Size Limits                 %s",
"???")); //    conformance_status (oconf->channel_access.test_status));
  LOG_REPORT ((log_string, "2.7  Timing                             %s",
    "Not implemented in open-osdp"));
  LOG_REPORT ((log_string, "2.8  Message Synchronization            %s",
    "Not implemented in open-osdp"));
  LOG_REPORT ((log_string, "2.9  Packet Formats                     %s",
    conformance_status (oconf->packet_format.test_status)));
  LOG_REPORT ((log_string, "2.10 SOM - Start of Message             %s",
    conformance_status (oconf->SOM.test_status)));
  LOG_REPORT ((log_string, "2.11 ADDR - Address                     %s",
"???")); //    conformance_status (oconf->channel_access.test_status));
  LOG_REPORT ((log_string, "2.12 LEN - Length                       %s",
    conformance_status (oconf->LEN.test_status)));
  LOG_REPORT ((log_string, "2.13 CTRL - Control                     %s",
    conformance_status (oconf->CTRL.test_status)));
  LOG_REPORT ((log_string, "2.14 Security Block (hdr process only)  %s",
    conformance_status (oconf->security_block.test_status)));
  LOG_REPORT ((log_string, "2.15 CMND/REPLY - Command/Reply Code    %s",
    conformance_status (oconf->CMND_REPLY.test_status)));
  LOG_REPORT ((log_string, "2.16 CHKSUM/CRC16 - Message Check Codes %s",
    conformance_status (oconf->CHKSUM_CRC16.test_status)));
  LOG_REPORT ((log_string, "2.17 Large Data Messages                %s",
"???")); //    conformance_status (oconf->channel_access.test_status));

//  23

  LOG_REPORT ((log_string, "3.1  Poll                               %s\n",
    conformance_status (oconf->cmd_poll.test_status)));
  LOG_REPORT ((log_string, "3.2  ID Report Request                  %s\n",
    conformance_status (oconf->cmd_id.test_status)));
  LOG_REPORT ((log_string, "3.3  Peripheral Device Capabilities Req %s\n",
    conformance_status (oconf->cmd_pdcap.test_status)));
  LOG_REPORT ((log_string, "3.4  Diagnostic Function Request        %s\n",
    conformance_status (oconf->cmd_diag.test_status)));
  LOG_REPORT ((log_string, "3.5  Local Status Report Request        %s\n",
    conformance_status (oconf->cmd_lstat.test_status)));
  LOG_REPORT ((log_string, "3.6  Input Status Report Request        %s\n",
    conformance_status (oconf->cmd_istat.test_status)));
  LOG_REPORT ((log_string, "3.7  Output Status Report Request        %s\n",
    conformance_status (oconf->cmd_ostat.test_status)));
  LOG_REPORT ((log_string, "3.8  Reader Status Report Request        %s\n",
    conformance_status (oconf->cmd_rstat.test_status)));
  LOG_REPORT ((log_string, "3.9  Output Control Command             %s\n",
    conformance_status (oconf->cmd_out.test_status)));
  LOG_REPORT ((log_string, "3.10 Reader LED Control Command         %s\n",
    conformance_status (oconf->cmd_led.test_status)));
  LOG_REPORT ((log_string, "3.11 Reader Buzzer Control Command      %s\n",
"???"));//    conformance_status (oconf->cmd_led.test_status));
  LOG_REPORT ((log_string, "3.12 Reader Text Output Command         %s\n",
"???"));//    conformance_status (oconf->cmd_led.test_status));
  LOG_REPORT ((log_string, "3.13 (Deprecated)\n"));
  LOG_REPORT ((log_string, "3.14 Communication Configuration Cmd    %s\n",
"???"));//    conformance_status (oconf->cmd_led.test_status));
  LOG_REPORT ((log_string, "3.15 (Deprecated)\n"));
  LOG_REPORT ((log_string, "3.16 Set Automatic Rdr Prompt Strings   %s\n",
"???"));//    conformance_status (oconf->cmd_led.test_status));
  LOG_REPORT ((log_string, "3.17 Scan and Send Biometric Template   %s\n",
"???"));//    conformance_status (oconf->cmd_led.test_status));
  LOG_REPORT ((log_string, "3.18 Scan and Match Biometric Template  %s\n",
"???"));//    conformance_status (oconf->cmd_led.test_status));
  LOG_REPORT ((log_string, "3.19 (Deprecated)\n"));
  LOG_REPORT ((log_string, "3.20 Manufacturer Specific Command      %s\n",
"???"));//    conformance_status (oconf->cmd_led.test_status));
  LOG_REPORT ((log_string, "3.21 Stop Multi Part Message            %s\n",
"???"));//    conformance_status (oconf->cmd_led.test_status));
  LOG_REPORT ((log_string, "3.22 Maximum Accetpable Reply Size      %s\n",
"???"));//    conformance_status (oconf->cmd_led.test_status));

// 10 11 12 13 14 15 16
  fprintf (ctx->log, "4.1  General Ack Nothing to Report      %s\n",
    conformance_status (oconf->rep_ack.test_status));
  fprintf (ctx->log, "4.2  Negative Ack Error Response        %s\n",
    conformance_status (oconf->rep_nak.test_status));
  fprintf (ctx->log, "4.3  Device Identification Report       %s\n",
    conformance_status (oconf->rep_device_ident.test_status));
  fprintf (ctx->log, "4.4  Device Capabilities Report         %s\n",
    conformance_status (oconf->rep_device_capas.test_status));
  fprintf (ctx->log, "4.5  Local Status Report                %s\n",
    conformance_status (oconf->rep_local_stat.test_status));
  fprintf (ctx->log, "4.6  Input Status Report                %s\n",
    conformance_status (oconf->rep_input_stat.test_status));
  fprintf (ctx->log, "4.7  Output Status                      %s\n",
    conformance_status (oconf->rep_output_stat.test_status));
  fprintf (ctx->log, "4.8  Reader Tamper Status               %s\n",
    conformance_status (oconf->rep_reader_tamper.test_status));
  fprintf (ctx->log, "4.9  Card Data Report, Raw Bit Array    %s\n",
    conformance_status (oconf->rep_raw.test_status));

  fprintf (ctx->log, "4.17 PD Busy Reply                      %s\n",
    conformance_status (oconf->rep_busy.test_status));

  LOG_REPORT ((log_string,
"4-8-1 osdp_RSTATR %s\n",
    conformance_status (oconf->resp_rstatr.test_status)));

  fprintf (ctx->log,
    "Passed: %d Failed: %d Untested: %d\n",
    oconf->pass, oconf->fail, oconf->untested);
  fprintf (ctx->log, "---end of report---\n");
fprintf (ctx->log, "mmt %d of %d\n",
  oconf->conforming_messages,
  PARAM_MMT);

} /* dump_conformance */


