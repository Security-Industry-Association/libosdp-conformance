/*
  oosdp_conformance - conformance reporting routines

  (C)Copyright 2017-2020 Smithee Solutions LLC

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


#include <open-osdp.h>
#include <osdp_conformance.h>

#define LOG_REPORT(lfargs) \
  { sprintf lfargs; fprintf (ctx->report, "%s\n", log_string); fflush (ctx->report); }; 
static char *role_tag;


int
  osdp_report
    (OSDP_CONTEXT
      *ctx);


extern OSDP_INTEROP_ASSESSMENT osdp_conformance;
char log_string [1024];
OSDP_CONTEXT context;

// test control info
typedef struct osdp_conformance_test
{
  char *name;
  unsigned char *conformance;
  int test_for_peripheral;
  int test_for_basic;
  int test_for_bio;
  int test_for_xpm;
  int test_for_transparent;
  char *description;
} OSDP_CONFORMANCE_TEST;

OSDP_CONFORMANCE_TEST
  test_control [] =
  {
    // alphabetical with symbol

    {         OOC_SYMBOL_cmd_crauth,
      &(osdp_conformance.cmd_crauth.test_status),
      0, 0, 0, 0, 0,
                        "Command: osdp_CRAUTH"},
    {         OOC_SYMBOL_cmd_genauth,
      &(osdp_conformance.cmd_genauth.test_status),
      0, 0, 0, 0, 0,
                        "Command: osdp_GENAUTH"},
    {         OOC_SYMBOL_cmd_poll,
      &(osdp_conformance.cmd_poll.test_status),
      1, 0, 0, 0, 0,
                        "Command: POLL"},
    {         OOC_SYMBOL_physical_interface,
      &(osdp_conformance.physical_interface.test_status),
      1, 0, 0, 0, 0,
                        "physical interface"},
    {         OOC_SYMBOL_rep_ack,
      &(osdp_conformance.rep_ack.test_status),
      1, 1, 1, 1, 0,
                        "Response: ACK" },
    {         OOC_SYMBOL_resp_crauthr,
      &(osdp_conformance.resp_crauthr.test_status),
      0, 0, 0, 0, 0,
                        "Response: osdp_CRAUTHR"},
    {         OOC_SYMBOL_resp_genauthr,
      &(osdp_conformance.resp_genauthr.test_status),
      0, 0, 0, 0, 0,
                        "Response: osdp_GENAUTHR"},
    {         OOC_SYMBOL_resp_lstatr,
      &(osdp_conformance.resp_lstatr.test_status),
      1, 1, 1, 1, 0,
                        "Response: LSTATR"},
    {         OOC_SYMBOL_resp_mfgerrr,
      &(osdp_conformance.resp_mfgerrr.test_status),
      1, 1, 1, 1, 0,
                        "Response: MFGERRR"},
    {         OOC_SYMBOL_signalling,
      &(osdp_conformance.signalling.test_status),
      1, 0, 0, 0, 0,
                        "signalling"},

    // old tag names

    { "2-2-2", &(osdp_conformance.alt_speed_2.test_status),
      1, 0, 0, 0, 0, "---"}, // ??
    { "2-2-3", &(osdp_conformance.alt_speed_3.test_status),
      1, 0, 0, 0, 0, "---"}, // ??
    { "2-2-4", &(osdp_conformance.alt_speed_4.test_status),
      1, 0, 0, 0, 0, "---"}, // ??
    { "2-3-1", &(osdp_conformance.character_encoding.test_status),
      1, 0, 0, 0, 0, "---"}, // ??
    { "2-4-1", &(osdp_conformance.channel_access.test_status),
      1, 0, 0, 0, 0, "---"}, // ??
    { "2-4-2", &(osdp_conformance.timeout_resend.test_status),
      1, 0, 0, 0, 0, "---"}, // ??
    { "2-4-3", &(osdp_conformance.busy_resend.test_status),
      1, 0, 0, 0, 0, "---"}, // ??
    { "2-4-4", &(osdp_conformance.new_on_busy.test_status),
      1, 0, 0, 0, 0, "---"}, // ??
    { "2-5-1", &(osdp_conformance.multibyte_data_encoding.test_status),
      1, 0, 0, 0, 0, "---"}, // ??
    { "2-6-1", &(osdp_conformance.packet_size_limits.test_status),
      1, 0, 0, 0, 0, "---"}, // ??
    { "2-6-2", &(osdp_conformance.packet_size_from_pd.test_status),
      1, 0, 0, 0, 0, "---"}, // ??
    { "2-6-3", &(osdp_conformance.packet_size_stress_cp.test_status),
      1, 0, 0, 0, 0, "---"}, // ??
    { "2-6-4", &(osdp_conformance.packet_size_from_acu.test_status),
      1, 0, 0, 0, 0, "---"}, // stress PD to ACU
    { "2-7-1", &(osdp_conformance.timing.test_status),
      1, 0, 0, 0, 0, "---"}, // ??
    { "2-7-2", &(osdp_conformance.max_delay.test_status),
      1, 0, 0, 0, 0, "---"}, // ??
    { "2-7-3", &(osdp_conformance.offline_test.test_status),
      1, 0, 0, 0, 0, "---"}, // ??
    { "2-8-1", &(osdp_conformance.message_synchronization.test_status),
      1, 0, 0, 0, 0, "---" }, // ??
    {         OOC_SYMBOL_packet_format,
      &(osdp_conformance.packet_format.test_status),
      1, 0, 0, 0, 0,
                        "seq_zero"},
    {         OOC_SYMBOL_seq_zero,
      &(osdp_conformance.seq_zero.test_status),
      1, 0, 0, 0, 0,
                        "seq_zero"},
    {         OOC_SYMBOL_SOM,
      &(osdp_conformance.SOM.test_status),
      1, 0, 0, 0, 0,
                        "SOM" },
    {         OOC_SYMBOL_SOM_sent,
      &(osdp_conformance.SOM_sent.test_status),
      1, 0, 0, 0, 0,
                        "SOM_sent" },
    { "2-11-1", &(osdp_conformance.ADDR.test_status),
      1, 0, 0, 0, 0, "---" }, // ??
    { "2-11-2", &(osdp_conformance.address_2.test_status),
      1, 0, 0, 0, 0, "---" }, // ??
    { "2-11-3", &(osdp_conformance.address_config.test_status),
      1, 0, 0, 0, 0, "---" }, // ??
    {         OOC_SYMBOL_LEN,
      &(osdp_conformance.LEN.test_status),
      1, 0, 0, 0, 0,
                        "LEN" },
    {         OOC_SYMBOL_CTRL,
      &(osdp_conformance.CTRL.test_status),
      1, 0, 0, 0, 0,
                        "CTRL" },
    { "2-13-2", &(osdp_conformance.control_2.test_status),
      1, 0, 0, 0, 0, "---" }, // ??
    { "2-13-3", &(osdp_conformance.ctl_seq.test_status),
      1, 0, 0, 0, 0, "---" }, // ??
    { "2-14-1", &(osdp_conformance.security_block.test_status),
      1, 0, 0, 0, 0, "---" }, // ??
    { "2-14-2", &(osdp_conformance.scb_absent.test_status),
      1, 0, 0, 0, 0, "---" }, // ??
    { "2-14-3", &(osdp_conformance.rogue_secure_poll.test_status),
      1, 0, 0, 0, 0, "---" }, // ??
    {         OOC_SYMBOL_CMND_REPLY,
      &(osdp_conformance.CMND_REPLY.test_status),
      1, 0, 0, 0, 0,
                        "Command/Reply"},
    { "2-15-2", &(osdp_conformance.invalid_command.test_status),
      1, 0, 0, 0, 0, "---" }, // ??
    { "2-16-1", &(osdp_conformance.CHKSUM_CRC16.test_status),
      1, 0, 0, 0, 0, "---" }, // ??
    { "2-16-2", &(osdp_conformance.checksum.test_status),
      1, 0, 0, 0, 0, "---" }, // ??
    { "2-17-1", &(osdp_conformance.multipart.test_status),
      0, 0, 0, 0, 0, "---"},

    { "3-1-2", &(osdp_conformance.cmd_poll_raw.test_status),
      1, 0, 0, 0, 0, "---" },
    {         OOC_SYMBOL_cmd_lstat,
      &(osdp_conformance.cmd_lstat.test_status),
      1, 0, 0, 0, 0,
                        "Command: LSTAT"},
    { "3-1-4", &(osdp_conformance.cmd_poll_response_4.test_status),
      1, 0, 0, 0, 0, "---" },
    {         OOC_SYMBOL_cmd_id,
      &(osdp_conformance.cmd_id.test_status),
      1, 0, 0, 0, 0,
                        "Command: ID"},
    {         OOC_SYMBOL_cmd_pdcap,
      &(osdp_conformance.cmd_pdcap.test_status),
      1, 0, 0, 0, 0,
                        "Command: PDCAP"},
    { "060-03-01", &(osdp_conformance.cmd_pdcap.test_status),
      1, 0, 0, 0, 0, "---" }, // optional in all cases
    { "3-4-1", &(osdp_conformance.cmd_diag.test_status),
      1, 0, 0, 0, 0, "---" }, // optional in all cases
    {         OOC_SYMBOL_cmd_lstat,
      &(osdp_conformance.cmd_lstat.test_status),
      1, 0, 0, 0, 0,
                        "Command: LSTAT"},
    {         OOC_SYMBOL_cmd_istat,
      &(osdp_conformance.cmd_istat.test_status),
      1, 0, 0, 0, 0,
                        "Command: ISTAT"},
    { "3-7-1", &(osdp_conformance.cmd_ostat.test_status),
      1, 0, 0, 0, 0, "---" },
    { "3-7-2", &(osdp_conformance.cmd_ostat_ack.test_status),
      1, 0, 0, 0, 0, "---" },
    { "3-8-1", &(osdp_conformance.cmd_rstat.test_status),
      1, 0, 0, 0, 0, "---" },
    { "3-9-1", &(osdp_conformance.cmd_out.test_status),
      1, 0, 0, 0, 0, "---" },
    {         OOC_SYMBOL_cmd_led_red,
      &(osdp_conformance.cmd_led_red.test_status),
      0, 0, 0, 0, 0,
                        "Command: LED(Red)"},
    {         OOC_SYMBOL_cmd_led_green,
      &(osdp_conformance.cmd_led_green.test_status),
      0, 0, 0, 0, 0,
                        "Command: LED(Green)"},
    {         OOC_SYMBOL_cmd_buz,
      &(osdp_conformance.cmd_buz.test_status),
      0, 0, 0, 0, 0,
                        "Command: osdp_BUZ"},
    { "3-12-1", &(osdp_conformance.cmd_text.test_status),
      0, 0, 0, 0, 0, "---" },
    {         OOC_SYMBOL_cmd_comset,
      &(osdp_conformance.cmd_comset.test_status),
      0, 0, 0, 0, 0,
                        "Command: osdp_COMSET"},
    {         OOC_SYMBOL_cmd_keyset,
      &(osdp_conformance.cmd_keyset.test_status),
      0, 0, 0, 0, 0,
                        "Command: osdp_KEYSET"},
    {         OOC_SYMBOL_cmd_chlng,
      &(osdp_conformance.cmd_chlng.test_status),
      0, 0, 0, 0, 0,
                        "Command: osdp_CHLNG"},
    {         OOC_SYMBOL_cmd_scrypt,
      &(osdp_conformance.cmd_scrypt.test_status),
      0, 0, 0, 0, 0,
                        "Command: osdp_SCRYPT"},
    { "3-16-1", &(osdp_conformance.cmd_prompt.test_status),
      0, 0, 0, 0, 0, "---" },
    { "3-17-1", &(osdp_conformance.cmd_bioread.test_status),
      0, 0, 0, 0, 0, "---" },
    { "3-18-1", &(osdp_conformance.cmd_biomatch.test_status),
      0, 0, 0, 0, 0, "---" },
    {         OOC_SYMBOL_cmd_bioread,
      &(osdp_conformance.cmd_bioread.test_status),
      0, 0, 0, 0, 0,
                        "Command: osdp_BIOREAD"},
    {         OOC_SYMBOL_cmd_biomatch,
      &(osdp_conformance.cmd_biomatch.test_status),
      0, 0, 0, 0, 0,
                        "Command: osdp_BIOMATCH"},
    {         OOC_SYMBOL_cmd_mfg,
      &(osdp_conformance.cmd_mfg.test_status),
      0, 0, 0, 0, 0,
                        "Command: osdp_MFG"},
    { "3-21-1", &(osdp_conformance.cmd_stop_multi.test_status),
      0, 0, 0, 0, 0, "---" },
    { "3-22-1", &(osdp_conformance.cmd_max_rec.test_status),
      0, 0, 0, 0, 0, "---" },
    {         OOC_SYMBOL_cmd_filetransfer,
      &(osdp_conformance.cmd_filetransfer.test_status),
      0, 0, 0, 0, 0,
                        "Command: osdp_FILETRANSFER"},
    {         OOC_SYMBOL_cmd_acurxsize,
      &(osdp_conformance.cmd_acurxsize.test_status),
      0, 0, 0, 0, 0,
                        "Command: osdp_ACURXSIZE"},
    {         OOC_SYMBOL_cmd_keepactive,
      &(osdp_conformance.cmd_keepactive.test_status),
      0, 0, 0, 0, 0,
                        "Command: osdp_KEEPACTIVE"},

    {         OOC_SYMBOL_rep_nak,
      &(osdp_conformance.rep_nak.test_status),
      1, 1, 1, 1, 0,
                        "Response: NAK" },
    {         OOC_SYMBOL_rep_device_ident,
      &(osdp_conformance.rep_device_ident.test_status),
      1, 1, 1, 1, 0,
                        "rep_device_ident"},
    {         OOC_SYMBOL_rep_pdid_check,
      &(osdp_conformance.rep_pdid_check.test_status),
      1, 1, 1, 1, 0,
                        "Response: PDID (check)"},
    {         OOC_SYMBOL_rep_device_capas,
      &(osdp_conformance.rep_device_capas.test_status),
      1, 1, 1, 1, 0,
                        "Response: PDCAP" },
    { "4-4-2", &(osdp_conformance.rep_capas_consistent.test_status),
      1, 1, 1, 1, 0,
                        "Response: PDCAP (check)" },
    {         OOC_SYMBOL_resp_lstatr_tamper,
      &(osdp_conformance.resp_lstatr_tamper.test_status),
      1, 1, 1, 1, 0,
                        "Response: LSTATR (tamper)"},
    {         OOC_SYMBOL_resp_lstatr_power,
      &(osdp_conformance.resp_lstatr_power.test_status),
      1, 1, 1, 1, 0,
                        "Response: LSTATR (power)"},
    { "4-6-1", &(osdp_conformance.resp_input_stat.test_status),
      1, 0, 0, 0, 0, "---" },
    { "4-6-2", &(osdp_conformance.resp_input_consistent.test_status),
      1, 0, 0, 0, 0, "---" },
    { "4-7-1", &(osdp_conformance.resp_output_stat.test_status),
      1, 0, 0, 0, 0, "---" },
    { "4-7-2", &(osdp_conformance.resp_ostatr_poll.test_status),
      1, 0, 0, 0, 0, "---" },
    { "4-7-3", &(osdp_conformance.resp_ostatr_range.test_status),
      0, 0, 0, 0, 0, "---" },
    { "4-8-1", &(osdp_conformance.resp_rstatr.test_status),
      0, 0, 0, 0, 0, "---" },
    {         OOC_SYMBOL_rep_raw,
      &(osdp_conformance.rep_raw.test_status),
      0, 0, 0, 0, 0,
                        "Response: osdp_RAW"},
    { "4-10-1", &(osdp_conformance.rep_formatted.test_status),
      0, 0, 0, 0, 0, "---" },
    { "4-11-1", &(osdp_conformance.resp_keypad.test_status),
      0, 0, 0, 0, 0, "Keypad" },
    { "4-11-1", &(osdp_conformance.resp_keypad.test_status),
      0, 0, 0, 0, 0, "---" },
    {         OOC_SYMBOL_resp_com,
      &(osdp_conformance.resp_com.test_status),
      0, 0, 0, 0, 0,
                        "Response: osdp_COM"},
    { "4-13-1", &(osdp_conformance.rep_scan_send.test_status),
      0, 0, 0, 0, 0, "---" },
    { "4-14-1", &(osdp_conformance.rep_scan_match.test_status),
      0, 0, 0, 0, 0, "---" },
    { "4-15-1", &(osdp_conformance.resp_mfg.test_status),
      0, 0, 0, 0, 0, "---" },
    {         OOC_SYMBOL_resp_busy,
      &(osdp_conformance.resp_busy.test_status),
      0, 0, 0, 0, 0,
                        "Response: osdp_BUSY"},
    { "070-15-01", &(osdp_conformance.resp_ccrypt.test_status),
      0, 0, 0, 0, 0, "Response: osdp_CCRYPT" },
    { "070-16-01", &(osdp_conformance.resp_rmac_i.test_status),
      0, 0, 0, 0, 0, "Response: osdp_RMAC_I" },
    {         OOC_SYMBOL_resp_ftstat,
      &(osdp_conformance.resp_ftstat.test_status),
      0, 0, 0, 0, 0,
                        "Response: osdp_FTSTAT"},
    { NULL, NULL, 0, 0, 0, 0, 0, "---" }
  };

// code to configure tests to skip
#include <oo-SKIP.c>


char
  *conformance_status
    (unsigned char
      cstat)

{ /* conformance_status */

  static char
    response [1024];

  switch (cstat)
  {
  case OCONFORM_SKIP:
    strcpy (response, "Skipped");
    osdp_conformance.skipped ++;
    break;
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
    strcpy (response, "Failed");
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

  char *profile_tag;


  oconf->pass = 0;
  oconf->fail = 0;
  oconf->untested = 0;
  oconf->skipped = 0;

  if (ctx->role EQUALS OSDP_ROLE_PD)
    role_tag = "ACU";
  else
    role_tag = "PD";
  profile_tag = "Basic"; // really should constrain tests to use etc.

  skip_conformance_tests (ctx, oconf);

  // fill in results for "minimal message threshhold" case

  if (oconf->conforming_messages >= PARAM_MMT)
  {
    osdp_test_set_status(OOC_SYMBOL_physical_interface, OCONFORM_EXERCISED);
    if (0 EQUALS strcmp (ctx->serial_speed, "9600"))
      osdp_test_set_status(OOC_SYMBOL_signalling, OCONFORM_EXERCISED);
      //oconf->signalling.test_status = OCONFORM_EXERCISED;
    osdp_test_set_status(OOC_SYMBOL_SOM, OCONFORM_EXERCISED);
    osdp_test_set_status(OOC_SYMBOL_packet_format, OCONFORM_EXERCISED);
    osdp_test_set_status(OOC_SYMBOL_SOM_sent, OCONFORM_EXERCISED);
    osdp_test_set_status(OOC_SYMBOL_LEN, OCONFORM_EXERCISED);
    osdp_test_set_status(OOC_SYMBOL_CTRL, OCONFORM_EXERCISED);
    oconf->CHKSUM_CRC16.test_status =
      OCONFORM_EXERCISED;
  };

  ctx->report = fopen ("/opt/osdp-conformance/results/report.log", "w");

  LOG_REPORT ((log_string, "Conformance Report:"));
  LOG_REPORT ((log_string,
    "Testing %s\n", role_tag));
  LOG_REPORT ((log_string, "Conformance Tester Version: %d.%d Build %d\n",
    OSDP_VERSION_MAJOR, OSDP_VERSION_MINOR, OSDP_VERSION_BUILD));

  osdp_report (ctx);

  LOG_REPORT ((log_string,
"2-1-1  Physical Interface                 %s",
    conformance_status (oconf->physical_interface.test_status)));
  LOG_REPORT ((log_string,
"2-2-1  Signalling (9600)                  %s",
    conformance_status (oconf->signalling.test_status)));
  LOG_REPORT ((log_string,
"2-2-2  Signalling (19200)                 %s",
    conformance_status (oconf->alt_speed_2.test_status)));
  LOG_REPORT ((log_string,
"2-2-3  Signalling (38400)                 %s",
    conformance_status (oconf->alt_speed_3.test_status)));
  LOG_REPORT ((log_string,
"2-2-4  Signalling (115200)                %s",
    conformance_status (oconf->alt_speed_4.test_status)));
  LOG_REPORT ((log_string,
"2-3-1  Character Encoding                 %s",
    conformance_status (oconf->character_encoding.test_status)));
  LOG_REPORT ((log_string,
"2-4-1  Channel Access                     %s",
    conformance_status (oconf->channel_access.test_status)));
  LOG_REPORT ((log_string,
"2-4-2  Timeout resend                     %s",
    conformance_status (oconf->timeout_resend.test_status)));
  LOG_REPORT ((log_string,
"2-4-3  Busy resend                        %s",
    conformance_status (oconf->busy_resend.test_status)));
  LOG_REPORT ((log_string,
"2-4-4  New on busy                        %s",
    conformance_status (oconf->new_on_busy.test_status)));
  LOG_REPORT ((log_string,
"2-5-1  Multi-byte Data Encoding           %s",
    conformance_status (oconf->multibyte_data_encoding.test_status)));
  LOG_REPORT ((log_string,
"2-6-1  Packet Size Limits                 %s",
    conformance_status (oconf->packet_size_limits.test_status)));
  LOG_REPORT ((log_string,
"2-6-2  Packet size from PD                %s",
    conformance_status (oconf->packet_size_from_pd.test_status)));
  LOG_REPORT ((log_string,
"2-6-3  Packet size stress ACU             %s",
    conformance_status (oconf->packet_size_stress_cp.test_status)));
  LOG_REPORT ((log_string,
"2-6-4  Stress PD to ACU                   %s",
    conformance_status (oconf->packet_size_stress_cp.test_status)));
  LOG_REPORT ((log_string,
"2-7-1  Timing                             %s",
    conformance_status (oconf->timing.test_status)));
  LOG_REPORT ((log_string,
"2-7-2  Max delay                          %s",
    conformance_status (oconf->timing.test_status)));
  LOG_REPORT ((log_string,
"2-7-3  Offline test                       %s",
    conformance_status (oconf->offline_test.test_status)));
  LOG_REPORT ((log_string,
"2-8-1  Message Synchronization            %s",
    conformance_status (oconf->message_synchronization.test_status)));
  LOG_REPORT ((log_string,
"2-9-1  Packet Formats                     %s",
    conformance_status (oconf->packet_format.test_status)));
  LOG_REPORT ((log_string,
"2-10-1 SOM Start of Message               %s",
    conformance_status (oconf->SOM.test_status)));
  LOG_REPORT ((log_string,
"2-10-2 SOM sent                           %s",
    conformance_status (oconf->SOM_sent.test_status)));
  LOG_REPORT ((log_string,
"2-11-1 ADDR                               %s",
    conformance_status (oconf->ADDR.test_status)));
  LOG_REPORT ((log_string,
"2-11-2 No data on 7F                      %s",
    conformance_status (oconf->address_2.test_status)));
  LOG_REPORT ((log_string,
"2-11-3 Config (0x7F) Address              %s",
    conformance_status (oconf->address_config.test_status)));
  LOG_REPORT ((log_string,
"2-12-1 LEN                                %s",
    conformance_status (oconf->LEN.test_status)));
  LOG_REPORT ((log_string,
"2-13-1 CTRL                               %s",
    conformance_status (oconf->CTRL.test_status)));
  LOG_REPORT ((log_string,
"2-13-2 Secure Control Block [5]           %s",
    conformance_status (oconf->control_2.test_status)));
  LOG_REPORT ((log_string,
"2-13-3 Sequence numbers                   %s",
    conformance_status (oconf->ctl_seq.test_status)));
  LOG_REPORT ((log_string,
"2-14-1 Security Block (hdr process only)  %s",
    conformance_status (oconf->security_block.test_status)));
  LOG_REPORT ((log_string,
"2-14-2 SCB absent                         %s",
    conformance_status (oconf->scb_absent.test_status)));
  LOG_REPORT ((log_string,
"2-14-3 Rogue Secure Poll                  %s",
    conformance_status (oconf->rogue_secure_poll.test_status)));
  LOG_REPORT ((log_string,
"2-15-1 Incoming C/R valid                 %s",
    conformance_status (oconf->CMND_REPLY.test_status)));
  LOG_REPORT ((log_string,
"2-15-2 No invalid C/R received            %s",
    conformance_status (oconf->invalid_command.test_status)));
  LOG_REPORT ((log_string,
"2-16-1 CHKSUM/CRC16                       %s",
    conformance_status (oconf->CHKSUM_CRC16.test_status)));
  LOG_REPORT ((log_string,
"2-16-2 Checksum                           %s",
    conformance_status (oconf->checksum.test_status)));
  LOG_REPORT ((log_string,
"2-17-1 Large Data Messages                %s",
    conformance_status (oconf->multipart.test_status)));

  LOG_REPORT ((log_string,
"3-1-1  Poll                               %s",
    conformance_status (oconf->cmd_poll.test_status)));
  LOG_REPORT ((log_string,
"3-1-2  Poll raw                           %s",
    conformance_status (oconf->cmd_poll_raw.test_status)));
  LOG_REPORT ((log_string,
"3-1-3  Poll lstatr                        %s",
    conformance_status (oconf->cmd_poll_lstat.test_status)));
  LOG_REPORT ((log_string,
"3-1-4  Poll response 4                    %s",
    conformance_status (oconf->cmd_poll_response_4.test_status)));
  LOG_REPORT ((log_string,
"3-2-1  ID Report Request                  %s",
    conformance_status (oconf->cmd_id.test_status)));
  LOG_REPORT ((log_string,
"3-3-1  Peripheral Device Capabilities Req %s",
    conformance_status (oconf->cmd_pdcap.test_status)));
  LOG_REPORT ((log_string,
"3-4-1  Diagnostic Function Request        %s",
    conformance_status (oconf->cmd_diag.test_status)));
  LOG_REPORT ((log_string,
"3-5-1  Local Status Report Request        %s",
    conformance_status (oconf->cmd_lstat.test_status)));
  LOG_REPORT ((log_string,
"3-6-1  Input Status Report Request        %s",
    conformance_status (oconf->cmd_istat.test_status)));
  LOG_REPORT ((log_string,
"3-7-1  Output Status Report Request       %s",
    conformance_status (oconf->cmd_ostat.test_status)));
  LOG_REPORT ((log_string,
"3-7-2  Ostat ack                          %s",
    conformance_status (oconf->cmd_ostat_ack.test_status)));
  LOG_REPORT ((log_string,
"3-8-1  Reader Status Report Request       %s",
    conformance_status (oconf->cmd_rstat.test_status)));
  LOG_REPORT ((log_string,
"3-9-1  Output Control Command             %s",
    conformance_status (oconf->cmd_out.test_status)));
  LOG_REPORT ((log_string,
"3-10-1 LED Test (Red)                     %s",
    conformance_status (oconf->cmd_led_red.test_status)));
  LOG_REPORT ((log_string,
"3-10-2 LED Test (Green)                   %s",
    conformance_status (oconf->cmd_led_green.test_status)));
  LOG_REPORT ((log_string,
"3-11-1 Buzzer Control                     %s",
    conformance_status (oconf->cmd_buz.test_status)));
  LOG_REPORT ((log_string,
"3-12-1 Text output                        %s",
    conformance_status (oconf->cmd_text.test_status)));
  LOG_REPORT ((log_string,
"3-14-1 COMSET                             %s",
    conformance_status (oconf->cmd_comset.test_status)));
  LOG_REPORT ((log_string,
"3-16-1 Reader Prompt                      %s",
    conformance_status (oconf->cmd_prompt.test_status)));
  LOG_REPORT ((log_string,
"3-17-1 Scan and send bio template         %s",
    conformance_status (oconf->cmd_bioread.test_status)));
  LOG_REPORT ((log_string,
"3-18-1 Scan and match bio template        %s",
    conformance_status (oconf->cmd_biomatch.test_status)));
  LOG_REPORT ((log_string,
"3-20-1 Manufacturer specific command      %s",
    conformance_status (oconf->cmd_mfg.test_status)));
  LOG_REPORT ((log_string,
"3-21-1 Stop multipart message             %s",
    conformance_status (oconf->cmd_stop_multi.test_status)));
  LOG_REPORT ((log_string,
"3-22-1 Maximum acceptable reply size      %s",
    conformance_status (oconf->cmd_max_rec.test_status)));

  LOG_REPORT ((log_string,
"4-1-1  General Ack Nothing to Report      %s",
    conformance_status (oconf->rep_ack.test_status)));
  LOG_REPORT ((log_string,
"4-2-1  Negative Ack Error Response        %s",
    conformance_status (oconf->rep_nak.test_status)));
  LOG_REPORT ((log_string,
"4-3-1  Device Identification Report       %s",
    conformance_status (oconf->rep_device_ident.test_status)));
  LOG_REPORT ((log_string,
"4-3-2  Ident report consistent            %s",
    conformance_status (oconf->rep_pdid_check.test_status)));
  LOG_REPORT ((log_string,
"4-4-1  Device Capabilities Report         %s",
    conformance_status (oconf->rep_device_capas.test_status)));
  LOG_REPORT ((log_string,
"4-4-2  Capabilities report consistent     %s",
    conformance_status (oconf->rep_capas_consistent.test_status)));
  LOG_REPORT ((log_string,
"4-5-1  osdp_LSTATR Local Status Report    %s",
    conformance_status (oconf->resp_lstatr.test_status)));
  LOG_REPORT ((log_string,
"4-5-2  osdp_LSTATR Tamper                 %s",
    conformance_status (oconf->resp_lstatr_tamper.test_status)));
  LOG_REPORT ((log_string,
"4-5-3  osdp_LSTATR Power                  %s",
    conformance_status (oconf->resp_lstatr_power.test_status)));
  LOG_REPORT ((log_string,
"4-6-1  Input Status Report                %s",
    conformance_status (oconf->resp_input_stat.test_status)));
  LOG_REPORT ((log_string,
"4-6-2  Input report consistent            %s",
    conformance_status (oconf->resp_input_consistent.test_status)));
  LOG_REPORT ((log_string,
"4-7-1  osdp_OSTATR                        %s",
    conformance_status (oconf->resp_output_stat.test_status)));
  LOG_REPORT ((log_string,
"4-7-2  osdp_OSTATR for POLL               %s",
    conformance_status (oconf->resp_ostatr_poll.test_status)));
  LOG_REPORT ((log_string,
"4-7-3  osdp_OSTATR for POLL               %s",
    conformance_status (oconf->resp_ostatr_range.test_status)));
  LOG_REPORT ((log_string,
"4-8-1  osdp_RSTATR                        %s",
    conformance_status (oconf->resp_rstatr.test_status)));
  LOG_REPORT ((log_string,
"4-9-1  RAW Read                           %s",
    conformance_status (oconf->rep_raw.test_status)));
  LOG_REPORT ((log_string,
"4-10-1 Formatted Read                     %s",
    conformance_status (oconf->rep_formatted.test_status)));
  LOG_REPORT ((log_string,
"4-11-1 Keypad input                       %s",
    conformance_status (oconf->resp_keypad.test_status)));
  LOG_REPORT ((log_string,
"4-12-1 COM Report                         %s",
    conformance_status (oconf->resp_com.test_status)));
  LOG_REPORT ((log_string,
"4-13-1 Biometrics Read                    %s",
    conformance_status (oconf->rep_scan_send.test_status)));
  LOG_REPORT ((log_string,
"4-14-1 Biometrics Match                   %s",
    conformance_status (oconf->rep_scan_match.test_status)));
  LOG_REPORT ((log_string,
"4-15-1 Mfg Response                       %s",
    conformance_status (oconf->resp_mfg.test_status)));
  LOG_REPORT ((log_string,
"4-16-1 Busy                               %s",
    conformance_status (oconf->resp_busy.test_status)));

  LOG_REPORT ((log_string,
"=== Passed:   %d",
    oconf->pass));
  LOG_REPORT ((log_string,
"    Failed:   %d",
    oconf->fail));
  LOG_REPORT ((log_string,
"    Untested: %d",
    oconf->untested));
  LOG_REPORT ((log_string,
"    Skipped:  %d",
    oconf->skipped));
  LOG_REPORT ((log_string,
"    Total:    %d",
    oconf->pass + oconf->fail + oconf->untested + oconf->skipped));
  LOG_REPORT ((log_string,
    "Testing %s with %s Profile\n", role_tag, profile_tag));
  LOG_REPORT ((log_string, "Version: %d.%d Build %d\n",
    ctx->fw_version [0], ctx->fw_version [1], ctx->fw_version [2]));
  LOG_REPORT ((log_string,
    "---end of report---"));
fprintf (ctx->log, "mmt %d of %d\n",
  oconf->conforming_messages,
  PARAM_MMT);
  if (ctx->report != NULL)
    fclose (ctx->report);

} /* dump_conformance */


int
  osdp_conform_confirm
    (char *test)

{ /* osdp_conform_confirm */

  return(osdp_test_set_status(test, OCONFORM_EXERCISED));

} /* osdp_conform_confirm */


int
  osdp_conform_fail
    (char
      *test)
{
  return (osdp_test_set_status (test, OCONFORM_FAIL));
}


int
  osdp_report
    (OSDP_CONTEXT
      *ctx)

{ /* osdp_report */

  time_t current_time;
  int done;
  int i;
  int status;
typedef struct score_counters
{
  int
    score_periph;
  int
    score_basic;
  int
    score_bio;
  int
    score_xpm;
  int
    score_xparnt;
  int
    score_optional;
} OSDP_SCORE_COUNTERS;
OSDP_SCORE_COUNTERS
  exercised_score;
OSDP_SCORE_COUNTERS
  required_score;
OSDP_SCORE_COUNTERS
  failed_score;

  status = ST_OK;
  memset (&exercised_score, 0, sizeof (exercised_score));
  memset (&required_score, 0, sizeof (required_score));
  memset (&failed_score, 0, sizeof (failed_score));
  done = 0;
  i = 0;
  while (!done)
  {
    if ((test_control [i].test_for_peripheral) &&
      (*(test_control [i].conformance) != OCONFORM_SKIP))
    {
      required_score.score_periph ++;
      if (*(test_control [i].conformance) EQUALS OCONFORM_EXERCISED)
        exercised_score.score_periph ++;
      if (*(test_control [i].conformance) EQUALS OCONFORM_FAIL)
        failed_score.score_periph ++;
    };
    if (test_control [i].test_for_basic)
    {
      required_score.score_basic ++;
      if (*(test_control [i].conformance) EQUALS OCONFORM_EXERCISED)
        exercised_score.score_basic ++;
      if (*(test_control [i].conformance) EQUALS OCONFORM_FAIL)
        failed_score.score_basic ++;
    };
    if (test_control [i].test_for_bio)
    {
      required_score.score_bio ++;
      if (*(test_control [i].conformance) EQUALS OCONFORM_EXERCISED)
        exercised_score.score_bio ++;
      if (*(test_control [i].conformance) EQUALS OCONFORM_FAIL)
        failed_score.score_bio ++;
    };
    if (test_control [i].test_for_xpm)
    {
      required_score.score_xpm ++;
      if (*(test_control [i].conformance) EQUALS OCONFORM_EXERCISED)
        exercised_score.score_xpm ++;
      if (*(test_control [i].conformance) EQUALS OCONFORM_FAIL)
        failed_score.score_xpm ++;
    };
    if (test_control [i].test_for_transparent)
    {
      required_score.score_xparnt ++;
      if (*(test_control [i].conformance) EQUALS OCONFORM_EXERCISED)
        exercised_score.score_xparnt ++;
      if (*(test_control [i].conformance) EQUALS OCONFORM_FAIL)
        failed_score.score_xparnt ++;
    };
    i++;
    if (test_control [i].name EQUALS NULL)
      done = 1;
  };
  current_time = time(NULL);
  if (strcmp (role_tag, "PD"))  // if I'm the PD I'm testing the CP...
  {
   LOG_REPORT ((log_string, 
"TEST RESULTS for ACU Conformance %s\n",
  asctime (localtime (&current_time)) ));
  }
  else
   LOG_REPORT ((log_string, 
"TEST RESULTS for PD Conformance %s\nVendor: %02x-%02x-%02x Product: Model %d. Version %d. Firmware %d.%d.%d S/N %02x-%02x-%02x-%02x\n",
     asctime (localtime (&current_time)),
     (unsigned)(ctx->vendor_code [0]), (unsigned)(ctx->vendor_code [1]), (unsigned)(ctx->vendor_code [2]),
     (unsigned)(ctx->model), (unsigned)(ctx->version),
     (unsigned)(ctx->fw_version [0]), (unsigned)(ctx->fw_version [1]), (unsigned)(ctx->fw_version [2]),
     (unsigned)(ctx->serial_number [0]), (unsigned)(ctx->serial_number [1]), (unsigned)(ctx->serial_number [2]), (unsigned)(ctx->serial_number [3])));

  LOG_REPORT ((log_string, 
"           Periph Basic Bio XPM Xprnt Opt"));
  LOG_REPORT ((log_string, 
"Exercised:   %2d    %2d   %2d  %2d   %2d   %2d",
    exercised_score.score_periph, exercised_score.score_basic,
    exercised_score.score_bio, exercised_score.score_xpm,
    exercised_score.score_xparnt, exercised_score.score_optional));
  LOG_REPORT ((log_string, 
" Required:   %2d    %2d   %2d  %2d   %2d   %2d",
    required_score.score_periph, required_score.score_basic,
    required_score.score_bio, required_score.score_xpm,
    required_score.score_xparnt, required_score.score_optional));
  LOG_REPORT ((log_string, 
"   Failed:   %2d    %2d   %2d  %2d   %2d   %2d\n",
    failed_score.score_periph, failed_score.score_basic,
    failed_score.score_bio, failed_score.score_xpm,
    failed_score.score_xparnt, failed_score.score_optional));

  return (status);

} /* osdp_report */


int
  osdp_test_set_status
    (char *test,
    int test_status)

{ /* osdp_test_set_status */

  int done;
  int idx;
  FILE *rf;
  char results_filename [1024];
  int status;


  status = ST_OK;
  idx = 0;
  done = 0;
  while (!done)
  {
    //DEBUG
    if (0) // (context.verbosity > 9)
    {
      fprintf(context.log, "osdp_test_set_status: checking %d.\n", idx);
      fflush(context.log);
      fprintf(context.log, "osdp_test_set_status: name %s\n", test_control [idx].name);
      fflush(context.log);
    };
    if (test_control [idx].name != NULL)
    {
      if (strcmp (test_control [idx].name, test) EQUALS 0)
    {
      *(test_control [idx].conformance) = test_status;
      sprintf(results_filename, "/opt/osdp-conformance/results/%s-results.json",
        test);
      rf = fopen(results_filename, "w");
      if (rf)
      {
        time_t current_time;
        char test_time [1024];

        current_time = time(NULL);
        strcpy(test_time, asctime(localtime(&current_time)));
        if (test_time [strlen(test_time)-1] == '\n')
          test_time [strlen(test_time)-1] = 0;
        fprintf(rf, "{\"test\":\"%s\",\"test-status\":\"%d\",\n",
          test, test_status);
        fprintf(rf, " \"test-time\":\"%s\",\"test-description\":\"%s\"}\n",
          test_time, test_control [idx].description);
        fclose(rf);
      }
      else
      {
        fprintf(context.log, "Error writing results for %s\n", test);
      };
      done = 1;
    };
    };
    if (test_control [idx].name EQUALS NULL)
    {
      fprintf (stderr, "Cannot find test %s, not updated.\n",
        test);
      done = 1;
    };
    // yes, if we find nothing we'll still return OK
    idx++;
  };
  return (status);

} /* osdp_test_set_status */


int
  osdp_test_set_status_ex
    (char *test,
    int test_status,
    char *aux)

{ /* osdp_test_set-status_ex */

  int done;
  int idx;
  char results_filename [1024];
  FILE *rf;
  int status;


  status = ST_OK;
  idx = 0;
  done = 0;
  while (!done)
  {
    if (context.verbosity > 9)
    {
      fprintf(context.log, "osdp_test_set_status: checking %d.\n", idx);
      fflush(context.log);
      fprintf(context.log, "osdp_test_set_status: name %s\n", test_control [idx].name);
      fflush(context.log);
    };
    if (test_control [idx].name != NULL)
    {
      if (strcmp (test_control [idx].name, test) EQUALS 0)
      {
        *(test_control [idx].conformance) = test_status;
        sprintf(results_filename, "/opt/osdp-conformance/results/%s-results.json",
          test);
        rf = fopen(results_filename, "w");
        if (rf)
        {
          time_t current_time;
          char test_time [1024];

        current_time = time(NULL);
        strcpy(test_time, asctime(localtime(&current_time)));
        if (test_time [strlen(test_time)-1] == '\n')
          test_time [strlen(test_time)-1] = 0;
        fprintf(rf, "{\"test\":\"%s\",\"test-status\":\"%d\",\n",
          test, test_status);
        fprintf(rf, " \"test-time\":\"%s\",\"test-description\":\"%s\",\n",
          test_time, test_control [idx].description);
        if (strlen(aux) > 0)
          fprintf(rf, "%s", aux);
        fprintf(rf, "\"_\":\"_\"}\n");
        fclose(rf);
      }
      else
      {
        fprintf(context.log, "Error writing results for %s\n", test);
      };
      done = 1;
    };
    };
    if (test_control [idx].name EQUALS NULL)
    {
      fprintf (stderr, "Cannot find test %s, not updated.\n",
        test);
      done = 1;
    };
    // yes, if we find nothing we'll still return OK
    idx++;
  };
  return (status);

} /* osdp_test_set_status */

