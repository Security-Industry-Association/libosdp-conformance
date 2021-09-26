/*
  osdp_conformance.h - conformance metrics per profiles

  (C)Copyright 2017-2021 Smithee Solutions LLC

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at
 
    http://www.apache.org/licenses/LICENSE-2.0
 
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Support provided by the Security Industry Association
  http://www.securityindustry.org
*/
#define OCONFORM_UNTESTED     (0)
#define OCONFORM_EXERCISED    (1)
#define OCONFORM_EX_GOOD_ONLY (2)
#define OCONFORM_FAIL         (3)
#define OCONFORM_SKIP         (4)

typedef struct osdp_conform
{
  unsigned char
    test_status;
} OSDP_CONFORM;

#define OOC_SYMBOL_physical_interface "050-01-01"
#define OOC_SYMBOL_signalling         "050-02-01"
#define OOC_SYMBOL_multibyte_data_encoding "050-05-01"
#define OOC_SYMBOL_packet_format      "050-09-01"
#define OOC_SYMBOL_seq_zero           "050-09-02"
#define OOC_SYMBOL_SOM                "050-09-03"
#define OOC_SYMBOL_LEN                "050-09-06"
#define OOC_SYMBOL_CTRL               "050-09-07"
#define OOC_SYMBOL_security_block     "050-09-08"
#define OOC_SYMBOL_CMND_REPLY         "050-09-09"
#define OOC_SYMBOL_checksum           "050-09-11"
#define OOC_SYMBOL_SOM_sent           "050-09-12"
#define OOC_SYMBOL_CRC                "050-09-15"
#define OOC_SYMBOL_CRC_bad_response   "050-09-16"
#define OOC_SYMBOL_CRC_bad_command    "050-09-17"

#define OOC_SYMBOL_cmd_poll           "060-02-01"
#define OOC_SYMBOL_poll_lstatr        "060-02-02"
#define OOC_SYMBOL_cmd_id             "060-03-01"
#define OOC_SYMBOL_cmd_cap            "060-04-01"
#define OOC_SYMBOL_cmd_lstat          "060-05-01"
#define OOC_SYMBOL_cmd_istat          "060-06-01"
#define OOC_SYMBOL_cmd_ostat          "060-07-01"
#define OOC_SYMBOL_cmd_rstat          "060-08-01"
#define OOC_SYMBOL_cmd_out            "060-09-01"
#define OOC_SYMBOL_cmd_led_any        "060-10-01"
// 10 02 through 09
#define OOC_SYMBOL_cmd_led_black      "060-10-02"
#define OOC_SYMBOL_cmd_led_red        "060-10-03"
#define OOC_SYMBOL_cmd_led_green      "060-10-04"
#define OOC_SYMBOL_cmd_led_amber      "060-10-05"
#define OOC_SYMBOL_cmd_led_blue       "060-10-06"
#define OOC_SYMBOL_cmd_led_magenta    "060-10-07"
#define OOC_SYMBOL_cmd_led_cyan       "060-10-08"
#define OOC_SYMBOL_cmd_led_white      "060-10-09"
#define OOC_SYMBOL_cmd_buz            "060-11-01"
#define OOC_SYMBOL_cmd_text           "060-12-01"
#define OOC_SYMBOL_cmd_comset         "060-13-01"
#define OOC_SYMBOL_cmd_bioread        "060-14-01"
#define OOC_SYMBOL_cmd_biomatch       "060-15-01"
#define OOC_SYMBOL_cmd_keyset         "060-16-01"
#define OOC_SYMBOL_scs_paired         "060-16-02"
#define OOC_SYMBOL_scs_rotate         "060-16-03"
#define OOC_SYMBOL_cmd_chlng          "060-17-01"
#define OOC_SYMBOL_cmd_scrypt         "060-18-01"
#define OOC_SYMBOL_cmd_mfg            "060-19-01"
#define OOC_SYMBOL_cmd_acurxsize      "060-20-01"
#define OOC_SYMBOL_cmd_keepactive     "060-21-01"
#define OOC_SYMBOL_cmd_pivdata        "060-23-01"
#define OOC_SYMBOL_cmd_genauth        "060-24-01"
#define OOC_SYMBOL_060_24_02          "060-24-02" // genauth after raw
#define OOC_SYMBOL_060_24_03          "060-24-03"
#define OOC_SYMBOL_cmd_crauth         "060-25-01"
#define OOC_SYMBOL_060_25_02          "060-25-02" // crauth after raw
#define OOC_SYMBOL_060_25_03          "060-25-03"
#define OOC_SYMBOL_cmd_filetransfer   "060-26-01"
#define OOC_SYMBOL_cmd_xwr            "060-27-01"

#define OOC_SYMBOL_rep_ack            "070-02-01"
#define OOC_SYMBOL_resp_ostatr_ack    "070-02-02"
#define OOC_SYMBOL_rep_nak            "070-03-01"
#define OOC_SYMBOL_resp_nak_not_msg   "070-03-02"
#define OOC_SYMBOL_rep_device_ident   "070-04-01"
#define OOC_SYMBOL_rep_pdid_check     "070-04-02"
#define OOC_SYMBOL_rep_device_capas   "070-05-01"
#define OOC_SYMBOL_resp_cap_card_fmt  "070-05-03"
#define OOC_SYMBOL_resp_lstatr        "070-06-01"
#define OOC_SYMBOL_resp_lstatr_tamper "070-06-02"
#define OOC_SYMBOL_resp_lstatr_power  "070-06-03"
#define OOC_SYMBOL_resp_istatr        "070-07-01"
#define OOC_SYMBOL_resp_ostatr        "070-08-01"
#define OOC_SYMBOL_resp_rstatr        "070-09-01"
#define OOC_SYMBOL_rep_raw            "070-10-01"
#define OOC_SYMBOL_resp_keypad        "070-12-01"
#define OOC_SYMBOL_resp_com           "070-13-01"
#define OOC_SYMBOL_resp_ccrypt        "070-16-01"
#define OOC_SYMBOL_resp_rmac_i        "070-17-01"
#define OOC_SYMBOL_resp_mfgrep        "070-18-01"
#define OOC_SYMBOL_resp_busy          "070-19-01"
#define OOC_SYMBOL_resp_pivdatar      "070-20-01"
#define OOC_SYMBOL_resp_genauthr      "070-21-01"
#define OOC_SYMBOL_resp_crauthr       "070-22-01"
#define OOC_SYMBOL_resp_mfgerrr       "070-24-01"
#define OOC_SYMBOL_resp_ftstat        "070-25-01"
#define OOC_SYMBOL_ftstat_dly_init    "070-25-02"
#define OOC_SYMBOL_ftstat_dly_final   "070-25-03"
#define OOC_SYMBOL_ftstat_bufsize     "070-25-04"

typedef struct osdp_interop_assessment
{
  int pass;
  int fail;
  int untested;
  int skipped;
  int conforming_messages;
  int last_unknown_command;

  // section 5

  OSDP_CONFORM physical_interface;
  OSDP_CONFORM signalling;
  OSDP_CONFORM alt_speed_2;             // 2-2-2
  OSDP_CONFORM alt_speed_3;             // 2-2-3
  OSDP_CONFORM alt_speed_4;             // 2-2-4
  OSDP_CONFORM character_encoding;      // 2-3-1
  OSDP_CONFORM channel_access;          // 2-4-1
  OSDP_CONFORM timeout_resend;          // 2-4-2
  OSDP_CONFORM busy_resend;             // 2-4-3
  OSDP_CONFORM new_on_busy;             // 2-4-4
  OSDP_CONFORM multibyte_data_encoding;
  OSDP_CONFORM packet_size_limits;      // 2-6-1 // stress test ACU to PD
  OSDP_CONFORM packet_size_from_pd;     // 2-6-2
  OSDP_CONFORM packet_size_stress_cp;   // 2-6-3 // stress test PD to ACU
  OSDP_CONFORM packet_size_from_acu;    // 2-6-4 
  OSDP_CONFORM timing;                  // 2-7-1
  OSDP_CONFORM max_delay;               // 2-7-2
  OSDP_CONFORM offline_test;            // 2-7-3
  OSDP_CONFORM message_synchronization; // 2-8-1
  OSDP_CONFORM packet_format;
  OSDP_CONFORM seq_zero;
  OSDP_CONFORM SOM;
  OSDP_CONFORM SOM_sent;
  OSDP_CONFORM ADDR;                    // 2-11-1
  OSDP_CONFORM address_2;               // 2-11-2
  OSDP_CONFORM address_config;          // 2-11-3
  OSDP_CONFORM LEN;
  OSDP_CONFORM CTRL;
  OSDP_CONFORM control_2;               // 2-13-2
  OSDP_CONFORM ctl_seq;                 // 2-13-3
  OSDP_CONFORM security_block;          // 2-14-1
  OSDP_CONFORM scb_absent;              // 2-14-2
  OSDP_CONFORM rogue_secure_poll;       // 2-14-3
  OSDP_CONFORM CMND_REPLY;
  OSDP_CONFORM invalid_command;         // 2-15-2
  OSDP_CONFORM CRC;          
  OSDP_CONFORM CRC_bad_response;
  OSDP_CONFORM CRC_bad_command;
  OSDP_CONFORM checksum;    
  OSDP_CONFORM multipart;               // 2.17

  // section 6

  OSDP_CONFORM cmd_poll;
  OSDP_CONFORM cmd_poll_raw;
  OSDP_CONFORM poll_lstatr;
  OSDP_CONFORM cmd_poll_response_4;     // 3-1-4
  OSDP_CONFORM cmd_id;
  OSDP_CONFORM cmd_cap;
  OSDP_CONFORM cmd_diag;                // 3-4-1
  OSDP_CONFORM cmd_lstat;
  OSDP_CONFORM cmd_istat;
  OSDP_CONFORM cmd_ostat;               // 3-7-1
  OSDP_CONFORM cmd_ostat_ack;           // 3-7-2
  OSDP_CONFORM cmd_rstat;               // 3-8-1
  OSDP_CONFORM cmd_out;                 // 3-9-1
  OSDP_CONFORM cmd_led_any;
  OSDP_CONFORM cmd_led_black;           // 060-10-02
  OSDP_CONFORM cmd_led_red;
  OSDP_CONFORM cmd_led_green;
  OSDP_CONFORM cmd_led_amber;
  OSDP_CONFORM cmd_led_blue;
  OSDP_CONFORM cmd_led_magenta;
  OSDP_CONFORM cmd_led_cyan;
  OSDP_CONFORM cmd_led_white;
  OSDP_CONFORM cmd_buz;
  OSDP_CONFORM cmd_text;                // 3-12-1
  OSDP_CONFORM cmd_comset;
  OSDP_CONFORM cmd_prompt;              // 3-16-1
  OSDP_CONFORM cmd_bioread;
  OSDP_CONFORM cmd_biomatch;
  OSDP_CONFORM cmd_keyset;
  OSDP_CONFORM scs_paired;
  OSDP_CONFORM cmd_chlng;
  OSDP_CONFORM cmd_scrypt;
  OSDP_CONFORM cmd_acurxsize;
  OSDP_CONFORM cmd_mfg;                 // 3-20-1
  OSDP_CONFORM cmd_stop_multi;          // 3-21-1
  OSDP_CONFORM cmd_max_rec;             // 3-22-1 //ACURXSIZE
  OSDP_CONFORM cmd_filetransfer;        // 3-23-1
  OSDP_CONFORM cmd_keepactive;          // 3-24-2
  OSDP_CONFORM cmd_crauth;
  OSDP_CONFORM cmd_genauth;
  OSDP_CONFORM cmd_pivdata;

  // section 7

  OSDP_CONFORM rep_ack;
  OSDP_CONFORM resp_ostatr_ack;
  OSDP_CONFORM rep_nak;
  OSDP_CONFORM resp_nak_not_msg;
  OSDP_CONFORM rep_device_ident;
  OSDP_CONFORM rep_pdid_check;
  OSDP_CONFORM rep_device_capas;
  OSDP_CONFORM resp_cap_card_fmt;
  OSDP_CONFORM rep_capas_consistent;    // 4-4-2
  OSDP_CONFORM resp_lstatr;
  OSDP_CONFORM resp_lstatr_tamper;
  OSDP_CONFORM resp_lstatr_power;
  OSDP_CONFORM resp_istatr;
  OSDP_CONFORM resp_ostatr;
  OSDP_CONFORM resp_input_consistent;   // 4-6-2
  OSDP_CONFORM resp_ostatr_poll;        // 4-7-2
  OSDP_CONFORM resp_ostatr_range;       // 4-7-3
  OSDP_CONFORM resp_rstatr;             // 4-8-1
  OSDP_CONFORM rep_raw;                 // 4-9
  OSDP_CONFORM rep_formatted;           // 4-10-1
  OSDP_CONFORM resp_keypad;
  OSDP_CONFORM resp_com;
  OSDP_CONFORM rep_scan_send;           // 4-13
  OSDP_CONFORM rep_scan_match;          // 4-14
  OSDP_CONFORM resp_ccrypt;
  OSDP_CONFORM resp_rmac_i;
  OSDP_CONFORM resp_mfg;                // 4-15-1
  OSDP_CONFORM resp_mfgerrr;
  OSDP_CONFORM resp_busy;
  OSDP_CONFORM resp_ftstat;
  OSDP_CONFORM resp_ftstat_dly_init;
  OSDP_CONFORM resp_ftstat_dly_final;
  OSDP_CONFORM resp_ftstat_bufsize;
  OSDP_CONFORM resp_genauthr;
  OSDP_CONFORM resp_crauthr;
  OSDP_CONFORM resp_pivdatar;
} OSDP_INTEROP_ASSESSMENT;

#define PARAM_MMT (8) // minimum message thresshold

#define SET_PASS(ctx,testnum) \
  { \
    (void) osdp_conform_confirm (testnum); \
    if (ctx->role != OSDP_ROLE_MONITOR) \
    { \
      fprintf (stderr, \
        "********Test %s PASSED********\n", \
        testnum); \
      fprintf (ctx->log, \
        "********Test %s PASSED********\n", \
        testnum); \
    }; \
    ctx->test_in_progress [0] = 0; \
  };
#define SET_FAIL(ctx,testnum) \
  { \
    (void) osdp_conform_fail (testnum); \
    if (ctx->role != OSDP_ROLE_MONITOR) \
    { \
      fprintf (stderr, \
        "********Test %s FAILED********\n", \
        testnum); \
      fprintf (ctx->log, \
        "********Test %s FAILED********\n", \
        testnum); \
    }; \
    ctx->test_in_progress [0] = 0; \
  };


void
  dump_conformance
    (OSDP_CONTEXT *ctx,
    OSDP_INTEROP_ASSESSMENT *oconf);
int
  osdp_conform_confirm
    (char
      *test);
int
  osdp_conform_fail
    (char
      *test);

