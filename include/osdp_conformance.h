/*
  osdp_conformance.h - conformance metrics per profiles

  (C)Copyright 2014-2017 Smithee,Spelvin,Agnew & Plinge, Inc.

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

typedef struct osdp_interop_assessment
{
  int
    pass;
  int
    fail;
  int
    untested;
  int
    skipped;
  int
    conforming_messages;
  int
    last_unknown_command;

  // 2-x

  OSDP_CONFORM physical_interface;      // 2-1-1
  OSDP_CONFORM signalling;              // 2-2-1
  OSDP_CONFORM alt_speed_2;             // 2-2-2
  OSDP_CONFORM alt_speed_3;             // 2-2-3
  OSDP_CONFORM alt_speed_4;             // 2-2-4
  OSDP_CONFORM character_encoding;      // 2-3-1
  OSDP_CONFORM channel_access;          // 2-4-1
  OSDP_CONFORM timeout_resend;          // 2-4-2
  OSDP_CONFORM busy_resend;             // 2-4-3
  OSDP_CONFORM new_on_busy;             // 2-4-4
  OSDP_CONFORM multibyte_data_encoding; // 2-5-1
  OSDP_CONFORM packet_size_limits;      // 2-6-1
  OSDP_CONFORM packet_size_from_pd;     // 2-6-2
  OSDP_CONFORM packet_size_stress_cp;   // 2-6-3
  OSDP_CONFORM timing;                  // 2-7-1
  OSDP_CONFORM max_delay;               // 2-7-2
  OSDP_CONFORM offline_test;            // 2-7-3
  OSDP_CONFORM message_synchronization; // 2-8-1
  OSDP_CONFORM packet_format;           // 2-9-1
  OSDP_CONFORM SOM;                     // 2-10-1
  OSDP_CONFORM SOM_sent;                // 2-10-2
  OSDP_CONFORM ADDR;                    // 2-11-1
  OSDP_CONFORM address_2;               // 2-11-2
  OSDP_CONFORM address_config;          // 2-11-3
  OSDP_CONFORM LEN;                     // 2-12-1
  OSDP_CONFORM CTRL;                    // 2-13-1
  OSDP_CONFORM control_2;               // 2-13-2
  OSDP_CONFORM scb_absent;              // 2-13-3
  OSDP_CONFORM ctl_seq;                 // 2-13-4
  OSDP_CONFORM security_block;          // 2-14-1
  OSDP_CONFORM CMND_REPLY;              // 2-15-1
  OSDP_CONFORM invalid_command;         // 2-15-2
  OSDP_CONFORM CHKSUM_CRC16;            // 2-16-1
  OSDP_CONFORM checksum;                // 2-16-2
  OSDP_CONFORM multipart;               // 2.17

  // 3-x

  OSDP_CONFORM cmd_poll;                // 3-1-1
  OSDP_CONFORM cmd_poll_raw;            // 3-1-2
  OSDP_CONFORM cmd_poll_lstatr;         // 3-1-3
  OSDP_CONFORM cmd_poll_response_4;     // 3-1-4
  OSDP_CONFORM cmd_id;                  // 3-2-1
  OSDP_CONFORM cmd_pdcap;               // 3-3-1
  OSDP_CONFORM cmd_diag;                // 3-4-1
  OSDP_CONFORM cmd_lstat;               // 3-5-1
  OSDP_CONFORM cmd_istat;               // 3-6-1
  OSDP_CONFORM cmd_ostat;               // 3-7-1
  OSDP_CONFORM cmd_ostat_ack;           // 3-7-2
  OSDP_CONFORM cmd_rstat;               // 3-8-1
  OSDP_CONFORM cmd_out;                 // 3-9-1
  OSDP_CONFORM cmd_led_red;             // 3-10-1
  OSDP_CONFORM cmd_led_green;           // 3-10-2
  OSDP_CONFORM cmd_buz;                 // 3-11-1
  OSDP_CONFORM cmd_text;                // 3-12-1
  OSDP_CONFORM cmd_comset;              // 3-13-1
  OSDP_CONFORM cmd_prompt;              // 3-16-1
  OSDP_CONFORM cmd_bioread;             // 3-17-1
  OSDP_CONFORM cmd_biomatch;            // 3-18-1
  OSDP_CONFORM cmd_keyset;              // 3-??-1
  OSDP_CONFORM cmd_chlng;               // 3-??-1
  OSDP_CONFORM cmd_scrypt;              // 3-??-1
  //OSDP_CONFORM cmd_cont;                // 3-19-1
  OSDP_CONFORM cmd_mfg;                 // 3-20-1
  OSDP_CONFORM cmd_stop_multi;          // 3-21-1
  OSDP_CONFORM cmd_max_rec;             // 3-22-1
  OSDP_CONFORM cmd_filetransfer;         // 3-23-1

  // 4-x Replies

  OSDP_CONFORM rep_ack;                 // 4-1-1
  OSDP_CONFORM rep_nak;                 // 4-2-1
  OSDP_CONFORM rep_device_ident;        // 4-3-1
  OSDP_CONFORM resp_ident_consistent;   // 4-3-2
  OSDP_CONFORM rep_device_capas;        // 4-4-1
  OSDP_CONFORM rep_capas_consistent;    // 4-4-2
  OSDP_CONFORM resp_lstatr;             // 4-5-1
  OSDP_CONFORM resp_lstatr_tamper;      // 4-5-2
  OSDP_CONFORM resp_lstatr_power;       // 4-5-3
  OSDP_CONFORM resp_input_stat;         // 4-6-1
  OSDP_CONFORM resp_input_consistent;   // 4-6-2
  OSDP_CONFORM resp_output_stat;        // 4-7-1
  OSDP_CONFORM resp_ostatr_poll;        // 4-7-2
  OSDP_CONFORM resp_ostatr_range;       // 4-7-3
  OSDP_CONFORM resp_rstatr;             // 4-8-1
  OSDP_CONFORM rep_raw;                 // 4-9
  OSDP_CONFORM rep_formatted;           // 4-10-1
  OSDP_CONFORM resp_keypad;             // 4-11-1
  OSDP_CONFORM resp_com;                // 4-12-1
  OSDP_CONFORM rep_scan_send;           // 4-13
  OSDP_CONFORM rep_scan_match;          // 4-14
  OSDP_CONFORM rep_ccrypt;              // 4-??
  OSDP_CONFORM resp_mfg;                // 4-15-1
  OSDP_CONFORM resp_busy;               // 4-16-1
  OSDP_CONFORM resp_ftstat;             // 4-17-1
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

