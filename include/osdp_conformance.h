/*
  osdp_conformance.h - conformance metrics per profiles

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
  OSDP_CONFORM address_3;               // 2-11-3
  OSDP_CONFORM LEN;                     // 2-12-1
  OSDP_CONFORM CTRL;                    // 2-13-1
  OSDP_CONFORM control_2;               // 2-13-2
  OSDP_CONFORM control_3;               // 2-13-3
  OSDP_CONFORM security_block;          // 2-14-1
  OSDP_CONFORM CMND_REPLY;              // 2-15-1
  OSDP_CONFORM invalid_command;         // 2-15-2
  OSDP_CONFORM CHKSUM_CRC16;            // 2-16-1
  OSDP_CONFORM checksum;                // 2-16-2
  OSDP_CONFORM multipart;               // 2.17

  // 3-x

  OSDP_CONFORM cmd_poll;                // 3-1-1
  OSDP_CONFORM cmd_poll_raw;            // 3-1-2
  OSDP_CONFORM cmd_poll_response_3;     // 3-1-3
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
  OSDP_CONFORM cmd_led;                 // 3.10
  OSDP_CONFORM cmd_buz;                 // 3.11
  OSDP_CONFORM cmd_text;                // 3.12
  OSDP_CONFORM cmd_comset;              // 3.13
  OSDP_CONFORM cmd_prompt;              // 3.16
  OSDP_CONFORM cmd_bioread;             // 3.17
  OSDP_CONFORM cmd_biomatch;            // 3.18
  OSDP_CONFORM cmd_cont;                // 3.19
  OSDP_CONFORM cmd_mfg;                 // 3.20

  // 4-x Replies

  OSDP_CONFORM rep_ack;                 // 4-1-1
  OSDP_CONFORM rep_nak;                 // 4-2-1
  OSDP_CONFORM rep_device_ident;        // 4-3-1
  OSDP_CONFORM rep_ident_consistent;    // 4-3-2
  OSDP_CONFORM rep_device_capas;        // 4-4-1
  OSDP_CONFORM rep_capas_consistent;    // 4-4-2
  OSDP_CONFORM resp_lstatr;             // 4-5-1
  OSDP_CONFORM resp_lstatr_tamper;      // 4-5-2
  OSDP_CONFORM resp_lstatr_power;       // 4-5-3
  OSDP_CONFORM rep_input_stat;          // 4-6-1
  OSDP_CONFORM rep_input_consistent;    // 4-6-2
  OSDP_CONFORM rep_output_stat;         // 4-7-1
  OSDP_CONFORM resp_ostatr_poll;        // 4-7-2
  OSDP_CONFORM resp_ostatr_range;       // 4-7-3
  OSDP_CONFORM resp_rstatr;             // 4-8-1
  OSDP_CONFORM rep_raw;                 // 4.9
  OSDP_CONFORM rep_formatted;           // 4.10
  OSDP_CONFORM rep_keypad;              // 4.11
  OSDP_CONFORM rep_comm;                // 4.12
  OSDP_CONFORM rep_scan_send;           // 4.13
  OSDP_CONFORM rep_scan_match;          // 4.14
  OSDP_CONFORM rep_busy;                // 4.17
} OSDP_INTEROP_ASSESSMENT;

#define PARAM_MMT (8) // minimum message thresshold


void
  dump_conformance
    (OSDP_CONTEXT *ctx,
    OSDP_INTEROP_ASSESSMENT *oconf);

