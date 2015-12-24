/*
  osdp_conformance.h - conformance metrics per profiles

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
#define OCONFORM_UNTESTED     (0)
#define OCONFORM_EXERCISED    (1)
#define OCONFORM_EX_GOOD_ONLY (2)
#define OCONFORM_FAIL         (3)

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
    conforming_messages;
  int
    last_unknown_command;
  // 2.x
  OSDP_CONFORM physical_interface;      // 2.1
  OSDP_CONFORM signalling;              // 2.2
  OSDP_CONFORM character_encoding;      // 2.3
  OSDP_CONFORM channel_access;          // 2.4
  OSDP_CONFORM multibyte_data_encoding; // 2.5
  OSDP_CONFORM packet_size_limits;      // 2.6
  OSDP_CONFORM timing;                  // 2.7
  OSDP_CONFORM message_sychronization;  // 2.8
  OSDP_CONFORM packet_format;           // 2.9
  OSDP_CONFORM SOM;                     // 2.10
  OSDP_CONFORM ADDR;                    // 2.11
  OSDP_CONFORM LEN;                     // 2.12
  OSDP_CONFORM CTRL;                    // 2.13
  OSDP_CONFORM security_block;          // 2.14
  OSDP_CONFORM CMND_REPLY;              // 2.15
  OSDP_CONFORM CHKSUM_CRC16;            // 2.16
  OSDP_CONFORM multipart;               // 2.17
  
  // 3.x
  OSDP_CONFORM cmd_poll;                // 3.1
  OSDP_CONFORM cmd_id;                  // 3.2
  OSDP_CONFORM cmd_pdcap;               // 3.3
  OSDP_CONFORM cmd_diag;                // 3.4
  OSDP_CONFORM cmd_lstat;               // 3.5
  OSDP_CONFORM cmd_istat;               // 3.6
  OSDP_CONFORM cmd_ostat;               // 3.7
  OSDP_CONFORM cmd_rstat;               // 3.8
  OSDP_CONFORM cmd_out;                 // 3.9
  OSDP_CONFORM cmd_led;                 // 3.10
  OSDP_CONFORM cmd_buz;                 // 3.11
  OSDP_CONFORM cmd_text;                // 3.12
  OSDP_CONFORM cmd_comset;              // 3.13
  OSDP_CONFORM cmd_prompt;              // 3.16
  OSDP_CONFORM cmd_bioread;             // 3.17
  OSDP_CONFORM cmd_biomatch;            // 3.18
  OSDP_CONFORM cmd_cont;                // 3.19
  OSDP_CONFORM cmd_mfg;                 // 3.20

  // 3.x partial...

  // 4.x Replies
  OSDP_CONFORM rep_ack;                 // 4.1
  OSDP_CONFORM rep_nak;                 // 4.2
  OSDP_CONFORM rep_device_ident;        // 4.3
  OSDP_CONFORM rep_device_capas;        // 4.4

  // 4.x partial...
  OSDP_CONFORM rep_raw;                 // 4.9

  OSDP_CONFORM rep_busy;                // 4.14

} OSDP_INTEROP_ASSESSMENT;

#define PARAM_MMT (3) // minimum message thresshold
