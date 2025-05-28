/*
  osdp-800-53.h - definitions for OSDP for PIV

  (C)Copyright 2017-2025 Smithee Solutions LLC

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


#define OSDP_CMD_MSC_GETPIV  (0x10)
#define OSDP_CMD_MSC_KP_ACT  (0x13)
#define OSDP_CMD_MSC_CR_AUTH (0x14)
#define OSDP_REP_MSC_PIVDATA (0x10)
#define OSDP_REP_MSC_CR_AUTH (0x14)
#define OSDP_REP_MSC_STAT    (0xFD)

typedef struct __attribute__((packed)) osdp_getpiv
{
  char piv_object [3];
  char piv_element;
  char piv_offset [2];
} OSDP_GETPIV;

typedef struct __attribute__((packed)) osdp_msc_crauth
{
  char vendor_code [3];
  char command_id;
  unsigned short int mpd_size_total;
  unsigned short int mpd_offset;
  unsigned short int mpd_fragment_size;
  unsigned char data [2]; // just first 2 of data.  algref and keyref in first block
} OSDP_MSC_CR_AUTH;

typedef struct __attribute__((packed)) osdp_msc_getpiv
{
  char vendor_code [3];
  char command_id;
  char piv_object [3];
  char piv_element;
  char piv_offset [2];
} OSDP_MSC_GETPIV;

typedef struct __attribute__((packed)) osdp_msc_kp_act
{
  char vendor_code [3];
  char command_id;
  unsigned short int kp_act_time;
} OSDP_MSC_KP_ACT;
  

