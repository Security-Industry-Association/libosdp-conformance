/*
  iec-nak.h - NAK response code definitions for IEC 60839-11-5 (OSDP)

  (C)Copyright 2017-2020 Smithee Solutions LLC

  Support provided by the Security Industry Association
  OSDP Working Group community.

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

// NAK response codes for use with IEC 60839-11-5 and beyond

// NAK error codes (this matches IEC 60839-11-5 Section 7.3 Table 47 (Page 39)

#define OO_NAK_CHECK_CRC            (1)
#define OO_NAK_COMMAND_LENGTH       (2)
#define OO_NAK_UNK_CMD              (3)
#define OO_NAK_SEQUENCE             (4)
#define OO_NAK_UNSUP_SECBLK         (5)
#define OO_NAK_ENC_REQ              (6)
#define OO_NAK_BIO_TYPE_UNSUPPORTED (7)
#define OO_NAK_BIO_FMT_UNSUPPORTED  (8)
#define OO_NAK_CMD_UNABLE           (0x09)

// NAK error codes from May 2019 proposed NAK code extension

// 0x0A-0x0F Reserved for future use

#define OO_NAK_CARD_NOT_FOUND       (0x10)
#define OO_NAK_XMIT_FAILED          (0x11)
#define OO_NAK_INTERNAL_ERROR       (0x12)

// 0x13-0x7F Reserved for future use

// 0x80-0xFE Reserved for manufacturer-specific use

#define OO_NAK_PRIVATE              (0xff)

