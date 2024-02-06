---
title: libosdp-conformance commands
---

Introduction
============

Commands in the form one JSONL (one line JSON files) can
be sent to libosdp-conformance.  There is a Unix socket created
at startup called open-osdp-control.  A utility is provided
to inject the commands, open-osdp-kick.

Command Usage
=============

Commands
========

(this is partial.  the markdonw file
is a work in progress.)

Command comset
--------------

This command causes the ACU to send an osdp_COMSET command
to set the address and speed of the PD.

There are no defaults.

| Argument | Value |
| -------- | ----- |
|          |       |
| command        | comset                                                  |
|                |                                                         |
| cleartext   | 1 to send in the clear even if a secure channel is active. |
|             |                                            |
| new_address | decimal value of a supported OSDP address. |
|             |                                            |
| new_speed   | decimal value of a supported OSDP speed.   |
|                |                                                         |
| reset-sequence | 1 to reset the sequence number to zero                  |
|                |                                                         |
| send-direct    | 1 to send on the current PD id else sends on 0x7F       |
|                |                                                         |

Command genauth
---------------

This command sends an osdp_CRAUTH to the PD.

There are no defaults.

| Argument | Value                    |
| -------- | -----                    |
|          |                          |
| command  | genauth                  |
|          |                          |
| template | "witness" or "challenge" |
|          |                          |
| keyref   | "8E" for card auth key.  See SP800-73-4 Part 1 Page 19 Table 4b.) |
|          |                                                                                       |
| algoref  | "07" for RSA, 11 fo ECC P-256 or 14 for ECC P-384.  See SP800-78-4 Table 6-2 page 12. |
|          |                                                                                       |
| payload  | "(hex bytes)", a well-formed Dynamic Authentication Template.                          |

Command identify
----------------

This command sends an osdp_ID to the PD.

Default behavior is to send to the currently-configured PD address on the current session (secure or unencrypted.)

| Argument | Value                    |
| -------- | -----                    |
|          |                          |
| command  | identify                 |
|          |                          |
| cleartext | "1" to send unencrypted. |
|          |                          |
| config-address | "1" to send to 0x7F, unencrypted. |
|          |                          |
| new-sequence | "1" to reset sequence number to zero. |

Command input-status
--------------------

This response sends an osdp_ISTATR to the ACU.  It is hard-coded to indicate input zero (the first one) is active.

| Argument | Value                    |
| -------- | -----                    |
|          |                          |
| command  | input-status             |

Command present-card
--------------------

This command causes the PD to respond with a card read, an osdp_RAW response.

Defaults

- bits from settings, or 26.
- format is 0 (unspecified)
- value from settings


| Argument | Value |
| -------- | ----- |
|          |       |
| command        | present-card                                            |
|                |                                                         |
| bits           | in decimal, number of bits in response.                 |
|             |                                            |
| format         | format field of RAW response.  Choices are "p-data-p" or a 2-hexit hex value. |
|             |                                            |
| raw            | hexadecimal raw value.                                  |
|                |                                                         |

Other Commands
--------------

- acurxsize
- bioread
- biomatch
- busy
- buzz
- capabilities
- conform_050_06_02
- conform_050_09_16
- conform-070-17-02
- conform_2_11_3
- conform_2_14_3
- conform_3_14_2
- conform_2_2_1
- conform_2_2_2
- conform_2_2_3
- conform_2_2_4
- conform_2_6_1
- conform_3_20_1
- conform_6_10_2
- conform_6_10_2
- factory-default
- induce-NAK
- keep-active
- keyset
- mfg
- mfg-response
- ondemand-lstatr
- pivdata
- polling
- reset
- reset-statistics
- scbk-default
- send-explicit
- text
- trace

