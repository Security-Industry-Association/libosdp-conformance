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
- identify
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

