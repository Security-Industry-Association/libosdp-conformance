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

Command present-card
--------------------

"command":"present-card"

"bits" - number of bits (in decimal)  in raw value.

"format" - format field of RAW response.  "p-data-p" or a 2-hexit hex value

"raw" - hex value.

defaults

- bits from settings, or 26.
- format is 0 (unspecified)
- value from settings

Other Commands
--------------

- acurxsize
- bioread
- biomatch
- busy
- buzz
- capabilities
- comset
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

