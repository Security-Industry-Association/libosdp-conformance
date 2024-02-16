---
title: libosdp-conformance commands
---

Introduction
============

Commands in the form one JSONL (one line JSON files) can
be sent to libosdp-conformance.  There is a Unix socket created
at startup called open-osdp-control.  A utility is provided
to inject the commands, open-osdp-kick.

## How to send commands ##

1. create a one-line json file


```
  echo >"led.json" "{\"command\":\"led\"}"
```

2. send it to the OSDP control socket.  Note it must be superuser to do this.  Assuming this is an ACU sending commands to a PD:

```
  sudo /opt/osdp-conformance/bin/open-osdp-kick ACU <led.json
```

Command Usage
=============

Commands
========

(this is partial.  the markdown file
is a work in progress.)

\newpage{}

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

\newpage {}

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

\newpage{}

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

\newpage {}

Command input-status
--------------------

This response sends an osdp_ISTATR to the ACU.  It is hard-coded to indicate input zero (the first one) is active.

| Argument | Value                    |
| -------- | -----                    |
|          |                          |
| command  | input-status             |

\newpage {}

## Command led ##

This command sends LED directives to the PD.

### Defaults ###

LED 0
Perm Off Time 0
Perm Off Color Black
Perm On Color Green
Perm On Time 30
Reader 0
Temp Control NOP
Temp Timer LSB=30 MSB=0
Temp Off 3
Temp Off Color Green
Temp On 3
Temp On Color Red


### Arguments ###

| Argument | Value |
| -------- | ----- |
|          |       |
| command-id  | mfg |
|             |                                            |
| led-number | LED number (in decimal, range 0-255) |
|             |                                            |
| perm-control | Perm command code (in decimal) |
|             |                                            |
| perm-off-time | Perm off time (in decimal) |

perm-off-color

perm-on-time

perm-on-color

perm-on-color

temp-off-color

temp-off-time

temp-on-time

temp-on-color

temp-timer

temp-control

\newpage{}

Command mfg
-----------

This command causes the ACU to send an osdp_MFG command.

Defaults
t.b.d.

| Argument | Value |
| -------- | ----- |
|          |       |
| command-id  | mfg |
|             |                                            |
| oui | 3-byte organizational unit identifier |
|             |                                            |
| command-id | command number, in hex |
|             |                                            |
| command-specific-data | data, as hex string |
|             |                                            |

\newpage{}

## Command mfg-response ##

This response causes the PD to send an osdp_MFGREP response.

Defaults
t.b.d.


| Argument | Value |
| -------- | ----- |
|          |       |
| response-id  | mfg-response |
|             |                                            |
| oui | 3-byte organizational unit identifier |
|             |                                            |
| command-id | command number, in hex |
|             |                                            |
| response-specific-data | data, as hex string |
|             |                                            |


\newpage{}

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

\newpage{}

## Command transfer ##

This command causes the ACU to initiate a file transfer.

Defaults

- the default file to be transfered is /opt/osdp-conformance/run/ACU/osdp_data_file

| Argument | Value |
| -------- | ----- |
|          |       |
| command        | identify |
|             |                                            |
| file         | fully path of file to be transferred. |
|             |                                            |

\newpage{}

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
- ondemand-lstatr
- pivdata
- polling
- reset
- reset-statistics
- scbk-default
- send-explicit
- text
- trace

