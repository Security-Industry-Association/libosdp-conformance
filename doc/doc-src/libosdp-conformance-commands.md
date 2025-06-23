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
The speed is saved in osdp-saved-parameters.json and 
will be used when the PD is next started.

There are no defaults.

| Argument | Value |
| -------- | ----- |
|          |       |
| command        | comset                                                  |
|                |                                                         |
| cleartext   | 1 to send in the clear even if a secure channel is active. |
|             |                                            |
| new-address | decimal value of a supported OSDP address. |
|             |                                            |
| new-speed   | decimal value of a supported OSDP speed.   |
|                |                                                         |
| reset-sequence | 1 to reset the sequence number to zero                  |
|                |                                                         |
| send-direct    | 1 to send on the current PD id else sends on 0x7F       |
|                |                                                         |

## Command conform-050-09-10 ##

PD conformance test.  Causes the next response to an osdp_POLL to contain
an invalid response code.

___Defaults___

- no default values.

___Arguments___

| Argument       | Value |
| --------       | ----- |
|                |       |
| none        |  |
|                |       |

## Command dump-status ##

Dumps status report to log and flushes test results to the results directory as JSON files.

___Defaults___

None.

___Arguments___

None.

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

This response sends an osdp_ISTATR to the ACU.  If no argument is given it sets input 0 to 0x01.

| Argument | Value                    |
| -------- | -----                    |
|          |                          |
| command  | input-status             |
|          |                          |
| input-0  | 0-0xff hex               |


\newpage {}

## Command led ##

This command sends LED directives to the PD.  All arguments are decimal numbers, see OSDP spec for values.
Times are in units of 100 milliseconds.  Reader number is hard-coded to zero.

### Arguments ###

| Argument | Value |
| -------- | ----- |
|          |       |
| command-id  | led |
| led-number | LED number (in decimal, range 0-255) |
| perm-control | Perm command code (in decimal) |
| perm-off-color | Perm off color (in decimal) |
| perm-off-time | Perm off time (in decimal) |
| perm-on-color | Perm on color (in decimal) |
| perm-on-time | Perm on time (in decimal) |
} temp-control | Perm command code (in decimal) |
| temp-off-color | Temporary off color (in decimal) |
| temp-off-time | Temp off time (in decimal) |
| temp-on-color | Temporary on color (in decimal) |
| temp-on-time | Temp on time (in decimal) |
| temp-timer | Temporary timer duration (in decimal) |

### Defaults ###

| Argument | Value |
| -------- | ----- |
|          |       |
| led-number | 0 |
| perm-control | 1 (set) |
| perm-off-color | 0  (black) |
| perm-off-time | 0 |
| perm-on-color | 2 (green) |
| perm-on-time | 30 (x100ms) |
| temp-control | 0 (no-op) |
| temp-off-color | 2 (green) |
| temp-off-time | 3 (x100ms) |
| temp-on-color | 1 (red) |
| temp-on-time | 3 (x100ms) |
| temp-timer | 30 (x100ms) |

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

Command react
-------------

This command causes a specific command upon receipt of an osdp_RAW response.
It us used by LED (and eventually GENAUTH/CRAUTH for that off-nominal use case.)

| Argument | Value |
| -------- | ----- |
|          |       |
| reaction-command        | LED or GENAUTH or CRAUTH                                            |
|                |                                                         |
| reaction-details           | hex string to use as payload for reaction command.                 |
|             |                                            |

# return-input #

This command returns an input status.  If no value is specified it sets input 0 to a 1.

| Argument | Value |
| -------- | ----- |
|          |       |
| command  | return-input                                           |
|                |                                                         |
| input-0           | hex value (00-FF) to use for input 0 .                 |
|             |                                            |

\newpage{}

## Command transfer ##

This command causes the ACU to initiate a file transfer.

___Defaults___

- the default file to be transfered is /opt/osdp-conformance/run/ACU/osdp_data_file

___Arguments___

| Argument | Value |
| -------- | ----- |
|          |       |
| command        | identify |
|             |                                            |
| file         | fully path of file to be transferred. |
|             |                                            |
| file-type | (optional) file type to use.  Hex, must be nonzero. |

\newpage{}

## Command TEMPLATE ##

Text description goes here.

___Defaults___

- no default values.

___Arguments___

| Argument       | Value |
| --------       | ----- |
|                |       |
| command        | TEMPLATE |
|                |                                            |
| param1         | example parameter. |

\newpage{}

Other Commands
--------------

Command processing happens in src-lib/oo-cmdbreech.c.

Commands to be documented:

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

