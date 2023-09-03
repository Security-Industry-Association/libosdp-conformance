libosdp-conformance commands
============================

comset
------

osdp_COMSET sets the address and speed of the PD.

| Argument | Value |
| -------- | ----- |
|          |       |
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



