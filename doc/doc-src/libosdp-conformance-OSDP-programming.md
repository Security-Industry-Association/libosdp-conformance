it's OUI is 0A0017

- it has x inputs
- it has x outputs
- it reports poweron
- it can report tamper
- it's max message size is zzz
- it accepts file transfer
- it has text output
- it supports card formats up to 1024 bits
- it supports CRC and checksum 
- it supports secure channel, with a standard SCBK-D, keyset, and out of band
key management.

\newpage{}

# Manufacturer Specific Commands #

## Manufacturer Ping ##

command 0x01
payload (first 8 reflected back)

response 0x01
payload (reflected first 8 from ping)

## Induce Error Response ##

command 0x03
payload as specified

command:mfg command-id:3 command-specific-data:313233

\newpage{}

