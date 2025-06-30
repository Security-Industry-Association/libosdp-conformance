---
title: libosdp-conformance release notice

---

This is libosdp-conformance, an ACU/PD/Monitor implementation of OSDP.

See Security-Industry-Association/osdp-verified for details on conformance testing.

### Updates in 1.101 Build 2 ###

Fix use of CP prefix in osdp commands.  factory default link in Test-ACU.html now works.
Update test results telemetry.

### Updates in 1.101 Build 1 ###

Added new command return-input to return supervised input.

### Updates in 1.100 Build 1 ###

Added refuse-comset option to cause PD to respond to COMSET with a COM
with unchanged values.  

Note both ACU and PD now have default-parameters options in the web UI.

Corrected comset/com processing for acu

### Updates in 1.91-1 Build 1 ###

Correct MFGREP logic (to stop sending MFGREP and an ACK.)

### Updates in 1.91 Build 0 ###

correct COMSET and COM behavior.  COM must be returned on current addr/speed and THEN
switch to the new address/speed, if in fact it's different.
Note that the default is now "command=comset" means a 0 s 9600 send on current address (not
on config address.)

### Updates in 1.90 Build 2 ###

Correct osdp_KEEPACTIVE command (it wasn't sending the 2 byte payload.)
Tune some debug log messages.
add action routine for PDCAP.
fix some log messages for osdp_RAW
tuned the error output for osdp_CCRYPT.

### Updates in 1.90 Build 1 ###

Added tone-code support to buzz command.

### Updates in 1.80 Build 4 ###

Correct PD processing of retry for checksum.

### Updates in 1.80 Build 3 ###

fix parity in default card number.
trim some debug messages from stderr.
enhance debug logging during secure channel

### Updates in 1.80 Build 2 ###

Clean up LED debug messages;
note introduces some seq 0 troubleshooting.

### Updates in 1.80 Build 1 ###

correct new-address/new-speed in comset script.

### Updates in 1.80 Build 0 ###

Added support for bad response testing
(command conform-050-09-10), using the preserved serial speed.
Updated settings documentation.
changed encryption blocking so a payload with an odd number of whole cipherblocks
is padded.

## Command conform-050-09-10 ##

### Updates in 1.71 Build 2 ###

Clear the keypad memory when stats are cleared.
Eliminated gratuitous log messages in multi-PD chains.

### Updates in 1.71 Build 1 ###

Added PD support for retries.  Cleartext only at this time.
Added support for interleaved responses in the PD.

### Updates in 1.70 Build 1 ###

Correct issue in file transfer UI.

## Updates in 1.70 Build 0 ###

Added support for interleaved responses during file transfer.

### Updates in 1.62 Build 0 ###

- Add support for file transfer with other file types via CGI.  (It was there already
with the "transfer" command, requires command line access.)

- Tune ACU HTML page and some logging. add page "transfer-exercises.html".

### Updates in 1.61 Build 0 ###

Correct PD secure channel set-up to accept a fresh CHLNG after a partial
connection.  This allows a default-key challenge after the ACU has determined
the alleged paired key is wrong.

### Updates in 1.60 Build 2 ###

- use variant-specific logic to validate RMAC_I response to ACU.
also allow protocol variant 0 but give warnings and fail it's test.
- respect filetransfer send size parameter in FTSTAT
- only output results files if (a) verbosity > 1 or (b) verbosity 1 and you do a REPORT command.
- minor command documentation update.
- correct package build workflow to include documentation (*.pdf in /opt/osdp-conformance/etc);
moved all PDF's there.
- aes install script moved to src-tools
- add UI option to set verbosity to 1 for test-only telemetry.

### updates in 1.60 Build 1

add text message if OSDP is already running.

Remove more logging at verbosity 1.  verbosity settings:
```
verbosity settings:
level 0: no/minimal logging or test reporting; tracing still works
level 1: no/minimal logging, test reporting available
level 3: default, logging and test reporting
level 9: debug
```


### updates in 1.51 Build 2

fixed hyphenation errors in status commands


### updates in 1.51 Build 1

fixed link in PD web page.

### updates in 1.51 Build 0

parameter update fixes

### updates in 1.50 build 3

fixed osdp_OSTATR secure channel response
fixed ISTATR response

### updates in 1.50 build 2

introduce SERVICE_ROOT environment variable for action callouts
refactored source code for action routines.

tune callout so osdp_MFG can be used with plugins

### updates in 1.50 build 1 ###

added osdp root path logic for actions and responses, moved actions, moved
responses out of tmp.  tuned ftstat logging.

### updates in 1.50 build 0 ###

change all _ to - in commands and command parameters

### updates in 1.41 build 1 ###

tune osdp_PDID output, add /opt/osdp-conformance/tmp/response_PDID

### updates in 1.41 build 0 ###

added 'react' command.

### updates in 1.40 build 2 ###

correct osdp_COM response to include full speed.

change the ISTATR response test to use the configured number of inputs

more subtle logging of FTSTAT; less uncontrolled logging to stderr

### updates in 1.40 build 1 ###

tweak nak logging for PD
instrument nak to all LED commands.

### updates in 1.39 build 5 ###

correct availability of input-status command.

### updates in 1.39 build 3 ###

added a "version" setting so you can spoof you OSPD capability report.

changed PDCAP output list to make it clearer that is a numbered list not the capabilities
number field.

add file-type option to file transfer command.

### updates in 1.39 build 2 ###

updated osdpcap doc in root directory

added 460800 and 921600 speeds

### updates in 1.39 build 1 ###

add command to induce istatr

### updates in 1.39 build 0 ###

fix double reporting of naks received.

tune osdp-status.json so it is more convienient to tail.


### updates in 1.38 build 4 ###

expand max size packet sent with text command

### updates in 1.38 build 3 ###

add OUI to osdp_MFGERRR
add delay to osdp_FTSTAT processing in reboot case
add service definitions for monitor and PD service variants

### updates in 1.38 build 2 ###

correct issue writing and reading osdp-saved-parameters.json (used in key management for secure channel.)

### updates in 1.38 build 1 ###

correct buzzer logic so it will use an on/off only buzzer.

### updates in 1.37 Build 1 ###

add RND.A and RND.B settings to open-osdp-params.json.

### updates in 1.32 Build 4 ###

started to change 100-ACU-test to use new style commands and test numbers

### updates in 1.32 Build 1 ###
updated send-explicit to work with max size commands

added mfg-response directive to allow PD to send a response.

changes in 1.31-5
input_status command properly queued (so it is not sometimes dropped.)
tune file transfer size calc to accomodate secure channel.
added new "outputs" option to output command (supports up to 16 outputs.)

see repo log for previous changes

