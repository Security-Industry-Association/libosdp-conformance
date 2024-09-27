---
title: libosdp-conformance release notice

---

This is libosdp-conformance, an ACU/PD/Monitor implementation of OSDP.

See Security-Industry-Association/osdp-verified for details on conformance testing.

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

