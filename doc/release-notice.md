---
title: libosdp-conformance release notice

---

This is libosdp-conformance, an ACU/PD/Monitor implementation of OSDP.

See Security-Industry-Association/osdp-verified for details on conformance testing.

### updates in 1.50 build 1 ###

added osdp root path logic for actions and responses, moved actions, moved
responses out of tmp

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

changes in 1.27-4
clarified some confusion in command injection shell infrastructure around ACU vs. CP naming.
fix conflation of max message size PD can receive vs. max message size PD can
reassemble.
pulled version numbers back in line

changes in 1.27-1
fix file transfer size calculations
fix large packet send/receive testing

changes in 1.26-2
merge in HTML changes

changes in 1.26-1
improved performance at verbosity zero to support PD actions for a faster ACU

changes in 1.25-2

enhanced instrumentation on speed tests

cleanup of test results logic (to use api everywhere)

correction of ghost test results

remove status update on every poll to reduce filesystem io

changes in 1.23-1

fix retry logic for secure channel commands

you can now create a debian package and install that.  Use "make service" to make packages.

libosdp-conformance can be run as a (systemd) service as an ACU.  See doc/INSTALL-service.txt


