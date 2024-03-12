OSDP Testing with libosdp-conformance

An open source implementation of SIA OSDP 2.2/IEC 60839-11-5 (Open
Supervised Device Protocol - OSDP.)

[]{#anchor}Quick Start
======================

From user opsadmin1 from a Ubuntu 20 or equivalent Linux platform\...

Get it:

github clone
https://github.com/Security-Industry-Association/libosdp-conformance

Set up to build:

apt get install build-essential gdb libjansson-dev libgnutls28-dev

git clone https://github.com/kokke/tiny-AES-c

Build:

cd tiny-AES-c

make

cd ../libosdp-conformance

sudo mkdir -p /opt/osdp-conformance; chown opsadmin1:opsadmin1
/opt/osdp-conformance

./install-aes

make 2\>stderr osdp-tls

tar czvf \~/libosdp-conformance.tgz opt

cd /

tar xvf \~/libosdp-conformance.tgz

Configure:

cd /opt/osdp-conformance/run/ACU

cp open-osdp-params-ACU.json open-osdp-params.json

You may want to alter values to control checksum, secure channel, etc.
See the configuration examples and the section on parameters to place in
open-osdp-params.json.

Run (as an ACU):

cd /opt/osdp-conformance/run/ACU

sudo /opt/osdp-conformance/bin/open-osdp

Similarly for the ACU or the Monitor. See the install details to set up
a platform with a web UI.

[]{#anchor-1}Introduction
=========================

DRAFT documentation. Web UI is being updated to support *OSDP Verified*.

The libosdp-conformance package implements the OSDP protocol as an ACU,
a PD, or in a monitoring configuration. It is written in C for use in a
generic Linux/Posix environment such as Ubuntu or Devuan or Raspbian. It
was originally built to operate from the linux command line, a
simplified HTML/CGI interface was later added. This document describes
how to build and operate the package. The main purpose of this package
is to provide a conformance test platform for protocol interoperability
testing. The monitor is useful by itself. ACU\'s or PD\'s can be
exercised with the package. It is assumed that a proper Linux serial
device driver is available to access a 2-wire RS-485 interface. TCP and
TLS are also available in the package.

[]{#anchor-2}Documentation
--------------------------

The doc directory contains this document and other files.

This document contains:

-   quick-start for build and run
-   build instructions
-   \...

Other documentation

-   example OSDP configuration files
-   example OSDP control directives
-   osdp pcap format documentation
-   example configuration files for installing libosdp-conformance on a
    Linux platform.
-   errata for recent IEC 60839-11-5 draft(s)

example platform set-up files

[]{#anchor-3}Whats in the repo
------------------------------

Contents of the package

src-lib

include

src-ui

test

doc

doc-src

doc-pdf

spec - iec errata

src-485

src-tls

src-tools

[]{#anchor-4}Building from source
=================================

This assumes a Linux platform. The description is written for user
\"opsadmin1\", which has sudo. It is assumed there is a 2-wire RS-485
device attached as /dev/ttyUSB0.

[]{#anchor-5}Steps to set up libosdp-conformance
------------------------------------------------

A. install these packages to build:

*apt install build-essential gdb libjansson-dev libgnutls28-dev apache2*

B. get the AES library from github

git clone https://github.com/kokke/tiny-AES-c

C. get libosdp-conformance from github

git clone
https://github.com/Security-Industry-Association/libosdp-conformance

D. set up environment

sudo mkdir /opt/osdp-conformance

sudo chown opsadmin1:opsadmin1 /opt/osdp-conformance

E. build AES

cd tiny-AES-c

make

F. install AES for use by OSDP

cd libosdp-conformance

./install-aes

G. build the OSDP code

make 2\>stderr osdp-tls

H. create the distribution tarball

tar czvf \~/libosdp-conformance.tgz opt

I. install the package

cd /

tar xvf \~/libosdp-conformance.tgz

[]{#anchor-6}Platform Set-Up
----------------------------

There is a linux socket to accept commands. This is accessed either
directly (send a file using open-osdp-kick) or through an HTML/CGI
interface. A Debian package is built (so you can use \"dpkg -i \...\" to
install it.) An additional package allows creation of an OSDP (ACU)
service on systemd-capable linux platforms.

The user interface uses HTML and CGI programs. It is built on apache2.
It also uses shell scripts which rely on \"sudo -n\" and so www-data has
been configured with a shell and sudo.

### []{#anchor-7}Platform Set-up (legacy configuration)

A. install apache2. place the apache config file (in
doc/linux-sample/\...) in /etc/apache2/sites-enabled. This causes
/opt/osdp-conformance/www to be the web server content directory and
/opt/osdp-conformance/cgi-bin to be the web applications directory.

-   remove the default configuration, replace it with the \"osdp.conf\"
    apache config file (see doc/linux-sample.)
-   enable CGI processing (add symlinks in /etc/apache2/mods-enabled)

B. Set up user www-data

-   change /etc/passwd so that www-data\'s default shell is /bin/bash
-   add a sudo entry to /etc/sudoers.d (see file in doc/linux-sample/.)

### []{#anchor-8}Platform Set-up (systemd)

Build the packages including the service set-up package

make clean

make service

Install the packages.

dpkg -i libosdp-conformance\_\... osdp-service\_\...

[]{#anchor-9}Operation
======================

This section describes how to use the package. It can act as a PD or an
ACU or a protocol monitor. This assumes you set up using the build
procedure so the package is in /opt/osdp-conformance and you have the
configuration parameters set (the default is 9600/address 0.)

[]{#anchor-10}Using the OSDP Monitor
------------------------------------

The osdp server can be used to monitor an OSDP session. The 2-wire
RS-485 data connection is capable of supporting an additional device.
This is used in monitor mode where it simply listens for connections. No
web user interface is used, you need to connect one or more console
sessions and \"tail\" the log.

### []{#anchor-11}Set-up

Create a parameter file in the MON directory

cd /opt/osdp-conformance/run/MON

cp open-osdp-params-MON.json open-osdp-params.json

### []{#anchor-12}Starting the Monitor

To start the monitor, start two shells.

In the first shell, strat the monitor:

cd /opt/osdp-conformance/run/MON

sudo /opt/osdp-conformance/bin/open-osdp

In the second shell, watch the log:

cd /opt/osdp-conformance/run/MON

tail -f osdp.log

[]{#anchor-13}Using the OSDP PD
-------------------------------

This is a PD implementation used to exercise ACU\'s. A log is created,
file /opt/osdp-conformance/run/PD/osdp.log. Set up the settings file
open-osdp-params.json once and then you can start it from the command
line or the web UI.

### []{#anchor-14}Set-up

One-time set-up: In the PD directory copy the sample parameter file to
open-osdp-params.json. This is set up for 9600, address 0. Edit the JSON
file with a text editor if you want to change the start-up settings.

cd /opt/osdp-conformance/run/PD

cp open-osdp-params-PD.json open-osdp-params.json

### []{#anchor-15}Running the PD

From the web UI navigate to http://tester/osdp-conformance-PD.html.
Start the PD, then use the PD status to conform there are messages being
exchanged.

### []{#anchor-16}PD (Web) Interface

The keywords in bold below appear as HTML links.

-   **Start** to start the PD
-   **Stop** to stop the PD
-   Display PD **status**. This displays the JSON status file. acu-polls
    and pd-acks should be changing.
-   Set the log verbosity to normal (**moderate**) or loud
    (**verbose**.) These correspond to verbosity 3 and verbosity 9
    respectively if you want to change the start-up settings.
-   You can generate an old-style conformance report (\"Generate
    **report**\"), and display it (\"Display **report**\".) Generating
    the report creates the new-style test result files for the automatic
    entries.
-   The most recent messages are displayed with \"Recent PD **log**\".
-   Errors in operation appear in the **error** log.
-   you can stop the platform with the **stop** command (it delays
    serveral seconds before poweroff.)

Various tests can be activated. Some tests are listed as \"automatic\"
which means the test results are reported either when the message
exchange happens or when a report is generated.

### []{#anchor-17}Command Line

From the command line

cd /opt/osdp-conformance/run/PD

sudo /opt/osdp-conformance/bin/open-osdp

[]{#anchor-18}Using the OSDP ACU
--------------------------------

This is an ACU implementation used to exercise PD\'s. A log is created,
file /opt/osdp-conformance/run/ACU/osdp.log. Set up the settings file
open-osdp-params.json once and then you can start it from the command
line or the web UI.

### []{#anchor-19}Set-up

One-time set-up: In the ACU directory copy the sample parameter file to
open-osdp-params.json. This is set up for 9600, address 0. Edit the JSON
file with a text editor if you want to change the start-up settings.

cd /opt/osdp-conformance/run/ACU

cp open-osdp-params-ACU.json open-osdp-params.json

### []{#anchor-20}Running the ACU

From the web UI navigate to http://tester/Test-ACU.html. Start the ACU,
then use the ACU status to conform there are messages being exchanged.

### []{#anchor-21}ACU (Web) Interface

The keywords in bold below appear as HTML links.

-   **Start** to start the ACU
-   **Stop** to stop the ACU
-   Display ACU **status**. This displays the JSON status file.
    acu-polls and pd-acks should be changing.
-   Set the log verbosity to normal (**moderate**) or loud
    (**verbose**.) These correspond to verbosity 3 and verbosity 9
    respectively if you want to change the start-up settings.
-   You can generate an old-style conformance report (\"Generate
    **report**\"), and display it (\"Display **report**\".) Generating
    the report creates the new-style test result files for the automatic
    entries.
-   The most recent messages are displayed with \"Recent ACU **log**\".
-   Errors in operation appear in the **error** log.

Various tests can be activated. Some tests are listed as \"automatic\"
which means the test results are reported either when the message
exchange happens or when a report is generated.

### []{#anchor-22}Command Line

From the command line

cd /opt/osdp-conformance/run/ACU

sudo /opt/osdp-conformance/bin/open-osdp

[]{#anchor-23}Additional Tools
------------------------------

### []{#anchor-24}osdp-decode

/cgi-bin/osdp-decode is a CGI form to run the message parser. Used with
hex byte strings, must start with the SOM (0x53)

[]{#anchor-25}Conformance Testing
=================================

[]{#anchor-26}Conformance Instrumentation
-----------------------------------------

There is code to exercise the tests listed in \[the test list\]. It
outputs test results, test by test, to JSON files in
/opt/osdp-conformance/results. There are commands to invoke many of the
exercises. some are automatic. Not all tests are covered, this is a work
in progress. There is an HTML interface (on port 80, unencrypted, no
password.) The interface uses HTML pages and CGI programs to run shell
scripts that inject actions into the OSDP process to exercise the
protocol.

[]{#anchor-27}Reporting
-----------------------

output. also, action routines when a command/response is received.

osdp.log

osdpcap trace file

other output and collected information.

\<json test results file format goes here or in appendix C\>

[]{#anchor-28}Conformance Exercises
-----------------------------------

use the tool to run the exercises. html is set up to align with the
conformance test list.

### []{#anchor-29}OSDP Process

A single process executes the protocol. It acts in one of the three
roles. Due to file name use you can only one run per machine at this
time. There is a settings file read on startup to configure it. A log
file is created, with various levels of detail available. Optionally a
raw trace file can be created.

### []{#anchor-30}Start-up Settings

The program takes one argument, the name of the settings file. If no
name is given it reads from open-osdp-params.json in the current
directory.

### []{#anchor-31}settings and saved configuration

-   Saved (and restored) parameters are in osdp-saved-parameters.json.

osdp-saved-parameters.json is written/read in the current working
directory. It is used to load a specified secure channel key. (yes it
should save/restore speed and address that\'s on the to-do list.)

start-up parameters are in appendix b.

[]{#anchor-32}Controlling the OSDP Process
==========================================

Control directives can be passed to the OSDP process. A Unix socket
mechanism is used. There are two control mechanisms.

-   write a single-line (JSON) command to the socket using
    open-osdp-kick.
-   Write a parameter file to open-osdp-command.json in the appropriate
    directory (/opt/osdp-conformance/run/ACU or PD) and \"kick\" the
    server process by sending a null byte to the unix socket. See
    \"/opt/osdp-conformance/bin/do-keep-active\" for an example.

Example command files are in doc/osdp-command-examples.

[]{#anchor-33}OSDP Commands
---------------------------

These are the values allowed for the "command" field in a command json
file. Some commands take sub-options (some are mandatory, some are
optional.)

### []{#anchor-34}acurxsize

\[ACU\]

Sends osdp\_ACURXSIZE to PD, using value from the code (approx 1k.)

### []{#anchor-35}bio-read

\[ACU\]

Sends osdp\_BIOREAD to PD.

### []{#anchor-36}bio-match

\[ACU\]

Sends osdp\_BIOMATCH to PD.

### []{#anchor-37}busy

\[PD\]

Causes the PD to respond with BUSY to next incoming command.

### []{#anchor-38}buzz

\[ACU\]

buzz \[off\_time=xx\] \[on\_time=xx\] \[repeat=xx\]

default

15 15 3

### []{#anchor-39}capabilities

\[ACU\]

capabilities - sends an osdp\_CAP to the PD.

Options:

\"cleartext\" - sends the command in the clear instead of inside the
current secure channel.

### []{#anchor-40}comset

\[ACU\]

comset \[new\_address:99\] \[new\_speed:999999\] \[cleartext:1\]
\[send-direct:1\]

Sends a command to request to set the speed and address of the PD.

Options:

New\_address must be 00-7E (hex.) (yes it\'s an underscore)

new\_speed must be a valid speed (9600, 19200, 38400, 57600, 115200,
230400) (yes it\'s an underscore)

\'cleartext\' makes it send the comset command in the clear even if a
secure channel is active.

send-direct makes it send with the PD address being the current address
(the default is 0x7f.)

### []{#anchor-41}conform\_x\_x\_x

\[ACU PD\]

These are used to induce various conditions for conformance testing. The
numbering comes from the old profile documents section headings.

conform\_2\_2\_1

conform\_2\_2\_2

conform\_2\_2\_3

conform\_2\_2\_4

conform\_2\_6\_1

conform\_2\_11\_3

conform\_2\_14\_3

conform\_3\_14\_2

conform\_3\_20\_1

conform\_6\_10\_2 - operator confirmation of Red LED

conform\_6\_10\_3 - operator confirmation of Green LED

### []{#anchor-42}dump\_status

### []{#anchor-43}factory-default

\[ACU PD\]

factory-default

removes saved parameters settings (i.e. the preshared key.)

Commands are JSON files. You create a command, copy it to

/opt/osdp-conformance/run/CP/open\_osdp\_command.json

then "HUP" the process (see do-HUP-CP.)

Example command. There\'s always a "command", the other items depend on
the specific command.

{

"command" : "xwrite",

"action" : "set-mode",

"mode" : "1",

"\#" : "\_end"

}

### []{#anchor-44}genauth

\[ACU\]

genauth \[template=\<witness \| challenge\>\] \[algoref=\<algo\>\]
\[payload=zzz\]

Template is the challenge operation type (witness crypto or challenge
cryto)

algoref is the algorithm used.

payload is the value to be sent as the input payload.

\<algo\> must be the character strings 07 or 11 or 14 (rsa, ECC P-256,
ECC P-384)

### []{#anchor-45}identify

\[ACU\]

identify - sends an osdp\_ID to the PD.

Options:

\"cleartext\" - sends the command in the clear instead of inside the
current secure channel.

### []{#anchor-46}induce-NAK

\[ACU\]

induce-NAK -- sends a bogus command to induce the PD to send a NAK

\[PD\]

induce-NAK - causes the PD to NAK the next incoming message.

Options:

\"reason\" -- decimal value of reason code

\"detail\" -- decimal value of one byte detail.

### []{#anchor-47}initiate-secure-channel

\[ACU\]

This command to the ACU initates a secure channel session. It sends an
osdp\_CHLNG. It has one parameter, \"key slot\", which specifies \"0\"
for SCBK-D or \"1\" for the selected key. The selected key has to either
be defined in the start-up parameter file (parameter \"key\") or the
saved settings file (parameter \"key\") - value is hex digits as a
string e.g. \"00112233445566778899aabbccddeeff\".

options:

\"key-slot\" - "0\" (for default - SCBK-D) or \"1\" (for specified key)

example:

{ "command":"initiate-secure-channel", "key-slot":"1"}

### []{#anchor-48}input\_status

\[ACU\]

local\_status - send osdp\_LSTAT request.

### []{#anchor-49}keep-active

keep-active \[milliseconds=xx\]

Sends osdp\_KEEPACTIVE. Default value is 7000 (7 milliseconds.)

### []{#anchor-50}keypad

keypad \[digits=zzz\]

Sends a key input or the (1-9) digits specified. Value for the digits
option is 1-9 OSDP keypad values (0-9,\*,\#)

### []{#anchor-51}keyset

\[ACU\]

keyset \[psk-hex=zzzz\]

sends an osdp\_KEYSET. Default is to send the key specified in the
settings. the psk-hex option provides a hex value for the key. Key must
be 16 octets (so 32 hexits.)

### []{#anchor-52}led

\[ACU\]

led \[led-number=x\] \[perm-control=x\] \[perm-off-time=x\]
\[perm-off-color=x\] \[perm-on-time=x\] \[perm-on-color=x\]
\[temp-off-color=x\] \[temp-off=x\] \[temp-on-color=x\] \[temp-timer=x\]
\[temp-control=x\]

default

LED 0

control=set

off-time=0

off-color black

on-color green

on timer 30

reader 0

temp - no operation

### []{#anchor-53}local\_status

\[ACU\]

local\_status - send osdp\_LSTAT request.

### []{#anchor-54}mfg

\[ACU\]

mfg \[command-id=xx\] \[command-specific-data=aaaa\] \[oui=aabbcc\]

command-id is in decimal.

command-specific-data is the payload.

oui is the organizational unit identifier.

### []{#anchor-55}mfg-response

\[PD\]

mfg-response \[response-id=xx\] \[response-specific-data=aaaa\]
\[oui=aabbcc\]

response-id is in decimal.

response-specific-data is the payload.

oui is the organizational unit identifier.

### []{#anchor-56}operator\_confirm

\[ACU PD\]

operator\_confirm test=xxx

confirms test xxx ran successfully.

### []{#anchor-57}output

\[ACU\]

output - outputs via osdp\_OUT. The default is output 0, permanent on
immediate, forever.

output \[output-number=x\] \[control-code=x\] \[timer=x\]

### []{#anchor-58}output\_status

\[PD\]

send osdp\_OSTAT to the PD.

### []{#anchor-59}polling

\[ACU\]

polling enables or disables sending poll commands.

\"polling\" toggles the setting.

\"polling action=reset\" resumes polling and resets the sequence number
to 0.

\"polling action=resume\" just resumes polling.

\"polling post-command-action=single-step disables polling after

file transfer completion

command send time-out

secure channel initialization

### []{#anchor-60}present\_card

\[PD\]

present\_card \[raw=xxx\] \[bits=n\] \[format=p-data-p\]

sends an osdp\_RAW to the ACU.

Options:

-   \"bits\" sets the bits in the message to the specified value.

```{=html}
<!-- -->
```
-   \"format\" sets the format to raw, \"format=p-data-p\" sets the data
    to P-data-P.
-   \"raw\" sets the card value to the specified hex string. string must
    contain enough hex bytes to contain the specified number of bits.

### []{#anchor-61}reader\_status

\[ACU\]

reader\_status - send osdp\_RSTAT to PD

### []{#anchor-62}reset

\[ACU\]

reset - resets sequence number to 0

### []{#anchor-63}reset\_power

\[PD\]

reset\_power - induces a power reset condition (reset after nex time
LSTATR is sent.)

### []{#anchor-64}reset-statistics

\[ACU\]

reset-statistics \-- resets the statistics counters presented in
osdp-status.json.

### []{#anchor-65}scbk-default

\[ACU\] \[PD\]

change the SCBK-D value. One argument, \"scbk-d\". takes a 32 byte hex
value.

### []{#anchor-66}send\_poll

\[ACU\]

send\_poll - directs the ACU to send a poll.

### []{#anchor-67}stop

\[ACU MON PD\]

stop - directs the program to stop.

### []{#anchor-68}tamper

\[PD\]

tamper - induces a tamper condition (reset after next time LSTATR is
sent.)

### []{#anchor-69}text

\[ACU\]

text message=zzz sends message in osdp\_TEXT.

### []{#anchor-70}trace

\[ACU PD MON\]

toggles tracing of OSDP data to ./current.osdpcap.

### []{#anchor-71}transfer

\[ACU\]

transfer \[file=fff\] - initiates a file transfer. the file zzz is used
if no file is specified.

### []{#anchor-72}verbosity

\[ACU MON PD\]

verbosity \[level=x\] - set message verbosity. By convention this is 0
(none), 3 (normal), or 9 (debug).

### []{#anchor-73}Command xwrite

\[ACU\]

issues an osdp\_XWRITE. The action is get mode, scan, set mode, set
zero, or done. an optional apdu hex payload may be provided.
Experimental.

options:

action : get-mode \| scan \| set-mode \| set-zero \| done\] \[apdu :
\<hex value\>\]

action - "set-mode" \[mode - "1" or "0"\]

example:

{

"command" : "xwrite",

"action" : "set-mode",

"mode" : "1",

"\#" : "\_end"

}

[]{#anchor-74}Tools
-------------------

### []{#anchor-75}OSDP Capture - OSDPCAP

### []{#anchor-76}Packet Decoder

A cgi for packet decode is provided.
opt/osdp-conformance/cgi-bin/osdp-decode takes a single field which is a
hex string dump (spaces ok.) A command line tool (osdp-dump) is also
available.

A command line tool for calculating secure channel values is provided
(osdp-sc-calc.)

[]{#anchor-77}Appendix
======================

[]{#anchor-78}A. Colophon
-------------------------

part of libosdp-conformance, see
github.com/security-industry-association/libosd-conformance.

[]{#anchor-79}B. Parameter Files
--------------------------------

### []{#anchor-80}Start-up settings - open-osdp-params.json

\"address\" : \"0\" - PD address

\"bits\" : \"26\" - bits in pd osdp\_RAW payload response

\"capability-scbk-d\" : \"1\" (default) for scbk-d reported supported in
capability, else 0 for not supported.

\"capability-sounder\" : \"0\" \"1\" or \"2\". 1 means we have a sounder
(default). 0 means we don\'t. 2 is timed, note that is not supported in
the code.

\"capability-text\" : \"0\" (none) or \"1\" (1 line of 16 characters)

\"check\" : \"CHECKSUM\" or \"CRC\"

\"disable\_checking\" : \"1\" - nonzero causes it to disable certificate
checking with osdp over tls.

\"enable-biometrics\" : \"0\" or \"1\" for enable. Note we nak things if
not enabled.

\"enable-install\" : \"1\" (setting not currently used.)

\"enable-trace\" : \"1\" for OSDPCAP tracing, default 0 for none.

\"enable-secure-channel\" : \"DEFAULT\" (use SCBK-D) or (a specific
key.) Note that keys are now set in osdp-saved-parameters so always set
this to DEFAULT for secure channel. If not set refuses to enter secure
channel.

\"fqdn\"

\"init\_command\" : \"\<filename\>\" - this is the shell script to run
at initialization time, should perform STTY\...

\"inputs\" - number of Inputs to report (max 8, can be zero.)

\"key\" : \"\<32-hexit string\>\" or \"DEFAULT\"

\"oui\" : \"(6 character hex string)\" - this is the OUI used in PDID
responses, MFG commands.

\"outputs\" - number of Outputs to act on (max 8, can be zero.)

*pdcap-format* - format of pdcap response. if this is not zero alternate
forms are used. 1 is small, 2 is smaller.

\"port\" - tcp port to be called (for osdp-tcp-client etc.)

raw\_value = hex string value to return as osdp\_RAW. See also \"bits\".

role : ACU PD or MON

serial\_device /dev/ttyUSB0

serial\_speed 9600

slow\_timer

verbosity: 3 or 9

### []{#anchor-81}Saved parameters

parameters in osdp-saved-parameters.json:

key - value is a 16 byte AES key in hex e.g.
\"aabbccdd11223344eeff001199887766\"
