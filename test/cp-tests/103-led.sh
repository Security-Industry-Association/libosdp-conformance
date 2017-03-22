#!/bin/bash
set -x

# use:
# 103-led <led-number><color-number>

# do any LED color

CMDPATH=/opt/osdp-conformance/run/CP/open_osdp_command.json
echo LED $1 Color $2
sudo -n echo  >${CMDPATH} "{"
sudo -n echo >>${CMDPATH} "  \"command\" : \"led\","
sudo -n echo >>${CMDPATH} "  \"perm_on_color\" : \"$2\","
sudo -n echo >>${CMDPATH} "  \"led_number\" : \"$1\","
sudo -n echo >>${CMDPATH} "  \"#\" : \"created by 103-led from UI\""

sudo -n echo >>${CMDPATH} "}"

sudo -n /opt/osdp-conformance/bin/HUP-CP

