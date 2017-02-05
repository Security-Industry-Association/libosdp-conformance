#!/bin/bash

# use:
# 102-led <color-number>

# do any LED color

CMDPATH=/opt/open-osdp/run/CP/open_osdp_command.json
echo Color is $1
echo  >${CMDPATH} "{"
echo >>${CMDPATH} "   \"command\" : \"led\""
echo >>${CMDPATH} "  ,\"perm_on_color\" : \"$1\""

echo >>${CMDPATH} "}"

/opt/open-osdp/bin/HUP-CP

