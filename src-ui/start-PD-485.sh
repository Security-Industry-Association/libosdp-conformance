#!/bin/bash

# (C)Copyright 2015-2016 Smithee,Spelvin,Agnew & Plinge, Inc.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#   http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cd /opt/osdp-conformance/run/PD
sudo -n killall open-osdp
sudo -n /opt/osdp-conformance/bin/exec-PD485
sudo -n chmod 777 /opt/osdp-conformance/tmp
sudo -n mkdir -p /opt/osdp-conformance/etc
sudo -n echo "PD" >/opt/osdp-conformance/tmp/current_role
sudo -n cp /opt/osdp-conformance/tmp/current_role /opt/osdp-conformance/etc
echo "Content-type: text/html"
echo ""

echo "<HTML><HEAD><TITLE>start PD RS-485 Server</TITLE>"
echo "<META HTTP-EQUIV=\"REFRESH\" CONTENT=\"1;URL=/osdp-conformance-PD.html\">"
echo "<BODY><PRE>"
echo "open-osdp started in PD run directory"
echo "</BODY></HTML>"


