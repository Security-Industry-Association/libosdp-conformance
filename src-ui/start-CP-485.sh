#!/bin/bash

# (C)Copyright 2017-2026 Smithee Solutions LLC

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#   http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

OSDPDIR=/opt/osdp-conformance
sudo rm -f ${OSDPDIR}/tmp/current-role
cd /opt/osdp-conformance/run/ACU
rm -f /opt/osdp-conformance/etc/current-role
echo "ACU" >/opt/osdp-conformance/etc/current-role
sudo -n killall open-osdp
sudo -n /opt/osdp-conformance/bin/exec-CP485
sudo -n chmod 777 /opt/osdp-conformance/tmp
sudo -n mkdir -p /opt/osdp-conformance/etc
sudo -n echo "ACU" >/opt/osdp-conformance/tmp/current-role
sudo -n cp /opt/osdp-conformance/tmp/current-role /opt/osdp-conformance/etc
echo "Content-type: text/html"
echo ""

echo "<HTML><HEAD><TITLE>start ACU RS-485 Server</TITLE>"
echo "<META HTTP-EQUIV=\"REFRESH\" CONTENT=\"2;URL=/Test-ACU.html\">"
echo "</HEAD>"
echo "<BODY><PRE>"
echo "open-osdp started in ACU run directory"
echo "</BODY></HTML>"


