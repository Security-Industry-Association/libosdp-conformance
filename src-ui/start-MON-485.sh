#!/bin/bash
set -x

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

rm -f /opt/osdp-conformance/etc/current_role
echo "MON" >/opt/osdp-conformance/etc/current_role

cd /opt/open-osdp/run/MON
echo "Content-type: text/html"
echo ""
echo "<HTML><HEAD><TITLE>start OSDP RS-485 Monitor</TITLE>"
echo "<BODY><PRE>"

sudo -n killall open-osdp
sudo -n rm -f stdout stderr
sudo -n touch /opt/open-osdp/run/MON/stdout
sudo -n touch /opt/open-osdp/run/MON/stderr
sudo chown www-data:www-data stdout stderr
sudo -n ls -l /opt/open-osdp/run/MON
sudo -n /opt/open-osdp/bin/open-osdp >stdout 2>stderr&

echo "open-osdp started in MON run directory"
echo "</BODY></HTML>"


