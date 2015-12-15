/*
  osdp-tls.h - defitions for osdp-tls

  (C)Copyright 2015 Smithee,Spelvin,Agnew & Plinge, Inc.

  Support provided by the Security Industry Association
  http://www.securityindustry.org

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/


typedef struct osdp_tls_config
{
//  int role;
  int
    listen_sap;
  int
    cmd_hist_counter;
  char
    cmd_dir [1024];
  char
    version [1024];
  char
    cert_file [1024];
  char
    key_file [1024];
  char
    ca_file [1024];
} OSDP_TLS_CONFIG;

#define MAX_BUF (1024)

