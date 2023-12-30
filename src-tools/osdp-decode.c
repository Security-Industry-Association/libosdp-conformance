/*
  osdp-decode - CGI program to front end OSDP PDU decoder

  paints a form and calls osdp-packet-decode to do the actual decoding.

  (C)Copyright 2015-2024 Smithee Solutions LLC

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

#include <stdio.h>


int
  main
    (int argc,
    char *argv [])

{ /* main for osdp-decode */

  int status;


  status = 0;
  printf("Content-type: text/html\n\n");
  printf ("<HTML><TITLE>OSDP Protocol Decoder</TITLE><BODY>\n");

  printf("OSDP Protocol Decoder<BR>\n");
  printf ("<FORM ACTION=\"/cgi-bin/osdp-packet-decode\" METHOD=GET>\n");
  printf (
"<INPUT TYPE=TEXT NAME=\"pdu\" size=64 maxlength=4000>\n");
  printf ("<INPUT TYPE=SUBMIT VALUE=\"Decode\"></FORM>\n");
  printf("</BODY></HTML>\n");
  return (status);

} /* main for osdp-decode */

