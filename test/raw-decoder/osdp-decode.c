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
"<INPUT TYPE=TEXT NAME=\"pdu\" size=64 maxlength=1000>\n");
  printf ("<INPUT TYPE=SUBMIT VALUE=\"Decode\"></FORM>\n");
  printf("</BODY></HTML>\n");
  return (status);

} /* main for osdp-decode */

