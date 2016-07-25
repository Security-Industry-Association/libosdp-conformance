/*
  open-osdp-CP-status - display CP status as refreshing HTML page

  (C)Copyright 2015-2016 Smithee,Spelvin,Agnew & Plinge, Inc.

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
#include <stdlib.h>
#include <string.h>
#include <time.h>


#include <open-osdp.h>


int
  main
    (int
      argc,
    char
      *argv [])

{ /* main for open-osdp-CP-status */

  time_t
    current_time;
  struct timespec
    current_time_fine;
  int
    status;


  status = ST_OK;
  printf ("Content-type: text/html\n\n");
  printf ("<HTML><HEAD><TITLE>open-osdp CP Status</TITLE>");
  printf ("<META HTTP-EQUIV=\"REFRESH\" CONTENT=\"3;\">");
  printf ("</HEAD><BODY>");

  printf ("<PRE>\n");

  clock_gettime (CLOCK_REALTIME, &current_time_fine);
  current_time = time (NULL);
  printf ("Timestamp: %08ld.%08ld %s",
      (unsigned long int)current_time_fine.tv_sec, current_time_fine.tv_nsec,
      asctime (localtime (&current_time)));
{
  FILE *sf;
  int status_io;
  char buffer [16384];

  sf = fopen ("/opt/open-osdp/run/CP/open-osdp-status.json", "r");
  if (sf != NULL)
  {
    status_io = fread (buffer, sizeof (buffer [0]), sizeof (buffer), sf);
    if (status_io > 0)
      printf ("%s", buffer);
    fclose (sf);
  };
};
  printf ("</PRE>\n");
  printf ("</BODY></HTML>\n");
  return (status);

} /* main for open-osdp-CP-status */

