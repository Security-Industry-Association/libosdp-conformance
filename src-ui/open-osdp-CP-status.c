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

