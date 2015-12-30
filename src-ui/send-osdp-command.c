int
  param_verbosity = 0;
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// stub
//<A HREF="/cgi-bin/send-osdp-command?cmd=CP-identify">Identify</A>

int
  main
    (int
      argc,
    char
      *argv [])

{ /* main for send-osdp-command */

  char
    arguments [1024];
  char
    command [1024];
  char
    shell_command [1024];
  int
    status;
  char
    tag [1024];


  status = -1;
  strcpy (arguments, getenv ("QUERY_STRING"));
  printf ("Content-type: text/html\n\n");
  printf ("<HTML><HEAD><TITLE>open-osdp CP console</TITLE>");
  printf ("<META HTTP-EQUIV=\"REFRESH\" CONTENT=\"3;URL=/open-osdp-CP.html\">");
  printf ("</HEAD><BODY>");
  if (param_verbosity > 1)
    fprintf (stderr, "arguments: %s\n",
      arguments);
  strcpy (tag, "cmd=CP-");
  if (0 == strncmp (tag, arguments, strlen (tag)))
  {
    strcpy (command, arguments+strlen(tag));
    // send the CP daemon a command
    if (param_verbosity > 1)
      fprintf (stderr, "STUB: sending CP daemon command: %s\n",
        command);
    printf ("<BR><BR><BR><P ALIGN=\"center\">Executing %s command...</P>\n",
      command);
    sprintf (shell_command,
"sudo -n /opt/open-osdp/bin/write-osdp-CP-command %s",
  command);
    system (shell_command);
    system ("sudo -n /opt/open-osdp/bin/HUP-CP");
    strcpy (tag, "stop");
    if (0 == strncmp (tag, command, strlen (tag)))
    {
      system ("sudo -n /opt/open-osdp/bin/STOP-CP");
    };
  };
  strcpy (tag, "cmd=PD-");
  if (0 == strncmp (tag, arguments, strlen (tag)))
  {
    strcpy (command, arguments+strlen(tag));
    strcpy (tag, "stop");
    if (0 == strncmp (tag, command, strlen (tag)))
    {
      system ("sudo -n /opt/open-osdp/bin/STOP-PD");
    };
  };
  printf ("</BODY></HTML>\n");
  return (status);

} /* main for send-osdp-command */

