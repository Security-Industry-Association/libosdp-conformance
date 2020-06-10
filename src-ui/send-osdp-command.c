int
  param_verbosity = 0;
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


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
  if (param_verbosity > 1)
    fprintf (stderr, "arguments: %s\n",
      arguments);
  strcpy (tag, "cmd=MON-");
  if (0 == strncmp (tag, arguments, strlen (tag)))
  {
    printf ("<HTML><HEAD><TITLE>libosdp Monitor Console</TITLE>");
    printf ("<META HTTP-EQUIV=\"REFRESH\" CONTENT=\"3;URL=/osdp-conformance-MON.html.html\">");
    printf ("</HEAD><BODY>");
    strcpy (command, arguments+strlen(tag));
    if (0 == strcmp (command, "stop"))
      system ("sudo -n killall open-osdp");
  };
  strcpy (tag, "cmd=CP-");
  if (0 == strncmp (tag, arguments, strlen (tag)))
  {
    printf ("<HTML><HEAD><TITLE>Control PD Testing (CP Emulator)</TITLE>");
#ifdef OSDP_CONFORMANCE
    printf
("<META HTTP-EQUIV=\"REFRESH\" CONTENT=\"1;URL=/Test-ACU.html\">");
#else
    printf
("<META HTTP-EQUIV=\"REFRESH\" CONTENT=\"3;URL=/open-osdp-CP.html\">");
#endif
    printf ("</HEAD><BODY>");
    strcpy (command, arguments+strlen(tag));
    // send the CP daemon a command
    printf ("<BR><BR><BR><P ALIGN=\"center\">Executing %s command...</P>\n",
      command);
    sprintf (shell_command,
"sudo -n /opt/osdp-conformance/bin/write-osdp-CP-command %s",
  command);
    system (shell_command);
    system ("sudo -n /opt/osdp-conformance/bin/HUP-CP");
    strcpy (tag, "stop");
    if (0 == strncmp (tag, command, strlen (tag)))
    {
      system ("sudo -n /opt/osdp-conformance/bin/STOP-CP");
    };
  };
  strcpy (tag, "cmd=PD-");
  if (0 == strncmp (tag, arguments, strlen (tag)))
  {
    printf ("<HTML><HEAD><TITLE>open-osdp PD console</TITLE>");
    printf
("<META HTTP-EQUIV=\"REFRESH\" CONTENT=\"1;URL=/Test-PD.html\">");
    printf ("</HEAD><BODY>");

    strcpy (command, arguments+strlen(tag));

    // send the PD daemon a command
    printf ("<BR><BR><BR><P ALIGN=\"center\">Executing %s command...</P>\n",
      command);
    sprintf (shell_command,
"sudo -n /opt/osdp-conformance/bin/write-osdp-PD-command %s",
  command);
    system (shell_command);
    system ("sudo -n /opt/osdp-conformance/bin/HUP-PD");

    strcpy (command, arguments+strlen(tag));
    strcpy (tag, "stop");
    if (0 == strncmp (tag, command, strlen (tag)))
    {
      system ("sudo -n /opt/osdp-conformance/bin/STOP-PD");
    };
  };
  printf ("</BODY></HTML>\n");
  return (status);

} /* main for send-osdp-command */

