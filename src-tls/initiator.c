/*
  initiator - re-runs a service repeatedly

  (because cleaning up the init code for TLS was more work.)
*/

int
  main
    (int
      argc,
    char
      *argv [])

{ /* initiator */

  int
    done;
  int
    status;

  status = 0;
  fprintf (stderr, "repeating command: %s\n",
    argv [1]);
  done = 0;
  system ("echo yes >server_enable");
  while (!done)
  {
    system (argv [1]);
    sleep (5);
    ef = fopen ("server_enable", "r");
    if (ef EQUALS NULL)
    {
      fprintf (stderr, "server no longer enabled.  exiting.\n");
      done = 1;
    };
  };
  if (status != 0)
    fprintf (stderr, "exit with status %d\n",
      status);
  return (status);

} /* initiator */

