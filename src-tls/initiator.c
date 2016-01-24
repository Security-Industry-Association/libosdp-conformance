/*
  initiator - re-runs a service repeatedly

  (because cleaning up the init code for TLS was more work.)

  (C)Copyright 2014-2015 Smithee Spelvin Agnew & Plinge, Inc.

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
#include <unistd.h>

#define EQUALS ==


int
  main
    (int
      argc,
    char
      *argv [])

{ /* initiator */

  int
    done;
  FILE
    *ef;
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

