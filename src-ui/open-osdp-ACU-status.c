/*
  open-osdp-ACU-status - display CP status as refreshing HTML page

  (C)Copyright 2017-2021 Smithee Solutions LLC

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


#include <open-osdp.h>


int  main (int argc, char *argv [])
{ /* main for open-osdp-ACU-status */

    printf ("Content-type: application/json\n\n");

    {
        FILE *sf;
        int status_io;
        char buffer [16384];

        sf = fopen ("/opt/osdp-conformance/run/ACU/osdp-status.json", "r");
        if (sf != NULL)
        {
            status_io = fread (buffer, sizeof (buffer [0]), sizeof (buffer), sf);
            if (status_io > 0)
                printf ("%s", buffer);
            fclose (sf);
        };
    };

    return ST_OK;

} /* main for open-osdp-ACU-status */

