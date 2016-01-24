/*
  oosdp_files - osdp file io/

  (C)2016 Smithee Spelvin Agnew & Plinge, Inc.

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
#include <string.h>
#include <time.h>
//#include <arpa/inet.h>


#include <osdp-tls.h>
#include <open-osdp.h>
#include <osdp_conformance.h>


extern OSDP_PARAMETERS
  p_card;


int
  write_status
    (OSDP_CONTEXT
      *ctx)

{ /* write_status */

  int
    count;
  char
    current_date_string [1024];
  time_t
    current_time;
  int
    i;
  int
    j;
  FILE
    *sf;
  char
    statfile [1024];
  int
    status;
  char
    tag [3];
  char
    val [1024];


  status = ST_OK;
  if (ctx->role EQUALS OSDP_ROLE_PD)
    strcpy (tag, "PD");
  else
    strcpy (tag, "CP");
  sprintf (statfile, "/opt/open-osdp/run/%s/open-osdp-status.json",
    tag);
  sf = fopen (statfile, "w");
  if (sf != NULL)
  {
    current_time = time (NULL);
    strcpy (current_date_string, asctime (localtime (&current_time)));
    current_date_string [strlen (current_date_string)-1] = 0;
    fprintf (sf, "{\n");
    fprintf (sf, "      \"last_update\" : \"%s\",\n",
      current_date_string);
    fprintf (sf, "             \"role\" : \"%d\",\n",
      ctx->role);
    fprintf (sf, "                \"#\" : \"0=CP 1=PD 2=MON\",\n");
    fprintf (sf, "       \"pd_address\" : \"%02x\",\n",
      p_card.addr);
    fprintf (sf, "         \"cp_polls\" : \"%d\",\n",
      ctx->cp_polls);
    fprintf (sf, "          \"pd_acks\" : \"%d\",\n",
      ctx->pd_acks);
    fprintf (sf, "        \"sent_naks\" : \"%d\",\n",
      ctx->sent_naks);
    for (j=0; j<OSDP_MAX_OUT; j++)
    {
      fprintf (sf, "       \"out-%02d\" : \"%d\",\n",
        j, ctx->out [j].current);
    };
    fprintf (sf, "     \"power_report\" : \"%d\",\n",
      ctx->power_report);
    fprintf (sf, "        \"verbosity\" : \"%d\",\n",
      ctx->verbosity);
    fprintf (sf, "              \"crc\" : \"%d\",\n",
      m_check);
    fprintf (sf, "          \"timeout\" : \"%d\",\n",
      m_idle_timeout);
    fprintf (sf, "             \"poll\" : \"%d\",\n",
      p_card.poll);
    fprintf (sf, "             \"dump\" : \"%d\",\n",
      m_dump);
    fprintf (sf, "  \"checksum_errors\" : \"%d\",\n",
      ctx->checksum_errs);

    // copy in all the octets holding the bits.

    memset (val, 0, sizeof (val));
    count = 0;
    fprintf (sf, "  \"raw_data_bits\" : \"%d\",\n",
      ctx->last_raw_read_bits);
    for (i=0; i<(7+ctx->last_raw_read_bits)/8; i++)
    {
      sprintf (val+(2*i), "%02x", ctx->last_raw_read_data [i]);
    };
    fprintf (sf, "  \"raw_data\" : \"%s\"\n", // LAST so no comma
      val);
    fprintf (sf, "}\n");

    fclose (sf);
  };
  return (status);

} /* write_status */

