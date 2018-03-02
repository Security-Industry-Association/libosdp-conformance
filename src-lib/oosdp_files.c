/*
  oosdp_files - osdp file io/

  (C)2017-2018 Smithee Solutions LLC
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
  osdp_filetransfer_validate
    (OSDP_CONTEXT *ctx,
    OSDP_HDR_FILETRANSFER *ftmsg,
    unsigned short int *fragsize,
    unsigned int *offset)

{ /* osdp_filetransfer_validate */

  int status;


  status = ST_OK;


  // ...and this also extracts the offset and fragment size as native integers

  osdp_array_to_doubleByte(ftmsg->FtFragmentSize, fragsize);
  (void)osdp_array_to_quadByte(ftmsg->FtOffset, offset);
  return (status);

} /* osdp_filetransfer_validate */


int
  osdp_ftstat_validate
    (OSDP_CONTEXT *ctx,
    OSDP_HDR_FTSTAT *ftstat)

{ /* osdp_ftstat_validate */

  unsigned short int new_size;
  int status;

  status = ST_OK;
// if FtAction bad set status

  if (status EQUALS ST_OK)
  {
    // update fragment size to send.

    osdp_array_to_doubleByte(ftstat->FtUpdateMsgMax, &new_size);
    if (new_size != 0)
      ctx->xferctx.current_send_length = new_size;
  };
  return (status);

} /* osdp_ftstat_validate */


void
  osdp_wrapup_filetransfer
    (OSDP_CONTEXT *ctx)
{
  ctx->xferctx.current_offset = 0;
  ctx->xferctx.total_length = 0;
  fclose(ctx->xferctx.xferf);
}


int
  write_status
    (OSDP_CONTEXT
      *ctx)

{ /* write_status */

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
  sprintf (statfile, "/opt/osdp-conformance/run/%s/open-osdp-status.json",
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
    if (strlen (ctx->text) > 0)
      fprintf (sf, "\"text\" : \"%s\",\n",
        ctx->text);
    fprintf (sf, "             \"role\" : \"%d\",\n",
      ctx->role);
    fprintf (sf, "                \"#\" : \"0=CP 1=PD 2=MON\",\n");
    fprintf (sf, "     \"serial_speed\" : \"%s\",\n",
      ctx->serial_speed);
    fprintf (sf, "       \"pd_address\" : \"%02x\",\n",
      p_card.addr);
    fprintf (sf,       "\"max_pd_send\" : \"%d\",\n",
      ctx->max_message);
    fprintf (sf, "         \"cp_polls\" : \"%d\",\n",
      ctx->cp_polls);
    fprintf (sf, "          \"pd_acks\" : \"%d\",\n",
      ctx->pd_acks);
    fprintf (sf, "        \"sent_naks\" : \"%d\",\n",
      ctx->sent_naks);
    for (j=0; j<OSDP_MAX_LED; j++)
    {
      if (ctx->led [j].state EQUALS OSDP_LED_ACTIVATED)
        fprintf (sf,
                 "     \"led_color_%02d\" : \"#%06x\",\n",
        j, ctx->led [j].web_color);
    };
    for (j=0; j<OSDP_MAX_OUT; j++)
    {
      fprintf (sf,
                 "        \"out-%02d\" : \"%d\",\n",
        j, ctx->out [j].current);
    };
    fprintf (sf, "     \"power_report\" : \"%d\",\n",
      ctx->power_report);
    fprintf (sf, "        \"verbosity\" : \"%d\",\n",
      ctx->verbosity);
    fprintf (sf, "              \"crc\" : \"%d\",\n",
      m_check);
    fprintf (sf, "          \"timeout\" : \"%ld\",\n",
      ctx->timer[0].i_sec);
    fprintf (sf, "             \"poll\" : \"%d\",\n",
      p_card.poll);
    fprintf (sf, "             \"dump\" : \"%d\",\n",
      m_dump);
    fprintf (sf,
"  \"checksum_errors\" : \"%d\",\n",
      ctx->checksum_errs);

    // copy in the keyboard "buffer"

    fprintf (sf,
"    \"keypad_last_8\" : \"%02x%02x- %02x%02x- %02x%02x- %02x%02x\",\n",
      ctx->last_keyboard_data [0], ctx->last_keyboard_data [1],
      ctx->last_keyboard_data [2], ctx->last_keyboard_data [3],
      ctx->last_keyboard_data [4], ctx->last_keyboard_data [5],
      ctx->last_keyboard_data [6], ctx->last_keyboard_data [7]);

    // copy in all the octets holding the bits.

    memset (val, 0, sizeof (val));
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

