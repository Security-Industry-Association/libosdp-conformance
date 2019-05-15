#include <string.h>
#include <ctype.h>
#include <stdio.h>


#define EQUALS ==
#define ST_OK (0)


/*
  bytes_from_string - forgivingly decode hex bytes

  skips a leading FF
  skips blanks
*/

void
  bytes_from_string
    (char *string,
    char *bytes,
    int *bytes_length)

{ /* bytes_from_string */

  int byte;
  int done;
  int len;
  int max_length;
  char *pdest;
  char *psource;
  char ptemp [1024];
  int status;


  status = 0;
  done = 0;
  if (*bytes_length < 1)
    status = -1;
  if (!string)
    status = -2;

  // remove blanks and pluses (blanks manifest as '+' through http)
  if (status EQUALS ST_OK)
  {
    char *p;
    int i;

    p = string;
    i = 0;
    memset(ptemp, 0, sizeof(ptemp));
    while (!done)
    {
      if (*p EQUALS 0)
        done = 1;
      else
      {
        if ((*p != ' ') && (*p != '+'))
        {
          ptemp [i] = *p;
          i++;
        };
      };
      p++;
    };
    psource = ptemp;
  };

  done = 0;
  if (!done)
  {
    len = strlen(psource);
    if (0 != (len % 2))
      done = 1;
  };
  if (!done)
  {
    // if it starts with 0xff, eat that
    if (tolower(*psource) EQUALS 'f')
      psource = psource + 2;

    pdest = bytes;
    max_length = *bytes_length;
    *bytes_length = 0;
    while (!done && (len > 0))
    {
      char octet [3];
      octet [2] = 0;
      memcpy(octet, psource, 2);
      sscanf(octet, "%x", &byte);
      *pdest = 0xff & byte;
      (*bytes_length) ++;
      pdest++;
      len--; len--; psource++; psource++;
    };
  };

} /* bytes_from_string */

