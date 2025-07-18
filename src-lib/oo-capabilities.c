/*
  oo-capabilities - primitives to manage the capabilities list

  (C) 2021-2025 Smithee Solutions LLC
*/


#include <string.h>


#include <open-osdp.h>

unsigned char special_pdcap_list [32*3];

int osdp_add_capability(OSDP_CONTEXT *ctx, unsigned char *capas, unsigned char capability, unsigned char compliance_level,
  unsigned char number_of, int *capabilities_response_length, int max);


/*
  osdp_get_capabilities - builds out capabilities response based on current configuration

  input: context, your capability list (must be 32*3 bytes)
  output: your list populated, length of list in bytes
*/
int
  osdp_get_capabilities
    (OSDP_CONTEXT *ctx,
    unsigned char *capabilities_list,
    int *capabilities_response_length)

{ /* osdp_get_capabilities */

  unsigned char capas [32*3];
  int i;
  int status;


  status = ST_OK;
  memset(capas, 0, sizeof(capas));
  *capabilities_response_length = 0;

  if (ctx->special_pdcap > 0)
  {
    // special list is a set of capability,compliance,number-of tuples in arbitrary order

    for (i=0; i<ctx->special_pdcap; i++)
    {
      status = osdp_add_capability(ctx, capas, special_pdcap_list [i*3], special_pdcap_list [1+i*3], special_pdcap_list [2+i*3],
        capabilities_response_length, sizeof(capas));
    };
  }
  else
  {

  // inputs
  if (ctx->pdcap_select EQUALS 0)
    status = osdp_add_capability(ctx, capas, 1, 2, ctx->configured_inputs, capabilities_response_length, sizeof(capas));

  // outputs
  if (ctx->pdcap_select EQUALS 0)
    status = osdp_add_capability(ctx, capas, 2, 2, ctx->configured_outputs, capabilities_response_length, sizeof(capas));

  // 1024 bits max in raw
  status = osdp_add_capability(ctx, capas, 3, 1, 0, capabilities_response_length, sizeof(capas));

  if (ctx->configured_led)
  {
    status = osdp_add_capability(ctx, capas, OSDP_CAP_LED_CONTROL, 1, 1, capabilities_response_length, sizeof(capas));
  }
  else
  {
    status = osdp_add_capability(ctx, capas, OSDP_CAP_LED_CONTROL, 0, 0, capabilities_response_length, sizeof(capas));
  };

  if (ctx->configured_sounder)
  {
    // audible annunciator present, claim on/off only
    // assumes capability_sounder is 1 (not 0 or 2)

    status = osdp_add_capability(ctx, capas, OSDP_CAP_AUDIBLE_OUT, 1, 0, capabilities_response_length, sizeof(capas));
  }
  else
  {
    status = osdp_add_capability(ctx, capas, OSDP_CAP_AUDIBLE_OUT, 0, 0, capabilities_response_length, sizeof(capas));
  };

  // text display, 1 row of 16 if enabled
  if (ctx->configured_text)
  {
    if (ctx->verbosity > 3)
      fprintf(ctx->log, "Enabling capability: Text output, 1 line of 16\n");
    status = osdp_add_capability(ctx, capas, 6, 1, 1, capabilities_response_length, sizeof(capas));
  }
  else
  {
    status = osdp_add_capability(ctx, capas, 6, 0, 0, capabilities_response_length, sizeof(capas));
  };

  // supports CRC-16?  use m_check to respond
  if (m_check EQUALS OSDP_CRC)
    status = osdp_add_capability(ctx, capas, 8, 1, 0, capabilities_response_length, sizeof(capas));
  else
    status = osdp_add_capability(ctx, capas, 8, 0, 0, capabilities_response_length, sizeof(capas));

  // supports secure channel, and scbk-d as configured.
  if (ctx->enable_secure_channel > 0)
  {
    status = osdp_add_capability(ctx, capas, 9, 1, ctx->configured_scbk_d, capabilities_response_length, sizeof(capas));
  }
  else
  {
    status = osdp_add_capability(ctx, capas, 9, 0, 0, capabilities_response_length, sizeof(capas));
  };

  // max PDU size
  if (ctx->pdcap_select EQUALS 0)
    status = osdp_add_capability(ctx, capas, 10, 
      0xff & ctx->capability_max_packet, (0xff00 & ctx->capability_max_packet)>>8, capabilities_response_length, sizeof(capas));

  // max assembled message size
  if (ctx->pdcap_select EQUALS 0)
    status = osdp_add_capability(ctx, capas, 11, 0xff & ctx->capability_max_packet, (0xff00 & ctx->capability_max_packet)>>8, capabilities_response_length, sizeof(capas));

  // no Smartcard
  if (ctx->pdcap_select EQUALS 0)
    status = osdp_add_capability(ctx, capas, 12, 0, 0, capabilities_response_length, sizeof(capas));

  // no Keypad
  status = osdp_add_capability(ctx, capas, 13, 0, 0, capabilities_response_length, sizeof(capas));

  // no biometrics
  if (ctx->pdcap_select EQUALS 0)
    status = osdp_add_capability(ctx, capas, 14, 0, 0, capabilities_response_length, sizeof(capas));

  // no SPE (Secure PIN Entry)
  if (ctx->pdcap_select EQUALS 0)
    status = osdp_add_capability(ctx, capas, 15, 0, 0, capabilities_response_length, sizeof(capas));

  // Version "SIA 2.2" of protocol (unless spoofed)
  if (ctx->pdcap_select EQUALS 0)
  {
    int my_version;

    my_version = 2;
    if (ctx->capability_version != -1)
      my_version = ctx->capability_version;
    status = osdp_add_capability(ctx, capas, 16, my_version, 0, capabilities_response_length, sizeof(capas));
  };
  };

  memcpy(capabilities_list, capas, *capabilities_response_length);
  return(status);

} /* osdp_get_capabilities */


int
  osdp_add_capability
    (OSDP_CONTEXT *ctx,
    unsigned char *capas,
    unsigned char capability,
    unsigned char compliance_level,
    unsigned char number_of,
    int *capabilities_response_length,
    int max)

{ /* osdp_add_capability */

  int idx;
  int status;


  if (ctx->verbosity > 3)
  {
    fprintf(ctx->log, "osdp_add_capability top, called for capas %02X level %02x number %02x\n", capability, compliance_level, number_of);
    fflush(ctx->log);
  };
  status = ST_OSDP_TOO_MANY_CAPAS;
  idx = *capabilities_response_length;
  if (*capabilities_response_length < (max-3))
  {
    capas [idx] = capability;
    capas [idx+1] = compliance_level;
    capas [idx+2] = number_of;
    if (ctx->verbosity > 2)
    {
      fprintf(ctx->log, "reporting capability %2d. Compliance level %d. Number of %d.\n",
        capability, compliance_level, number_of);
    };
    idx = idx + 3;
    *capabilities_response_length = *capabilities_response_length + 3;
  };
  return(status);

} /* osdp_add_capability */

