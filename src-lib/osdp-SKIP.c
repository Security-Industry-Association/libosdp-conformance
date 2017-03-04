void
  skip_conformance_tests
    (OSDP_CONTEXT *ctx,
    OSDP_INTEROP_ASSESSMENT *oconf)

{ /* skip_conformance_tests */

  // some we just skip in this build.
  oconf->address_3.test_status =
    OCONFORM_SKIP;
  oconf->channel_access.test_status =
    OCONFORM_SKIP;
  oconf->character_encoding.test_status =
    OCONFORM_SKIP;
  oconf->control_2.test_status =
    OCONFORM_SKIP;
  oconf->packet_size_stress_cp.test_status =
    OCONFORM_SKIP;

  // skip in this phase of the project.

  oconf->cmd_diag.test_status =
    OCONFORM_SKIP;

  if (ctx->profile EQUALS OSDP_PROFILE_PERIPHERAL_TEST_PD)
  {
    oconf->channel_access.test_status = OCONFORM_SKIP;
    oconf->cmd_led.test_status = OCONFORM_SKIP;
    oconf->cmd_buz.test_status = OCONFORM_SKIP;
    oconf->cmd_text.test_status = OCONFORM_SKIP;
    oconf->cmd_comset.test_status = OCONFORM_SKIP;
    oconf->cmd_prompt.test_status = OCONFORM_SKIP;
    oconf->cmd_bioread.test_status = OCONFORM_SKIP;
    oconf->cmd_biomatch.test_status = OCONFORM_SKIP;
    oconf->cmd_cont.test_status = OCONFORM_SKIP;
    oconf->cmd_mfg.test_status = OCONFORM_SKIP;
  };
  if (ctx->profile EQUALS OSDP_PROFILE_BASIC)
  {
  };
  if (ctx->profile EQUALS OSDP_PROFILE_BIO)
  {
  };
  if (ctx->profile EQUALS OSDP_PROFILE_PIV)
  {
  };

} /* skip_conformance_tests */

