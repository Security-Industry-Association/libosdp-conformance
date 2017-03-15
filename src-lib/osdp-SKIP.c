void
  skip_conformance_tests
    (OSDP_CONTEXT *ctx,
    OSDP_INTEROP_ASSESSMENT *oconf)

{ /* skip_conformance_tests */

  // some we just skip in this build.
  oconf->channel_access.test_status =
    OCONFORM_SKIP;
  oconf->character_encoding.test_status =
    OCONFORM_SKIP;
  oconf->cmd_bioread.test_status = OCONFORM_SKIP;
  oconf->cmd_biomatch.test_status = OCONFORM_SKIP;
  oconf->cmd_cont.test_status = OCONFORM_SKIP;
  oconf->cmd_diag.test_status = OCONFORM_SKIP;
  oconf->cmd_mfg.test_status = OCONFORM_SKIP;
  oconf->cmd_ostat_ack.test_status =
    OCONFORM_SKIP;
  oconf->cmd_poll_response_3.test_status =
    OCONFORM_SKIP;
  oconf->cmd_poll_response_4.test_status =
    OCONFORM_SKIP;
  oconf->cmd_prompt.test_status =
    OCONFORM_SKIP;
  oconf->cmd_stop_multi.test_status =
    OCONFORM_SKIP;
  oconf->cmd_max_rec.test_status =
    OCONFORM_SKIP;
  oconf->control_2.test_status =
    OCONFORM_SKIP;
  oconf->invalid_command.test_status = OCONFORM_SKIP;
  oconf->max_delay.test_status = OCONFORM_SKIP;
  oconf->offline_test.test_status = OCONFORM_SKIP;
  oconf->packet_size_stress_cp.test_status =
    OCONFORM_SKIP;
  oconf->rep_capas_consistent.test_status =
    OCONFORM_SKIP;
  oconf->rep_formatted.test_status = OCONFORM_SKIP;
  oconf->rep_ident_consistent.test_status =
    OCONFORM_SKIP;
  oconf->rep_input_consistent.test_status =
    OCONFORM_SKIP;
  oconf->rep_scan_match.test_status = OCONFORM_SKIP;
  oconf->rep_scan_send.test_status = OCONFORM_SKIP;
  oconf->resp_mfg.test_status = OCONFORM_SKIP;
  oconf->resp_ostatr_range.test_status =
    OCONFORM_SKIP;
  oconf->timing.test_status = OCONFORM_SKIP;

} /* skip_conformance_tests */

