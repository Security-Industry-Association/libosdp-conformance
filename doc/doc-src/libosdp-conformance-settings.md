# Start-up Settings #

These are set in open-osdp-params.json in the current directory when open-ospd starts.

## Settings ##

- address.  Set to a decimal address value in the range 0 to 126.
- bits
- capability-scbk-d
- capability-sounder
- capability-text
- check.  Set to "CHECK" or "CHECKSUM".  Default CHECK.
- disable_checking
- enable-biometrics
- enable-poll.  Set to 0 to cause the ACU to not poll upon startup.  Default 1.
- enable-secure-channel - set this to enable use of secure channel by the PD. Values are "DEFAULT" or a specific SCBK value in hex.
- pdcap-format
- raw_value
- RND.A - sets the value to use as an ACU in secure channel operations.  Value is hex.  Default "303132333435363738".
- RND.B - sets the value to use as a PD in secure channel operations. Value is hex.  Default is "6162636465666768"
- serial_device
- serial_speed

## Other settings ##

``
  // parameter "enable-install"
  // parameter "enable-trace"
  // parameter "fqdn"
  // parameter "init_command"
  // parameter "inputs" (value must be in range 0 - OOSDP_DEFAULT_INPUTS)
  // parameter  "key" ("DEFAULT" or a 16-byte hex value)
  // parameter "max-send"
  // parameter "network_address"
  // parameter "oui"
  // parameter "outputs" (value must be in range 0 - OOSDP_DEFAULT_OUTPUTS)
  // parameter "pd-filetransfer-recsize" is bytes to ask for in osdp_FTSTAT response (for a PD)
  // port - port number at the other end of tls or tcp connection
  // privacy - 1 to not dump PII
  // parameter "serial-number"
  // parameter "service-root" - where libosdp-conformance runs from
  // parameter "timeout"
  // parameter "timeout-nsec" - timeout in nanoseconds.
  // parameter "serial-read-timeout" - nanoseconds.
  // parameter "verbosity"
  // parameter "role"
``

