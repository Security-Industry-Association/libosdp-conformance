# Start-up Settings #

These are set in open-osdp-params.json in the current directory when open-osdp starts.

## Settings ##

- address.  Set to a decimal address value in the range 0 to 126.
- bits
- capability-led - set to 0 to disable LED.
- capability-scbk-d
- capability-sounder - set to 0 to disable buzzer.
- capability-text
- check.  Set to "CHECK" or "CHECKSUM".  Default CHECK.
- disable-checking
- enable-biometrics
- enable-poll.  Set to 0 to cause the ACU to not poll upon startup.  Default 1.
- enable-secure-channel - set this to enable use of secure channel by the PD. Values are "DEFAULT" or a specific SCBK value in hex.
- enable-trace - set to to enable osdpcap trace output
- model-version - model and version number (as 2-octet hex string.)
- oui - Organizational Unit Indicator.  3 octet hex value.  Default is 0A0017 (which is legitimate
because bit 1 of the first octet is a 1 meaning a private value.)
- pdcap-format
- raw-value
- role - PD or ACU or MON
- RND.A - sets the value to use as an ACU in secure channel operations.  Value is hex.  Default "303132333435363738".
- RND.B - sets the value to use as a PD in secure channel operations. Value is hex.  Default is "6162636465666768"
- serial-device
- serial-speed
- verbosity - level of logging.  0 for quiet, 3 for normal, 9 for debug.
- version - version number to return if not '2'.  must be postive decimal number.

## Other settings ##

```
  // parameter "enable-install"
  // parameter "fqdn"
  // parameter "init-command"
  // parameter "inputs" (value must be in range 0 - OOSDP_DEFAULT_INPUTS)
  // parameter "max-send"
  // parameter "network-address"
  // parameter "outputs" (value must be in range 0 - OOSDP_DEFAULT_OUTPUTS)
  // parameter "pd-filetransfer-recsize" is bytes to ask for in osdp_FTSTAT response (for a PD)
  // port - port number at the other end of tls or tcp connection
  // privacy - 1 to not dump PII
  // parameter "serial-number"
  // parameter "service-root" - where libosdp-conformance runs from
  // parameter "timeout"
  // parameter "timeout-nsec" - timeout in nanoseconds.
  // parameter "serial-read-timeout" - nanoseconds.
```

