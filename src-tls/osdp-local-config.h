/*
  osdp-local-config.h - local (platform) configuration values
*/

// the server key and cert for the OSDP TLS server

#define OSDP_LCL_CA_KEYS        "/opt/osdp-conformance/etc/ca_keys.pem"
#define OSDP_LCL_CLIENT_CERT "/opt/osdp-conformance/etc/client_cert.pem"
#define OSDP_LCL_CLIENT_KEY  "/opt/osdp-conformance/etc/client_key.pem"
#define OSDP_LCL_SERVER_CERT "/opt/osdp-conformance/etc/server_cert.pem"
#define OSDP_LCL_SERVER_KEY  "/opt/osdp-conformance/etc/server_key.pem"
#define OSDP_LCL_COMMAND_PATH   "/opt/osdp-conformance/run/%s/open_osdp_command.json"
#define OSDP_LCL_SERVER_RESULTS "/opt/osdp-conformance/run/%s"
#define OSDP_LCL_CONTROL        "/opt/osdp-conformance/run/%s/open-osdp-control"

#define OSDP_LCL_DEFAULT_PSK    "speakFriend&3ntr"

#define OSPD_LCL_SET_PID_TEMPLATE \
  "sudo -n /opt/osdp-conformance/bin/set-pid %s %d"

