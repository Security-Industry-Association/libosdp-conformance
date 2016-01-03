/*
  osdp-local-config.h - local (platform) configuration values
*/

// the server key and cert for the OSDP TLS server

#define OSDP_LCL_CA_KEYS        "/opt/open-osdp/etc/ca_keys.pem"
#define OSDP_LCL_SERVER_CERT "/opt/open-osdp/etc/cert.pem"
#define OSDP_LCL_SERVER_KEY  "/opt/open-osdp/etc/key.pem"
#define OSDP_LCL_COMMAND_PATH   "/opt/open-osdp/run/%s/open_osdp_command.json"
#define OSDP_LCL_SERVER_RESULTS "/opt/open-osdp/run/%s"
#define OSDP_LCL_UNIX_SOCKET    "/opt/open-osdp/run/%s/open-osdp-control"

#define OSDP_LCL_DEFAULT_PSK    "speakFriend&3ntr"

#define OSPD_LCL_SET_PID_TEMPLATE \
  "sudo -n /opt/open-osdp/bin/set-pid %s %d"

