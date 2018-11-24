// definitions for extended write / extended read commands

typedef struct osdp_xwr_command
{
  unsigned char xrw_mode;
  unsigned char xwr_pcmnd;
  unsigned char xwr_pdata [2];
} OSDP_XWR_COMMAND;
#define OSDP_XWR_0_GET_MODE (1) // per table 34 in 60839-11-5
#define OSDP_XWR_0_SET_MODE (2) // per table 34 in 60839-11-5
#define OSDP_XWR_1_APDU            (1) // per table 40
#define OSDP_XWR_1_DONE            (2) // per table 34 in 60839-11-5 and table 41
#define OSDP_XWR_1_SMART_CARD_SCAN (4) // per table 34 in 60839-11-5 and table 43

