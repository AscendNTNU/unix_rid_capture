/* -*- tab-width: 2; mode: c; -*-
 * 
 *
 *
 * Copyright (c) 2022-2023 Steve Jack
 *
 * MIT licence
 *
 */

#include <stdint.h>
#include <sys/types.h>

#include "opendroneid.h"

#define VERSION        "0.98"

/* Bluetooth LE */
#define BLUEZ_SNIFFER  1 /* Linux standard Bluetooth stack. */
#define NRF_SNIFFER    0 /* nRF52840 dongle running nRF's sniffer program. */

/* WiFi */
#define ENABLE_PCAP    1

/* Protocols */
#define ID_FRANCE      1

/* Outputs.
 * Positive number turns an output on.
 * The number is seconds between updates.
 */
#define FA_EXPORT      3 /* FlightAware format.                  */
#define ASTERIX        0 /* Eurocontrol ASTERIX cat. 129 format. */
#define WWW_PAGE       0

/* Display */
#define USE_CURSES     0 /* For testing, displays should use the UDP output. */

/* Analysis */
#define VERIFY         0 /* For investigating auth messages.     */

/* Experimental */
#define BATT_VOLTS     0


#define MAX_UAVS      20
#define ID_OD_AUTH_DATUM  1546300800LU

struct UAV_RID {u_char            mac[6], counter[16];
                unsigned int      packets;
                time_t            last_rx, last_retx;
                ODID_UAS_Data     odid_data;
                ODID_BasicID_data basic_serial, basic_caa_reg;
#if VERIFY
                int               auth_length;
                uint8_t           auth_buffer[ODID_AUTH_MAX_PAGES * ODID_AUTH_PAGE_NONZERO_DATA_SIZE + 1];
#endif
                int               rssi;
                double            min_lat, max_lat, min_long, max_long, min_alt, max_alt;
};

void  parse_odid(u_char *,u_char *,int,int,const char *,const float *);
int   mac_index(uint8_t *,struct UAV_RID *);
void  dump(char *,uint8_t *,int);
char *printable_text(uint8_t *,int);
int   write_json(char *);

#include "display.h"

/* nrf_sniffer.c */
pid_t start_nrf_sniffer(const char *,int *);
void  parse_nrf_sniffer(uint8_t *,int);
void  stop_nrf_sniffer(void);

/* bluez_sniffer.c */
int   start_bluez_sniffer(const char *);
int   parse_bluez_sniffer(void);
void  stop_bluez_sniffer(void);

/* france.c */
void  parse_id_france(uint8_t *,uint8_t *,struct UAV_RID *);

/* verify.c */
int   init_crypto(uint8_t *,int,uint8_t *,int,FILE *);
int   parse_auth(ODID_UAS_Data *,ODID_MessagePack_encoded *,struct UAV_RID *);
void  close_crypto(void);

/* export.c */
int   fa_export(time_t,struct UAV_RID *);

/* asterix.c */
void  asterix_init(void);
void  asterix_transmit(struct UAV_RID *);
void  asterix_end(void);

/* summary.c */
void  print_summary(char *,FILE *,struct UAV_RID *,int);
int   www_export(char *,time_t,struct UAV_RID *);

void  calc_m_per_deg(double,double *,double *);

/*
 *
 */
