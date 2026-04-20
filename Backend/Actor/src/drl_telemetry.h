#ifndef DRL_TELEMETRY_H
#define DRL_TELEMETRY_H

#include <stdint.h>

#define DRL_MAGIC_NUMBER 0x44524C50 /* "DRLP" */
#define DRL_ETHER_TYPE 0x9999

/* 
 * DRL-Stack Global Header (RFC style Bit-packed)
 * Total Size: 32 bytes 
 */
struct drl_global_hdr {
    uint32_t magic;             /* 0x44524C50 ("DRLP") */
    uint32_t seq_num;           /* Monotonically increasing sequence number */

    /* 32-bit packed word 1 */
    uint32_t version : 4;       /* Protocol Version */
    uint32_t flags : 4;         /* Reserved Alerts/Flags */
    uint32_t idle_pol_rat : 10; /* Average Idle Polling Ratio (0-1000) */
    uint32_t anomaly_rate : 14; /* Anomaly Detection Rate x 10000 */

    /* 32-bit packed word 2 */
    uint32_t active_cores : 8;  /* Number of active queues/cores */
    uint32_t mempool_free : 24; /* Mempool Free Mbuf Count */

    uint32_t rx_pps;            /* Global RX Packets Per Second */
    uint32_t imissed_pps;       /* Global IMISSED (Hardware Drops) */

    uint32_t total_flows;       /* Total ML Inferred Flows */
    uint64_t rx_bps;            /* Global RX Bytes Per Second */

    uint64_t tsc_timestamp;     /* TSC Timestamp (64 bits) */
} __attribute__((__packed__));

#endif /* DRL_TELEMETRY_H */
