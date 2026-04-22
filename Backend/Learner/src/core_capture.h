#ifndef DPDKCAP_CORE_CAPTURE_H
#define DPDKCAP_CORE_CAPTURE_H

#include <stdint.h>
#include <rte_ethdev.h>

#define DPDKCAP_CAPTURE_BURST_SIZE 256

/* Core configuration structures */
struct core_capture_config {
  bool volatile * stop_condition;
  struct core_capture_stats *stats;
  uint16_t rx_port;
  uint16_t rx_queue;
  uint16_t tx_port;
  uint16_t tx_queue;
  struct rte_ether_addr target_mac;
  struct rte_ether_addr tx_mac;
};

/* Statistics structure */
struct core_capture_stats {
  int core_id;
  uint64_t packets; //Packets successfully enqueued
  uint64_t missed_packets; //Packets core could not enqueue
};

/* Telemetry core configuration structure */
struct telemetry_config {
  bool volatile * stop_condition;
  uint16_t rx_port;
  uint16_t rx_queue;
};

/* DRL-Stack V1.1 Telemetry Protocol (44 Bytes payload) */
#define DRL_TELEMETRY_ETHER_TYPE 0x9999
#define DRL_TELEMETRY_MAGIC 0x44524C50  // "DRLP"

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

/* ================= POSIX Shared Memory IPC ================= */
#define DRL_STATE_SHM_NAME "/drl_state_shm"
#define DRL_SHM_MAGIC 0xD8A7A7A5
#define MAX_ACTOR_NODES 64

struct node_state_shm {
    uint32_t seq_num;
    uint16_t idle_pol_rat;
    uint16_t anomaly_rate; // x 10000
    uint32_t rx_pps;
    uint32_t imissed_pps;
    uint32_t mempool_free;
    uint32_t total_flows;
    uint64_t rx_bps;
    uint64_t tsc_timestamp; // Valid flag: if tsc > 0, node is active
} __attribute__((aligned(64))); // 64-byte aligned to prevent false sharing cache line bounces

struct drl_state_shm {
    uint32_t magic;           // 0xD8A7A7A5 (Init sanity check)
    uint32_t active_nodes;    // Number of nodes currently alive
    uint64_t update_count;    // Seqlock memory tear protection
    struct node_state_shm nodes[MAX_ACTOR_NODES];
    uint8_t  initial_reta[512]; // Hardware real RETA topology for Python cold-start seamless takeover
    uint64_t bucket_totals[512]; // Absolute packet counters mapped tightly for per-bucket delta metering
};

#define DRL_ACTION_SHM_NAME "/drl_action_shm"
#define DRL_ACTION_MAGIC 0xAC710055 

struct drl_action_shm {
    uint32_t magic;
    uint64_t action_seq;
    uint8_t  reta_buckets[512];
} __attribute__((aligned(64)));  // Padding up to 576 byte layout for strict CTypes coherence

/* Global RSS Bucket Stats (RTE_MAX_LCORE x 512 Buckets) */
/* 512 is for i40e RETA size. 
   We rely on simple array indexing without locks for per-core writing. */
extern uint32_t g_bucket_pps[RTE_MAX_LCORE][512];

/* Launches a capture task */
int capture_core(const struct core_capture_config * config);

/* Launches the telemetry reception task */
int telemetry_core(void *arg);

#endif
