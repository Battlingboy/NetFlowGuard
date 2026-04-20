#ifndef DPDKCAP_CORE_CAPTURE_H
#define DPDKCAP_CORE_CAPTURE_H

#include <stdint.h>
#include <rte_ethdev.h>

#define DPDKCAP_CAPTURE_BURST_SIZE 256

/* Core configuration structures */
struct core_capture_config {
  struct rte_ring * ring;
  bool volatile * stop_condition;
  struct core_capture_stats *stats;
  uint8_t port;
  uint8_t queue;
};

/* Statistics structure */
struct core_capture_stats {
  int core_id;
  uint64_t packets; //Packets successfully enqueued
  uint64_t missed_packets; //Packets core could not enqueue
};

/* Global RSS Bucket Stats (RTE_MAX_LCORE x 512 Buckets) */
/* 512 is for i40e RETA size. 
   We rely on simple array indexing without locks for per-core writing. */
extern uint64_t g_rss_bucket_stats[RTE_MAX_LCORE][512];

/* Launches a capture task */
int capture_core(const struct core_capture_config * config);

#endif
