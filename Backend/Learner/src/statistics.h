#ifndef DPDKCAP_STATISTICS_H
#define DPDKCAP_STATISTICS_H

#include "core_write.h"
#include "core_capture.h"

struct stats_data {
  struct rte_ring * ring;
  struct core_write_stats * cores_stats_write_list;
  unsigned int cores_write_stats_list_size;
  struct core_capture_stats * cores_stats_capture_list;
  unsigned int cores_capture_stats_list_size;
  unsigned int * port_list;
  unsigned int port_list_size;
  unsigned int queue_per_port;
  char * log_file;
  int rl_delay;
};


/*
 * Starts a non blocking statistics display
 */
void start_stats_display(struct stats_data * data, uint32_t timeout);
void check_and_apply_rl_action(uint16_t port_id, int num_queues, int rl_delay);
void start_stats_send(struct stats_data * data, uint32_t timeout, uint32_t send);
void stop_capture_until(struct stats_data * data, uint32_t timeout);
void final_stas_display(struct stats_data * data);
void final_stas_dispaly_and_send(struct stats_data * data);

#endif
