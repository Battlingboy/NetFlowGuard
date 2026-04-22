#ifndef DPDKCAP_CORE_WRITE_H
#define DPDKCAP_CORE_WRITE_H

#include <stdbool.h>
#include <stdint.h>

#include <mysql/mysql.h>

#include <rte_common.h>
#include <rte_ethdev.h>

#define DPDKCAP_OUTPUT_FILENAME_LENGTH 100
#define DPDKCAP_WRITE_BURST_SIZE 256
#define TABLES_NUM 2
#define DEFAULT_NUM_IPV4_FLOWS    (1024*1024)
#define DEFAULT_NUM_IPV6_FLOWS    (1024*1024)
#define IPV4_FLOWS_LIMIT_IN_TABLE   DEFAULT_NUM_IPV4_FLOWS / 2
#define IPV6_FLOWS_LIMIT_IN_TABLE   DEFAULT_NUM_IPV6_FLOWS / 2
#define MAX_PORTS 65536
#define MAX_PROTOCOLS 128

/* Writing core configuration */
struct core_write_config {
  struct rte_ring * ring;
  bool volatile * stop_condition;
  struct core_write_stats * stats;
  char * output_file_template;
  // char * csv_file_template;
  int compression;
  unsigned int snaplen;
  unsigned long rotate_seconds;
  uint64_t file_size_limit;
  rte_be32_t ip;
  rte_be32_t ip_upperborder;
  rte_be32_t ip_lowerborder;
  rte_be16_t port;
  uint16_t ports[MAX_PORTS];
  int num_ports;
  uint8_t protocol;
  uint16_t protocols[MAX_PROTOCOLS];
  int num_protocols;
  MYSQL *mysql_conn;
};

/* Statistics structure */
struct core_write_stats {
  int core_id;
  char output_file[DPDKCAP_OUTPUT_FILENAME_LENGTH];
  uint64_t current_file_packets;
  uint64_t current_file_bytes;
  uint64_t current_file_compressed_bytes;
  uint64_t packets_written;
  uint64_t packets_filtered;
  uint64_t bytes;
  uint64_t compressed_bytes;
};

struct WriteUploadIpv4Flow {
    int core_id;
  int table_id;
  struct rte_hash *ipv4_flow_table;
  struct IPv4FlowFeature *ipv4_flow_features;
  MYSQL *mysql_conn;
};

/* Launches a write task */
int write_core(const struct core_write_config * config);

#endif
