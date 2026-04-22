#ifndef FLOW_EXTRACTOR_H
#define FLOW_EXTRACTOR_H

#include <rte_ethdev.h>
#include <rte_hash.h>

#include <time.h>

#define DEFAULT_FLOW_SEQ_LEN 24
#define DEFAULT_FLOW_STR_LEN 128

struct IPv4FlowTuple {
    rte_be32_t src_ip;
    rte_be32_t dst_ip;
    rte_be16_t src_port;
    rte_be16_t dst_port;
    uint8_t proto_id;
};

struct IPv6FlowTuple {
	uint8_t  src_ip[16];	/**< IP address of source host. */
	uint8_t  dst_ip[16];	/**< IP address of destination host(s). */
    rte_be16_t src_port;
    rte_be16_t dst_port;
    uint8_t proto_id;
};

struct IPv4PktInfo {
    struct IPv4FlowTuple flow;
    uint64_t pkt_timestamp;
    uint16_t pdu_len;
    uint16_t packet_len;
};

struct IPv6PktInfo {
    struct IPv6FlowTuple flow;
    uint64_t pkt_timestamp;
    uint16_t pdu_len;
    uint16_t packet_len;
};

struct IPv4FlowFeature {
    struct IPv4FlowTuple flow;  
    time_t start_time;                            
    uint64_t first_pkt_time;
    uint64_t last_pkt_time;
    uint64_t pkt_count; 
    uint64_t bytes_count;
    uint16_t min_payload_len;
    uint16_t max_payload_len;
    uint64_t sum_sq_payload_len;
    
    uint16_t min_packet_len;
    uint16_t max_packet_len;
    uint64_t sum_packet_len;
    uint64_t sum_sq_packet_len;

    uint16_t prev_payload_len;
    int32_t min_payload_diff;
    int32_t max_payload_diff;
    int64_t sum_payload_diff;
    uint64_t sum_sq_payload_diff;
};

struct IPv6FlowFeature {
    struct IPv6FlowTuple flow; 
    time_t start_time;                                  
    uint64_t first_pkt_time;
    uint64_t last_pkt_time;
    uint64_t pkt_count; 
    uint64_t bytes_count;
    uint16_t min_payload_len;
    uint16_t max_payload_len;
    uint64_t sum_sq_payload_len;
    
    uint16_t min_packet_len;
    uint16_t max_packet_len;
    uint64_t sum_packet_len;
    uint64_t sum_sq_packet_len;

    uint16_t prev_payload_len;
    int32_t min_payload_diff;
    int32_t max_payload_diff;
    int64_t sum_payload_diff;
    uint64_t sum_sq_payload_diff;
};

#define uint32_t_to_char(ip, a, b, c, d) do {\
		*a = (uint8_t)(ip >> 24 & 0xff);\
		*b = (uint8_t)(ip >> 16 & 0xff);\
		*c = (uint8_t)(ip >> 8 & 0xff);\
		*d = (uint8_t)(ip & 0xff);\
	} while (0)

int parse_ipv4(struct rte_mbuf * mbuf, struct IPv4PktInfo * pkt, uint16_t offset);
int parse_ipv6(struct rte_mbuf * mbuf, struct IPv6PktInfo * pkt, uint16_t offset);
bool ipv4_flow_equal(const struct IPv4FlowTuple * flow1, const struct IPv4FlowTuple * flow2);
void ipv4flow_print(struct IPv4FlowTuple *flow);
void ipv6flow_print(struct IPv6FlowTuple *flow);
void ipv4flow_format(struct IPv4FlowTuple *flow, char * str);
void ipv6flow_format(struct IPv6FlowTuple *flow, char * str);
char * ipv4flow_format_str(struct IPv4FlowTuple *flow);
char * ipv6flow_format_str(struct IPv6FlowTuple *flow);
struct rte_hash * create_hash_table(const char * name, uint32_t entries, uint32_t key_len, uint32_t socket_id);
int populate_ipv4_hash_table(struct rte_hash *hash_table, struct IPv4PktInfo *pkt, struct IPv4FlowFeature *ipv4_flow_features);
int populate_ipv6_hash_table(struct rte_hash *hash_table, struct IPv6PktInfo *pkt, struct IPv6FlowFeature *ipv6_flow_features);
int write_ipv4_flow_features_to_csv(struct IPv4FlowFeature *ipv4_flow_features, uint32_t num_ipv4_flows, FILE *fp);
int write_ipv6_flow_features_to_csv(struct IPv6FlowFeature *ipv6_flow_features, uint32_t num_ipv6_flows, FILE *fp);

#endif