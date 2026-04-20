#ifndef FLOW_EXTRACTOR_H
#define FLOW_EXTRACTOR_H

#include <rte_ethdev.h>
#include <rte_hash.h>

#include <time.h>
#include <rte_atomic.h>
#include <rte_ring.h>
#include <rte_mempool.h>

extern rte_atomic64_t total_inferred_flows;
extern rte_atomic64_t total_anomaly_flows;
extern struct rte_ring *anomaly_ring;
extern struct rte_mempool *anomaly_mempool;

extern double g_initial_nids_threshold;

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
    uint64_t pkt_tsc;
    uint16_t ip_tot_len;      // IP total length
    uint16_t raw_pkt_len;     // mbuf->pkt_len
    uint16_t hdr_len;         // IP header + L4 header 
    uint16_t payload_len;     // L4 payload length
    uint8_t  tcp_flags;
    uint16_t tcp_window;
};

struct IPv6PktInfo {
    struct IPv6FlowTuple flow;
    uint64_t pkt_tsc;
    uint16_t ip_tot_len;      // IPv6 payload + header
    uint16_t raw_pkt_len;     // mbuf->pkt_len
    uint16_t hdr_len;         // IPv6 header + L4 header
    uint16_t payload_len;     // L4 payload length
    uint8_t  tcp_flags;
    uint16_t tcp_window;
};

struct IPv4FlowFeature {
    struct IPv4FlowTuple flow;  // Source IP, Destination IP, Source Port, Destination Port, Protocol
    
    // Time features (stored in TSC to avoid per-packet division)
    // CIC-IDS-2017 uses micro-seconds (us) natively for all duration and IAT fields.
    uint64_t first_pkt_tsc;
    uint64_t last_pkt_tsc;      // Used for: Flow Duration
    uint64_t prev_pkt_tsc;
    uint64_t last_detect_tsc;

    // Packet and Bytes Count
    uint32_t fwd_pkt_count;       // CIC-IDS-2017: Total Fwd Packets
    uint32_t fwd_payload_tot_len; // CIC-IDS-2017: Total Length of Fwd Packets
    uint32_t fwd_header_tot_len;  // CIC-IDS-2017: Fwd Header Length

    // Payload Length (Fwd Packet Length)
    uint16_t fwd_pkt_len_max;     // CIC-IDS-2017: Fwd Packet Length Max
    uint16_t fwd_pkt_len_min;     // CIC-IDS-2017: Fwd Packet Length Min
    uint64_t fwd_pkt_len_sum_sq;  // Used for: Fwd Packet Length Mean, Fwd Packet Length Std

    // Fwd IAT (Inter-Arrival Time) 
    uint64_t fwd_iat_max;         // CIC-IDS-2017: Fwd IAT Max
    uint64_t fwd_iat_min;         // CIC-IDS-2017: Fwd IAT Min
    uint64_t fwd_iat_sum_sq;      // Used for: Fwd IAT Total, Fwd IAT Mean, Fwd IAT Std

    // TCP Flags count
    uint32_t fwd_psh_flags;       // CIC-IDS-2017: Fwd PSH Flags
    uint32_t fwd_urg_flags;       // CIC-IDS-2017: Fwd URG Flags
    uint32_t fin_flag_cnt;        // CIC-IDS-2017: FIN Flag Count
    uint32_t syn_flag_cnt;        // CIC-IDS-2017: SYN Flag Count
    uint32_t rst_flag_cnt;        // CIC-IDS-2017: RST Flag Count
    uint32_t ack_flag_cnt;        // CIC-IDS-2017: ACK Flag Count

    // Raw Packet Length (All Headers + Payload)
    uint16_t pkt_len_min;         // CIC-IDS-2017: Min Packet Length
    uint16_t pkt_len_max;         // CIC-IDS-2017: Max Packet Length
    uint64_t pkt_len_sum;         // Used for: Packet Length Mean
    uint64_t pkt_len_sum_sq;      // Used for: Packet Length Std

    // Windows
    uint32_t init_win_bytes_fwd;  // CIC-IDS-2017: Init_Win_bytes_forward
};

struct IPv6FlowFeature {
    struct IPv6FlowTuple flow;  // Source IP, Destination IP, Source Port, Destination Port, Protocol
    
    // Time features (stored in TSC to avoid per-packet division)
    // CIC-IDS-2017 uses micro-seconds (us) natively for all duration and IAT fields.
    uint64_t first_pkt_tsc;
    uint64_t last_pkt_tsc;      // Used for: Flow Duration
    uint64_t prev_pkt_tsc;
    uint64_t last_detect_tsc;

    // Packet and Bytes Count
    uint32_t fwd_pkt_count;       // CIC-IDS-2017: Total Fwd Packets
    uint32_t fwd_payload_tot_len; // CIC-IDS-2017: Total Length of Fwd Packets
    uint32_t fwd_header_tot_len;  // CIC-IDS-2017: Fwd Header Length

    // Payload Length (Fwd Packet Length)
    uint16_t fwd_pkt_len_max;     // CIC-IDS-2017: Fwd Packet Length Max
    uint16_t fwd_pkt_len_min;     // CIC-IDS-2017: Fwd Packet Length Min
    uint64_t fwd_pkt_len_sum_sq;  // Used for: Fwd Packet Length Mean, Fwd Packet Length Std

    // Fwd IAT (Inter-Arrival Time) 
    uint64_t fwd_iat_max;         // CIC-IDS-2017: Fwd IAT Max
    uint64_t fwd_iat_min;         // CIC-IDS-2017: Fwd IAT Min
    uint64_t fwd_iat_sum_sq;      // Used for: Fwd IAT Total, Fwd IAT Mean, Fwd IAT Std

    // TCP Flags count
    uint32_t fwd_psh_flags;       // CIC-IDS-2017: Fwd PSH Flags
    uint32_t fwd_urg_flags;       // CIC-IDS-2017: Fwd URG Flags
    uint32_t fin_flag_cnt;        // CIC-IDS-2017: FIN Flag Count
    uint32_t syn_flag_cnt;        // CIC-IDS-2017: SYN Flag Count
    uint32_t rst_flag_cnt;        // CIC-IDS-2017: RST Flag Count
    uint32_t ack_flag_cnt;        // CIC-IDS-2017: ACK Flag Count

    // Raw Packet Length (All Headers + Payload)
    uint16_t pkt_len_min;         // CIC-IDS-2017: Min Packet Length
    uint16_t pkt_len_max;         // CIC-IDS-2017: Max Packet Length
    uint64_t pkt_len_sum;         // Used for: Packet Length Mean
    uint64_t pkt_len_sum_sq;      // Used for: Packet Length Std

    // Windows
    uint32_t init_win_bytes_fwd;  // CIC-IDS-2017: Init_Win_bytes_forward
};

// Extern prediction hook for multi-phase anomaly detection
extern void predict_flow_anomaly(void *feature_ptr, int is_ipv4);
int init_onnx_model(const char* model_path);

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