#include <rte_ring.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_branch_prediction.h>
#include <rte_version.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_tcp.h>
#include <rte_jhash.h>
#include <rte_hash_crc.h>
#include <math.h>

#include "flow_extractor.h"
#include "dpdk_lgbm_c_model/header.h"
#include <rte_memzone.h>
#include <onnxruntime_c_api.h>

#define RTE_LOGTYPE_DPDKCAP RTE_LOGTYPE_USER1

rte_atomic64_t total_inferred_flows = RTE_ATOMIC64_INIT(0);
rte_atomic64_t total_anomaly_flows = RTE_ATOMIC64_INIT(0);
struct rte_ring *anomaly_ring = NULL;
struct rte_mempool *anomaly_mempool = NULL;

const OrtApi* g_ort = NULL;
OrtEnv* g_ort_env = NULL;
OrtSession* g_ort_session = NULL;
OrtSessionOptions* g_session_options = NULL;
OrtMemoryInfo* g_memory_info = NULL;

static char* g_input_name = NULL;
static char* g_output_name = NULL;

int init_onnx_model(const char* model_path) {
    g_ort = OrtGetApiBase()->GetApi(ORT_API_VERSION);
    if (!g_ort) {
        RTE_LOG(ERR, DPDKCAP, "Failed to get ONNX Runtime API.\n");
        return -1;
    }

    if (g_ort->CreateEnv(ORT_LOGGING_LEVEL_WARNING, "sys_infer", &g_ort_env) != NULL) {
        RTE_LOG(ERR, DPDKCAP, "Failed to create ORT Environment.\n");
        return -1;
    }

    if (g_ort->CreateSessionOptions(&g_session_options) != NULL) {
        RTE_LOG(ERR, DPDKCAP, "Failed to create ORT Session Options.\n");
        return -1;
    }

    g_ort->SetIntraOpNumThreads(g_session_options, 1);
    g_ort->SetSessionGraphOptimizationLevel(g_session_options, ORT_ENABLE_ALL);

    if (g_ort->CreateSession(g_ort_env, model_path, g_session_options, &g_ort_session) != NULL) {
        RTE_LOG(ERR, DPDKCAP, "Failed to create ORT Session from %s.\n", model_path);
        return -1;
    }

    if (g_ort->CreateCpuMemoryInfo(OrtArenaAllocator, OrtMemTypeDefault, &g_memory_info) != NULL) {
        RTE_LOG(ERR, DPDKCAP, "Failed to create ORT Memory Info.\n");
        return -1;
    }

    OrtAllocator* allocator;
    g_ort->GetAllocatorWithDefaultOptions(&allocator);
    
    // Get input and output names dynamically
    g_ort->SessionGetInputName(g_ort_session, 0, allocator, &g_input_name);
    g_ort->SessionGetOutputName(g_ort_session, 0, allocator, &g_output_name);

    if (!g_input_name) g_input_name = strdup("input");
    if (!g_output_name) g_output_name = strdup("output");

    RTE_LOG(INFO, DPDKCAP, "ONNX Runtime Initialized: Loaded model %s. Input: %s, Output: %s\n", model_path, g_input_name, g_output_name);
    return 0;
}

double g_initial_nids_threshold = 0.5;

#define DEFAULT_HASH_FUNC       rte_jhash

int parse_ipv4(struct rte_mbuf * mbuf, struct IPv4PktInfo * pkt, uint16_t offset) {
    pkt->pkt_tsc = rte_rdtsc();

    struct rte_ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, offset);
    pkt->flow.src_ip = rte_be_to_cpu_32(ipv4_hdr->src_addr);
    pkt->flow.dst_ip = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
    pkt->flow.proto_id = ipv4_hdr->next_proto_id;
    pkt->ip_tot_len = rte_be_to_cpu_16(ipv4_hdr->total_length);
    pkt->raw_pkt_len = pkt->ip_tot_len + 14; // Adding approximate Ethernet header length
    pkt->ip_tot_len = rte_be_to_cpu_16(ipv4_hdr->total_length);
    pkt->tcp_flags = 0;
    pkt->tcp_window = 0;

    switch (ipv4_hdr->next_proto_id) {
        case IPPROTO_TCP:;
            struct rte_tcp_hdr *tcp_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_tcp_hdr *, offset + sizeof(struct rte_ipv4_hdr));
            pkt->flow.src_port = rte_be_to_cpu_16(tcp_hdr->src_port);
            pkt->flow.dst_port = rte_be_to_cpu_16(tcp_hdr->dst_port);
            pkt->hdr_len = (ipv4_hdr->ihl * 4) + (((tcp_hdr->data_off & 0xf0) >> 4) * 4);
            pkt->payload_len = pkt->ip_tot_len > pkt->hdr_len ? pkt->ip_tot_len - pkt->hdr_len : 0;
            pkt->tcp_flags = tcp_hdr->tcp_flags;
            pkt->tcp_window = rte_be_to_cpu_16(tcp_hdr->rx_win);
            break;
        case IPPROTO_UDP:;
            struct rte_udp_hdr *udp_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_udp_hdr *, offset + sizeof(struct rte_ipv4_hdr));
            pkt->flow.src_port = rte_be_to_cpu_16(udp_hdr->src_port);
            pkt->flow.dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);
            pkt->hdr_len = (ipv4_hdr->ihl * 4) + 8;
            pkt->payload_len = rte_be_to_cpu_16(udp_hdr->dgram_len) > 8 ? rte_be_to_cpu_16(udp_hdr->dgram_len) - 8 : 0;
            break;
        default:        // 其他协议暂不支持
            pkt->flow.src_port = 0;
            pkt->flow.dst_port = 0;
            pkt->hdr_len = ipv4_hdr->ihl * 4;
            pkt->payload_len = pkt->ip_tot_len > pkt->hdr_len ? pkt->ip_tot_len - pkt->hdr_len : 0;
            break;
    }

    return 0;
}

int parse_ipv6(struct rte_mbuf * mbuf, struct IPv6PktInfo * pkt, uint16_t offset) {
    pkt->pkt_tsc = rte_rdtsc();

    struct rte_ipv6_hdr *ipv6_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv6_hdr *, offset);
    rte_memcpy(pkt->flow.src_ip, ipv6_hdr->src_addr, sizeof(ipv6_hdr->src_addr));
    rte_memcpy(pkt->flow.dst_ip, ipv6_hdr->dst_addr, sizeof(ipv6_hdr->dst_addr));
    pkt->flow.proto_id = ipv6_hdr->proto;
    pkt->ip_tot_len = rte_be_to_cpu_16(ipv6_hdr->payload_len) + sizeof(struct rte_ipv6_hdr);
    pkt->raw_pkt_len = pkt->ip_tot_len + 14; // Adding approximate Ethernet header length
    pkt->ip_tot_len = rte_be_to_cpu_16(ipv6_hdr->payload_len) + sizeof(struct rte_ipv6_hdr);
    pkt->tcp_flags = 0;
    pkt->tcp_window = 0;

    switch (ipv6_hdr->proto) {
        case IPPROTO_TCP:;
            struct rte_tcp_hdr *tcp_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_tcp_hdr *, offset + sizeof(struct rte_ipv6_hdr));
            pkt->flow.src_port = rte_be_to_cpu_16(tcp_hdr->src_port);
            pkt->flow.dst_port = rte_be_to_cpu_16(tcp_hdr->dst_port);
            pkt->hdr_len = sizeof(struct rte_ipv6_hdr) + (((tcp_hdr->data_off & 0xf0) >> 4) * 4);
            pkt->payload_len = pkt->ip_tot_len > pkt->hdr_len ? pkt->ip_tot_len - pkt->hdr_len : 0;
            pkt->tcp_flags = tcp_hdr->tcp_flags;
            pkt->tcp_window = rte_be_to_cpu_16(tcp_hdr->rx_win);
            break;
        case IPPROTO_UDP:;
            struct rte_udp_hdr *udp_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_udp_hdr *, offset + sizeof(struct rte_ipv6_hdr));
            pkt->flow.src_port = rte_be_to_cpu_16(udp_hdr->src_port);
            pkt->flow.dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);
            pkt->hdr_len = sizeof(struct rte_ipv6_hdr) + 8;
            pkt->payload_len = rte_be_to_cpu_16(udp_hdr->dgram_len) > 8 ? rte_be_to_cpu_16(udp_hdr->dgram_len) - 8 : 0;
            break;
        default:        // 其他协议暂不支持
            pkt->flow.src_port = 0;
            pkt->flow.dst_port = 0;
            pkt->hdr_len = sizeof(struct rte_ipv6_hdr);
            pkt->payload_len = rte_be_to_cpu_16(ipv6_hdr->payload_len);
            break;
    }

    return 0;
}

bool ipv4_flow_equal(const struct IPv4FlowTuple * flow1, const struct IPv4FlowTuple * flow2) {
    if (flow1->src_ip != flow2->src_ip && flow1->src_ip != flow2->dst_ip) {
        return false;
    }
    if (flow1->dst_ip != flow2->src_ip && flow1->dst_ip != flow2->dst_ip) {
        return false;
    }
    if (flow1->src_port != flow2->src_port && flow1->src_port != flow2->dst_port) {
        return false;
    }
    if (flow1->dst_port != flow2->src_port && flow1->dst_port != flow2->dst_port) {
        return false;
    }
    if (flow1->proto_id != flow2->proto_id) {
        return false;
    }

    return true;
}

void ipv4flow_print(struct IPv4FlowTuple * flow) {
    char a, b, c, d;

    // %hhu输出占一个字节，%hu输出占两个字节
    uint32_t_to_char(rte_bswap32(flow->src_ip), &a, &b, &c, &d);
    printf("src: %3hhu.%3hhu.%3hhu.%3hhu \t", a, b, c, d);

    uint32_t_to_char(rte_bswap32(flow->dst_ip), &a, &b, &c, &d);
    printf("dst: %3hhu.%3hhu.%3hhu.%3hhu \t", a, b, c, d);

    printf("src port: %5hu \tdst port: %5hu \tprotocol: %3hhu\n", flow->src_port, flow->dst_port, flow->proto_id);
}

void ipv6flow_print(struct IPv6FlowTuple * flow) {
    uint8_t *addr;

    addr = flow->src_ip;
    printf("src: %4hx:%4hx:%4hx:%4hx:%4hx:%4hx:%4hx:%4hx\t",
           (uint16_t)((addr[0] << 8) | addr[1]),
           (uint16_t)((addr[2] << 8) | addr[3]),
           (uint16_t)((addr[4] << 8) | addr[5]),
           (uint16_t)((addr[6] << 8) | addr[7]),
           (uint16_t)((addr[8] << 8) | addr[9]),
           (uint16_t)((addr[10] << 8) | addr[11]),
           (uint16_t)((addr[12] << 8) | addr[13]),
           (uint16_t)((addr[14] << 8) | addr[15]));

    addr = flow->dst_ip;
    printf("dst: %4hx:%4hx:%4hx:%4hx:%4hx:%4hx:%4hx:%4hx",
           (uint16_t)((addr[0] << 8) | addr[1]),
           (uint16_t)((addr[2] << 8) | addr[3]),
           (uint16_t)((addr[4] << 8) | addr[5]),
           (uint16_t)((addr[6] << 8) | addr[7]),
           (uint16_t)((addr[8] << 8) | addr[9]),
           (uint16_t)((addr[10] << 8) | addr[11]),
           (uint16_t)((addr[12] << 8) | addr[13]),
           (uint16_t)((addr[14] << 8) | addr[15]));

    printf("src port: %5hu \tdst port: %5hu \tprotocol: %3hhu\n", flow->src_port, flow->dst_port, flow->proto_id);
}

// 格式化IPv4流
void ipv4flow_format(struct IPv4FlowTuple * flow, char * str) {
    char a, b, c, d;

    uint32_t_to_char(rte_bswap32(flow->src_ip), &a, &b, &c, &d);
    sprintf(str, "%3hhu.%3hhu.%3hhu.%3hhu,", a, b, c, d);

    uint32_t_to_char(rte_bswap32(flow->dst_ip), &a, &b, &c, &d);
    sprintf(str + strlen(str), "%3hhu.%3hhu.%3hhu.%3hhu,%5hu,%5hu,%3hhu", a, b, c, d, flow->src_port, flow->dst_port, flow->proto_id);
}

// 格式化IPv6流
void ipv6flow_format(struct IPv6FlowTuple * flow, char * str) {
    uint8_t *addr;

    addr = flow->src_ip;
    sprintf(str, "%4hx:%4hx:%4hx:%4hx:%4hx:%4hx:%4hx:%4hx,",
            (uint16_t)((addr[0] << 8) | addr[1]),
            (uint16_t)((addr[2] << 8) | addr[3]),
            (uint16_t)((addr[4] << 8) | addr[5]),
            (uint16_t)((addr[6] << 8) | addr[7]),
            (uint16_t)((addr[8] << 8) | addr[9]),
            (uint16_t)((addr[10] << 8) | addr[11]),
            (uint16_t)((addr[12] << 8) | addr[13]),
            (uint16_t)((addr[14] << 8) | addr[15]));

    addr = flow->dst_ip;
    sprintf(str + strlen(str), "%4hx:%4hx:%4hx:%4hx:%4hx:%4hx:%4hx:%4hx,%5hu,%5hu,%3hhu",
            (uint16_t)((addr[0] << 8) | addr[1]),
            (uint16_t)((addr[2] << 8) | addr[3]),
            (uint16_t)((addr[4] << 8) | addr[5]),
            (uint16_t)((addr[6] << 8) | addr[7]),
            (uint16_t)((addr[8] << 8) | addr[9]),
            (uint16_t)((addr[10] << 8) | addr[11]),
            (uint16_t)((addr[12] << 8) | addr[13]),
            (uint16_t)((addr[14] << 8) | addr[15]),
            flow->src_port, flow->dst_port, flow->proto_id);
}

// 格式化IPv4FlowTuple字符串并返回字符串
char * ipv4flow_format_str(struct IPv4FlowTuple * flow) {
    char * str = (char *)malloc(100);
    ipv4flow_format(flow, str);
    return str;
}

// 格式化IPv6FlowTuple字符串并返回字符串
char * ipv6flow_format_str(struct IPv6FlowTuple * flow) {
    char * str = (char *)malloc(100);
    ipv6flow_format(flow, str);
    return str;
}

// 创建hash表
struct rte_hash * create_hash_table(const char * name, uint32_t entries, uint32_t key_len, uint32_t socket_id) {
    struct rte_hash_parameters hash_params = {
        .name = name,
        .entries = entries,
        .key_len = key_len,
        .socket_id = socket_id,
        .hash_func = rte_hash_crc,
        .hash_func_init_val = 0,
    };

    struct rte_hash * hash_table = rte_hash_create(&hash_params);

    return hash_table;
}

// Helper: safe tsc to microsecond conversion avoiding overflow
static inline uint64_t tsc_to_us(uint64_t tsc) {
    uint64_t hz = rte_get_timer_hz();
    if (unlikely(hz == 0)) return tsc; // Fallback
    return (tsc / hz) * 1000000 + ((tsc % hz) * 1000000) / hz;
}

// 打桩函数：待未来接入真实的 LightGBM/TL2cgen API
void predict_flow_anomaly(void *feature_ptr, int is_ipv4) {
    if (unlikely(!feature_ptr)) return;
    
    rte_atomic64_add(&total_inferred_flows, 1);

    union Entry data[26] = {0};
    uint64_t duration_us;
    uint32_t count, payload_tot, hdr_tot;
    uint16_t pkt_max, pkt_min;
    double pkt_mean, pkt_std;
    uint64_t iat_tot, iat_max, iat_min;
    double iat_mean, iat_std;
    uint16_t raw_min, raw_max;
    double raw_mean, raw_std;
    uint32_t psh, urg, fin, syn, rst, ack, win;
    double pps, bps;
    
    if (is_ipv4) {
        struct IPv4FlowFeature *f = (struct IPv4FlowFeature *)feature_ptr;
        duration_us = f->last_pkt_tsc >= f->first_pkt_tsc ? tsc_to_us(f->last_pkt_tsc - f->first_pkt_tsc) : 0;
        count = f->fwd_pkt_count;
        payload_tot = f->fwd_payload_tot_len;
        hdr_tot = f->fwd_header_tot_len;
        pkt_max = f->fwd_pkt_len_max;
        pkt_min = f->fwd_pkt_len_min;
        
        double mean_payload = count > 0 ? (double)payload_tot / count : 0.0;
        double var_payload = count > 0 ? ((double)f->fwd_pkt_len_sum_sq / count) - (mean_payload * mean_payload) : 0.0;
        pkt_mean = mean_payload;
        pkt_std = var_payload > 0 ? sqrt(var_payload) : 0.0;
        
        iat_tot = duration_us;
        iat_max = f->fwd_iat_max;
        iat_min = count > 1 ? f->fwd_iat_min : 0;
        double mean_iat = count > 1 ? (double)iat_tot / (count - 1) : 0.0;
        double var_iat = count > 1 ? ((double)f->fwd_iat_sum_sq / (count - 1)) - (mean_iat * mean_iat) : 0.0;
        iat_mean = mean_iat;
        iat_std = var_iat > 0 ? sqrt(var_iat) : 0.0;
        
        raw_min = f->pkt_len_min;
        raw_max = f->pkt_len_max;
        double mean_packet = count > 0 ? (double)f->pkt_len_sum / count : 0.0;
        double var_packet = count > 0 ? ((double)f->pkt_len_sum_sq / count) - (mean_packet * mean_packet) : 0.0;
        raw_mean = mean_packet;
        raw_std = var_packet > 0 ? sqrt(var_packet) : 0.0;
        
        psh = f->fwd_psh_flags;
        urg = f->fwd_urg_flags;
        fin = f->fin_flag_cnt;
        syn = f->syn_flag_cnt;
        rst = f->rst_flag_cnt;
        ack = f->ack_flag_cnt;
        win = f->init_win_bytes_fwd;
        
        double duration_sec = (double)duration_us / 1000000.0;
        if (duration_sec < 0.000001) duration_sec = 0.000001;
        pps = count / duration_sec;
        bps = payload_tot / duration_sec;
    } else {
        struct IPv6FlowFeature *f = (struct IPv6FlowFeature *)feature_ptr;
        duration_us = f->last_pkt_tsc >= f->first_pkt_tsc ? tsc_to_us(f->last_pkt_tsc - f->first_pkt_tsc) : 0;
        count = f->fwd_pkt_count;
        payload_tot = f->fwd_payload_tot_len;
        hdr_tot = f->fwd_header_tot_len;
        pkt_max = f->fwd_pkt_len_max;
        pkt_min = f->fwd_pkt_len_min;
        
        double mean_payload = count > 0 ? (double)payload_tot / count : 0.0;
        double var_payload = count > 0 ? ((double)f->fwd_pkt_len_sum_sq / count) - (mean_payload * mean_payload) : 0.0;
        pkt_mean = mean_payload;
        pkt_std = var_payload > 0 ? sqrt(var_payload) : 0.0;
        
        iat_tot = duration_us;
        iat_max = f->fwd_iat_max;
        iat_min = count > 1 ? f->fwd_iat_min : 0;
        double mean_iat = count > 1 ? (double)iat_tot / (count - 1) : 0.0;
        double var_iat = count > 1 ? ((double)f->fwd_iat_sum_sq / (count - 1)) - (mean_iat * mean_iat) : 0.0;
        iat_mean = mean_iat;
        iat_std = var_iat > 0 ? sqrt(var_iat) : 0.0;
        
        raw_min = f->pkt_len_min;
        raw_max = f->pkt_len_max;
        double mean_packet = count > 0 ? (double)f->pkt_len_sum / count : 0.0;
        double var_packet = count > 0 ? ((double)f->pkt_len_sum_sq / count) - (mean_packet * mean_packet) : 0.0;
        raw_mean = mean_packet;
        raw_std = var_packet > 0 ? sqrt(var_packet) : 0.0;
        
        psh = f->fwd_psh_flags;
        urg = f->fwd_urg_flags;
        fin = f->fin_flag_cnt;
        syn = f->syn_flag_cnt;
        rst = f->rst_flag_cnt;
        ack = f->ack_flag_cnt;
        win = f->init_win_bytes_fwd;
        
        double duration_sec = (double)duration_us / 1000000.0;
        if (duration_sec < 0.000001) duration_sec = 0.000001;
        pps = count / duration_sec;
        bps = payload_tot / duration_sec;
    }
    float input_tensor_values[26];
    input_tensor_values[0] = (float)duration_us;
    input_tensor_values[1] = (float)count;
    input_tensor_values[2] = payload_tot == 0 ? 0.0f : (float)payload_tot;
    input_tensor_values[3] = (float)hdr_tot;
    input_tensor_values[4] = pkt_max == 0 ? 0.0f : (float)pkt_max;
    input_tensor_values[5] = (float)pkt_min;
    input_tensor_values[6] = pkt_mean == 0.0 ? 0.0f : (float)pkt_mean;
    input_tensor_values[7] = pkt_std == 0.0 ? 0.0f : (float)pkt_std;
    input_tensor_values[8] = (float)iat_tot;
    input_tensor_values[9] = (float)iat_max;
    input_tensor_values[10] = (float)iat_min;
    input_tensor_values[11] = (float)iat_mean;
    input_tensor_values[12] = (float)iat_std;
    input_tensor_values[13] = (float)raw_min;
    input_tensor_values[14] = (float)raw_max;
    input_tensor_values[15] = (float)raw_mean;
    input_tensor_values[16] = (float)raw_std;
    input_tensor_values[17] = (float)psh;
    input_tensor_values[18] = (float)urg;
    input_tensor_values[19] = (float)fin;
    input_tensor_values[20] = (float)syn;
    input_tensor_values[21] = (float)rst;
    input_tensor_values[22] = (float)ack;
    input_tensor_values[23] = (float)win;
    input_tensor_values[24] = (float)pps;
    input_tensor_values[25] = (float)bps;

    double result[1] = {0.0};

    // --- ONNX Runtime CPU Inference ---
    if (likely(g_ort_session != NULL)) {
        int64_t input_shape[] = {1, 26};
        OrtValue* input_tensor = NULL;
        
        g_ort->CreateTensorWithDataAsOrtValue(
            g_memory_info, input_tensor_values, 26 * sizeof(float),
            input_shape, 2, ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT, &input_tensor);

        const char* input_names[] = {g_input_name};
        const char* output_names[] = {g_output_name};
        OrtValue* output_tensor = NULL;

        // Run inference
        OrtStatus* status = g_ort->Run(g_ort_session, NULL, input_names, (const OrtValue* const*)&input_tensor, 1, output_names, 1, &output_tensor);
        
        if (status == NULL && output_tensor != NULL) {
            struct OrtTensorTypeAndShapeInfo* shape_info;
            g_ort->GetTensorTypeAndShape(output_tensor, &shape_info);
            size_t out_len;
            g_ort->GetTensorShapeElementCount(shape_info, &out_len);
            
            ONNXTensorElementDataType type;
            g_ort->GetTensorElementType(shape_info, &type);
            
            // If AutoEncoder (26d float output), calculate MSE. 
            if (out_len == 26 && type == ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT) {
                float* floatarr;
                g_ort->GetTensorMutableData(output_tensor, (void**)&floatarr);
                double mse = 0.0;
                for (int i = 0; i < 26; i++) {
                    double diff = (double)input_tensor_values[i] - (double)floatarr[i];
                    mse += diff * diff;
                }
                result[0] = mse / 26.0;
            } else if (out_len > 0) {
                // If Classifier (1d output), extract value robustly based on type
                if (type == ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT) {
                    float* floatarr;
                    g_ort->GetTensorMutableData(output_tensor, (void**)&floatarr);
                    result[0] = (double)floatarr[0];
                } else if (type == ONNX_TENSOR_ELEMENT_DATA_TYPE_INT64) {
                    int64_t* int64arr;
                    g_ort->GetTensorMutableData(output_tensor, (void**)&int64arr);
                    result[0] = (double)int64arr[0];
                } else if (type == ONNX_TENSOR_ELEMENT_DATA_TYPE_INT32) {
                    int32_t* int32arr;
                    g_ort->GetTensorMutableData(output_tensor, (void**)&int32arr);
                    result[0] = (double)int32arr[0];
                } else if (type == ONNX_TENSOR_ELEMENT_DATA_TYPE_BOOL) {
                    bool* boolarr;
                    g_ort->GetTensorMutableData(output_tensor, (void**)&boolarr);
                    result[0] = boolarr[0] ? 1.0 : 0.0;
                }
            }
            
            g_ort->ReleaseTensorTypeAndShapeInfo(shape_info);
            g_ort->ReleaseValue(output_tensor);
        } else {
            // Inference failed, handle error or skip silently
            if (status != NULL) {
                // Ignore error in fast path, maybe log once
                g_ort->ReleaseStatus(status);
            }
            result[0] = 0.0;
        }

        if (input_tensor) {
            g_ort->ReleaseValue(input_tensor);
        }
    } else {
        // Fallback or disabled
        result[0] = 0.0;
    }
    // ----------------------------------

    static __thread double dynamic_threshold = -1.0;
    if (unlikely(dynamic_threshold < 0.0)) {
        dynamic_threshold = g_initial_nids_threshold;
    }
    static __thread uint64_t window_total = 0;
    static __thread uint64_t window_normal = 0;

    window_total++;
    if (result[0] <= dynamic_threshold) {
        window_normal++;
    }

    if (window_total >= 128) {
        double normal_rate = (double)window_normal / 128.0;
        if (normal_rate > 0.50) {
            dynamic_threshold -= 0.02;
        } 
        else if (normal_rate < 0.45) {
            dynamic_threshold += 0.02;
        }
        
        if (dynamic_threshold < 0.0001) dynamic_threshold = 0.0001;
        if (dynamic_threshold > 0.9999) dynamic_threshold = 0.9999;
        
        window_total = 0;
        window_normal = 0;
    }

    if (result[0] > dynamic_threshold) {
        rte_atomic64_add(&total_anomaly_flows, 1);


        if (anomaly_ring && anomaly_mempool) {
            void *obj = NULL;
            if (rte_mempool_get(anomaly_mempool, &obj) == 0) {
                // To discriminate between IPv4 and IPv6 when dequeued, we always 
                // fill the start with an indicator if needed, but for now we only support IPv4 strictly in anomaly exported structs
                // The size of mempool objects implies copying the structure directly.
                if (is_ipv4) {
                    memcpy(obj, feature_ptr, sizeof(struct IPv4FlowFeature));
                } else {
                    memcpy(obj, feature_ptr, sizeof(struct IPv6FlowFeature));
                }
                if (rte_ring_enqueue(anomaly_ring, obj) != 0) {
                    rte_mempool_put(anomaly_mempool, obj);
                }
            }
        }
        // Do nothing specific for normal flows
    }
}

// 更新IPv4 hash表
int populate_ipv4_hash_table(struct rte_hash *hash_table, struct IPv4PktInfo *pkt, struct IPv4FlowFeature *ipv4_flow_features) {
    int ret = rte_hash_add_key(hash_table, &(pkt->flow));
    if (ret < 0) {
        if (ret == -ENOSPC) {
            fprintf(stderr, "Hash table is full\n");
        }
        fprintf(stderr, "Unable to add key to the hash table\n");
        return ret;
    } else {
        uint64_t current_us = tsc_to_us(pkt->pkt_tsc);
        uint32_t pkt_count = ipv4_flow_features[ret].fwd_pkt_count;
        
        if (pkt_count == 0) {
            // First packet initialization
            memset(&ipv4_flow_features[ret], 0, sizeof(struct IPv4FlowFeature));
            ipv4_flow_features[ret].flow = pkt->flow;
            
            ipv4_flow_features[ret].first_pkt_tsc = current_us;
            ipv4_flow_features[ret].last_pkt_tsc = current_us;
            ipv4_flow_features[ret].prev_pkt_tsc = current_us;
            ipv4_flow_features[ret].last_detect_tsc = current_us;

            ipv4_flow_features[ret].fwd_pkt_count = 1;
            ipv4_flow_features[ret].fwd_payload_tot_len = pkt->payload_len;
            ipv4_flow_features[ret].fwd_header_tot_len = pkt->hdr_len;

            ipv4_flow_features[ret].fwd_pkt_len_max = pkt->payload_len;
            ipv4_flow_features[ret].fwd_pkt_len_min = pkt->payload_len;
            ipv4_flow_features[ret].fwd_pkt_len_sum_sq = (uint64_t)pkt->payload_len * pkt->payload_len;

            ipv4_flow_features[ret].init_win_bytes_fwd = pkt->tcp_window;

            if (pkt->tcp_flags & RTE_TCP_PSH_FLAG) ipv4_flow_features[ret].fwd_psh_flags++;
            if (pkt->tcp_flags & RTE_TCP_URG_FLAG) ipv4_flow_features[ret].fwd_urg_flags++;
            if (pkt->tcp_flags & RTE_TCP_FIN_FLAG) ipv4_flow_features[ret].fin_flag_cnt++;
            if (pkt->tcp_flags & RTE_TCP_SYN_FLAG) ipv4_flow_features[ret].syn_flag_cnt++;
            if (pkt->tcp_flags & RTE_TCP_RST_FLAG) ipv4_flow_features[ret].rst_flag_cnt++;
            if (pkt->tcp_flags & RTE_TCP_ACK_FLAG) ipv4_flow_features[ret].ack_flag_cnt++;

            ipv4_flow_features[ret].pkt_len_min = pkt->raw_pkt_len;
            ipv4_flow_features[ret].pkt_len_max = pkt->raw_pkt_len;
            ipv4_flow_features[ret].pkt_len_sum = pkt->raw_pkt_len;
            ipv4_flow_features[ret].pkt_len_sum_sq = (uint64_t)pkt->raw_pkt_len * pkt->raw_pkt_len;
        } else {
            // Subsequent packets update
            ipv4_flow_features[ret].fwd_pkt_count++;
            ipv4_flow_features[ret].fwd_payload_tot_len += pkt->payload_len;
            ipv4_flow_features[ret].fwd_header_tot_len += pkt->hdr_len;

            if (pkt->payload_len > ipv4_flow_features[ret].fwd_pkt_len_max) ipv4_flow_features[ret].fwd_pkt_len_max = pkt->payload_len;
            if (pkt->payload_len < ipv4_flow_features[ret].fwd_pkt_len_min) ipv4_flow_features[ret].fwd_pkt_len_min = pkt->payload_len;
            ipv4_flow_features[ret].fwd_pkt_len_sum_sq += (uint64_t)pkt->payload_len * pkt->payload_len;

            uint64_t iat = current_us > ipv4_flow_features[ret].prev_pkt_tsc ? current_us - ipv4_flow_features[ret].prev_pkt_tsc : 0;
            if (pkt_count == 1) { // 2nd packet
                ipv4_flow_features[ret].fwd_iat_max = iat;
                ipv4_flow_features[ret].fwd_iat_min = iat;
            } else {
                if (iat > ipv4_flow_features[ret].fwd_iat_max) ipv4_flow_features[ret].fwd_iat_max = iat;
                if (iat < ipv4_flow_features[ret].fwd_iat_min) ipv4_flow_features[ret].fwd_iat_min = iat;
            }
            ipv4_flow_features[ret].fwd_iat_sum_sq += iat * iat;
            ipv4_flow_features[ret].prev_pkt_tsc = current_us;
            ipv4_flow_features[ret].last_pkt_tsc = current_us;

            if (pkt->tcp_flags & RTE_TCP_PSH_FLAG) ipv4_flow_features[ret].fwd_psh_flags++;
            if (pkt->tcp_flags & RTE_TCP_URG_FLAG) ipv4_flow_features[ret].fwd_urg_flags++;
            if (pkt->tcp_flags & RTE_TCP_FIN_FLAG) ipv4_flow_features[ret].fin_flag_cnt++;
            if (pkt->tcp_flags & RTE_TCP_SYN_FLAG) ipv4_flow_features[ret].syn_flag_cnt++;
            if (pkt->tcp_flags & RTE_TCP_RST_FLAG) ipv4_flow_features[ret].rst_flag_cnt++;
            if (pkt->tcp_flags & RTE_TCP_ACK_FLAG) ipv4_flow_features[ret].ack_flag_cnt++;

            if (pkt->raw_pkt_len > ipv4_flow_features[ret].pkt_len_max) ipv4_flow_features[ret].pkt_len_max = pkt->raw_pkt_len;
            if (pkt->raw_pkt_len < ipv4_flow_features[ret].pkt_len_min) ipv4_flow_features[ret].pkt_len_min = pkt->raw_pkt_len;
            ipv4_flow_features[ret].pkt_len_sum += pkt->raw_pkt_len;
            ipv4_flow_features[ret].pkt_len_sum_sq += (uint64_t)pkt->raw_pkt_len * pkt->raw_pkt_len;
        }

        // Multiphasic Triggers
        uint32_t c = ipv4_flow_features[ret].fwd_pkt_count;
        if (c == 1 || c == 10 || c == 50 || c == 100) {
            predict_flow_anomaly(&ipv4_flow_features[ret], 1);
            if (c == 100) ipv4_flow_features[ret].last_detect_tsc = current_us;
        } else if (c > 100) {
            if (current_us > ipv4_flow_features[ret].last_detect_tsc && (current_us - ipv4_flow_features[ret].last_detect_tsc) >= 1000000) {
                predict_flow_anomaly(&ipv4_flow_features[ret], 1);
                ipv4_flow_features[ret].last_detect_tsc = current_us;
            }
        }
    }

    return 0;
}

// 更新IPv6 hash表
int populate_ipv6_hash_table(struct rte_hash *hash_table, struct IPv6PktInfo *pkt, struct IPv6FlowFeature *ipv6_flow_features) {
    int ret = rte_hash_add_key(hash_table, &(pkt->flow));
    if (ret < 0) {
        if (ret == -ENOSPC) {
            fprintf(stderr, "Hash table is full\n");
        }
        fprintf(stderr, "Unable to add key to the hash table\n");
        return ret;
    } else {
        uint64_t current_us = tsc_to_us(pkt->pkt_tsc);
        uint32_t pkt_count = ipv6_flow_features[ret].fwd_pkt_count;
        
        if (pkt_count == 0) {
            // First packet initialization
            memset(&ipv6_flow_features[ret], 0, sizeof(struct IPv6FlowFeature));
            ipv6_flow_features[ret].flow = pkt->flow;
            
            ipv6_flow_features[ret].first_pkt_tsc = current_us;
            ipv6_flow_features[ret].last_pkt_tsc = current_us;
            ipv6_flow_features[ret].prev_pkt_tsc = current_us;
            ipv6_flow_features[ret].last_detect_tsc = current_us;

            ipv6_flow_features[ret].fwd_pkt_count = 1;
            ipv6_flow_features[ret].fwd_payload_tot_len = pkt->payload_len;
            ipv6_flow_features[ret].fwd_header_tot_len = pkt->hdr_len;

            ipv6_flow_features[ret].fwd_pkt_len_max = pkt->payload_len;
            ipv6_flow_features[ret].fwd_pkt_len_min = pkt->payload_len;
            ipv6_flow_features[ret].fwd_pkt_len_sum_sq = (uint64_t)pkt->payload_len * pkt->payload_len;

            ipv6_flow_features[ret].init_win_bytes_fwd = pkt->tcp_window;

            if (pkt->tcp_flags & RTE_TCP_PSH_FLAG) ipv6_flow_features[ret].fwd_psh_flags++;
            if (pkt->tcp_flags & RTE_TCP_URG_FLAG) ipv6_flow_features[ret].fwd_urg_flags++;
            if (pkt->tcp_flags & RTE_TCP_FIN_FLAG) ipv6_flow_features[ret].fin_flag_cnt++;
            if (pkt->tcp_flags & RTE_TCP_SYN_FLAG) ipv6_flow_features[ret].syn_flag_cnt++;
            if (pkt->tcp_flags & RTE_TCP_RST_FLAG) ipv6_flow_features[ret].rst_flag_cnt++;
            if (pkt->tcp_flags & RTE_TCP_ACK_FLAG) ipv6_flow_features[ret].ack_flag_cnt++;

            ipv6_flow_features[ret].pkt_len_min = pkt->raw_pkt_len;
            ipv6_flow_features[ret].pkt_len_max = pkt->raw_pkt_len;
            ipv6_flow_features[ret].pkt_len_sum = pkt->raw_pkt_len;
            ipv6_flow_features[ret].pkt_len_sum_sq = (uint64_t)pkt->raw_pkt_len * pkt->raw_pkt_len;
        } else {
            // Subsequent packets update
            ipv6_flow_features[ret].fwd_pkt_count++;
            ipv6_flow_features[ret].fwd_payload_tot_len += pkt->payload_len;
            ipv6_flow_features[ret].fwd_header_tot_len += pkt->hdr_len;

            if (pkt->payload_len > ipv6_flow_features[ret].fwd_pkt_len_max) ipv6_flow_features[ret].fwd_pkt_len_max = pkt->payload_len;
            if (pkt->payload_len < ipv6_flow_features[ret].fwd_pkt_len_min) ipv6_flow_features[ret].fwd_pkt_len_min = pkt->payload_len;
            ipv6_flow_features[ret].fwd_pkt_len_sum_sq += (uint64_t)pkt->payload_len * pkt->payload_len;

            uint64_t iat = current_us > ipv6_flow_features[ret].prev_pkt_tsc ? current_us - ipv6_flow_features[ret].prev_pkt_tsc : 0;
            if (pkt_count == 1) { // 2nd packet
                ipv6_flow_features[ret].fwd_iat_max = iat;
                ipv6_flow_features[ret].fwd_iat_min = iat;
            } else {
                if (iat > ipv6_flow_features[ret].fwd_iat_max) ipv6_flow_features[ret].fwd_iat_max = iat;
                if (iat < ipv6_flow_features[ret].fwd_iat_min) ipv6_flow_features[ret].fwd_iat_min = iat;
            }
            ipv6_flow_features[ret].fwd_iat_sum_sq += iat * iat;
            ipv6_flow_features[ret].prev_pkt_tsc = current_us;
            ipv6_flow_features[ret].last_pkt_tsc = current_us;

            if (pkt->tcp_flags & RTE_TCP_PSH_FLAG) ipv6_flow_features[ret].fwd_psh_flags++;
            if (pkt->tcp_flags & RTE_TCP_URG_FLAG) ipv6_flow_features[ret].fwd_urg_flags++;
            if (pkt->tcp_flags & RTE_TCP_FIN_FLAG) ipv6_flow_features[ret].fin_flag_cnt++;
            if (pkt->tcp_flags & RTE_TCP_SYN_FLAG) ipv6_flow_features[ret].syn_flag_cnt++;
            if (pkt->tcp_flags & RTE_TCP_RST_FLAG) ipv6_flow_features[ret].rst_flag_cnt++;
            if (pkt->tcp_flags & RTE_TCP_ACK_FLAG) ipv6_flow_features[ret].ack_flag_cnt++;

            if (pkt->raw_pkt_len > ipv6_flow_features[ret].pkt_len_max) ipv6_flow_features[ret].pkt_len_max = pkt->raw_pkt_len;
            if (pkt->raw_pkt_len < ipv6_flow_features[ret].pkt_len_min) ipv6_flow_features[ret].pkt_len_min = pkt->raw_pkt_len;
            ipv6_flow_features[ret].pkt_len_sum += pkt->raw_pkt_len;
            ipv6_flow_features[ret].pkt_len_sum_sq += (uint64_t)pkt->raw_pkt_len * pkt->raw_pkt_len;
        }

        // Multiphasic Triggers
        uint32_t c = ipv6_flow_features[ret].fwd_pkt_count;
        if (c == 1 || c == 10 || c == 50 || c == 100) {
            predict_flow_anomaly(&ipv6_flow_features[ret], 0);
            if (c == 100) ipv6_flow_features[ret].last_detect_tsc = current_us;
        } else if (c > 100) {
            if (current_us > ipv6_flow_features[ret].last_detect_tsc && (current_us - ipv6_flow_features[ret].last_detect_tsc) >= 1000000) {
                predict_flow_anomaly(&ipv6_flow_features[ret], 0);
                ipv6_flow_features[ret].last_detect_tsc = current_us;
            }
        }
    }
    
    return 0;
}

// 将IPv4流特征写入CSV文件
int write_ipv4_flow_features_to_csv(struct IPv4FlowFeature *ipv4_flow_features, uint32_t num_ipv4_flows, FILE *fp) {
    fprintf(fp, "Source IP,Destination IP,Source Port,Destination Port,Protocol,Flow Duration,Total Fwd Packets,Total Length of Fwd Packets,Fwd Header Length,"
                "Fwd Packet Length Max,Fwd Packet Length Min,Fwd Packet Length Mean,Fwd Packet Length Std,"
                "Fwd IAT Total,Fwd IAT Max,Fwd IAT Min,Fwd IAT Mean,Fwd IAT Std,"
                "Min Packet Length,Max Packet Length,Packet Length Mean,Packet Length Std,"
                "Fwd PSH Flags,Fwd URG Flags,FIN Flag Count,SYN Flag Count,RST Flag Count,ACK Flag Count,Init_Win_bytes_forward,"
                "Flow Packets/s,Flow Bytes/s\n");

    for (uint32_t i = 0; i < num_ipv4_flows; i++) {
        uint32_t count = ipv4_flow_features[i].fwd_pkt_count;
        if (count == 0) continue;

        uint64_t flow_duration_us = ipv4_flow_features[i].last_pkt_tsc > ipv4_flow_features[i].first_pkt_tsc ? ipv4_flow_features[i].last_pkt_tsc - ipv4_flow_features[i].first_pkt_tsc : 0;
        
        double mean_payload = (double)ipv4_flow_features[i].fwd_payload_tot_len / count;
        double var_payload = ((double)ipv4_flow_features[i].fwd_pkt_len_sum_sq / count) - (mean_payload * mean_payload);
        double std_payload = var_payload > 0 ? sqrt(var_payload) : 0;

        double mean_packet = (double)ipv4_flow_features[i].pkt_len_sum / count;
        double var_packet = ((double)ipv4_flow_features[i].pkt_len_sum_sq / count) - (mean_packet * mean_packet);
        double std_packet = var_packet > 0 ? sqrt(var_packet) : 0;

        double mean_iat = 0, std_iat = 0;
        uint64_t iat_tot = flow_duration_us;
        if (count > 1) {
            mean_iat = (double)iat_tot / (count - 1);
            double var_iat = ((double)ipv4_flow_features[i].fwd_iat_sum_sq / (count - 1)) - (mean_iat * mean_iat);
            std_iat = var_iat > 0 ? sqrt(var_iat) : 0;
        }

        double duration_sec = (double)flow_duration_us / 1000000.0;
        if (duration_sec < 0.000001) duration_sec = 0.000001; 
        double flow_packets_s = count / duration_sec;
        double flow_bytes_s = ipv4_flow_features[i].fwd_payload_tot_len / duration_sec; 

        fprintf(fp, "%u,%u,%hu,%hu,%hu,%lu,%u,%u,%u,"
                    "%hu,%hu,%.2f,%.2f,"
                    "%lu,%lu,%lu,%.2f,%.2f,"
                    "%hu,%hu,%.2f,%.2f,"
                    "%u,%u,%u,%u,%u,%u,%u,"
                    "%.2f,%.2f\n",
            ipv4_flow_features[i].flow.src_ip, ipv4_flow_features[i].flow.dst_ip,
            ipv4_flow_features[i].flow.src_port, ipv4_flow_features[i].flow.dst_port, ipv4_flow_features[i].flow.proto_id,
            flow_duration_us, count, ipv4_flow_features[i].fwd_payload_tot_len, ipv4_flow_features[i].fwd_header_tot_len,
            ipv4_flow_features[i].fwd_pkt_len_max, ipv4_flow_features[i].fwd_pkt_len_min, mean_payload, std_payload,
            iat_tot, ipv4_flow_features[i].fwd_iat_max, ipv4_flow_features[i].fwd_iat_min, mean_iat, std_iat,
            ipv4_flow_features[i].pkt_len_min, ipv4_flow_features[i].pkt_len_max, mean_packet, std_packet,
            ipv4_flow_features[i].fwd_psh_flags, ipv4_flow_features[i].fwd_urg_flags, ipv4_flow_features[i].fin_flag_cnt,
            ipv4_flow_features[i].syn_flag_cnt, ipv4_flow_features[i].rst_flag_cnt, ipv4_flow_features[i].ack_flag_cnt,
            ipv4_flow_features[i].init_win_bytes_fwd,
            flow_packets_s, flow_bytes_s);

        ipv4_flow_features[i].fwd_pkt_count = 0;
    }
    return 0;
}     

// 将IPv6流特征写入CSV文件
int write_ipv6_flow_features_to_csv(struct IPv6FlowFeature *ipv6_flow_features, uint32_t num_ipv6_flows, FILE *fp) {
    fprintf(fp, "Flow ID,Flow Duration,Total Fwd Packets,Total Length of Fwd Packets,Fwd Header Length,"
                "Fwd Packet Length Max,Fwd Packet Length Min,Fwd Packet Length Mean,Fwd Packet Length Std,"
                "Fwd IAT Total,Fwd IAT Max,Fwd IAT Min,Fwd IAT Mean,Fwd IAT Std,"
                "Min Packet Length,Max Packet Length,Packet Length Mean,Packet Length Std,"
                "Fwd PSH Flags,Fwd URG Flags,FIN Flag Count,SYN Flag Count,RST Flag Count,ACK Flag Count,Init_Win_bytes_forward,"
                "Flow Packets/s,Flow Bytes/s\n");

    char flow_str[DEFAULT_FLOW_STR_LEN];

    for (uint32_t i = 0; i < num_ipv6_flows; i++) {
        uint32_t count = ipv6_flow_features[i].fwd_pkt_count;
        if (count == 0) continue;

        ipv6flow_format(&ipv6_flow_features[i].flow, flow_str);

        uint64_t flow_duration_us = ipv6_flow_features[i].last_pkt_tsc > ipv6_flow_features[i].first_pkt_tsc ? ipv6_flow_features[i].last_pkt_tsc - ipv6_flow_features[i].first_pkt_tsc : 0;
        
        double mean_payload = (double)ipv6_flow_features[i].fwd_payload_tot_len / count;
        double var_payload = ((double)ipv6_flow_features[i].fwd_pkt_len_sum_sq / count) - (mean_payload * mean_payload);
        double std_payload = var_payload > 0 ? sqrt(var_payload) : 0;

        double mean_packet = (double)ipv6_flow_features[i].pkt_len_sum / count;
        double var_packet = ((double)ipv6_flow_features[i].pkt_len_sum_sq / count) - (mean_packet * mean_packet);
        double std_packet = var_packet > 0 ? sqrt(var_packet) : 0;

        double mean_iat = 0, std_iat = 0;
        uint64_t iat_tot = flow_duration_us;
        if (count > 1) {
            mean_iat = (double)iat_tot / (count - 1);
            double var_iat = ((double)ipv6_flow_features[i].fwd_iat_sum_sq / (count - 1)) - (mean_iat * mean_iat);
            std_iat = var_iat > 0 ? sqrt(var_iat) : 0;
        }

        double duration_sec = (double)flow_duration_us / 1000000.0;
        if (duration_sec < 0.000001) duration_sec = 0.000001;
        double flow_packets_s = count / duration_sec;
        double flow_bytes_s = ipv6_flow_features[i].fwd_payload_tot_len / duration_sec;

        fprintf(fp, "%s,%lu,%u,%u,%u,"
                    "%hu,%hu,%.2f,%.2f,"
                    "%lu,%lu,%lu,%.2f,%.2f,"
                    "%hu,%hu,%.2f,%.2f,"
                    "%u,%u,%u,%u,%u,%u,%u,"
                    "%.2f,%.2f\n",
            flow_str, flow_duration_us, count, ipv6_flow_features[i].fwd_payload_tot_len, ipv6_flow_features[i].fwd_header_tot_len,
            ipv6_flow_features[i].fwd_pkt_len_max, ipv6_flow_features[i].fwd_pkt_len_min, mean_payload, std_payload,
            iat_tot, ipv6_flow_features[i].fwd_iat_max, ipv6_flow_features[i].fwd_iat_min, mean_iat, std_iat,
            ipv6_flow_features[i].pkt_len_min, ipv6_flow_features[i].pkt_len_max, mean_packet, std_packet,
            ipv6_flow_features[i].fwd_psh_flags, ipv6_flow_features[i].fwd_urg_flags, ipv6_flow_features[i].fin_flag_cnt,
            ipv6_flow_features[i].syn_flag_cnt, ipv6_flow_features[i].rst_flag_cnt, ipv6_flow_features[i].ack_flag_cnt,
            ipv6_flow_features[i].init_win_bytes_fwd,
            flow_packets_s, flow_bytes_s);

        ipv6_flow_features[i].fwd_pkt_count = 0;
    }
    return 0;
}   


// int add_ipv4_hash_table(const struct rte_hash *hash_table, struct IPv4FlowTuple *flow) {
//     int ret = 0;

//     ret = rte_hash_lookup(hash_table, flow);
//     if (ret < 0) {
//         if (ret == -ENOENT) {
//             ret = rte_hash_add_key_data(hash_table, flow, 1);
//             if (ret < 0) {
//                 rte_exit(EXIT_FAILURE, "Unable to add the entry to the hash table\n");
//                 return ret;
//             } else {
//                 return 0;
//             }
//         } else {
//             rte_exit(EXIT_FAILURE, "Unable to lookup this flow in the table\n");
//             return ret;
//         }
//     } else {
//         printf("ret: %d, %d\n", ret);
//         return 0;
//     }
// }

// int add_ipv6_hash_table(const struct rte_hash *hash_table, struct IPv6FlowTuple *flow) {
//     int ret = 0;

//     ret = rte_hash_lookup(hash_table, flow);
//     if (ret < 0) {
//         if (ret == -ENOENT) {
//             ret = rte_hash_add_key_data(hash_table, flow, 1);
//             if (ret < 0) {
//                 rte_exit(EXIT_FAILURE, "Unable to add the entry to the hash table\n");
//                 return ret;
//             } else {
//                 return 0;
//             }
//         } else {
//             rte_exit(EXIT_FAILURE, "Unable to lookup this flow in the table\n");
//             return ret;
//         }
//     } else {
//         printf("ret: %d\n", ret);
//         return 0;
//     }
// }