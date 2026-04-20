#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <argp.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include <mysql/mysql.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memcpy.h>
#include <rte_ethdev.h>
#include <rte_errno.h>
#include <rte_string_fns.h>
#include <rte_version.h>

#include <pthread.h>
#include <math.h>
#include <unistd.h>

#include "pcap.h"
#include "core_write.h"
#include "core_capture.h"
#include "statistics.h"
#include "mysql_op.h"
#include "flow_extractor.h"

#define STR1(x) #x
#define STR(x) STR1(x)

#define RX_DESC_DEFAULT 512

#define NUM_MBUFS_DEFAULT 8192
#define MBUF_CACHE_SIZE 256

#define MAX_LCORES 1000

#define DPDKCAP_OUTPUT_TEMPLATE_TOKEN_FILECOUNT "\%FCOUNT"
#define DPDKCAP_OUTPUT_TEMPLATE_TOKEN_CORE_ID "\%COREID"
#define DPDKCAP_OUTPUT_TEMPLATE_DEFAULT "output_" DPDKCAP_OUTPUT_TEMPLATE_TOKEN_CORE_ID

#define DPDKCAP_OUTPUT_TEMPLATE_LENGTH 2 * DPDKCAP_OUTPUT_FILENAME_LENGTH

#define RTE_LOGTYPE_DPDKCAP RTE_LOGTYPE_USER1

/* ARGP */
char global_output_file_name[DPDKCAP_OUTPUT_FILENAME_LENGTH] = {0};
const char *argp_program_version = "dpdkcap 1.1";
const char *argp_program_bug_address = "w.b.devries@utwente.nl";
static char doc[] = "A DPDK-based packet capture tool";
static char args_doc[] = "";
static struct argp_option options[] = {
    {"output", 'o', "FILE", 0, "Output FILE template (don't add the "
                               "extension). Use \"" DPDKCAP_OUTPUT_TEMPLATE_TOKEN_CORE_ID "\" for "
                               "inserting the lcore id into the file name (automatically added if not "
                               "used). (default: " DPDKCAP_OUTPUT_TEMPLATE_DEFAULT ")",
     0},
    {"statistics", 'S', 0, 0, "Print statistics every few seconds.", 0},
    {"num-mbuf", 'm', "NB_MBUF", 0, "Total number of memory buffer used to "
                                    "store the packets. Optimal values, in terms of memory usage, are powers "
                                    "of 2 minus 1 (2^q-1) (default: " STR(NUM_MBUFS_DEFAULT) ")",
     0},
    {"per_port_c_cores", 'c', "NB_CORES_PER_PORT", 0, "Number of cores per "
                                                      "port used for capture (default: 1)",
     0},
    {"rx_desc", 'd', "RX_DESC_MATRIX", 0, "This option can be used to "
                                          "override the default number of RX descriptors configured for all queues "
                                          "of each port (" STR(RX_DESC_DEFAULT) "). RX_DESC_MATRIX can have "
                                                                                "multiple formats:\n"
                                                                                "- A single positive value, which will simply replace the default "
                                                                                " number of RX descriptors,\n"
                                                                                "- A list of key-values, assigning a configured number of RX "
                                                                                "descriptors to the given port(s). Format: \n"
                                                                                "  <matrix>   := <key>.<nb_rx_desc> { \",\" <key>.<nb_rx_desc> \",\" "
                                                                                "...\n"
                                                                                "  <key>      := { <interval> | <port> }\n"
                                                                                "  <interval> := <lower_port> \"-\" <upper_port>\n"
                                                                                "  Examples: \n"
                                                                                "  512               - all ports have 512 RX desc per queue\n"
                                                                                "  0.256, 1.512      - port 0 has 256 RX desc per queue,\n"
                                                                                "                      port 1 has 512 RX desc per queue\n"
                                                                                "  0-2.256, 3.1024   - ports 0, 1 and 2 have 256 RX desc per "
                                                                                " queue,\n"
                                                                                "                      port 3 has 1024 RX desc per queue.",
     0},
    {"rotate_seconds", 'G', "T", 0, "Create a new set of files every T "
                                    "seconds. Use strftime formats within the output file template to rename "
                                    "each file accordingly.",
     0},
    {"limit_file_size", 'C', "SIZE", 0, "Before writing a packet, check "
                                        "whether the target file excess SIZE bytes. If so, creates a new file. "
                                        "Use \"" DPDKCAP_OUTPUT_TEMPLATE_TOKEN_FILECOUNT "\" within the output "
                                        "file template to index each new file.",
     0},
    {"portmask", 'p', "PORTMASK", 0, "Ethernet ports mask (default: 0x1).", 0},
    {"snaplen", 's', "LENGTH", 0, "Snap the capture to snaplen bytes "
                                  "(default: 65535).",
     0},
    {"logs", 700, "FILE", 0, "Writes the logs into FILE instead of "
                             "stderr.",
     0},
    {"ip", 'I', "IP", 0, "IP address (default: all ips)", 0},
    {"port", 'P', "Port", 0, "Port (default: all ports)", 0},
    {"timeout", 'T', "Timeout", 0, "Timeout in seconds (default: 10)", 10},
    {"compression", 701, 0, 0, "Compress capture files.", 0},
    {"protocol", 702, "Protocol", 0, "Capture only packets of the given protocol. (default: all protocols)", 0},
    {"send", 703, "Send", 0, "定时将统计信息发送给服务器", 0},
    {"larr-delay", 704, "SECONDS", 0, "Delay in seconds before starting LARR load balancing. -1 to disable. (default: 5)", 0},
    {"nids-threshold", 705, "THRESHOLD", 0, "Initial dynamic threshold for NIDS (default: 0.5)", 0},
    {"help", 'h', 0, 0, "Print this help and exit.", 0},
    {0}};

struct arguments
{
    char *args[2];
    char output_file_template[DPDKCAP_OUTPUT_FILENAME_LENGTH];
    uint64_t portmask;
    int statistics;
    unsigned long nb_mbufs;
    char *num_rx_desc_str_matrix;
    unsigned long per_port_c_cores;
    int compression;
    unsigned long snaplen;
    unsigned long rotate_seconds;
    uint64_t file_size_limit;
    char *log_file;
    rte_be32_t ip;
    rte_be32_t ip_lowerborder;
    rte_be32_t ip_upperborder;
    rte_be16_t port;
    uint16_t ports[MAX_PORTS]; // 端口号数组
    int num_ports; // 实际存储的端口号数量
    uint8_t protocol;
    uint16_t protocols[MAX_PROTOCOLS];
    int num_protocols;
    uint32_t timeout; // 程序运行时间，单位是s
    uint32_t send;    // 定时将统计信息发送给服务器
    int larr_delay;   // LARR delay seconds
    double nids_threshold;
};

static int parse_matrix_opt(char *arg, unsigned long *matrix,
                            unsigned long max_len)
{
    char *comma_tokens[100];
    int nb_comma_tokens;
    char *dot_tokens[3];
    int nb_dot_tokens;
    char *dash_tokens[3];
    int nb_dash_tokens;

    char *end;

    unsigned long left_key;
    unsigned long right_key;
    unsigned long value;

    nb_comma_tokens = rte_strsplit(arg, strlen(arg), comma_tokens, 100, ',');
    // Case with a single value
    if (nb_comma_tokens == 1 && strchr(arg, '.') == NULL)
    {
        errno = 0;
        value = strtoul(arg, &end, 10);
        if (errno || *end != '\0')
            return -EINVAL;
        for (unsigned long key = 0; key < max_len; key++)
        {
            matrix[key] = value;
        }
        return 0;
    }

    // Key-value matrix
    if (nb_comma_tokens > 0)
    {
        for (int comma = 0; comma < nb_comma_tokens; comma++)
        {
            // Split between left and right side of the dot
            nb_dot_tokens = rte_strsplit(comma_tokens[comma],
                                         strlen(comma_tokens[comma]), dot_tokens, 3, '.');
            if (nb_dot_tokens != 2)
                return -EINVAL;

            // Handle value
            errno = 0;
            value = strtoul(dot_tokens[1], &end, 10);
            if (errno || *end != '\0')
                return -EINVAL;

            // Handle key
            nb_dash_tokens = rte_strsplit(dot_tokens[0],
                                          strlen(dot_tokens[0]), dash_tokens, 3, '-');
            if (nb_dash_tokens == 1)
            {
                // Single value
                left_key = strtoul(dash_tokens[0], &end, 10);
                if (errno || *end != '\0')
                    return -EINVAL;
                right_key = left_key;
            }
            else if (nb_dash_tokens == 2)
            {
                // Interval value
                left_key = strtoul(dash_tokens[0], &end, 10);
                if (errno || *end != '\0')
                    return -EINVAL;
                right_key = strtoul(dash_tokens[1], &end, 10);
                if (errno || *end != '\0')
                    return -EINVAL;
            }
            else
            {
                return -EINVAL;
            }

            // Fill-in the matrix
            if (right_key < max_len && right_key >= left_key)
            {
                for (unsigned long key = left_key; key <= right_key; key++)
                {
                    matrix[key] = value;
                }
            }
            else
            {
                return -EINVAL;
            }
        }
    }
    else
    {
        return -EINVAL;
    }
    return 0;
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arguments *arguments = state->input;
    char *end;

    struct sockaddr_in sockaddr;
    int ret;

    errno = 0;
    end = NULL;
    switch (key)
    {
    case 'p':
        /* parse hexadecimal string */
        arguments->portmask = strtoul(arg, &end, 16);
        if (arguments->portmask == 0)
        {
            RTE_LOG(ERR, DPDKCAP, "Invalid portmask '%s', no port used\n", arg);
            return -EINVAL;
        }
        break;
    case 'o':
        strncpy(arguments->output_file_template, arg,
                DPDKCAP_OUTPUT_FILENAME_LENGTH);
        break;
    case 'S':
        arguments->statistics = 1;
        break;
    case 'm':
        arguments->nb_mbufs = strtoul(arg, &end, 10);
        break;
    case 'd':
        arguments->num_rx_desc_str_matrix = arg;
        break;
    case 'c':
        arguments->per_port_c_cores = strtoul(arg, &end, 10);
        break;
    case 's':
        arguments->snaplen = strtoul(arg, &end, 10);
        break;
    case 'G':
        arguments->rotate_seconds = strtoul(arg, &end, 10);
        break;
    case 'C':
        arguments->file_size_limit = strtoll(arg, &end, 10);
        break;
    case 'I':
        if (strcmp(arg, "0") == 0)
        {
            arguments->ip = 0;
            break;
        }
        else
        {
            bzero(&sockaddr, sizeof(sockaddr));
            ret = inet_pton(AF_INET, arg, &sockaddr.sin_addr);
            if (ret != 1)
            {
                int len = strlen(arg);
                int slash_count = 0;
                int slash_pos = -1;
                for (int i = 0; i < len; i++)
                {
                    if (arg[i] == '/')
                    {
                        slash_count++;
                        if (slash_count > 1)
                            break;
                        slash_pos = i;
                    }
                }
                if (slash_count == 1)
                {
                    char ip_part[slash_pos + 1];
                    char num_part[len - slash_pos];
                    strncpy(ip_part, arg, slash_pos);
                    ip_part[slash_pos] = '\0';
                    strcpy(num_part, arg + slash_pos + 1);
                    ret = inet_pton(AF_INET, ip_part, &sockaddr.sin_addr);
                    if (ret == 1)
                    {
                        char *endptr;
                        long subnet = strtol(num_part, &endptr, 10);
                        if (subnet < 1 || subnet > 32 || *endptr != '\0')
                        {
                            fprintf(stderr, "inet_pton error: %s is not a valid subnet number\n", num_part);
                            return ARGP_ERR_UNKNOWN;
                        }
                        // arguments->ip = htonl(sockaddr.sin_addr.s_addr);
                        uint32_t mask = (0xFFFFFFFFu << subnet) & 0xFFFFFFFFu;
                        arguments->ip_lowerborder = htonl(sockaddr.sin_addr.s_addr) & mask;
                        arguments->ip_upperborder = htonl(sockaddr.sin_addr.s_addr) | (~mask);
                        printf("Lower Border: %d.%d.%d.%d\n", (arguments->ip_lowerborder >> 24) & 0xFF, (arguments->ip_lowerborder >> 16) & 0xFF, (arguments->ip_lowerborder >> 8) & 0xFF, arguments->ip_lowerborder & 0xFF);
                        printf("Upper Border: %d.%d.%d.%d\n", (arguments->ip_upperborder >> 24) & 0xFF, (arguments->ip_upperborder >> 16) & 0xFF, (arguments->ip_upperborder >> 8) & 0xFF, arguments->ip_upperborder & 0xFF);
                        break;
                    }
                }
                if (ret == 0)
                {
                    fprintf(stderr, "inet_pton error: %s is not a valid ip text\n", arg);
                }
                else if (ret == -1)
                {
                    perror("inet_pton error");
                }
                fprintf(stderr, "inet_pton error: unkown error");
                return ARGP_ERR_UNKNOWN;
            }
            arguments->ip = htonl(sockaddr.sin_addr.s_addr);
            break;
        }
    
    case 'P':
    {
        char *token;
        char *saveptr;
        uint16_t ports[MAX_PORTS]; // 定义一个足够大的数组来存储端口号
        int num_ports = 0; // 记录实际存储的端口号数量
        
        // 使用 strtok_r 函数按逗号分割输入字符串
        token = strtok_r(arg, ",", &saveptr);
        while (token != NULL) {
            // 将分割后的子字符串转换为端口号
            errno = 0; // 清除 errno 的值
            char *endptr;
            uint16_t port = strtoul(token, &endptr, 10);
            
            // 检查是否发生了转换错误
            if (errno || (*endptr != '\0' && *endptr != ',')) {
                break;
            }

            // 存储端口号到数组中
            if (port != 0)
                ports[num_ports++] = port;
            
            // 继续处理下一个子字符串
            token = strtok_r(NULL, ",", &saveptr);
        }
        if (errno || (end != NULL && *end != '\0')) break;
        // 将解析得到的端口号数组存储到 arguments 结构体中
        memcpy(arguments->ports, ports, num_ports * sizeof(uint16_t));
        arguments->num_ports = num_ports;
        break;
    }
    case 'T':
        arguments->timeout = strtoul(arg, &end, 10);
    case 700:
        arguments->log_file = arg;
        break;
    case 701:
        arguments->compression = 1;
        break;
    case 702:
    {
        char *token_pro;
        char *saveptr_pro;
        uint16_t protocols[MAX_PROTOCOLS];
        int num_protocols = 0;
        
        token_pro = strtok_r(arg, ",", &saveptr_pro);
        while (token_pro != NULL) {
            errno = 0;
            char *endptr_pro;
            uint16_t protocol = strtoul(token_pro, &endptr_pro, 10);

            if (errno || (*endptr_pro != '\0' && *endptr_pro != ',')) {
                break;
            }
            if (protocol != 0)
                protocols[num_protocols++] = protocol;

            token_pro = strtok_r(NULL, ",", &saveptr_pro);
        }
        if (errno || (end != NULL && *end != '\0')) break;
        memcpy(arguments->protocols, protocols, num_protocols * sizeof(uint16_t));
        arguments->num_protocols = num_protocols;
        break;
    }
    
    case 703:
        arguments->send = strtoul(arg, &end, 10);
        break;
    case 704:
        arguments->larr_delay = strtol(arg, &end, 10);
        break;
    case 705:
        arguments->nids_threshold = strtod(arg, &end);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    if (errno || (end != NULL && *end != '\0'))
    {
        RTE_LOG(ERR, DPDKCAP, "Invalid value '%s'\n", arg);
        return -EINVAL;
    }
    return 0;
}
static struct argp argp = {options, parse_opt, args_doc, doc, 0, 0, 0};
/* END OF ARGP */

static struct rte_ring *write_rings[MAX_LCORES];

struct arguments arguments;

static unsigned int portlist[64];
static unsigned int nb_ports;

static struct core_write_stats *cores_stats_write_list;
static struct core_capture_stats *cores_stats_capture_list;

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .mq_mode = RTE_ETH_MQ_RX_NONE,
        .max_lro_pkt_size = RTE_ETHER_MAX_LEN,
    }};

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static int port_init(
    uint8_t port,
    const uint16_t rx_rings,
    unsigned int num_rxdesc,
    struct rte_mempool *mbuf_pool)
{

    struct rte_eth_conf port_conf = port_conf_default;
    struct rte_eth_dev_info dev_info;
    int retval;
    uint16_t q;
    uint16_t dev_count;

    /* Check if the port id is valid */
#if RTE_VERSION >= RTE_VERSION_NUM(18, 11, 3, 16)
    dev_count = rte_eth_dev_count_avail() - 1;
#else
    dev_count = rte_eth_dev_count() - 1;
#endif

    if (rte_eth_dev_is_valid_port(port) == 0)
    {
        RTE_LOG(ERR, DPDKCAP, "Port identifier %d out of range (0 to %d) or not"
                              " attached.\n",
                port, dev_count);
        return -EINVAL;
    }

    /* Get the device info */
    rte_eth_dev_info_get(port, &dev_info);

    /* Check if the requested number of queue is valid */
    if (rx_rings > dev_info.max_rx_queues)
    {
        RTE_LOG(ERR, DPDKCAP, "Port %d can only handle up to %d queues (%d "
                              "requested).\n",
                port, dev_info.max_rx_queues, rx_rings);
        return -EINVAL;
    }

    /* Check if the number of requested RX descriptors is valid */
    if (num_rxdesc > dev_info.rx_desc_lim.nb_max ||
        num_rxdesc < dev_info.rx_desc_lim.nb_min ||
        num_rxdesc % dev_info.rx_desc_lim.nb_align != 0)
    {
        RTE_LOG(ERR, DPDKCAP, "Port %d cannot be configured with %d RX "
                              "descriptors per queue (min:%d, max:%d, align:%d)\n",
                port, num_rxdesc, dev_info.rx_desc_lim.nb_min,
                dev_info.rx_desc_lim.nb_max, dev_info.rx_desc_lim.nb_align);
        return -EINVAL;
    }

    /* Configure multiqueue (Activate Receive Side Scaling on UDP/TCP fields) */
    RTE_LOG(INFO, DPDKCAP, "[DEBUG] Configuring Port %d with %d rings...\n", port, rx_rings);
    if (rx_rings > 1)
    {
        /* Orthogonal RSS Key for Actor Machine (Anti-Polarization) */
        static uint8_t rss_actor_key[52] = {
            0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12,
            0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
            0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x00, 0x99,
            0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10,
            0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x90,
            0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08,
            0x4D, 0x3C, 0x2B, 0x1A,
        };

        port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
        port_conf.rx_adv_conf.rss_conf.rss_key = rss_actor_key;
        port_conf.rx_adv_conf.rss_conf.rss_key_len = 52;
        port_conf.rx_adv_conf.rss_conf.rss_hf = (RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP) & dev_info.flow_type_rss_offloads;
        RTE_LOG(INFO, DPDKCAP, "[DEBUG] RSS Enabled with Orthogonal Key. Final RSS HF=0x%lx\n", port_conf.rx_adv_conf.rss_conf.rss_hf);
    } else {
        RTE_LOG(WARNING, DPDKCAP, "[DEBUG] RSS Disabled (Single Queue). rx_rings=%d\n", rx_rings);
    }

    /* Configure the Ethernet device. (1 TX queue for DR-Stack) */
    retval = rte_eth_dev_configure(port, rx_rings, 1, &port_conf);
    if (retval)
    {
        RTE_LOG(ERR, DPDKCAP, "rte_eth_dev_configure(...): %s\n",
                rte_strerror(-retval));
        return retval;
    }

    /* Allocate and set up TX queue 0 for DR-Stack Telemetry. */
    retval = rte_eth_tx_queue_setup(port, 0, 512, rte_eth_dev_socket_id(port), NULL);
    if (retval)
    {
        RTE_LOG(ERR, DPDKCAP, "rte_eth_tx_queue_setup(...): %s\n",
                rte_strerror(-retval));
        return retval;
    }

    /* Allocate and set up RX queues. */
    for (q = 0; q < rx_rings; q++)
    {
        // struct rte_eth_rxconf rx_conf;
        // rx_conf.offloads = 0;
        // rx_conf.rx_seg = NULL;
        // rx_conf.rx_nseg = 0;
        rte_eth_rx_queue_setup(port, q, num_rxdesc,
                               rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval)
        {
            RTE_LOG(ERR, DPDKCAP, "rte_eth_rx_queue_setup(...): %s\n",
                    rte_strerror(-retval));
            return retval;
        }
    }

    /* Stats bindings (if more than one queue) */
    if (dev_info.max_rx_queues > 1)
    {
        for (q = 0; q < rx_rings; q++)
        {
            retval = rte_eth_dev_set_rx_queue_stats_mapping(port, q, q);
            // printf("rx_rings: %d, max_rx_queues: %d, port: %d, queue_id: %d, stat_id: %d\n", rx_rings, dev_info.max_rx_queues, port, q, q);
            if (retval)
            {
                RTE_LOG(WARNING, DPDKCAP, "rte_eth_dev_set_rx_queue_stats_mapping(...):"
                                          " %s\n",
                        rte_strerror(-retval));
                RTE_LOG(WARNING, DPDKCAP, "The queues statistics mapping failed. The "
                                          "displayed queue statistics are thus unreliable.\n");
            }
        }
    }

    /* Enable RX in promiscuous mode for the Ethernet device. */
    retval = rte_eth_promiscuous_enable(port);
    if (retval)
    {
        RTE_LOG(ERR, DPDKCAP, "rte_eth_promiscuous_enable(...): %s\n",
                rte_strerror(-retval));
        return retval;
    }

    /* Display the port MAC address. */
    struct rte_ether_addr addr;
    rte_eth_macaddr_get(port, &addr);
    RTE_LOG(INFO, DPDKCAP, "Port %u: MAC=%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ", RXdesc/queue=%d\n",
            (unsigned)port,
            addr.addr_bytes[0], addr.addr_bytes[1], addr.addr_bytes[2],
            addr.addr_bytes[3], addr.addr_bytes[4], addr.addr_bytes[5],
            num_rxdesc);

    return 0;
}

/*
 * Handles signals
 */
volatile bool should_stop = false;
void signal_handler(int sig)
{
    RTE_LOG(NOTICE, DPDKCAP, "Caught signal %s on core %u%s\n",
            strsignal(sig), rte_lcore_id(),
            rte_get_main_lcore() == rte_lcore_id() ? " (MASTER CORE)" : "");
    should_stop = true;
}

static void *anomaly_writer_thread(void *arg) {
    (void)arg;
    FILE *fp = fopen("csv/anomalies.csv", "w");
    if (!fp) {
        RTE_LOG(ERR, DPDKCAP, "Failed to open csv/anomalies.csv for writing. Ensure 'csv/' directory exists.\n");
        return NULL;
    }
    
    // Print CSV header
    fprintf(fp, "Source IP,Destination IP,Source Port,Destination Port,Protocol,Flow Duration,Total Fwd Packets,Total Length of Fwd Packets,Fwd Header Length,"
                "Fwd Packet Length Max,Fwd Packet Length Min,Fwd Packet Length Mean,Fwd Packet Length Std,"
                "Fwd IAT Total,Fwd IAT Max,Fwd IAT Min,Fwd IAT Mean,Fwd IAT Std,"
                "Min Packet Length,Max Packet Length,Packet Length Mean,Packet Length Std,"
                "Fwd PSH Flags,Fwd URG Flags,FIN Flag Count,SYN Flag Count,RST Flag Count,ACK Flag Count,Init_Win_bytes_forward,"
                "Flow Packets/s,Flow Bytes/s\n");
    fflush(fp);

    void *objs[512];
    uint64_t last_flush_tsc = rte_rdtsc();
    uint64_t flush_interval = 5 * rte_get_timer_hz();
    int buffered_count = 0;

    struct IPv4FlowFeature *buffered_flows_ipv4[512]; 

    while(!should_stop) {
        int n = rte_ring_dequeue_burst(anomaly_ring, objs, 512 - buffered_count, NULL);
        if (n > 0) {
            for(int i=0; i<n; i++) {
                buffered_flows_ipv4[buffered_count++] = (struct IPv4FlowFeature *)objs[i];
            }
        }

        uint64_t now = rte_rdtsc();
        if (buffered_count == 512 || (buffered_count > 0 && (now - last_flush_tsc) > flush_interval)) {
            for(int i=0; i<buffered_count; i++) {
                struct IPv4FlowFeature *f = buffered_flows_ipv4[i];
                uint32_t count = f->fwd_pkt_count;
                if (count == 0) continue;

                uint64_t flow_duration_us = f->last_pkt_tsc > f->first_pkt_tsc ? f->last_pkt_tsc - f->first_pkt_tsc : 0;
                uint64_t hz = rte_get_timer_hz();
                flow_duration_us = hz > 0 ? (flow_duration_us / hz) * 1000000 + ((flow_duration_us % hz) * 1000000) / hz : flow_duration_us;
                
                double mean_payload = (double)f->fwd_payload_tot_len / count;
                double var_payload = ((double)f->fwd_pkt_len_sum_sq / count) - (mean_payload * mean_payload);
                double std_payload = var_payload > 0 ? sqrt(var_payload) : 0;

                double mean_packet = (double)f->pkt_len_sum / count;
                double var_packet = ((double)f->pkt_len_sum_sq / count) - (mean_packet * mean_packet);
                double std_packet = var_packet > 0 ? sqrt(var_packet) : 0;

                double mean_iat = 0, std_iat = 0;
                uint64_t iat_tot = flow_duration_us;
                if (count > 1) {
                    mean_iat = (double)iat_tot / (count - 1);
                    double var_iat = ((double)f->fwd_iat_sum_sq / (count - 1)) - (mean_iat * mean_iat);
                    std_iat = var_iat > 0 ? sqrt(var_iat) : 0;
                }

                double duration_sec = (double)flow_duration_us / 1000000.0;
                if (duration_sec < 0.000001) duration_sec = 0.000001; 
                double flow_packets_s = count / duration_sec;
                double flow_bytes_s = f->fwd_payload_tot_len / duration_sec; 

                fprintf(fp, "%u,%u,%hu,%hu,%hu,%lu,%u,%u,%u,"
                            "%hu,%hu,%.2f,%.2f,"
                            "%lu,%lu,%lu,%.2f,%.2f,"
                            "%hu,%hu,%.2f,%.2f,"
                            "%u,%u,%u,%u,%u,%u,%u,"
                            "%.2f,%.2f\n",
                    f->flow.src_ip, f->flow.dst_ip,
                    f->flow.src_port, f->flow.dst_port, f->flow.proto_id,
                    flow_duration_us, count, f->fwd_payload_tot_len, f->fwd_header_tot_len,
                    f->fwd_pkt_len_max, f->fwd_pkt_len_min, mean_payload, std_payload,
                    iat_tot, f->fwd_iat_max, f->fwd_iat_min, mean_iat, std_iat,
                    f->pkt_len_min, f->pkt_len_max, mean_packet, std_packet,
                    f->fwd_psh_flags, f->fwd_urg_flags, f->fin_flag_cnt,
                    f->syn_flag_cnt, f->rst_flag_cnt, f->ack_flag_cnt,
                    f->init_win_bytes_fwd,
                    flow_packets_s, flow_bytes_s);
                
                rte_mempool_put(anomaly_mempool, f);
            }
            fflush(fp);
            buffered_count = 0;
            last_flush_tsc = now;
        } else if (n == 0) {
            usleep(1000); 
        }
    }
    
    for(int i=0; i<buffered_count; i++) {
        rte_mempool_put(anomaly_mempool, buffered_flows_ipv4[i]);
    }
    if (fp) fclose(fp);
    return NULL;
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */

char g_inference_mode[16] = "cpu";
struct rte_ether_addr g_learner_mac;
int g_learner_mac_set = 0;

static void load_forward_ini(void) {
    FILE *f = fopen("forward.ini", "r");
    if (f) {
        char line_buf[128];
        while (fgets(line_buf, sizeof(line_buf), f) != NULL) {
            line_buf[strcspn(line_buf, "\r\n")] = 0;
            if (strncmp(line_buf, "dst_mac=", 8) == 0) {
                char *mac_str = line_buf + 8;
                if (rte_ether_unformat_addr(mac_str, &g_learner_mac) == 0) {
                    RTE_LOG(INFO, DPDKCAP, "Learner MAC loaded from forward.ini: %s\n", mac_str);
                    g_learner_mac_set = 1;
                }
            } else if (strncmp(line_buf, "inference_mode=", 15) == 0) {
                char *mode_str = line_buf + 15;
                strncpy(g_inference_mode, mode_str, sizeof(g_inference_mode)-1);
                RTE_LOG(INFO, DPDKCAP, "Inference Mode loaded from forward.ini: %s\n", g_inference_mode);
            }
        }
        fclose(f);
    } else {
        RTE_LOG(WARNING, DPDKCAP, "forward.ini not found, using default CPU inference mode.\n");
    }
}

struct rte_mempool *mbuf_pool;

int main(int argc, char *argv[])
{
    signal(SIGINT, signal_handler);
    struct core_capture_config *cores_config_capture_list;
    struct core_write_config *cores_config_write_list;
    unsigned int lcoreid_list[MAX_LCORES];
    unsigned int nb_lcores;
    unsigned int port_id;
    unsigned int i, j;
    unsigned int required_cores;
    unsigned int core_index;
    int result;
    uint16_t dev_count;
    FILE *log_file;
    struct rte_flow_error error;

    /* Initialize the Environment Abstraction Layer (EAL). */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= ret;
    argv += ret;

    /* Parse arguments */
    arguments = (struct arguments){
        .statistics = 0,
        .nb_mbufs = NUM_MBUFS_DEFAULT,
        .num_rx_desc_str_matrix = NULL,
        .compression = 0,
        .snaplen = PCAP_SNAPLEN_DEFAULT,
        .portmask = 0x1,
        .rotate_seconds = 0,
        .file_size_limit = 0,
        .log_file = NULL,
        .ip = 0,
        .ip_upperborder = 0,
        .ip_lowerborder = 0,
        .port = 0,
        .num_ports = 0,
        .num_protocols = 0,
        .protocol = 0,
        .timeout = 10,
        .send = 0,
        .larr_delay = 5,
        .nids_threshold = 0.5,
    };
    strncpy(arguments.output_file_template, DPDKCAP_OUTPUT_TEMPLATE_DEFAULT, DPDKCAP_OUTPUT_FILENAME_LENGTH);
    argp_parse(&argp, argc, argv, 0, 0, &arguments);
    
    g_initial_nids_threshold = arguments.nids_threshold;

    load_forward_ini();

    printf("IP: %u, port: %d, protocol: %d, timeout: %d\n", arguments.ip, arguments.port, arguments.protocol, arguments.timeout);

    /* Set log level */
#if RTE_VERSION >= RTE_VERSION_NUM(17, 5, 0, 16)
    rte_log_set_level(RTE_LOG_DEBUG, RTE_LOG_DEBUG);
#else
    rte_set_log_type(RTE_LOGTYPE_DPDKCAP, 1);
    rte_set_log_level(RTE_LOG_DEBUG);
#endif

    /* Change log stream if needed */
    if (arguments.log_file)
    {
        log_file = fopen(arguments.log_file, "w");
        if (!log_file)
        {
            rte_exit(EXIT_FAILURE, "Error: Could not open log file: (%d) %s\n",
                     errno, strerror(errno));
        }
        result = rte_openlog_stream(log_file);
        if (result)
        {
            rte_exit(EXIT_FAILURE, "Error: Could not change log stream: (%d) %s\n",
                     errno, strerror(errno));
        }
    }

    // 如果二者相等，说明没有指定-o参数
    if (strcmp(arguments.output_file_template, DPDKCAP_OUTPUT_TEMPLATE_DEFAULT) == 0)
    {
        // 以当前时间作为文件名前缀
        time_t now;
        struct tm *lt;
        time(&now);
        lt = gmtime(&now);
        // sprintf(arguments.output_file_template, "/home/Pcaps/output-%d%02d%02d-%02d%02d%02d", 1900 + lt->tm_year, 1 + lt->tm_mon, lt->tm_mday, 8 + lt->tm_hour, lt->tm_min, lt->tm_sec);
        sprintf(arguments.output_file_template, "./pcaps/output-%d%02d%02d-%02d%02d%02d", 1900 + lt->tm_year, 1 + lt->tm_mon, lt->tm_mday, 8 + lt->tm_hour, lt->tm_min, lt->tm_sec);
        sprintf(global_output_file_name, "./pcaps/output-%d%02d%02d-%02d%02d%02d", 1900 + lt->tm_year, 1 + lt->tm_mon, lt->tm_mday, 8 + lt->tm_hour, lt->tm_min, lt->tm_sec);
    }
    /* Add suffixes to output if needed */
    if (!strstr(arguments.output_file_template, DPDKCAP_OUTPUT_TEMPLATE_TOKEN_CORE_ID))
        strcat(arguments.output_file_template, "_" DPDKCAP_OUTPUT_TEMPLATE_TOKEN_CORE_ID);
    if (arguments.file_size_limit && !strstr(arguments.output_file_template, DPDKCAP_OUTPUT_TEMPLATE_TOKEN_FILECOUNT))
        strcat(arguments.output_file_template, "_" DPDKCAP_OUTPUT_TEMPLATE_TOKEN_FILECOUNT);

    strcat(arguments.output_file_template, ".pcap");

    if (arguments.compression)
        strcat(arguments.output_file_template, ".lzo");

        /* Check if at least one port is available */
#if RTE_VERSION >= RTE_VERSION_NUM(18, 11, 3, 16)
    dev_count = rte_eth_dev_count_avail();
#else
    dev_count = rte_eth_dev_count();
#endif

    if (dev_count == 0)
        rte_exit(EXIT_FAILURE, "Error: No port available.\n");

    /* Fills in the number of rx descriptors matrix */
    unsigned long *num_rx_desc_matrix = calloc(dev_count, sizeof(int));
    if (arguments.num_rx_desc_str_matrix != NULL &&
        parse_matrix_opt(arguments.num_rx_desc_str_matrix,
                         num_rx_desc_matrix, dev_count) < 0)
    {
        rte_exit(EXIT_FAILURE, "Invalid RX descriptors matrix.\n");
    }

    /* Creates the port list */
    nb_ports = 0;
    for (i = 0; i < 64; i++)
    {
        if (!((uint64_t)(1ULL << i) & arguments.portmask))
            continue;
        if (i < dev_count)
            portlist[nb_ports++] = i;
        else
            RTE_LOG(WARNING, DPDKCAP, "Warning: port %d is in portmask, "
                                      "but not enough ports are available. Ignoring...\n",
                    i);
    }
    if (nb_ports == 0)
        rte_exit(EXIT_FAILURE, "Error: Found no usable port. Check portmask "
                               "option.\n");

    RTE_LOG(INFO, DPDKCAP, "Using %u ports to listen on\n", nb_ports);

    /* Checks core number */
    required_cores = (1 + nb_ports * arguments.per_port_c_cores * 2);
    if (rte_lcore_count() < required_cores)
    {
        rte_exit(EXIT_FAILURE, "Assign at least %d cores to dpdkcap.\n",
                 required_cores);
    }
    RTE_LOG(INFO, DPDKCAP, "Using %u cores out of %d allocated\n",
            required_cores, rte_lcore_count());

    /* Creates a new mempool in memory to hold the mbufs. */
    // Scale mbufs based on number of pipelines to prevent starvation
    unsigned int num_pipelines = arguments.per_port_c_cores * nb_ports;
    // Ensure we have at least defaults, plus extra for each additional pipeline. 
    // Default 8192 is good for 1 pair. For N pairs, we want N * 8192 approx.
    unsigned long scaled_mbufs = arguments.nb_mbufs * num_pipelines;
    
    // Check for overflow or crazy values (optional but good practice)
    if (scaled_mbufs > 0x10000000) scaled_mbufs = 0x10000000; 

    RTE_LOG(INFO, DPDKCAP, "Allocating %lu mbufs for %u pipelines\n", scaled_mbufs, num_pipelines);

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", scaled_mbufs,
                                        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    /* Initialize Anomaly Export Ring Buffer and Mempool */
    anomaly_mempool = rte_mempool_create("anomaly_mempool", 65535,
                                         sizeof(struct IPv4FlowFeature), 256, 0, NULL, NULL, NULL, NULL, rte_socket_id(), 0);
    if (!anomaly_mempool)
        rte_exit(EXIT_FAILURE, "Cannot create anomaly mbuf pool\n");
        
    anomaly_ring = rte_ring_create("anomaly_ring", 131072, rte_socket_id(), 0);
    if (!anomaly_ring)
        rte_exit(EXIT_FAILURE, "Cannot create anomaly ring\n");

    pthread_t anomaly_thread;
    if (pthread_create(&anomaly_thread, NULL, anomaly_writer_thread, NULL) != 0) {
        rte_exit(EXIT_FAILURE, "Cannot create anomaly writer thread\n");
    }

    // Initialize buffer for writing to disk
    // write_ring = rte_ring_create("Ring for writing",
    //                              rte_align32pow2(arguments.nb_mbufs), rte_socket_id(), 0);

    /* Core index */
    core_index = rte_get_next_lcore(-1, 1, 0);

    /* Init stats list */
    cores_stats_write_list =
        malloc(sizeof(struct core_write_stats) * arguments.per_port_c_cores * nb_ports);
    cores_stats_capture_list =
        malloc(sizeof(struct core_capture_stats) * arguments.per_port_c_cores * nb_ports);

    /* Init config lists */
    cores_config_write_list =
        malloc(sizeof(struct core_write_config) * arguments.per_port_c_cores * nb_ports);
    cores_config_capture_list =
        malloc(sizeof(struct core_capture_config) * arguments.per_port_c_cores * nb_ports);

    nb_lcores = 0;

    /* 初始化数据库 */
    MYSQL mysql_conn;

    // Enable LOCAL INFILE support for the client
    mysql_init(&mysql_conn);
    unsigned int local_infile = 1;
    mysql_options(&mysql_conn, MYSQL_OPT_LOCAL_INFILE, &local_infile);

    // Pass the initialized handle to collect_mysql (refactor collect_mysql to accept pre-init or specific options?)
    // Actually collect_mysql calls mysql_init again which overwrites options. 
    // We should modify collect_mysql in mysql_op.c properly. 
    // But since I cannot change the signature easily in one go, I will modify collect_mysql logic. 
    // Wait, collect_mysql takes `MYSQL *mysql_conn`. If I init it here, collect_mysql calling mysql_init might reset it.
    // Let's rely on modifying `mysql_op.c` to handle the connection setup details, including options.
    // So I will just leave the call here as is, and fix it in mysql_op.c.
    
    if (collect_mysql(&mysql_conn, MYSQL_HOST, MYSQL_USER, MYSQL_PASS, MYSQL_DB) != 0)
    { // 连接数据库
        return -1;
    }

    if (create_table(&mysql_conn, MYSQL_TABLE_NAME) != 0)
    {
        return -1;
    }

    // Initialize ONNX Runtime
    if (init_onnx_model("src/model/model.onnx") < 0) {
        rte_exit(EXIT_FAILURE, "Failed to initialize ONNX Runtime for CPU inference.\n");
    }


    /* Set up write and capture cores */
    /* For each port */
    RTE_LOG(INFO, DPDKCAP, "[DEBUG] Starting Port Initialization Loop...\n");
    for (i = 0; i < nb_ports; i++)
    {
        port_id = portlist[i];

        /* Port init */
        int retval = port_init(
            port_id,
            arguments.per_port_c_cores,
            (num_rx_desc_matrix[i] != 0) ? num_rx_desc_matrix[i] : RX_DESC_DEFAULT,
            mbuf_pool);
        if (retval)
        {
            rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu8 "\n", port_id);
        }

        /* Start the port once everything is ready to capture */
        retval = rte_eth_dev_start(port_id);
        if (retval)
        {
            rte_exit(EXIT_FAILURE, "Cannot start port %" PRIu8 "\n", port_id);
        }

        /* Capturing cores */
        for (j = 0; j < arguments.per_port_c_cores; j++)
        {
            // Configure capture core
            /* 
             * 1:1 Sharding Implementation 
             * Create a dedicated ring for this capture-write pair (CPU) or use MPSC (GPU)
             */
            struct rte_ring *pair_ring = NULL;

            // SPSC Ring for CPU Inference
            char ring_name[32];
            snprintf(ring_name, sizeof(ring_name), "write_ring_%d_%d", i, j);
            pair_ring = rte_ring_create(ring_name,
                                         rte_align32pow2(arguments.nb_mbufs), rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
            
            if (pair_ring == NULL) {
                 rte_exit(EXIT_FAILURE, "Cannot create ring %s\n", ring_name);
            }
            // write_rings[global_index] = pair_ring; 

            // ============================================
            // 1. Launch Write Core (Consumer)
            // ============================================
            struct core_write_config *w_config = &(cores_config_write_list[i * arguments.per_port_c_cores + j]);
            w_config->ring = pair_ring; // Dedicated Ring
            w_config->stop_condition = &should_stop;
            w_config->stats = &(cores_stats_write_list[i * arguments.per_port_c_cores + j]);
            w_config->output_file_template = arguments.output_file_template;
            w_config->compression = arguments.compression;
            w_config->snaplen = arguments.snaplen;
            w_config->rotate_seconds = arguments.rotate_seconds;
            w_config->file_size_limit = arguments.file_size_limit;
            w_config->ip = arguments.ip;
            w_config->ip_upperborder = arguments.ip_upperborder;
            w_config->ip_lowerborder = arguments.ip_lowerborder;
            w_config->port = arguments.port; // Note: Global filter port, not necessary the captured port
            memcpy(w_config->ports, arguments.ports, arguments.num_ports * sizeof(uint16_t));
            w_config->num_ports = arguments.num_ports;
            w_config->protocol = arguments.protocol;
            memcpy(w_config->protocols, arguments.protocols, arguments.num_protocols * sizeof(uint16_t));
            w_config->num_protocols = arguments.num_protocols;
            w_config->mysql_conn = &mysql_conn;

            if (rte_eal_remote_launch((lcore_function_t *)write_core, w_config, core_index) < 0) {
                rte_exit(EXIT_FAILURE, "Could not launch writing process on lcore %d.\n", core_index);
            }
            lcoreid_list[nb_lcores++] = core_index;
            core_index = rte_get_next_lcore(core_index, SKIP_MAIN, 0);


            // ============================================
            // 2. Launch Capture Core (Producer)
            // ============================================
            struct core_capture_config *c_config =
                &(cores_config_capture_list[i * arguments.per_port_c_cores + j]);
            c_config->ring = pair_ring; // Same Dedicated Ring
            c_config->stop_condition = &should_stop;
            c_config->stats =
                &(cores_stats_capture_list[i * arguments.per_port_c_cores + j]);
            c_config->port = port_id;
            c_config->queue = j;

            if (rte_eal_remote_launch((lcore_function_t *)capture_core,
                                      c_config, core_index) < 0)
                rte_exit(EXIT_FAILURE, "Could not launch capture process on lcore %d.\n", core_index);

            lcoreid_list[nb_lcores++] = core_index;
            core_index = rte_get_next_lcore(core_index, SKIP_MAIN, 0);
        }

        // /* Start the port once everything is ready to capture */
        // retval = rte_eth_dev_start(port_id);
        // if (retval) {
        //   rte_exit(EXIT_FAILURE, "Cannot start port %"PRIu8 "\n", port_id);
        // }
    }

    // Initialize statistics timer
    // TODO: Update stats display to support 1:1 mapping if needed. 
    // For now, we reuse the existing structures but note that cores_stats_write_list size changed.
    struct stats_data sd = {
        .ring = NULL, // Global ring is no longer valid for stats
        .cores_stats_write_list = cores_stats_write_list,
        .cores_write_stats_list_size = arguments.per_port_c_cores * nb_ports,
        .cores_stats_capture_list = cores_stats_capture_list,
        .cores_capture_stats_list_size = arguments.per_port_c_cores * nb_ports,
        .port_list = portlist,
        .port_list_size = nb_ports,
        .queue_per_port = arguments.per_port_c_cores,
        .queue_per_port = arguments.per_port_c_cores,
        .log_file = arguments.log_file,
        .larr_delay = arguments.larr_delay,
    };

    if (!should_stop)
    {
        RTE_LOG(INFO, DPDKCAP, "[DEBUG] Initialization complete. Entering main loop.\n");
        if (arguments.statistics && arguments.send == 0)
        {
            signal(SIGINT, SIG_DFL);
            start_stats_display(&sd, arguments.timeout);
            should_stop = true;
        }
        else if (!arguments.statistics && arguments.send != 0)
        {
            signal(SIGINT, SIG_DFL);
            start_stats_send(&sd, arguments.timeout, arguments.send);
            should_stop = true;
        }
        else if (!arguments.statistics && arguments.send == 0)
        {
            signal(SIGINT, SIG_DFL);
            stop_capture_until(&sd, arguments.timeout);
            should_stop = true;
        }
        else
        {
            rte_exit(EXIT_FAILURE, "Invalid combination of arguments.\n");
        }
    }

    // if (arguments.statistics && !should_stop) {
    //   signal(SIGINT, SIG_DFL);
    //   start_stats_display(&sd, arguments.timeout);
    //   should_stop=true;
    // } else if (!arguments.statistics && !should_stop) {
    //   signal(SIGINT, SIG_DFL);
    //   stop_capture_until(&sd, arguments.timeout);
    //   should_stop=true;
    // }

    // Wait for all the cores to complete and exit
    //  RTE_LOG(NOTICE, DPDKCAP, "Waiting for all cores to exit\n");
    //  for(i=0;i<nb_lcores;i++) {
    //    result = rte_eal_wait_lcore(lcoreid_list[i]);
    //    if (result < 0) {
    //      RTE_LOG(ERR, DPDKCAP, "Core %d did not stop correctly.\n",
    //          lcoreid_list[i]);
    //    }
    //  }

    rte_eal_mp_wait_lcore();

    for (int i = 0; i < nb_ports; i++)
    {
        rte_flow_flush(portlist[i], &error);
        ret = rte_eth_dev_stop(portlist[i]);
        if (ret < 0)
        {
            printf("Failed to stop port %u: %s", port_id, rte_strerror(-ret));
        }
        rte_eth_dev_close(portlist[i]);
    }

    if (arguments.send == 0)
    {
        final_stas_display(&sd);
    }
    else
    {
        final_stas_dispaly_and_send(&sd);
    }

    // Finalize
    free(cores_stats_write_list);
    free(cores_stats_capture_list);
    free(cores_config_write_list);
    free(cores_config_capture_list);
    free(num_rx_desc_matrix);

    mysql_close(&mysql_conn); // 关闭连接
    mysql_library_end();      // 关闭MySQL库

    rte_eal_cleanup();

    return 0;
}
