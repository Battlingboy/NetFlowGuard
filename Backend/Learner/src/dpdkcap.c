#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <argp.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <mysql/mysql.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memcpy.h>
#include <rte_ethdev.h>
#include <rte_errno.h>
#include <rte_string_fns.h>
#include <rte_version.h>

#include "pcap.h"
#include "core_write.h"
#include "core_capture.h"
#include "statistics.h"
#include "mysql_op.h"

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
#if 0
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
    {"send", 703, "Send", 0, "Forward statistics to server.", 0},
    {"rl-delay", 704, "SECONDS", 0, "Delay in seconds before accepting RL Action from SHM. -1 to disable RL scheduling. (default: 5)", 0},
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
    uint16_t ports[MAX_PORTS];
    int num_ports;
    uint8_t protocol;
    uint16_t protocols[MAX_PROTOCOLS];
    int num_protocols;
    uint32_t timeout;
    uint32_t send;
    int rl_delay;   // RL delay seconds
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
        uint16_t ports[MAX_PORTS];
        int num_ports = 0;

        token = strtok_r(arg, ",", &saveptr);
        while (token != NULL) {
            errno = 0;
            char *endptr;
            uint16_t port = strtoul(token, &endptr, 10);

            if (errno || (*endptr != '\0' && *endptr != ',')) {
                break;
            }

            if (port != 0)
                ports[num_ports++] = port;

            token = strtok_r(NULL, ",", &saveptr);
        }
        if (errno || (end != NULL && *end != '\0')) break;
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
        arguments->rl_delay = strtol(arg, &end, 10);
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
#endif
/* END OF ARGP */

#define MAX_CORES 64

char rx_pci[64] = "0000:af:00.0";
char tx_pci[64] = "0000:af:00.1";
int num_cores = 4;
int timeout = 0; // 0 means run forever
int rl_delay = 0; // RL delay seconds, -1 to disable, 0 means take action at tick 0
struct rte_ether_addr target_macs[MAX_CORES];

static uint8_t rss_learner_key[52] = {
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
    0x90, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x1A, 0x2B, 0x3C, 0x4D,
};

static void parse_forward_ini(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        RTE_LOG(WARNING, DPDKCAP, "Cannot open config file %s, using defaults\n", filename);
        return;
    }
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == ';' || line[0] == '\n' || line[0] == '[') continue;
        char key[128], val[128];
        if (sscanf(line, "%127[^=]=%127s", key, val) == 2) {
            if (strcmp(key, "rx_pci") == 0) strcpy(rx_pci, val);
            else if (strcmp(key, "tx_pci") == 0) strcpy(tx_pci, val);
            else if (strcmp(key, "num_cores") == 0) num_cores = atoi(val);
            else if (strcmp(key, "timeout") == 0) timeout = atoi(val);
            else if (strcmp(key, "rl_delay") == 0) rl_delay = atoi(val);
            else if (strncmp(key, "mac_", 4) == 0) {
                int id = atoi(key + 4);
                if (id >= 0 && id < MAX_CORES) {
                    unsigned int bytes[6];
                    if (sscanf(val, "%x:%x:%x:%x:%x:%x", 
                        &bytes[0], &bytes[1], &bytes[2], 
                        &bytes[3], &bytes[4], &bytes[5]) == 6) {
                        for(int addr_idx=0; addr_idx<6; addr_idx++) {
                            target_macs[id].addr_bytes[addr_idx] = bytes[addr_idx];
                        }
                    }
                }
            }
        }
    }
    fclose(f);
}

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .mq_mode = RTE_ETH_MQ_RX_NONE,
    },
    .txmode = {
        .mq_mode = RTE_ETH_MQ_TX_NONE,
        .offloads = 0x10000, /* RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE */
    }
};

static int port_init_rx(uint16_t port, uint16_t rx_rings, struct rte_mempool *mbuf_pool) {
    struct rte_eth_conf port_conf = port_conf_default;
    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(port, &dev_info);
    
    if (rx_rings > 1) {
        port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
        port_conf.rx_adv_conf.rss_conf.rss_key = rss_learner_key;
        port_conf.rx_adv_conf.rss_conf.rss_key_len = 52;
        port_conf.rx_adv_conf.rss_conf.rss_hf = (RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP) & dev_info.flow_type_rss_offloads;
    }
    
    int retval = rte_eth_dev_configure(port, rx_rings, 0, &port_conf);
    if (retval) return retval;
    
    struct rte_eth_rxconf rxconf = dev_info.default_rxconf;
    rxconf.rx_free_thresh = 32;

    for (uint16_t q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, 256, rte_eth_dev_socket_id(port), &rxconf, mbuf_pool);
        if (retval) return retval;
    }
    return rte_eth_promiscuous_enable(port);
}

static int port_init_tx(uint16_t port, uint16_t tx_rings, struct rte_mempool *mbuf_pool) {
    struct rte_eth_conf port_conf = port_conf_default;
    int retval = rte_eth_dev_configure(port, 1, tx_rings, &port_conf);
    if (retval) return retval;
    
    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(port, &dev_info);

    struct rte_eth_rxconf rxconf = dev_info.default_rxconf;
    rxconf.rx_free_thresh = 32;
    retval = rte_eth_rx_queue_setup(port, 0, 256, rte_eth_dev_socket_id(port), &rxconf, mbuf_pool);
    if (retval) return retval;

    struct rte_eth_txconf txconf = dev_info.default_txconf;
    txconf.tx_free_thresh = 32;
    txconf.tx_rs_thresh = 32;
    txconf.offloads = port_conf.txmode.offloads;
    
    for (uint16_t q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, 256, rte_eth_dev_socket_id(port), &txconf);
        if (retval) return retval;
    }

    return rte_eth_promiscuous_enable(port);
}

volatile bool should_stop = false;
static void signal_handler(int sig) {
    RTE_LOG(NOTICE, DPDKCAP, "Caught signal %s\n", strsignal(sig));
    should_stop = true;
}

int main(int argc, char *argv[]) {
    signal(SIGINT, signal_handler);
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    parse_forward_ini("forward.ini");
    
    uint16_t rx_port_id, tx_port_id;
    if (rte_eth_dev_get_port_by_name(rx_pci, &rx_port_id) != 0) {
        rte_exit(EXIT_FAILURE, "Cannot find RX PCI %s\n", rx_pci);
    }
    if (rte_eth_dev_get_port_by_name(tx_pci, &tx_port_id) != 0) {
        rte_exit(EXIT_FAILURE, "Cannot find TX PCI %s\n", tx_pci);
    }
    
    unsigned long scaled_mbufs = NUM_MBUFS_DEFAULT * num_cores * 2;
    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", scaled_mbufs,
                                         MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mbuf_pool) rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
    
    if (port_init_rx(rx_port_id, num_cores, mbuf_pool) != 0) {
        rte_exit(EXIT_FAILURE, "Cannot init RX port\n");
    }
    if (port_init_tx(tx_port_id, num_cores, mbuf_pool) != 0) {
        rte_exit(EXIT_FAILURE, "Cannot init TX port\n");
    }
    
    rte_eth_dev_start(rx_port_id);
    rte_eth_dev_start(tx_port_id);

    struct rte_ether_addr tx_mac;
    rte_eth_macaddr_get(tx_port_id, &tx_mac);

    printf("\n================ Configuration ================\n");
    printf("RX PCI: %s (Port %u)\n", rx_pci, rx_port_id);
    printf("TX PCI: %s (Port %u)\n", tx_pci, tx_port_id);
    printf("Number of Cores: %d\n", num_cores);
    printf("RL Delay: %d seconds (%s)\n", rl_delay, rl_delay < 0 ? "DISABLED" : "ENABLED");
    for (int i = 0; i < num_cores; i++) {
        printf(" Core %d -> Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", i,
            target_macs[i].addr_bytes[0], target_macs[i].addr_bytes[1], target_macs[i].addr_bytes[2],
            target_macs[i].addr_bytes[3], target_macs[i].addr_bytes[4], target_macs[i].addr_bytes[5]);
    }
    printf("===============================================\n");

    struct core_capture_config *configs = calloc(num_cores, sizeof(struct core_capture_config));
    struct core_capture_stats *stats = calloc(num_cores, sizeof(struct core_capture_stats));
    
    unsigned int required_cores = num_cores + 2; // 1 main + N workers + 1 telemetry
    if (rte_lcore_count() < required_cores) {
        rte_exit(EXIT_FAILURE, "Ensure at least %u lcores are provided (-l or -c), currently %u\n", required_cores, rte_lcore_count());
    }
    
    unsigned int core_index = rte_get_next_lcore(-1, 1, 0);
    for (int i = 0; i < num_cores; i++) {
        configs[i].stop_condition = &should_stop;
        configs[i].stats = &stats[i];
        configs[i].rx_port = rx_port_id;
        configs[i].rx_queue = i;
        configs[i].tx_port = tx_port_id;
        configs[i].tx_queue = i;
        configs[i].target_mac = target_macs[i];
        configs[i].tx_mac = tx_mac;
        
        rte_eal_remote_launch((lcore_function_t *)capture_core, &configs[i], core_index);
        core_index = rte_get_next_lcore(core_index, SKIP_MAIN, 0);
    }

    struct telemetry_config tel_config = {
        .stop_condition = &should_stop,
        .rx_port = tx_port_id,
        .rx_queue = 0
    };
    rte_eal_remote_launch((lcore_function_t *)telemetry_core, &tel_config, core_index);

    struct rte_eth_stats port_stats;
    uint64_t prev_packets[MAX_CORES] = {0};
    uint64_t prev_bytes[MAX_CORES] = {0};
    uint64_t prev_tsc = rte_rdtsc();
    uint64_t timer_hz = rte_get_timer_hz();
    uint32_t elapsed_total_sec = 0;
    
    while (!should_stop) {
        rte_delay_ms(1000);
        uint64_t cur_tsc = rte_rdtsc();
        double elapsed_sec = (double)(cur_tsc - prev_tsc) / timer_hz;
        elapsed_total_sec++;
        
        rte_eth_stats_get(tx_port_id, &port_stats);
        for (int i = 0; i < num_cores; i++) {
            uint64_t current_p = stats[i].packets;
            uint64_t current_b = port_stats.q_obytes[i];
            
            uint64_t diff_p = current_p - prev_packets[i];
            uint64_t diff_b = current_b - prev_bytes[i];

            double fwd_pps = (double)diff_p / elapsed_sec;
            double fwd_bps = (double)diff_b * 8 / elapsed_sec;

            printf("[FWD] seq=%u core=%d fwd_pps=%.0f fwd_bps=%.0f tx_success=%lu\n", 
                   elapsed_total_sec, i, fwd_pps, fwd_bps, current_p);

            prev_packets[i] = current_p;
            prev_bytes[i] = current_b;
        }
        
        if (timeout > 0) {
            if (elapsed_total_sec >= timeout) {
                RTE_LOG(NOTICE, DPDKCAP, "Timeout reached. Stopping loops...\n");
                should_stop = true;
            }
        }
        prev_tsc = cur_tsc;

        check_and_apply_rl_action(rx_port_id, num_cores, rl_delay);
    }

    rte_eal_mp_wait_lcore();
    rte_eth_dev_stop(rx_port_id);
    rte_eth_dev_stop(tx_port_id);
    rte_eth_dev_close(rx_port_id);
    rte_eth_dev_close(tx_port_id);
    
    free(configs);
    free(stats);
    return 0;
}
