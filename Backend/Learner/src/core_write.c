#include <stdbool.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <dirent.h>
#include <pthread.h>

#include <rte_ring.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_branch_prediction.h>
#include <rte_version.h>
#include <rte_malloc.h>

#include "core_write.h"
#include "flow_extractor.h"
#include "mysql_op.h"

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#define RTE_LOGTYPE_DPDKCAP RTE_LOGTYPE_USER1

// static struct IPv4FlowFeature ipv4_flow_features[DEFAULT_NUM_IPV4_FLOWS];
// static struct IPv6FlowFeature ipv6_flow_features[DEFAULT_NUM_IPV6_FLOWS];

/*
 * Change file name from template
 */
void write_upload_flow(struct WriteUploadIpv4Flow *write_upload_ipv4_flow) {
    char csv_file_name[DPDKCAP_OUTPUT_FILENAME_LENGTH] = {0};
    FILE *fp;
    sprintf(csv_file_name, "./csv/output_ipv4_%d_%d.csv", write_upload_ipv4_flow->core_id, write_upload_ipv4_flow->table_id);
    fp = fopen(csv_file_name, "w");
    if (unlikely(!fp)) {
        RTE_LOG(ERR, DPDKCAP, "Core %d could not open %s in write mode: %d (%s)\n",
                rte_lcore_id(), csv_file_name, errno, strerror(errno));
    }
    write_ipv4_flow_features_to_csv(write_upload_ipv4_flow->ipv4_flow_features, DEFAULT_NUM_IPV4_FLOWS, fp);
    fclose(fp);

    char csv_file_abpath[DPDKCAP_OUTPUT_FILENAME_LENGTH] = {0};
    realpath(csv_file_name, csv_file_abpath);

    rte_hash_reset(write_upload_ipv4_flow->ipv4_flow_table);
    memset(write_upload_ipv4_flow->ipv4_flow_features, 0, DEFAULT_NUM_IPV4_FLOWS * sizeof(struct IPv4FlowFeature));

    pthread_exit(NULL);
}


/*
 * Write the packets form the write ring into a pcap compressed file
 */
int write_core(const struct core_write_config *config)
{
    int to_write;
    struct rte_mbuf *dequeued[DPDKCAP_WRITE_BURST_SIZE];
    struct rte_mbuf *bufptr;
    
    // Init stats
    *(config->stats) = (struct core_write_stats){
        .core_id = rte_lcore_id(),
        .current_file_packets = 0,
        .current_file_bytes = 0,
        .current_file_compressed_bytes = 0,
        .packets_written = 0,
        .packets_filtered = 0,
        .bytes = 0,
        .compressed_bytes = 0,
    };
    
    // Log
    RTE_LOG(INFO, DPDKCAP, "Core %d starting in PRE-REDIS BENCHMARK MODE (No PCAP Write).\n", rte_lcore_id());

    struct rte_hash *ipv4_flow_hash_tables[TABLES_NUM];
    struct rte_hash *ipv6_flow_hash_tables[TABLES_NUM];
    char flow_hash_name[32] = {0};
    for (int i = 0; i < TABLES_NUM; i++) {
        sprintf(flow_hash_name, "ipv4_flow_hash_%d_%d", rte_lcore_id(), i);
        ipv4_flow_hash_tables[i] = create_hash_table((const char *)flow_hash_name, DEFAULT_NUM_IPV4_FLOWS, sizeof(struct IPv4FlowTuple), rte_socket_id());
        if (ipv4_flow_hash_tables[i] == NULL) {
            fprintf(stderr, "Unable to create the hash table: %s (rte_errno=%d, %s)\n", flow_hash_name, rte_errno, rte_strerror(rte_errno));
            rte_exit(EXIT_FAILURE, "Unable to create the hash table: %s (rte_errno=%d, %s)\n", flow_hash_name, rte_errno, rte_strerror(rte_errno));
        }
        printf("Hash table %s created, entries: %d, key_len: %lu, socket_id: %d\n", flow_hash_name, DEFAULT_NUM_IPV4_FLOWS, sizeof(struct IPv4FlowTuple), rte_socket_id());

        // sprintf(flow_hash_name, "ipv6_flow_hash_%d_%d", rte_lcore_id(), i);
        // ipv6_flow_hash_tables[i] = create_hash_table((const char *)flow_hash_name, DEFAULT_NUM_IPV6_FLOWS, 36, rte_socket_id());
        // if (ipv6_flow_hash_tables[i] == NULL) {
        //     fprintf(stderr, "Unable to create the hash table: %s (rte_errno=%d, %s)\n", flow_hash_name, rte_errno, rte_strerror(rte_errno));
        //     rte_exit(EXIT_FAILURE, "Unable to create the hash table: %s (rte_errno=%d, %s)\n", flow_hash_name, rte_errno, rte_strerror(rte_errno));
        // }
        // printf("Hash table %s created, entries: %d, key_len: %d, socket_id: %d\n", flow_hash_name, DEFAULT_NUM_IPV6_FLOWS, 36, rte_socket_id());
        ipv6_flow_hash_tables[i] = NULL;

    }
    // struct rte_hash *ipv4_flow_table = create_hash_table("ipv4_flow_table", DEFAULT_NUM_IPV4_FLOWS, sizeof(struct IPv4FlowTuple), rte_lcore_id());
    // struct rte_hash *ipv6_flow_table = create_hash_table("ipv6_flow_table", DEFAULT_NUM_IPV6_FLOWS, sizeof(struct IPv6FlowTuple), rte_lcore_id());

    struct IPv4FlowFeature *ipv4_flow_features[TABLES_NUM];
    struct IPv6FlowFeature *ipv6_flow_features[TABLES_NUM];

    for (int i = 0; i < TABLES_NUM; i++) {
        char mem_name[32];
        
        snprintf(mem_name, sizeof(mem_name), "ipv4_feat_%d_%d", rte_lcore_id(), i);
        ipv4_flow_features[i] = (struct IPv4FlowFeature *)rte_malloc(mem_name, DEFAULT_NUM_IPV4_FLOWS * sizeof(struct IPv4FlowFeature), 0);
        if (ipv4_flow_features[i] == NULL) {
            rte_exit(EXIT_FAILURE, "Unable to allocate memory for IPv4 flow features on core %d (table %d)\n", rte_lcore_id(), i);
        }

        // snprintf(mem_name, sizeof(mem_name), "ipv6_feat_%d_%d", rte_lcore_id(), i);
        // ipv6_flow_features[i] = (struct IPv6FlowFeature *)rte_malloc(mem_name, DEFAULT_NUM_IPV6_FLOWS * sizeof(struct IPv6FlowFeature), 0);
        // if (ipv6_flow_features[i] == NULL) {
        //     rte_exit(EXIT_FAILURE, "Unable to allocate memory for IPv6 flow features on core %d (table %d)\n", rte_lcore_id(), i);
        // }
        ipv6_flow_features[i] = NULL;
    }
// struct IPv6FlowFeature *ipv6_flow_features = (struct IPv6FlowFeature *)rte_malloc("ipv4 flow features", sizeof(struct IPv6FlowFeature) * DEFAULT_NUM_IPV6_FLOWS, 0);

    uint32_t table_id = 0;
    struct WriteUploadIpv4Flow write_upload_ipv4_flow[TABLES_NUM];

    uint32_t ipv4_flows_num = 0;
    uint32_t ipv6_flows_num = 0;

    pthread_t write_upload_ipv4_flow_thread[TABLES_NUM];
    memset(write_upload_ipv4_flow_thread, 0, sizeof(write_upload_ipv4_flow_thread));


    for (;;)
    {
        if (unlikely(*(config->stop_condition) && rte_ring_empty(config->ring)))
        { 
            break;
        }

        // Get packets from the ring
#if RTE_VERSION >= RTE_VERSION_NUM(17, 5, 0, 16)
        to_write = rte_ring_dequeue_burst(config->ring, (void *)dequeued,
                                          DPDKCAP_WRITE_BURST_SIZE, NULL);
#else
        to_write = rte_ring_dequeue_burst(config->ring, (void *)dequeued,
                                          DPDKCAP_WRITE_BURST_SIZE);
#endif


        // Update stats
        //  config->stats->packets += to_write;
        int i;

        // printf("Got %d packets from ring\n", to_write);

        for (i = 0; i < to_write; i++)
        {
            // Cast to packet
            bufptr = dequeued[i];
            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod_offset(bufptr, struct rte_ether_hdr *, 0);

            struct IPv4PktInfo ipv4_pkt;
            memset(&ipv4_pkt.flow, 0, sizeof(ipv4_pkt.flow)); 
            
            struct IPv6PktInfo ipv6_pkt;
            bool is_ipv4 = false;
            bool is_ipv6 = false;
            int ret;
            switch (rte_be_to_cpu_16(eth_hdr->ether_type))
            {
            case RTE_ETHER_TYPE_IPV4:
                is_ipv4 = true;
                ret = parse_ipv4(bufptr, &ipv4_pkt, sizeof(struct rte_ether_hdr));
                if (ret == -1)
                {
                    fprintf(stderr, "Parse ipv4 error\n");
                    RTE_LOG(ERR, DPDKCAP, "Parse ipv4 error\n");
                }
                break;
                break;
            case RTE_ETHER_TYPE_IPV6:
                // is_ipv6 = true;
                // ret = parse_ipv6(bufptr, &ipv6_pkt, sizeof(struct rte_ether_hdr));
                // if (ret == -1)
                // {
                //     fprintf(stderr, "Parse ipv6 error\n");
                //     RTE_LOG(ERR, DPDKCAP, "Parse ipv6 error\n");
                // }
                break;
            case RTE_ETHER_TYPE_VLAN:;
                struct rte_vlan_hdr *vlan_hdr = rte_pktmbuf_mtod_offset(bufptr, struct rte_vlan_hdr *, sizeof(struct rte_ether_hdr));
                switch (rte_be_to_cpu_16(vlan_hdr->eth_proto))
                {
                case RTE_ETHER_TYPE_IPV4:
                    is_ipv4 = true;
                    ret = parse_ipv4(bufptr, &ipv4_pkt, sizeof(struct rte_ether_hdr) + sizeof(struct rte_vlan_hdr));
                    if (ret == -1)
                    {
                        fprintf(stderr, "Parse ipv4 error\n");
                        RTE_LOG(ERR, DPDKCAP, "Parse ipv4 error\n");
                    }
                    break;
                case RTE_ETHER_TYPE_IPV6:
                    is_ipv6 = true;
                    ret = parse_ipv6(bufptr, &ipv6_pkt, sizeof(struct rte_ether_hdr) + sizeof(struct rte_vlan_hdr));
                    if (ret == -1)
                    {
                        fprintf(stderr, "Parse ipv6 error\n");
                        RTE_LOG(ERR, DPDKCAP, "Parse ipv6 error\n");
                    }
                    break;
                default:
                    break;
                }
                break;
            default:
                break;
            }

            // if (is_ipv4 && !is_ipv6) {
            //     ipv4flow_print(&ipv4_flow);
            // } else if (is_ipv6 && !is_ipv4) {
            //     ipv6flow_print(&ipv6_flow);
            // }

            if (is_ipv4 && !is_ipv6)
            {
                // printf("sip: %u, dip: %u, sport: %d, dport: %d, protocol: %d\n", ipv4_pkt.flow.src_ip, ipv4_pkt.flow.dst_ip, ipv4_pkt.flow.src_port, ipv4_pkt.flow.dst_port, ipv4_pkt.flow.proto_id);
                if (config->ip != 0 && config->ip != ipv4_pkt.flow.src_ip && config->ip != ipv4_pkt.flow.dst_ip)
                {
                    rte_pktmbuf_free(dequeued[i]);
                    config->stats->packets_filtered++;
                    continue;
                }
                if (config->ip_upperborder != 0 && (!(ipv4_pkt.flow.src_ip >= config->ip_lowerborder && ipv4_pkt.flow.src_ip <= config->ip_upperborder)) && (!(ipv4_pkt.flow.dst_ip >= config->ip_lowerborder && ipv4_pkt.flow.dst_ip <= config->ip_upperborder)))
                {
                    rte_pktmbuf_free(dequeued[i]);
                    config->stats->packets_filtered++;
                    continue;
                }
                // if (config->protocol != 0 && config->protocol != ipv4_pkt.flow.proto_id)
                // {
                //     rte_pktmbuf_free(dequeued[i]);
                //     config->stats->packets_filtered++;
                //     continue;
                // }
                bool is_proto_in_filter;
                is_proto_in_filter = false;
                for (int i = 0; i < config->num_protocols; i++) 
                {
                    if (ipv4_pkt.flow.proto_id == config->protocols[i]) 
                    {
                        is_proto_in_filter = true;
                        break;
                    }
                }
                if (config->num_protocols > 0 && !is_proto_in_filter)
                {
                    rte_pktmbuf_free(dequeued[i]);
                    config->stats->packets_filtered++;
                    continue;
                }

                bool is_port_in_filter;
                is_port_in_filter = false;
                for (int i = 0; i < config->num_ports; i++) 
                {
                    if (ipv4_pkt.flow.src_port == config->ports[i]) 
                    {
                        is_port_in_filter = true;
                        break;
                    }
                    if (ipv4_pkt.flow.dst_port == config->ports[i]) 
                    {
                        is_port_in_filter = true;
                        break;
                    }
                }
                if (config->num_ports > 0 && !is_port_in_filter)
                {
                    rte_pktmbuf_free(dequeued[i]);
                    config->stats->packets_filtered++;
                    continue;
                }
            }
            else if (is_ipv6 && !is_ipv4)
            {
                if (config->ip != 0 && memcmp(&config->ip, &ipv6_pkt.flow.src_ip, 16) && memcmp(&config->ip, &ipv6_pkt.flow.dst_ip, 16))
                {
                    rte_pktmbuf_free(dequeued[i]);
                    config->stats->packets_filtered++;
                    continue;
                }
                if (config->protocol != 0 && config->protocol != ipv6_pkt.flow.proto_id)
                {
                    rte_pktmbuf_free(dequeued[i]);
                    config->stats->packets_filtered++;
                    continue;
                }
                if (config->port != 0 && config->port != ipv6_pkt.flow.src_port && config->port != ipv6_pkt.flow.dst_port)
                {
                    rte_pktmbuf_free(dequeued[i]);
                    config->stats->packets_filtered++;
                    continue;
                }
            }

            if (is_ipv4 && !is_ipv6) {
                ret = populate_ipv4_hash_table(ipv4_flow_hash_tables[table_id], &ipv4_pkt, ipv4_flow_features[table_id]);
                if (ret < 0) {
                    fprintf(stderr, "populate ipv4 hash table error\n");
                    RTE_LOG(ERR, DPDKCAP, "populate ipv4 hash table error\n");
                }
            } else if (is_ipv6 && !is_ipv4) {
                populate_ipv6_hash_table(ipv6_flow_hash_tables[table_id], &ipv6_pkt, ipv6_flow_features[table_id]);
                if (ret < 0) {
                    fprintf(stderr, "populate ipv6 hash table error\n");
                    RTE_LOG(ERR, DPDKCAP, "populate ipv6 hash table error\n");
                }
            }

            // Free buffer
            rte_pktmbuf_free(dequeued[i]);

            // Update stats
            config->stats->packets_written++;
            config->stats->current_file_packets++;
        }

        uint32_t flow_nums_in_table = rte_hash_count(ipv4_flow_hash_tables[table_id]);
        if (unlikely(flow_nums_in_table > IPV4_FLOWS_LIMIT_IN_TABLE)) {
            ipv4_flows_num += flow_nums_in_table;

            write_upload_ipv4_flow[table_id].core_id = rte_lcore_id();
            write_upload_ipv4_flow[table_id].table_id = table_id;
            write_upload_ipv4_flow[table_id].ipv4_flow_table = ipv4_flow_hash_tables[table_id];
            write_upload_ipv4_flow[table_id].ipv4_flow_features = ipv4_flow_features[table_id];
            write_upload_ipv4_flow[table_id].mysql_conn = config->mysql_conn;

            // write_upload_ipv4_flow = {
            //     .core_id = rte_lcore_id(),
            //     .table_id = table_id,
            //     .ipv4_flow_table = ipv4_flow_hash_tables[table_id],
            //     .ipv4_flow_features = ipv4_flow_features[table_id],
            //     .mysql_conn = config->mysql_conn,
            // };

            if (pthread_create(&write_upload_ipv4_flow_thread[table_id], NULL, (void *)write_upload_flow, &write_upload_ipv4_flow[table_id]) < 0 ) {
                fprintf(stderr, "create write_upload_flow thread error");
                RTE_LOG(ERR, DPDKCAP, "create write_upload_flow thread error");
                rte_exit(EXIT_FAILURE, "create write_upload_flow thread error");
            }

            uint32_t next_table_id = (table_id + 1) % TABLES_NUM;

            if (write_upload_ipv4_flow_thread[next_table_id] != 0) {
                 pthread_join(write_upload_ipv4_flow_thread[next_table_id], NULL);
                 write_upload_ipv4_flow_thread[next_table_id] = 0;
            }

            table_id = next_table_id;
        }

    }

cleanup:
    RTE_LOG(INFO, DPDKCAP, "Closed writing core %d\n", rte_lcore_id());

    for (int i = 0; i < TABLES_NUM; i++) {
        if (write_upload_ipv4_flow_thread[i] == 0) {
            continue;
        }
        int ret = pthread_join(write_upload_ipv4_flow_thread[i], NULL);
        if (ret != 0) {
        } else {
        }
        write_upload_ipv4_flow_thread[i] = 0;
    }

    uint32_t flow_nums_in_table = rte_hash_count(ipv4_flow_hash_tables[table_id]);
    if (likely(flow_nums_in_table > 0)) {
        ipv4_flows_num += flow_nums_in_table;

        char csv_file_name[DPDKCAP_OUTPUT_FILENAME_LENGTH];
        FILE *fp;
        sprintf(csv_file_name, "./csv/output_ipv4_%d_%d.csv", rte_lcore_id(), table_id);
        fp = fopen(csv_file_name, "w");
        if (unlikely(!fp)) {
            RTE_LOG(ERR, DPDKCAP, "Core %d could not open %s in write mode: %d (%s)\n",
                    rte_lcore_id(), csv_file_name, errno, strerror(errno));
        }
        write_ipv4_flow_features_to_csv(ipv4_flow_features[table_id], DEFAULT_NUM_IPV4_FLOWS, fp);
        fclose(fp);
    }

    printf("Core %d finished, ipv4 flows num: %u, ipv6 flows num: %u\n", rte_lcore_id(), ipv4_flows_num, ipv6_flows_num);

    for (int i = 0; i < TABLES_NUM; i++ ) {
        if (ipv4_flow_features[i]) rte_free(ipv4_flow_features[i]);
        // if (ipv6_flow_features[i]) rte_free(ipv6_flow_features[i]);

        if (ipv4_flow_hash_tables[i]) rte_hash_free(ipv4_flow_hash_tables[i]);
        // if (ipv6_flow_hash_tables[i]) rte_hash_free(ipv6_flow_hash_tables[i]);
    }

    return 0;
}
