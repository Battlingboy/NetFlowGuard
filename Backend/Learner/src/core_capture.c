#include <stdbool.h>
#include "core_capture.h"
#include <rte_log.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

/* Global RSS Bucket Stats storage */

#define RTE_LOGTYPE_DPDKCAP RTE_LOGTYPE_USER1

/*
 * Capture the traffic from the given port/queue tuple
 */
/* Global definitions */
uint32_t g_bucket_pps[RTE_MAX_LCORE][512] = {0};

/*
 * Capture the traffic from the given port/queue tuple
 */
int capture_core(const struct core_capture_config *config)
{
    struct rte_mbuf *bufs[DPDKCAP_CAPTURE_BURST_SIZE];
    uint16_t nb_rx;
    int i;

    uint64_t total_rx_pkts = 0;

    RTE_LOG(INFO, DPDKCAP, "Core %u is forwarding packets rx_port=%u, rx_queue=%u -> tx_port=%u, tx_queue=%u\n",
            rte_lcore_id(), config->rx_port, config->rx_queue, config->tx_port, config->tx_queue);

    /* Init stats */
    *(config->stats) = (struct core_capture_stats){
        .core_id = rte_lcore_id(),
        .packets = 0,
        .missed_packets = 0,
    };

    /* Run until the application is quit or killed. */
    for (;;)
    {
        /* Stop condition */
        if (unlikely(*(config->stop_condition)))
        {
            break;
        }

        /* Retrieve packets and put them into the ring */
        nb_rx = rte_eth_rx_burst(config->rx_port, config->rx_queue, bufs, DPDKCAP_CAPTURE_BURST_SIZE);

        uint16_t lcore_id = rte_lcore_id();
        for (i = 0; i < nb_rx; i++) {
            struct rte_mbuf *m = bufs[i];

            uint32_t hash = m->hash.rss;
            uint16_t bucket_id = hash & 0x01FF;
            g_bucket_pps[lcore_id][bucket_id]++;

            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

            rte_ether_addr_copy(&config->target_mac, &eth_hdr->dst_addr);
        }

        total_rx_pkts += nb_rx;

        /* Transmit packets directly out of tx_port */
        if (likely(nb_rx > 0)) {
            uint16_t nb_tx = rte_eth_tx_burst(config->tx_port, config->tx_queue, bufs, nb_rx);
            if (nb_tx == nb_rx) {
                config->stats->packets += nb_tx;
            } else {
                config->stats->missed_packets += (nb_rx - nb_tx);
                for (i = nb_tx; i < nb_rx; i++) {
                    rte_pktmbuf_free(bufs[i]);
                }
            }
        }
        else
        {
            // Flash TX buffer if rx traffic is paused preventing packet hang in hardware queue
            rte_eth_tx_burst(config->tx_port, config->tx_queue, NULL, 0);
        }
    }

    RTE_LOG(INFO, DPDKCAP, "Closed forwarding core %d\n",
            rte_lcore_id());

    return 0;
}

int telemetry_core(void *arg) {
    struct telemetry_config *config = (struct telemetry_config *)arg;
    struct rte_mbuf *bufs[DPDKCAP_CAPTURE_BURST_SIZE];
    uint16_t nb_rx;
    int i;

    RTE_LOG(INFO, DPDKCAP, "Telemetry Core %u is listening on rx_port=%u (tx_pci), rx_queue=%u\n",
            rte_lcore_id(), config->rx_port, config->rx_queue);

    // Initialize POSIX SHM (C to Python)
    int shm_fd = shm_open(DRL_STATE_SHM_NAME, O_CREAT | O_RDWR, 0666);
    if (shm_fd < 0) {
        RTE_LOG(ERR, DPDKCAP, "Failed to create SHM: %s\n", DRL_STATE_SHM_NAME);
        return -1;
    }
    if (ftruncate(shm_fd, sizeof(struct drl_state_shm)) == -1) {
        RTE_LOG(ERR, DPDKCAP, "Failed to ftruncate SHM\n");
        return -1;
    }
    struct drl_state_shm *shm_ptr = mmap(0, sizeof(struct drl_state_shm), PROT_WRITE | PROT_READ, MAP_SHARED, shm_fd, 0);
    if (shm_ptr == MAP_FAILED) {
        RTE_LOG(ERR, DPDKCAP, "Failed to mmap SHM\n");
        return -1;
    }
    RTE_LOG(INFO, DPDKCAP, "Successfully mapped POSIX SHM at %s\n", DRL_STATE_SHM_NAME);
    
    // Initialize SHM to zero and set magic
    memset(shm_ptr, 0, sizeof(struct drl_state_shm));
    shm_ptr->magic = DRL_SHM_MAGIC;
    shm_ptr->update_count = 0;
    
    struct rte_eth_rss_reta_entry64 query_conf[512 / RTE_ETH_RETA_GROUP_SIZE];
    memset(query_conf, 0, sizeof(query_conf));
    for (int i = 0; i < (512 / RTE_ETH_RETA_GROUP_SIZE); i++) query_conf[i].mask = UINT64_MAX;

    if (rte_eth_dev_rss_reta_query(0, query_conf, 512) == 0) {
        for (int b = 0; b < 512; b++) {
            int idx = b / RTE_ETH_RETA_GROUP_SIZE;
            int shift = b % RTE_ETH_RETA_GROUP_SIZE;
            shm_ptr->initial_reta[b] = query_conf[idx].reta[shift];
        }
        RTE_LOG(INFO, DPDKCAP, "[RL-INIT] Successfully mapped initial hardware RETA table into State SHM.\n");
    } else {
        RTE_LOG(ERR, DPDKCAP, "[RL-INIT] Failed to query initial hardware RETA table.\n");
    }

    uint64_t latest_tsc_timestamp[MAX_ACTOR_NODES] = {0};
    struct drl_global_hdr latest_state[MAX_ACTOR_NODES] = {0};
    bool has_state[MAX_ACTOR_NODES] = {false};

    uint64_t prev_tsc = rte_rdtsc();
    uint64_t prev_tsc_50ms = prev_tsc;
    uint64_t timer_hz = rte_get_timer_hz();

    for (;;) {
        if (unlikely(*(config->stop_condition))) {
            break;
        }

        nb_rx = rte_eth_rx_burst(config->rx_port, config->rx_queue, bufs, DPDKCAP_CAPTURE_BURST_SIZE);

        for (i = 0; i < nb_rx; i++) {
            struct rte_mbuf *m = bufs[i];
            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

            if (eth_hdr->ether_type == rte_cpu_to_be_16(DRL_TELEMETRY_ETHER_TYPE)) {
                uint8_t *tel = (uint8_t *)(eth_hdr + 1); // Get pointer to payload
                
                uint32_t *raw_32 = (uint32_t *)tel;
                uint32_t magic = rte_be_to_cpu_32(raw_32[0]);
                
                if (magic == DRL_TELEMETRY_MAGIC) {
                    struct drl_global_hdr hdr = {0};
                    hdr.magic = magic;
                    hdr.seq_num = rte_be_to_cpu_32(raw_32[1]);
                    
                    uint32_t word_1 = rte_le_to_cpu_32(raw_32[2]);
                    hdr.version      = word_1 & 0xF;
                    hdr.flags        = (word_1 >> 4) & 0xF;
                    hdr.idle_pol_rat = (word_1 >> 8) & 0x3FF;
                    hdr.anomaly_rate = (word_1 >> 18) & 0x3FFF;
                    
                    uint32_t word_2 = rte_le_to_cpu_32(raw_32[3]);
                    hdr.active_cores = word_2 & 0xFF;
                    hdr.mempool_free = (word_2 >> 8) & 0xFFFFFF;
                    
                    hdr.rx_pps       = rte_be_to_cpu_32(raw_32[4]);
                    hdr.imissed_pps  = rte_be_to_cpu_32(raw_32[5]);
                    hdr.total_flows  = rte_be_to_cpu_32(raw_32[6]);

                    uint64_t *raw_bps = (uint64_t *)((uint8_t *)tel + 28);
                    uint64_t *raw_tsc = (uint64_t *)((uint8_t *)tel + 36);
                    hdr.rx_bps       = rte_be_to_cpu_64(*raw_bps);
                    hdr.tsc_timestamp = rte_be_to_cpu_64(*raw_tsc);

                    uint8_t node_id = eth_hdr->src_addr.addr_bytes[5] & 0x3F;

                    if (hdr.tsc_timestamp > latest_tsc_timestamp[node_id]) {
                        latest_tsc_timestamp[node_id] = hdr.tsc_timestamp;
                        latest_state[node_id] = hdr;
                        has_state[node_id] = true;

                        __atomic_add_fetch(&shm_ptr->update_count, 1, __ATOMIC_SEQ_CST);
                        
                        shm_ptr->nodes[node_id].seq_num = hdr.seq_num;
                        shm_ptr->nodes[node_id].idle_pol_rat = hdr.idle_pol_rat;
                        shm_ptr->nodes[node_id].anomaly_rate = hdr.anomaly_rate;
                        shm_ptr->nodes[node_id].rx_pps = hdr.rx_pps;
                        shm_ptr->nodes[node_id].imissed_pps = hdr.imissed_pps;
                        shm_ptr->nodes[node_id].mempool_free = hdr.mempool_free;
                        shm_ptr->nodes[node_id].total_flows = hdr.total_flows;
                        shm_ptr->nodes[node_id].rx_bps = hdr.rx_bps;
                        shm_ptr->nodes[node_id].tsc_timestamp = hdr.tsc_timestamp;

                        __atomic_add_fetch(&shm_ptr->update_count, 1, __ATOMIC_SEQ_CST);
                    }
                }
            }
            rte_pktmbuf_free(m);
        }

        uint64_t cur_tsc = rte_rdtsc();

        if (unlikely(cur_tsc - prev_tsc_50ms >= timer_hz / 20)) {
            __atomic_add_fetch(&shm_ptr->update_count, 1, __ATOMIC_SEQ_CST);
            for (int b = 0; b < 512; b++) {
                uint64_t sum = 0;
                for (int c = 0; c < RTE_MAX_LCORE; c++) {
                    sum += g_bucket_pps[c][b];
                }
                shm_ptr->bucket_totals[b] = sum;
            }
            __atomic_add_fetch(&shm_ptr->update_count, 1, __ATOMIC_SEQ_CST);
            prev_tsc_50ms = cur_tsc;
        }

        if (unlikely(cur_tsc - prev_tsc >= timer_hz)) {
            static uint32_t telemetry_seq = 0;
            telemetry_seq++;

            for (int n = 0; n < MAX_ACTOR_NODES; n++) {
                if (has_state[n]) {
                    printf("[ECHO] seq=%u node=%u echo_pps=%u echo_bps=%lu idle=%u anomaly=%u mempool=%u flows=%u\n", 
                           telemetry_seq, n, latest_state[n].rx_pps, latest_state[n].rx_bps,
                           latest_state[n].idle_pol_rat, latest_state[n].anomaly_rate,
                           latest_state[n].mempool_free, latest_state[n].total_flows);
                }
            }
            prev_tsc = cur_tsc;
        }
    }

    // Clean up POSIX SHM
    munmap(shm_ptr, sizeof(struct drl_state_shm));
    shm_unlink(DRL_STATE_SHM_NAME);
    
    RTE_LOG(INFO, DPDKCAP, "Closed telemetry core %u and unlinked SHM %s\n", rte_lcore_id(), DRL_STATE_SHM_NAME);
    return 0;
}
