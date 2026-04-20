#include <stdbool.h>
#include <signal.h>
#include <string.h>

#include <rte_log.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_version.h>

#include "core_capture.h"

/* Global RSS Bucket Stats storage */
uint64_t g_rss_bucket_stats[RTE_MAX_LCORE][512] = {{0}};

#define RTE_LOGTYPE_DPDKCAP RTE_LOGTYPE_USER1

/*
 * Capture the traffic from the given port/queue tuple
 */
/*
 * Capture the traffic from the given port/queue tuple
 */
int capture_core(const struct core_capture_config *config)
{
    struct rte_mbuf *bufs[DPDKCAP_CAPTURE_BURST_SIZE];
    uint16_t nb_rx;
    int nb_rx_enqueued;
    int i;

    /* ================= 监控变量定义 (Monitor Variables) ================= */
    // 使用函数内局部变量，天然线程安全 (Thread-Local via Stack)
    // 软件计数器：累加该核心实际收到的所有包
    uint64_t total_rx_pkts = 0; 
    uint64_t total_rx_bytes = 0; // 新增：累计接收字节数
    
    // 监控用历史状态变量
    uint64_t mon_prev_tsc = 0;
//     uint64_t mon_prev_pkts = 0;   // 记录上一次的 total_rx_pkts
//     uint64_t mon_prev_bytes = 0;  // 记录上一次的 total_rx_bytes
//     uint64_t mon_prev_sw_missed = 0; 
    
    uint64_t timer_tsc = 0;
    uint64_t cur_tsc;
    /* ============================================================= */

    RTE_LOG(INFO, DPDKCAP, "Core %u is capturing packets for port %u\n",
            rte_lcore_id(), config->port);

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
        // 如果ring已满，则无法再放入数据，此时会阻塞
        nb_rx = rte_eth_rx_burst(config->port, config->queue, bufs, DPDKCAP_CAPTURE_BURST_SIZE);
        
        // 软件计数器累加 (Software Counter Accumulation)
        for (i = 0; i < nb_rx; i++) {
            total_rx_bytes += rte_pktmbuf_pkt_len(bufs[i]);
            
            // RSS Bucket Load Monitoring (Fast Path)
            // No CheckSum Check needed here, just raw hash
            // 512 is the RETA size
            uint32_t bucket_id = bufs[i]->hash.rss % 512;
            g_rss_bucket_stats[rte_lcore_id()][bucket_id]++;
        }
        total_rx_pkts += nb_rx;

        /* ================= 最终修复版监控代码 (Final Fix) ================= */
        // 使用软件计数器 total_rx_pkts 计算 PPS，确保数值准确且不为 0
        if (unlikely(timer_tsc == 0)) timer_tsc = rte_get_timer_hz();

        cur_tsc = rte_rdtsc();
        if (unlikely(cur_tsc - mon_prev_tsc > timer_tsc)) {
            struct rte_eth_stats stats;
            // 依然需要读取硬件统计来获取丢包数 (imissed)
            rte_eth_stats_get(config->port, &stats);

            // 更新历史值
            // mon_prev_pkts = total_rx_pkts;
            // mon_prev_bytes = total_rx_bytes;
            // mon_prev_sw_missed = config->stats->missed_packets;
            mon_prev_tsc = cur_tsc;
        }
        /* ============================================================= */

        /* [PERFORMANCE DEBUG] Enqueue Enabled */
        if (likely(nb_rx > 0))
        {
            nb_rx_enqueued = rte_ring_enqueue_burst(config->ring, (void *)bufs, nb_rx, NULL);

            // Update stats
            if (nb_rx_enqueued == nb_rx)
            {
                config->stats->packets += nb_rx_enqueued;
            }
            else
            {
                config->stats->missed_packets += (nb_rx - nb_rx_enqueued);
                // Free whatever we can't put in the write ring
                for (i = nb_rx_enqueued; i < nb_rx; i++)
                {
                    rte_pktmbuf_free(bufs[i]);
                }
            }
        }
    }

    RTE_LOG(INFO, DPDKCAP, "Closed capture core %d (port %d)\n",
            rte_lcore_id(), config->port);

    return 0;
}
