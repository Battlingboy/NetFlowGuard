#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/shm.h>
#include <unistd.h>

#include <rte_ethdev.h>
#include <rte_timer.h>
#include <rte_ring.h>
#include <rte_log.h>

#include "statistics.h"
#include "utils.h"
#include "core_capture.h" // For g_rss_bucket_stats
#include "drl_telemetry.h"
#include "flow_extractor.h"
#include <rte_mbuf.h>

#define RTE_LOGTYPE_DPDKCAP RTE_LOGTYPE_USER1

// RSS Helper Struct
struct BucketStats {
    uint32_t id;
    uint64_t pps;
};

// Comparison function for qsort (Descending PPS)
static int compare_bucket_stats(const void *a, const void *b) {
    const struct BucketStats *ba = (const struct BucketStats *)a;
    const struct BucketStats *bb = (const struct BucketStats *)b;
    if (bb->pps > ba->pps) return 1;
    if (bb->pps < ba->pps) return -1;
    return 0;
}

// Previous RSS stats for delta calculation
static uint64_t prev_rss_stats[RTE_MAX_LCORE][512] = {{0}};


#define RTE_LOGTYPE_DPDKCAP RTE_LOGTYPE_USER1

#define STATS_PERIOD_MS 50
#define TERMINAL_UPDATE_MS 1000
#define ROTATING_CHAR "-\\|/"
#define MAX_LCORES 1000

#define MYPORT 21345
#define BUFFER_SIZE 1024

int sock_cli = 0;
char sendbuf[BUFFER_SIZE];
int time_sequence = 0;

uint64_t global_total_packets_missed = 0;
uint64_t global_total_packets_droped = 0;

extern char csv_file_name[DPDKCAP_OUTPUT_FILENAME_LENGTH];

/*
 * Prints a set of stats
 */
// Rate Monitor State
struct monitor_pipeline_state {
    uint64_t prev_nic_rx;
    uint64_t prev_nic_miss; // Hardware Miss
    
    uint64_t prev_cap_rx;   // Capture Received (Packet)
    uint64_t prev_cap_miss; // Capture Ring Full (SW Miss)
    uint64_t prev_cap_enq;  // Capture Enqueue (Packet)

    uint64_t prev_write_rx; // Write Received (Packet)
};

static struct monitor_pipeline_state prev_states[MAX_LCORES];
static int state_init = 0;

/* ================= LARR Load Balancer (Holt-PID Upgrade) ================= */

#define LARR_ELEPHANT_THR_PCT 0.01
#define RETA_SIZE 512
#define RETA_CONF_SIZE (RETA_SIZE / RTE_ETH_RETA_GROUP_SIZE)

// --- Holt-PID Constants ---
#define HOLT_ALPHA 0.5
#define HOLT_BETA  0.3

#define PID_KP 0.8
#define PID_KI 0.05
#define PID_KD 0.1
#define PID_MAX_I 2000000.0  // Integral Anti-Windup Clamp (2M pps)

#define COLD_START_TICKS 5

// --- Logic Structures ---
struct CoreControllerState {
    double level;       // L_t
    double trend;       // T_t
    double prev_error;  // e_{t-1}
    double integral;    // \sum e
};

static struct CoreControllerState core_controllers[RTE_MAX_LCORE];
static int larr_tick = 0;

struct CoreLoad {
    uint32_t queue_id;
    uint64_t current_pps;
    double pred_pps;      // Predicted Load
    int64_t target_shed;  // Calculated by PID
};

// Returns the queue_id with minimum predicted load
static uint32_t find_leanest_queue(struct CoreLoad *loads, int num_queues) {
    uint32_t min_q = 0;
    double min_load = 1e15; // huge double
    for (int i = 0; i < num_queues; i++) {
        if (loads[i].pred_pps < min_load) {
            min_load = loads[i].pred_pps;
            min_q = loads[i].queue_id;
        }
    }
    return min_q;
}

// 2. Holt's Linear Exponential Smoothing (Forecast next second)
static double predict_next_load(double current_pps, struct CoreControllerState *state) {
    // If level is 0 (first run), initialize
    if (state->level == 0.0) {
        state->level = current_pps;
        state->trend = 0.0;
        return current_pps;
    }

    // Holt's equations
    double last_level = state->level;
    
    // Lt = alpha * Yt + (1-alpha) * (Lt-1 + Tt-1)
    state->level = HOLT_ALPHA * current_pps + (1.0 - HOLT_ALPHA) * (last_level + state->trend);
    
    // Tt = beta * (Lt - Lt-1) + (1-beta) * Tt-1
    state->trend = HOLT_BETA * (state->level - last_level) + (1.0 - HOLT_BETA) * state->trend;

    // Forecast: Y_{t+1} = Lt + Tt
    double pred = state->level + state->trend;
    return pred > 0.0 ? pred : 0.0;
}

// 3. PID Calculation (Calculate Shed Amount)
static int64_t calculate_migration_target(double pred_load, double target_load, struct CoreControllerState *state) {
    // Error > 0 means Overloaded (Need to shed)
    double error = pred_load - target_load;

    // Update Integral with Anti-Windup
    state->integral += error;
    if (state->integral > PID_MAX_I) state->integral = PID_MAX_I;
    if (state->integral < -PID_MAX_I) state->integral = -PID_MAX_I;

    // Derivative
    double derivative = error - state->prev_error;
    state->prev_error = error;

    // PID Output
    double output = (PID_KP * error) + (PID_KI * state->integral) + (PID_KD * derivative);

    return (int64_t)output;
}

static void larr_balance(uint16_t port_id, int num_queues, int delay_seconds) {
    int ret;
    struct rte_eth_rss_reta_entry64 reta_conf[RETA_CONF_SIZE];
    struct BucketStats bucket_infos[RETA_SIZE];
    struct CoreLoad core_loads[RTE_MAX_QUEUES_PER_PORT]; 

    // Cold Start Protection
    // Cold Start / Delay Protection
    larr_tick++;
    
    // If delay is -1, disable LARR
    if (delay_seconds == -1) return;

    // Wait until delay seconds passed
    if (larr_tick <= delay_seconds) {
        // Just observe (we still need to run prediction to update state, but don't migrate)
        // Wait, we need to populate core_loads current_pps to run prediction.
        // Let's proceed but skip "Execution" phase.
    }

    // 0. Initialize
    memset(core_loads, 0, sizeof(core_loads));
    for(int i=0; i<num_queues; i++) core_loads[i].queue_id = i;

    memset(reta_conf, 0, sizeof(reta_conf));
    for (int i = 0; i < RETA_CONF_SIZE; i++) reta_conf[i].mask = UINT64_MAX;

    // 1. Query Current RETA
    ret = rte_eth_dev_rss_reta_query(port_id, reta_conf, RETA_SIZE);
    if (ret != 0) return;

    // 2. Aggregate Stats & Calculate Current Load
    uint64_t total_cluster_pps = 0;
    
    for (int b = 0; b < RETA_SIZE; b++) {
        uint64_t current_total = 0;
        for (int c = 0; c < RTE_MAX_LCORE; c++) {
            current_total += g_rss_bucket_stats[c][b];
        }
        
        static uint64_t larr_prev_bucket[512] = {0};
        uint64_t delta = current_total - larr_prev_bucket[b];
        larr_prev_bucket[b] = current_total; 

        bucket_infos[b].id = b;
        bucket_infos[b].pps = delta;
        total_cluster_pps += delta;

        // Map PPS to Queue
        int idx = b / RTE_ETH_RETA_GROUP_SIZE;
        int shift = b % RTE_ETH_RETA_GROUP_SIZE;
        uint16_t q_id = reta_conf[idx].reta[shift];
        
        if (q_id < num_queues) {
            core_loads[q_id].current_pps += delta;
        }
    }

    // 3. Prediction Phase (Holt's)
    double total_pred_load = 0;
    for (int q = 0; q < num_queues; q++) {
        // Warning: core_controllers uses MAX_LCORE index, but here we iterate queues.
        // We assume 1:1 mapping Queue ID -> Controller Index.
        // This is safe if num_queues <= MAX_LCORE.
        core_loads[q].pred_pps = predict_next_load((double)core_loads[q].current_pps, &core_controllers[q]);
        total_pred_load += core_loads[q].pred_pps;
    }

    if (larr_tick <= delay_seconds) return; // Skip Execution during Cold Start/Delay

    if (total_cluster_pps < 10000) return; 

    // 4. Decision Phase (PID)
    double avg_pred_load = total_pred_load / num_queues;
    uint64_t elephant_thr = (uint64_t)(total_cluster_pps * LARR_ELEPHANT_THR_PCT);

    int migrated_buckets = 0;

    for (int q = 0; q < num_queues; q++) {
        // Calculate Shed Target via PID
        core_loads[q].target_shed = calculate_migration_target(core_loads[q].pred_pps, avg_pred_load, &core_controllers[q]);
        
        // Threshold check (Deadband: 1% of Avg Load)
        // Helps avoid micro-migrations when system is already balanced
        int64_t deadband = (int64_t)(avg_pred_load * 0.01);
        if (core_loads[q].target_shed > deadband) {
            int64_t needed = core_loads[q].target_shed;
            
            // Greedy Search
            for (int b = 0; b < RETA_SIZE; b++) {
                int idx = b / RTE_ETH_RETA_GROUP_SIZE;
                int shift = b % RTE_ETH_RETA_GROUP_SIZE;
                if (reta_conf[idx].reta[shift] == q) {
                    
                    // Constraint 1: Not Elephant
                    if (bucket_infos[b].pps > elephant_thr) continue;
                    
                    // Greedy Fit
                    if (bucket_infos[b].pps > 0 && bucket_infos[b].pps <= (uint64_t)needed) {
                         // MIGRATE
                         uint32_t target_q = find_leanest_queue(core_loads, num_queues);
                         
                         // Skip if target is same (shouldn't happen if overloaded, but safety)
                         if (target_q == q) continue;

                         reta_conf[idx].reta[shift] = target_q;
                         
                         // Update Forecasts immediately to reflect move?
                         // Yes, otherwise we overshoot.
                         core_loads[q].pred_pps -= bucket_infos[b].pps;
                         core_loads[target_q].pred_pps += bucket_infos[b].pps;
                         needed -= bucket_infos[b].pps;
                         migrated_buckets++;
                         
                         if (needed <= 0) break;
                    }
                }
            }
        }
    }

    // 5. Execution Phase
    if (migrated_buckets > 0) {
        ret = rte_eth_dev_rss_reta_update(port_id, reta_conf, RETA_SIZE);
        if (ret == 0) {
            // Silent balancing (User request to hide larr monitoring)
            // printf("[LARR-PID] Balanced! Migrated %d buckets. Avg Pred Load: %.0f\n", migrated_buckets, avg_pred_load);
        }
    }
}

static struct rte_ether_addr learner_mac;
static struct rte_mempool *drl_mempool = NULL;

extern struct rte_ether_addr g_learner_mac;
extern int g_learner_mac_set;

static void init_learner_mac(void) {
    if (!g_learner_mac_set) {
        rte_exit(EXIT_FAILURE, "CRITICAL ERROR: 'dst_mac=' not found in 'forward.ini'! Learner MAC is required.\n");
    }
    learner_mac = g_learner_mac;
}

static int print_stats(__attribute__((unused)) struct rte_timer *timer, struct stats_data *data)
{
    static int nb_updates = 0;
    static uint32_t drl_seq_num = 0;
    static uint32_t latest_marg_50ms = 0;
    static double latest_duty_50ms = 0.0;
    nb_updates++;
    
    // --- 0. Core Headroom Calculation (Runs every STATS_PERIOD_MS) ---
    uint64_t delta_active_cycles_sum_50ms = 0;
    static uint64_t prev_active_cycles_50ms[MAX_LCORES] = {0};
    static uint64_t prev_tsc_50ms = 0;
    
    uint64_t current_tsc_50ms = rte_rdtsc();
    uint64_t delta_tsc_50ms = current_tsc_50ms - prev_tsc_50ms;
    if (prev_tsc_50ms == 0) delta_tsc_50ms = 1;
    prev_tsc_50ms = current_tsc_50ms;

    for (unsigned int c = 0; c < data->cores_write_stats_list_size; c++) {
        uint64_t active = data->cores_stats_write_list[c].active_processing_cycles;
        delta_active_cycles_sum_50ms += (active - prev_active_cycles_50ms[c]);
        prev_active_cycles_50ms[c] = active;
    }
    
    int num_cores_50ms = data->cores_write_stats_list_size;
    double duty_cycle_50ms = num_cores_50ms > 0 ? (double)delta_active_cycles_sum_50ms / (delta_tsc_50ms * num_cores_50ms) : 0.0;
    if (duty_cycle_50ms > 1.0) duty_cycle_50ms = 1.0;
    if (duty_cycle_50ms < 0.0) duty_cycle_50ms = 0.0;
    uint32_t marg_duty_cycle_50ms = (uint32_t)((1.0 - duty_cycle_50ms) * 100000.0);
    latest_marg_50ms = marg_duty_cycle_50ms;
    latest_duty_50ms = duty_cycle_50ms;
    // -----------------------------------------------------------------
    
    static uint32_t disp_pps = 0, disp_imissed = 0, disp_anom = 0, disp_free = 0, disp_seq = 0;
    static uint64_t disp_bps = 0;
    static uint32_t disp_flows = 0;
    static uint8_t disp_cores = 0;

    // --- 1. Fast-Path DRL-Stack Telemetry TX (Runs every STATS_PERIOD_MS) ---
    if (drl_mempool && data->port_list_size > 0) {
        struct rte_mbuf *m = rte_pktmbuf_alloc(drl_mempool);
        if (m) {
            struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
            struct drl_global_hdr *drl = (struct drl_global_hdr *)(eth + 1);

            rte_ether_addr_copy(&learner_mac, &eth->dst_addr);
            rte_eth_macaddr_get(data->port_list[0], &eth->src_addr);
            eth->ether_type = rte_cpu_to_be_16(DRL_ETHER_TYPE);

            struct rte_eth_stats stats;
            rte_eth_stats_get(data->port_list[0], &stats);

            static uint64_t last_ipackets = 0;
            static uint64_t last_ibytes = 0;
            static uint64_t last_hw_drops = 0;
            static uint64_t last_sw_drops = 0;
            
            uint64_t diff_pkts = stats.ipackets > last_ipackets ? stats.ipackets - last_ipackets : 0;
            uint32_t current_pps = diff_pkts * (1000 / STATS_PERIOD_MS);

            uint64_t diff_bytes = stats.ibytes > last_ibytes ? stats.ibytes - last_ibytes : 0;
            uint64_t current_bps = diff_bytes * (1000 / STATS_PERIOD_MS);
            
            uint64_t total_hw_drops = stats.imissed + stats.rx_nombuf;
            
            uint64_t total_sw_drops = 0;
            uint64_t total_captured = 0;
            uint64_t total_written = 0;
            uint64_t total_filtered = 0;

            for (unsigned int c = 0; c < data->cores_capture_stats_list_size; c++) {
                total_captured += data->cores_stats_capture_list[c].packets;
            }
            
            for (unsigned int c = 0; c < data->cores_write_stats_list_size; c++) {
                total_written += data->cores_stats_write_list[c].packets_written;
                total_filtered += data->cores_stats_write_list[c].packets_filtered;
            }
            
            if (total_captured > (total_written + total_filtered)) {
                total_sw_drops = total_captured - total_written - total_filtered;
            }

            uint64_t diff_hw_drops = total_hw_drops > last_hw_drops ? total_hw_drops - last_hw_drops : 0;
            uint64_t diff_sw_drops = total_sw_drops > last_sw_drops ? total_sw_drops - last_sw_drops : 0;
            uint32_t current_total_drops_pps = (diff_hw_drops + diff_sw_drops) * (1000 / STATS_PERIOD_MS);

            last_ipackets = stats.ipackets;
            last_ibytes = stats.ibytes;
            last_hw_drops = total_hw_drops;
            last_sw_drops = total_sw_drops;

            uint64_t inf = (uint64_t)rte_atomic64_read(&total_inferred_flows);
            uint64_t anom = (uint64_t)rte_atomic64_read(&total_anomaly_flows);
            uint32_t current_anom_rate = inf > 0 ? (anom * 10000 / inf) : 0;

            drl->magic = rte_cpu_to_be_32(DRL_MAGIC_NUMBER);
            drl->seq_num = rte_cpu_to_be_32(drl_seq_num++);
            drl->version = 1;
            drl->flags = 0;
            drl->idle_pol_rat = 0; 
            drl->anomaly_rate = current_anom_rate & 0x3FFF;
            
            extern struct rte_mempool *mbuf_pool;
            uint32_t current_free_mbufs = mbuf_pool ? rte_mempool_avail_count(mbuf_pool) : 0;

            drl->active_cores = data->queue_per_port;
            drl->mempool_free = current_free_mbufs & 0xFFFFFF;
            drl->rx_pps = rte_cpu_to_be_32(current_pps);
            // Overwrite imissed_pps with the computed Margin Duty Cycle (0~100000)
            drl->imissed_pps = rte_cpu_to_be_32(marg_duty_cycle_50ms);
            drl->total_flows = rte_cpu_to_be_32(inf);
            drl->rx_bps = rte_cpu_to_be_64(current_bps);
            drl->tsc_timestamp = rte_cpu_to_be_64(rte_rdtsc());

            disp_pps = current_pps;
            disp_imissed = current_total_drops_pps;
            disp_anom = current_anom_rate;
            disp_free = drl->mempool_free;
            disp_cores = drl->active_cores;
            disp_seq = drl_seq_num;
            disp_bps = current_bps;
            disp_flows = inf;

            m->data_len = sizeof(struct rte_ether_hdr) + sizeof(struct drl_global_hdr);
            m->pkt_len = m->data_len;

            rte_eth_tx_burst(data->port_list[0], 0, &m, 1);
        }
    }

    // --- 2. Terminal UI Refresh ---
    if ((nb_updates * STATS_PERIOD_MS) % TERMINAL_UPDATE_MS != 0) {
        return 0;
    }

    // Calculate AI Compute Margin Experiments
    uint64_t total_queue_len = 0;
    uint64_t total_ema = 0, total_ema_fast = 0, total_ema_slow = 0;
    uint32_t max_q_hwm = 0;
    uint64_t delta_active_cycles_sum = 0;

    static uint64_t prev_active_cycles[MAX_LCORES] = {0};
    static uint64_t prev_tsc = 0;
    uint64_t current_tsc = rte_rdtsc();
    uint64_t delta_tsc = current_tsc - prev_tsc;
    if (prev_tsc == 0) delta_tsc = 1; // avoid div by 0 on first run
    prev_tsc = current_tsc;

    for (unsigned int c = 0; c < data->cores_write_stats_list_size; c++) {
        struct core_write_stats *s = &data->cores_stats_write_list[c];
        total_queue_len += s->current_queue_length;
        
        if (s->max_queue_length > max_q_hwm) {
            max_q_hwm = s->max_queue_length;
        }
        s->max_queue_length = 0; // Reset HWM for next window
        
        total_ema += s->ema_inference_cycles;
        total_ema_fast += s->ema_inference_cycles_fast;
        total_ema_slow += s->ema_inference_cycles_slow;
        
        uint64_t active = s->active_processing_cycles;
        delta_active_cycles_sum += (active - prev_active_cycles[c]);
        prev_active_cycles[c] = active;
    }
    
    // Baseline averages
    int num_cores = data->cores_write_stats_list_size;
    double avg_q = num_cores > 0 ? (double)total_queue_len / num_cores : 0.0;
    
    double hz_us = (double)rte_get_timer_hz() / 1000000.0;
    double t_cpu = (num_cores > 0 && hz_us > 0.0) ? (double)total_ema / num_cores / hz_us : 0.0;
    double t_cpu_fast = (num_cores > 0 && hz_us > 0.0) ? (double)total_ema_fast / num_cores / hz_us : 0.0;
    double t_cpu_slow = (num_cores > 0 && hz_us > 0.0) ? (double)total_ema_slow / num_cores / hz_us : 0.0;

    // --- Original Combo Tests ---
    double SLA_500us = 500.0;
    double SLA_1ms = 1000.0;
    double SLA_2ms = 2000.0;
    
    double mr_fast = 1.0 - ((avg_q * t_cpu_fast) / SLA_500us); if (mr_fast < 0.0) mr_fast = 0.0;
    double mr_base = 1.0 - ((avg_q * t_cpu) / SLA_1ms);        if (mr_base < 0.0) mr_base = 0.0;
    double mr_slow = 1.0 - ((avg_q * t_cpu_slow) / SLA_2ms);    if (mr_slow < 0.0) mr_slow = 0.0;

    uint32_t marg_500us_fast = (uint32_t)(mr_fast * 100000.0);
    uint32_t marg_1ms_base = (uint32_t)(mr_base * 100000.0);
    uint32_t marg_2ms_slow = (uint32_t)(mr_slow * 100000.0);

    // --- Strategy 1: Duty Cycle ---
    double duty_cycle = num_cores > 0 ? (double)delta_active_cycles_sum / (delta_tsc * num_cores) : 0.0;
    if (duty_cycle > 1.0) duty_cycle = 1.0;
    if (duty_cycle < 0.0) duty_cycle = 0.0;
    uint32_t marg_duty_cycle = (uint32_t)((1.0 - duty_cycle) * 100000.0);
    
    // --- Strategy 2: High Water Mark (HWM) ---
    // If HWM reaches max Mbufs (16384), margin is 0. Parametrize to 8192.
    double hwm_SLA_pkts = 8192.0; 
    double mr_hwm = 1.0 - ((double)max_q_hwm / hwm_SLA_pkts);
    if (mr_hwm < 0.0) mr_hwm = 0.0;
    uint32_t marg_hwm = (uint32_t)(mr_hwm * 100000.0);

    // Clear screen and reset cursor to top-left for a clean "dashboard" feel
    // printf("\033[2J\033[H"); // User requested no clear screen
    
    printf("\n[%c] | DRL-Stack Telemetry Monitor (TX @ %dms) \n", ROTATING_CHAR[(nb_updates * STATS_PERIOD_MS / TERMINAL_UPDATE_MS) % 4], STATS_PERIOD_MS);
    printf("======================================================================\n");
    printf("  %-22s : 0x%X\n", "Magic Number", DRL_MAGIC_NUMBER);
    printf("  %-22s : %u\n", "Sequence Number", disp_seq);
    printf("  %-22s : %u\n", "Active Cores", disp_cores);
    printf("  %-22s : %u\n", "Mempool Free (Mbuf)", disp_free);
    printf("  %-22s : %u pps\n", "Global RX Rate", disp_pps);
    printf("  %-22s : %u pps\n", "Total Drops (HW+SW)", disp_imissed);
    printf("  %-22s : %u\n", "Total Tracked Flows", disp_flows);
    printf("  %-22s : %lu Bps\n", "Global RX Throughput", disp_bps);
    printf("  %-22s : %.4f %%\n", "Anomaly Rate", (double)disp_anom / 100.0);
    printf("  [ Margin TTC Base ]    : %u / 100000  (SLA=1000us, a=1/256)\n", marg_1ms_base);
    printf("  [ Margin HWM Queue ]   : %u / 100000  (Max Q last 1s: %u pkts)\n", marg_hwm, max_q_hwm);
    printf("  [ Margin Duty UI-1s ]  : %u / 100000  (Active: %.2f%% CPU Time)\n", marg_duty_cycle, duty_cycle * 100.0);
    printf("  [ Margin Duty Sent-50ms]: %u / 100000  (Active: %.2f%% CPU Time)\n", latest_marg_50ms, latest_duty_50ms * 100.0);
    printf("======================================================================\n");

    /* 
     * --- Legacy Monitoring (Commented out per user request) --- 
     *
    if (!state_init) {
        memset(prev_states, 0, sizeof(prev_states));
        state_init = 1;
    }
    printf("%-6s | %-12s | %-12s | %-12s | %-12s | %-12s | %-12s | %-12s | %s\n", 
           "Core", "NIC Rx", "Cap Rx", "Ring Tx", "Write Rx", "SW Drops", "Total Input", "Total Loss", "Loss %");
    
    struct rte_eth_stats port_stats;
    unsigned int i;
    for (i = 0; i < data->cores_capture_stats_list_size; i++) {
        // [Per-core stats updates code...]
    }
    */

    // --- Export Per-Core PPS for JFI (Python Control Plane) ---
    static uint64_t prev_core_pkts[MAX_LCORES] = {0};
    FILE *f_jfi = fopen("csv/jfi_stats.txt", "w");
    if (f_jfi) {
        for (unsigned int c = 0; c < data->cores_write_stats_list_size; c++) {
            uint64_t current_pkts = data->cores_stats_write_list[c].packets_written;
            uint64_t pps = current_pkts > prev_core_pkts[c] ? current_pkts - prev_core_pkts[c] : 0; 
            prev_core_pkts[c] = current_pkts;
            fprintf(f_jfi, "%lu", pps);
            if (c < data->cores_write_stats_list_size - 1) fprintf(f_jfi, ",");
        }
        fclose(f_jfi);
    }

    // Call LARR Load Balancer silently in the background
    int active_queues = data->cores_capture_stats_list_size;
    if (active_queues > RTE_MAX_QUEUES_PER_PORT) active_queues = RTE_MAX_QUEUES_PER_PORT;
    larr_balance((uint16_t)data->port_list[0], active_queues, data->larr_delay);

    uint64_t inf = (uint64_t)rte_atomic64_read(&total_inferred_flows);
    uint64_t anom = (uint64_t)rte_atomic64_read(&total_anomaly_flows);
    double rate = inf > 0 ? (double)anom * 100.0 / inf : 0.0;
    printf("\n[ML Inference Stats] Total Flows Scanned: %lu | Anomalous Flows: %lu (%.4f%%)\n", inf, anom, rate);

    return 0;
}

// 发送统计信息stats到服务器
static void send_stats(__attribute__((unused)) struct rte_timer *timer, struct stats_data *data)
{
    uint64_t total_packets_captured = 0;
    uint64_t total_packets_droped = 0;
    uint64_t total_packets_missed = 0;
    uint64_t total_packets_written = 0;
    uint64_t total_packets_filtered = 0;
    uint64_t total_bytes_wrritten = 0;
    uint64_t total_compressedbytes_written = 0;

    static struct rte_eth_stats port_statistics;

    unsigned int i;

    for (i = 0; i < data->cores_capture_stats_list_size; i++)
    {
        total_packets_captured += data->cores_stats_capture_list[i].packets;
    }

    for (i = 0; i < data->cores_write_stats_list_size; i++)
    {
        total_packets_written += data->cores_stats_write_list[i].packets_written;
        total_packets_filtered += data->cores_stats_write_list[i].packets_filtered;
        total_bytes_wrritten += data->cores_stats_write_list[i].bytes;
        total_compressedbytes_written += data->cores_stats_write_list[i].compressed_bytes;
    }

    // total_packets_droped = total_packets_captured - total_packets_written - total_packets_filtered;

    for (i = 0; i < data->port_list_size; i++)
    {
        rte_eth_stats_get(data->port_list[i], &port_statistics);
        total_packets_missed += port_statistics.imissed;
        total_packets_droped += port_statistics.ierrors;
    }

    global_total_packets_missed = total_packets_missed;
    global_total_packets_droped = total_packets_droped;

    time_sequence ++;
    extern char global_output_file_name[DPDKCAP_OUTPUT_FILENAME_LENGTH];
    sprintf(sendbuf, "{\"sequence\": %d, \"packets_captured\": %lu, \"packets_missed\": %lu, \"packets_droped\": %lu, \"packets_written\": %lu, \"packets_filtered\": %lu, \"bytes_written\": %lu, \"bytes_compressed\": %lu, \"output_filename\": \"%s\"}\n", 
            time_sequence, total_packets_captured, total_packets_missed, total_packets_droped, total_packets_written,
            total_packets_filtered, total_bytes_wrritten, total_compressedbytes_written, global_output_file_name);

    printf("发送：%s\n", sendbuf);

    send(sock_cli, sendbuf, strlen(sendbuf), 0); // 发送
}

/*
 * Handles signals
 */
// static bool should_stop = false;
// static void signal_handler(int sig) {
//   RTE_LOG(NOTICE, DPDKCAP, "Caught signal %s on core %u%s\n",
//       strsignal(sig), rte_lcore_id(),
//       rte_get_main_lcore()==rte_lcore_id()?" (MASTER CORE)":"");
//   should_stop = true;
// }

static struct rte_timer stats_timer;

void start_stats_display(struct stats_data *data, uint32_t timeout)
{
    extern volatile bool should_stop;
    extern void signal_handler(int sig);

    uint64_t prev_tsc = 0, cur_tsc, diff_tsc;
    uint64_t hz;
    uint64_t timer_resolution_cycles;

    struct timeval start_time;
    struct timeval now_time;
    gettimeofday(&start_time, NULL);

    hz = rte_get_timer_hz();
    timer_resolution_cycles = hz / 100; /* around 10ms for finer scheduling */

    init_learner_mac();
    drl_mempool = rte_pktmbuf_pool_create("DRL_TELEMETRY_POOL", 1024,
        32, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!drl_mempool) {
        RTE_LOG(WARNING, DPDKCAP, "Could not create DRL_TELEMETRY_POOL map. Telemetry disabled.\n");
    }

    signal(SIGINT, signal_handler);
    // Initialize timers
    rte_timer_subsystem_init();
    // Timer launch
    rte_timer_init(&(stats_timer));
    rte_timer_reset(&(stats_timer), hz / (1000 / STATS_PERIOD_MS), PERIODICAL, rte_lcore_id(), (void *)print_stats, data);

    // Wait for ctrl+c
    for (;;)
    {
        gettimeofday(&now_time, NULL);
        if (now_time.tv_sec - start_time.tv_sec > timeout)
        {
            should_stop = true;
        }

        if (unlikely(should_stop))
        {
            break;
        }

        cur_tsc = rte_get_timer_cycles();
        diff_tsc = cur_tsc - prev_tsc;
        if (diff_tsc > timer_resolution_cycles)
        {
            rte_timer_manage();
            prev_tsc = cur_tsc;
        }
    }
    rte_timer_stop(&(stats_timer));
    signal(SIGINT, SIG_DFL);
}

void start_stats_send(struct stats_data *data, uint32_t timeout, uint32_t send)
{
    extern volatile bool should_stop;
    extern void signal_handler(int sig);

    uint64_t prev_tsc = 0, cur_tsc, diff_tsc;
    uint64_t hz;
    uint64_t timer_resolution_cycles;

    // 定义sockfd
    sock_cli = socket(AF_INET, SOCK_STREAM, 0);

    unlink("./client.sock"); // 删除socket文件，避免bind失败

    // 定义sockaddr_in
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(MYPORT);                      ///服务器端口
    servaddr.sin_addr.s_addr = inet_addr("【【】】"); ///服务器ip

    // 连接服务器，成功返回0，错误返回-1
    if (connect(sock_cli, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        should_stop = true;
        printf("Connect Error!");
        perror("connect");
        exit(1);
    }

    struct timeval start_time;
    struct timeval now_time;
    gettimeofday(&start_time, NULL);

    hz = rte_get_timer_hz();
    timer_resolution_cycles = hz / 10; /* around 100ms */

    signal(SIGINT, signal_handler);
    // Initialize timers
    rte_timer_subsystem_init();
    // Timer launch
    rte_timer_init(&(stats_timer));
    rte_timer_reset(&(stats_timer), hz * send, PERIODICAL, rte_lcore_id(), (void *)send_stats, data);

    // Wait for ctrl+c
    for (;;)
    {
        gettimeofday(&now_time, NULL);
        if (now_time.tv_sec - start_time.tv_sec > timeout)
        {
            should_stop = true;
        }

        if (unlikely(should_stop))
        {
            break;
        }

        cur_tsc = rte_get_timer_cycles();
        diff_tsc = cur_tsc - prev_tsc;
        if (diff_tsc > timer_resolution_cycles)
        {
            rte_timer_manage();
            prev_tsc = cur_tsc;
        }
    }
    rte_timer_stop(&(stats_timer));
    signal(SIGINT, SIG_DFL);
}

// 计时停止
void stop_capture_until(struct stats_data *data, uint32_t timeout)
{
    extern volatile bool should_stop;
    extern void signal_handler(int sig);

    struct timeval start_time;
    struct timeval now_time;
    gettimeofday(&start_time, NULL);

    signal(SIGINT, signal_handler);

    while (1)
    {
        gettimeofday(&now_time, NULL);
        if (now_time.tv_sec - start_time.tv_sec > timeout)
        {
            should_stop = true;
        }

        if (unlikely(should_stop))
        {
            break;
        }
    }

    signal(SIGINT, SIG_DFL);
}


// 输出最终统计信息
void final_stas_display(struct stats_data *data)
{
    uint64_t total_packets_captured = 0;
    uint64_t total_packets_missed = 0;
    uint64_t total_packets_droped = 0;
    uint64_t total_packets_written = 0;
    uint64_t total_packets_filtered = 0;
    uint64_t total_bytes_wrritten = 0;
    uint64_t total_compressedbytes_written = 0;
    unsigned int i;
    // unsigned int j;
    // static struct rte_eth_stats port_statistics;

    // printf("-- PER PORT --\n");
    // for (i = 0; i < data->port_list_size; i++)
    // {
    //     rte_eth_stats_get(data->port_list[i], &port_statistics);
    //     printf("- PORT %d -\n", data->port_list[i]);
    //     printf("Built-in counters:\n"
    //            "  RX Successful packets: %lu\n"
    //            "  RX Successful bytes: %s (avg: %d bytes/pkt)\n"
    //            "  RX Unsuccessful packets: %lu\n"
    //            "  RX Missed packets: %lu\n  No MBUF: %lu\n",
    //            port_statistics.ipackets,
    //            bytes_format(port_statistics.ibytes),
    //            port_statistics.ipackets ? (int)((float)port_statistics.ibytes / (float)port_statistics.ipackets) : 0,
    //            port_statistics.ierrors,
    //            port_statistics.imissed, port_statistics.rx_nombuf);
    //     printf("Per queue:\n");
    //     for (j = 0; j < data->queue_per_port; j++)
    //     {
    //         printf("  Queue %d RX: %lu RX-Error: %lu\n", j,
    //                port_statistics.q_ipackets[j], port_statistics.q_errors[j]);
    //     }
    //     printf("  (%d queues hidden)\n",
    //            RTE_ETHDEV_QUEUE_STAT_CNTRS - data->queue_per_port);
    // }

    printf("Global===================================\n");

    for (i = 0; i < data->cores_capture_stats_list_size; i++)
    {
        total_packets_captured += data->cores_stats_capture_list[i].packets;
    }

    for (i = 0; i < data->cores_write_stats_list_size; i++)
    {
        total_packets_written += data->cores_stats_write_list[i].packets_written;
        total_packets_filtered += data->cores_stats_write_list[i].packets_filtered;
        total_bytes_wrritten += data->cores_stats_write_list[i].bytes;
        total_compressedbytes_written += data->cores_stats_write_list[i].compressed_bytes;
    }

    total_packets_missed = total_packets_captured - total_packets_written - total_packets_filtered;
    total_packets_missed = global_total_packets_missed > total_packets_missed ? global_total_packets_missed : total_packets_missed;
    total_packets_droped = global_total_packets_droped;

    printf("%lu 个数据包收到,\n"
           "%lu 个数据包Missed,\n"
           "%lu 个数据包Droped,\n"
           "%lu 个数据包写入,\n"
           "%lu 个数据包过滤\n"
           "%lu 字节写入,\n"
           "%lu 字节压缩后\n",
           total_packets_captured, total_packets_missed, total_packets_droped, total_packets_written, total_packets_filtered, total_bytes_wrritten, total_compressedbytes_written);

    printf("===================================\n");
}

// 输出最终统计信息并发送最终的统计信息
void final_stas_dispaly_and_send(struct stats_data *data)
{
    uint64_t total_packets_captured = 0;
    uint64_t total_packets_missed = 0;
    uint64_t total_packets_droped = 0;
    uint64_t total_packets_written = 0;
    uint64_t total_packets_filtered = 0;
    uint64_t total_bytes_wrritten = 0;
    uint64_t total_compressedbytes_written = 0;

    unsigned int i;

    for (i = 0; i < data->cores_capture_stats_list_size; i++)
    {
        total_packets_captured += data->cores_stats_capture_list[i].packets;
        // total_packets_droped += data->cores_stats_capture_list[i].missed_packets;
    }

    for (i = 0; i < data->cores_write_stats_list_size; i++)
    {
        total_packets_written += data->cores_stats_write_list[i].packets_written;
        total_packets_filtered += data->cores_stats_write_list[i].packets_filtered;
        total_bytes_wrritten += data->cores_stats_write_list[i].bytes;
        total_compressedbytes_written += data->cores_stats_write_list[i].compressed_bytes;
    }

    total_packets_missed = total_packets_captured - total_packets_written - total_packets_filtered;
    total_packets_missed = global_total_packets_missed > total_packets_missed ? global_total_packets_missed : total_packets_missed;
    total_packets_droped = global_total_packets_droped;

    printf("Global===================================\n");

    printf("%lu 个数据包收到,\n"
           "%lu 个数据包Missed,\n"
           "%lu 个数据包Droped,\n"
           "%lu 个数据包写入,\n"
           "%lu 个数据包过滤\n"
           "%lu 字节写入,\n"
           "%lu 字节压缩后\n",
           total_packets_captured, total_packets_missed, total_packets_droped, total_packets_written, total_packets_filtered, total_bytes_wrritten, total_compressedbytes_written);

    printf("===================================\n");

    // sprintf(sendbuf, "{\"sequence\": -1, \"packets_captured\": %lu, \"packets_droped\": %lu, \"packets_written\": %lu, \"packets_filtered\": %lu, \"bytes_written\": %lu, \"bytes_compressed\": %lu}",
    //     total_packets_captured, total_packets_droped, total_packets_written,
    //     total_packets_filtered, total_bytes_wrritten, total_compressedbytes_written);

    sprintf(sendbuf, "{\"sequence\": -1, \"packets_captured\": %lu, \"packets_missed\": %lu, \"packets_droped\": %lu, \"packets_written\": %lu, \"packets_filtered\": %lu, \"bytes_written\": %lu, \"bytes_compressed\": %lu}\n", 
        total_packets_captured, total_packets_missed, total_packets_droped, total_packets_written,
        total_packets_filtered, total_bytes_wrritten, total_compressedbytes_written);

    printf("发送最终统计信息：%s\n", sendbuf);
    send(sock_cli, sendbuf, strlen(sendbuf), 0); // 发送

    // 关闭连接
    close(sock_cli);
}