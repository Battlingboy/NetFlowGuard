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
#include <sys/mman.h>

#define RTE_LOGTYPE_DPDKCAP RTE_LOGTYPE_USER1

#define RETA_SIZE 512
#define RETA_CONF_SIZE (RETA_SIZE / RTE_ETH_RETA_GROUP_SIZE)
#define MAX_LARR_ROUNDS 5

char global_output_file_name[DPDKCAP_OUTPUT_FILENAME_LENGTH] = {0};
char csv_file_name[DPDKCAP_OUTPUT_FILENAME_LENGTH] = {0};
void signal_handler(int sig) { (void)sig; }

static struct drl_action_shm *g_action_shm = NULL;
static uint64_t last_action_seq = 0;

static void init_action_shm_listener() {
    int fd = shm_open(DRL_ACTION_SHM_NAME, O_RDONLY, 0666);
    if (fd >= 0) {
        g_action_shm = mmap(NULL, sizeof(struct drl_action_shm), PROT_READ, MAP_SHARED, fd, 0);
        if (g_action_shm == MAP_FAILED) {
            g_action_shm = NULL;
        }
        close(fd);
    }
}

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

void check_and_apply_rl_action(uint16_t port_id, int num_queues, int rl_delay) {
    if (rl_delay < 0) return; // Disabled by passing -1
    
    static int rl_tick = 0;
    if (rl_tick <= rl_delay) {
        rl_tick++;
        return; // Skipped during start delay 
    }
    
    if (!g_action_shm) {
        static int retry_tick = 0;
        if (retry_tick++ % 5 == 0) { 
            init_action_shm_listener();
        }
        return;
    }

    if (g_action_shm->magic != DRL_ACTION_MAGIC) {
        return; // Wait silently until magic is populated
    }

    if (g_action_shm->action_seq <= last_action_seq) {
        return;
    }

    struct rte_eth_rss_reta_entry64 reta_conf[RETA_CONF_SIZE];
    memset(reta_conf, 0, sizeof(reta_conf));
    for (int i = 0; i < RETA_CONF_SIZE; i++) reta_conf[i].mask = UINT64_MAX;

    for (int b = 0; b < RETA_SIZE; b++) {
        int idx = b / RTE_ETH_RETA_GROUP_SIZE;
        int shift = b % RTE_ETH_RETA_GROUP_SIZE;
        uint16_t target_q = g_action_shm->reta_buckets[b];

        if (target_q >= num_queues) {
            target_q = 0;
        }
        reta_conf[idx].reta[shift] = target_q;
    }

    int ret = rte_eth_dev_rss_reta_update(port_id, reta_conf, RETA_SIZE);
    if (ret == 0) {
        last_action_seq = g_action_shm->action_seq;
        // printf("\n[RL-ACTION] Applied Directly Assembled RETA from RL! Seq: %lu\n", last_action_seq);

        /*
        struct rte_eth_rss_reta_entry64 query_conf[RETA_CONF_SIZE];
        memset(query_conf, 0, sizeof(query_conf));
        for (int i = 0; i < RETA_CONF_SIZE; i++) query_conf[i].mask = UINT64_MAX;
        
        if (rte_eth_dev_rss_reta_query(port_id, query_conf, RETA_SIZE) == 0) {
            uint32_t q_counts[RTE_MAX_QUEUES_PER_PORT] = {0};
            for (int b = 0; b < RETA_SIZE; b++) {
                int idx = b / RTE_ETH_RETA_GROUP_SIZE;
                int shift = b % RTE_ETH_RETA_GROUP_SIZE;
                uint16_t q = query_conf[idx].reta[shift];
                if (q < RTE_MAX_QUEUES_PER_PORT) q_counts[q]++;
            }
            printf("[RL-ACTION-VERIFY] Hardware RETA successfully queried: ");
            for (int q = 0; q < num_queues; q++) {
                printf("Q%d[%u] ", q, q_counts[q]);
            }
            printf("\n");
        }
        */
    } else {
        printf("\n[RL-ACTION-ERROR] Failed to update RETA table! (Err: %d)\n", ret);
    }
}

// Previous RSS stats for delta calculation
static uint64_t prev_rss_stats[RTE_MAX_LCORE][512] = {{0}};

static void print_rss_top20(void) {
    struct BucketStats collapsed[512];
    uint64_t total_pps = 0;

    for (int b = 0; b < 512; b++) {
        uint64_t current_total = 0;
        uint64_t prev_total = 0;

        for (int c = 0; c < RTE_MAX_LCORE; c++) {
            current_total += g_bucket_pps[c][b];
            prev_total += prev_rss_stats[c][b];
            // Update prev for next time
            prev_rss_stats[c][b] = g_bucket_pps[c][b];
        }

        uint64_t delta = current_total - prev_total;
        collapsed[b].id = b;
        collapsed[b].pps = delta;
        total_pps += delta;
    }

    // Sort
    qsort(collapsed, 512, sizeof(struct BucketStats), compare_bucket_stats);

    printf("\n[RSS Load Monitor] Total RSS PPS: %lu\n", total_pps);
    printf("Top 20 Hot Buckets:\n");
    printf("Bucket ID | PPS        | %% Load\n");
    printf("----------+------------+--------\n");
    
    for (int i = 0; i < 20; i++) {
        if (collapsed[i].pps == 0) break; 
        double load_pct = total_pps > 0 ? (double)collapsed[i].pps / total_pps * 100.0 : 0.0;
        printf("%-9u | %-10lu | %.2f%%\n", collapsed[i].id, collapsed[i].pps, load_pct);
    }
    printf("------------------------------\n");
}

#define RTE_LOGTYPE_DPDKCAP RTE_LOGTYPE_USER1

#define STATS_PERIOD_MS 500
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

#ifndef RTE_RETA_GROUP_SIZE
#define RTE_RETA_GROUP_SIZE RTE_ETH_RETA_GROUP_SIZE
#endif

#define LARR_ELEPHANT_THR_PCT 0.01
#define RETA_SIZE 512
#define RETA_CONF_SIZE (RETA_SIZE / RTE_RETA_GROUP_SIZE)

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
            current_total += g_bucket_pps[c][b];
        }
        
        static uint64_t larr_prev_bucket[512] = {0};
        uint64_t delta = current_total - larr_prev_bucket[b];
        larr_prev_bucket[b] = current_total; 

        bucket_infos[b].id = b;
        bucket_infos[b].pps = delta;
        total_cluster_pps += delta;

        // Map PPS to Queue
        int idx = b / RTE_RETA_GROUP_SIZE;
        int shift = b % RTE_RETA_GROUP_SIZE;
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
                int idx = b / RTE_RETA_GROUP_SIZE;
                int shift = b % RTE_RETA_GROUP_SIZE;
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
            printf("[LARR-PID] Balanced! Migrated %d buckets. Avg Pred Load: %.0f\n", migrated_buckets, avg_pred_load);
        }
    }
}

static int print_stats(__attribute__((unused)) struct rte_timer *timer, struct stats_data *data)
{
    // Initialize state on first run
    if (!state_init) {
        memset(prev_states, 0, sizeof(prev_states));
        state_init = 1;

// Display Global HW Drops separately instead of assigning to Q0
// static uint64_t global_hw_drop_display = 0;
// We can use a local variable in print_stats if we aggregate?
// Actually, just reading port_stats.imissed diff is enough.

// Removed 'HW Drops' column from header as it's not per-core
        printf("\n%-6s | %-12s | %-12s | %-12s | %-12s | %-12s | %-12s | %-12s | %s\n", 
               "Core", "NIC Rx", "Cap Rx", "Ring Tx", "Write Rx", "SW Drops", "Total Input", "Total Loss", "Loss %");
        printf("-------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------\n");
    }

    struct rte_eth_stats port_stats;
    unsigned int i;
    
    // We iterate through pipelines. 
    // Assumption: 1:1 mapping means cores_stats_capture_list[i] corresponds to cores_stats_write_list[i]
    // And they likely share the same port.
    
    for (i = 0; i < data->cores_capture_stats_list_size; i++)
    {
        uint32_t cap_core_id = data->cores_stats_capture_list[i].core_id;
        // uint32_t write_core_id = data->cores_stats_write_list[i].core_id;
        uint32_t port_id = data->port_list[0]; // Assuming single port for simplicity or derived maps? 
        // Logic: dpdkcap.c stores sequential mapping. port_list might have multiple ports.
        // We need to map pipeline index 'i' to specific port.
        // Given 'j' loop in dpdkcap.c for per_port_c_cores, 'i' = port_idx * per_port_c_cores + core_idx
        
        uint32_t port_idx = i / data->queue_per_port;
        uint32_t queue_id = i % data->queue_per_port;
        
        if (port_idx < data->port_list_size) {
            port_id = data->port_list[port_idx];
        }

        // Get Port Stats (Global or Per-Queue if avail)
        rte_eth_stats_get(port_id, &port_stats);
        // Note: q_ipackets is "Received by Queue".
        uint64_t nic_rx_total = port_stats.q_ipackets[queue_id];
        // imissed is usually Global for the port, not per queue.
        // So we can only approximate NIC Miss per queue by dividing? OR just show global miss.
        // Let's show Global Miss for the Port on the first queue of that port?
        // uint64_t nic_miss_total = port_stats.imissed;
        // Show global stats for now, user can infer.
        // Per-pipeline previous allows us to diff global stats?
        // If we have 3 queues, reading global miss 3 times is fine, but diffing it 3 times means
        // each row shows the TOTAL NIC drop rate (not per queue). That is acceptable.
        uint64_t nic_miss_total = port_stats.imissed;

        // Capture Stats
        uint64_t cap_enq_total = data->cores_stats_capture_list[i].packets;
        uint64_t cap_miss_total = data->cores_stats_capture_list[i].missed_packets;
        uint64_t cap_rx_total = cap_enq_total + cap_miss_total;

        // Write Stats
        uint64_t write_rx_total = data->cores_stats_write_list[i].packets_written + 
                                  data->cores_stats_write_list[i].packets_filtered;

        // Calculate Deltas (PPS)
        uint64_t d_nic_rx = nic_rx_total - prev_states[i].prev_nic_rx;
        uint64_t d_nic_miss = nic_miss_total - prev_states[i].prev_nic_miss; // Global
        
        uint64_t d_cap_rx = cap_rx_total - prev_states[i].prev_cap_rx;
        uint64_t d_cap_miss = cap_miss_total - prev_states[i].prev_cap_miss;
        uint64_t d_cap_enq = cap_enq_total - prev_states[i].prev_cap_enq;
        
        uint64_t d_write_rx = write_rx_total - prev_states[i].prev_write_rx;

        // Fix for 0 NIC Rx:
        // Use MAX(NIC Rx, Cap Rx) as effective NIC Rx to handle missing driver stats
        uint64_t effective_nic_rx = d_nic_rx > d_cap_rx ? d_nic_rx : d_cap_rx;

        // Loss Rate Calculation
        uint64_t total_input = effective_nic_rx;
        // REMOVED: Do not add HW Drops to Q0 input anymore
        // if (queue_id == 0) total_input += d_nic_miss;
        
        uint64_t total_loss = 0;
        if (total_input > d_write_rx) {
             total_loss = total_input - d_write_rx;
        }
        
        double loss_rate = 0.0;
        if (total_input > 0) {
            loss_rate = (double)total_loss / (double)total_input * 100.0;
        } else if (total_loss > 0) {
            loss_rate = 100.0; // If input is 0 but loss > 0 (weird), assume 100% loss
        }
        
        char loss_pct_str[32];
        snprintf(loss_pct_str, 32, "%.1f%%", loss_rate);

        // Removed HW Drops column
        printf("C%-2u/Q%-2u | %-12lu | %-12lu | %-12lu | %-12lu | %-12lu | %-12lu | %-12lu | %-8s\n", 
               cap_core_id, queue_id, 
               d_nic_rx, 
               d_cap_rx, 
               d_cap_enq, 
               d_write_rx,
               d_cap_miss,
               total_input,
               total_loss,
               loss_pct_str);

        // Update State
        prev_states[i].prev_nic_rx = nic_rx_total;
        prev_states[i].prev_nic_miss = nic_miss_total;
        prev_states[i].prev_cap_rx = cap_rx_total;
        prev_states[i].prev_cap_miss = cap_miss_total;
        prev_states[i].prev_cap_enq = cap_enq_total;
        prev_states[i].prev_write_rx = write_rx_total;
    }
    
    // Separate Global Port Miss print?
    // printf("Global Port Miss: %lu\n", port_stats.imissed);

    // Separate Global Port Miss print?
    // printf("Global Port Miss: %lu\n", port_stats.imissed);

    // Print RSS Top 20 Buckets
    // Note: Uncommenting this after a long time will show a huge spike in the first second 
    // because prev_stats wasn't updated in the background. Result will normalize after 1 second.
    // print_rss_top20();

    int active_queues = data->cores_capture_stats_list_size;
    if (active_queues > RTE_MAX_QUEUES_PER_PORT) active_queues = RTE_MAX_QUEUES_PER_PORT;

    check_and_apply_rl_action((uint16_t)data->port_list[0], active_queues, data->rl_delay);

    return 0;
}

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

    send(sock_cli, sendbuf, strlen(sendbuf), 0);
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
    timer_resolution_cycles = hz / 10; /* around 100ms */

    signal(SIGINT, signal_handler);
    // Initialize timers
    rte_timer_subsystem_init();
    // Timer launch
    rte_timer_init(&(stats_timer));
    rte_timer_reset(&(stats_timer), hz / 2, PERIODICAL, rte_lcore_id(), (void *)print_stats, data);

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

    sock_cli = socket(AF_INET, SOCK_STREAM, 0);

    unlink("./client.sock");

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(MYPORT);
    servaddr.sin_addr.s_addr = inet_addr("【【】】");

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
    send(sock_cli, sendbuf, strlen(sendbuf), 0);

    close(sock_cli);
}