#include "statistics.h"

#include <signal.h>
#include <ncurses.h>
#include <unistd.h>
#include <stdint.h>

#include <rte_ethdev.h>
#include <rte_timer.h>
#include <rte_ring.h>
#include <rte_log.h>
#include <rte_cycles.h>

#include "utils.h"
#include "flow_extractor.h"
#include "drl_telemetry.h"
#include <rte_mbuf.h>

#define RTE_LOGTYPE_DPDKCAP RTE_LOGTYPE_USER1

#define GLOBAL_STATS_WINDOW_HEIGHT 10
#define STATS_PERIOD_MS 50
#define TERMINAL_UPDATE_MS 1000
#define ROTATING_CHAR "-\\|/"

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

static void wglobal_stats(WINDOW * window, struct stats_data * data) {
  if(data->log_file)
    wprintw(window,"Writing logs to: %s\n", data->log_file);
  else
    wprintw(window,"Writing logs to stderr\n");
  wprintw(window,"Entries free on ring: %u\n",
      rte_ring_free_count(data->ring));

  uint64_t inf = (uint64_t)rte_atomic64_read(&total_inferred_flows);
  uint64_t anom = (uint64_t)rte_atomic64_read(&total_anomaly_flows);
  double rate = inf > 0 ? (double)anom * 100.0 / inf : 0.0;
  
  wattron(window, A_BOLD);
  wprintw(window, "\n[LightGBM Fast-Path ML Inference Pipeline]\n");
  wattroff(window, A_BOLD);
  wprintw(window, "  -> Anomalous / Total Flows: %lu / %lu (%.4f%%)\n", anom, inf, rate);
  if (anomaly_ring) {
      wprintw(window, "  -> Anomalies Buffered for Export: %u\n", rte_ring_count(anomaly_ring));
  }
}

static void wcapture_stats(WINDOW * window, struct stats_data * data) {
  static uint64_t * last_per_port_packets = NULL;
  unsigned int i,j;
  static struct rte_eth_stats port_statistics;

  if (!last_per_port_packets) last_per_port_packets =
    malloc(sizeof(uint64_t) * data->cores_capture_stats_list_size);

  for (i=0; i<data->port_list_size; i++) {
    rte_eth_stats_get(data->port_list[i], &port_statistics);

    wprintw(window,"PORT %d:\n", data->port_list[i]);
    wprintw(window,"  RX Successful bytes: %s (avg: %d bytes/pkt)\n",
        bytes_format(port_statistics.ibytes),
        port_statistics.ipackets?(int)((float)port_statistics.ibytes/
          (float)port_statistics.ipackets):0);
    wprintw(window, "  RX Successful packets: %s\n",
        ul_format(port_statistics.ipackets));
    wprintw(window, "  RX Unsuccessful packets: %s\n",
        ul_format(port_statistics.ierrors));
    wprintw(window, "  RX Missed packets: %s\n",
        ul_format(port_statistics.imissed));
    wprintw(window, "  MBUF Allocation failures: %s\n",
        ul_format(port_statistics.rx_nombuf));

    wprintw(window,"  Per queue:\n");
    for (j=0; j<data->queue_per_port; j++) {
      wprintw(window, "  - Queue %2d handled by core %2d:\n",
          j,
          data->cores_stats_capture_list[i*data->queue_per_port+j].core_id);
      wprintw(window, "           HW:       RX: %s",
          ul_format(port_statistics.q_ipackets[j]));
      wprintw(window, "  RX-Error: %s\n",
          ul_format(port_statistics.q_errors[j]));
      wprintw(window, "         Ring: Enqueued: %s",
          ul_format(data->cores_stats_capture_list[i*data->queue_per_port+j]
            .packets));
      wprintw(window, "  Missed: %s\n",
          ul_format(data->cores_stats_capture_list[i*data->queue_per_port+j]
            .missed_packets));
      wprintw(window, "    Packets/s: %s\n",
          ul_format((
         data->cores_stats_capture_list[i*data->queue_per_port+j].packets-
      last_per_port_packets[i*data->queue_per_port+j])*1000/STATS_PERIOD_MS));

      last_per_port_packets[i*data->queue_per_port+j] =
         data->cores_stats_capture_list[i*data->queue_per_port+j].packets;
    }
    wprintw(window, "\n");
  }
}

static void wwrite_stats(WINDOW * window, struct stats_data * data) {
  static uint64_t last_total_packets = 0,
              last_total_bytes = 0,
              last_total_compressedbytes = 0;

  uint64_t total_packets = 0,
           total_bytes = 0,
           total_compressedbytes = 0;
  uint64_t instant_packets,
           instant_bytes,
           instant_compressedbytes;
  unsigned int i;

  // Calculate aggregated stats from writing cores
  for (i=0; i<data->cores_write_stats_list_size; i++) {
    total_packets += data->cores_stats_write_list[i].packets;
    total_bytes += data->cores_stats_write_list[i].bytes;
    total_compressedbytes += data->cores_stats_write_list[i].compressed_bytes;
  }

  // Calculate instant stats
  instant_packets = (total_packets-last_total_packets)
    *1000/STATS_PERIOD_MS;
  instant_bytes = (total_bytes-last_total_bytes)
    *1000/STATS_PERIOD_MS;
  instant_compressedbytes = (total_compressedbytes-last_total_compressedbytes)
    *1000/STATS_PERIOD_MS;

  last_total_packets = total_packets;
  last_total_bytes = total_bytes;
  last_total_compressedbytes = total_compressedbytes;

  wprintw(window,"Total packets written: %s\n",
      ul_format(total_packets));
  wprintw(window,"Total bytes written: %s", bytes_format(total_bytes));
  wprintw(window," compressed to %s\n",
      bytes_format(total_compressedbytes));
  wprintw(window,"Compressed/uncompressed size ratio: 1 / %.2f\n\n",
      total_compressedbytes?
      (float)total_bytes/(float)total_compressedbytes:0.0f);

  wprintw(window,"Packets written/s: %s/s\n",
      ul_format(instant_packets));
  wprintw(window,"Bytes written/s: %s/s", bytes_format(instant_bytes));
  wprintw(window," compressed to %s/s\n",
      bytes_format(instant_compressedbytes));
  wprintw(window,"Instant compressed/uncompressed size ratio: 1 / %.2f\n\n",
      instant_compressedbytes?
      (float)instant_bytes/(float)instant_compressedbytes:0.0f);

  wprintw(window,"  Per core stats:\n");
  for (i=0; i<data->cores_write_stats_list_size; i++) {
    wprintw(window, "Writing core %2d: %s ",
        data->cores_stats_write_list[i].core_id,
        data->cores_stats_write_list[i].output_file);
    wprintw(window,"(%s)\n", bytes_format(
          data->cores_stats_write_list[i].current_file_compressed_bytes));
  }
}

/*
 * Handles signals
 */
static bool should_stop = false;
static void signal_handler(int sig) {
  RTE_LOG(NOTICE, DPDKCAP, "Caught signal %s on core %u%s\n",
      strsignal(sig), rte_lcore_id(),
      rte_get_main_lcore()==rte_lcore_id()?" (MASTER CORE)":"");
  should_stop = true;
}



static WINDOW * border_global, * border_write, * border_capture;
static WINDOW * window_global, * window_write, * window_capture;

static void mv_windows(void) {
  wclear(border_global);
  wclear(border_write);
  wclear(border_capture);
  wclear(window_global);
  wclear(window_write);
  wclear(window_capture);

  wresize(border_global,  GLOBAL_STATS_WINDOW_HEIGHT, COLS/2);
  wresize(border_write,   (LINES-1)-GLOBAL_STATS_WINDOW_HEIGHT, COLS/2);
  wresize(border_capture, LINES-1, COLS/2);
  wresize(window_global,  GLOBAL_STATS_WINDOW_HEIGHT-2, COLS/2-2);
  wresize(window_write,   (LINES-1)-GLOBAL_STATS_WINDOW_HEIGHT-2, COLS/2-2);
  wresize(window_capture, LINES-1-2, COLS/2-2);

  mvderwin(border_global, 1, 0);
  mvderwin(border_write,  GLOBAL_STATS_WINDOW_HEIGHT+1, 0);
  mvderwin(border_capture,1, COLS/2);
/*  mvderwin(window_global, 2, 1);
  mvderwin(window_write,  GLOBAL_STATS_WINDOW_HEIGHT+2, 1);
  mvderwin(window_capture,2, COLS/2+2);
*/
  mvderwin(window_global, 1, 1);
  mvderwin(window_write,  1, 1);
  mvderwin(window_capture,1, 1);


}

static void init_windows(void) {
  border_global = subwin(stdscr,0,0,0,0);
  border_write = subwin(stdscr,0,0,0,0);
  border_capture = subwin(stdscr,0,0,0,0);

  window_global = subwin(border_global,0,0,0,0);
  window_write = subwin(border_write,0,0,0,0);
  window_capture = subwin(border_capture,0,0,0,0);

  scrollok(window_global,TRUE);
  scrollok(window_capture,TRUE);
  scrollok(window_write,TRUE);

  mv_windows();
}

static int printscreen(
    __attribute__((unused))struct rte_timer * timer,
    __attribute__((unused))struct stats_data * data) {
    static int nb_updates = 0;
    static uint32_t drl_seq_num = 0;
    nb_updates++;

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
            static uint64_t last_imissed  = 0;
            
            uint64_t diff_pkts = stats.ipackets > last_ipackets ? stats.ipackets - last_ipackets : 0;
            uint32_t current_pps = diff_pkts * (1000 / STATS_PERIOD_MS);
            
            uint64_t diff_missed = stats.imissed > last_imissed ? stats.imissed - last_imissed : 0;
            uint32_t current_imissed_pps = diff_missed * (1000 / STATS_PERIOD_MS);

            last_ipackets = stats.ipackets;
            last_imissed  = stats.imissed;

            uint64_t inf = (uint64_t)rte_atomic64_read(&total_inferred_flows);
            uint64_t anom = (uint64_t)rte_atomic64_read(&total_anomaly_flows);
            uint32_t current_anom_rate = inf > 0 ? (anom * 10000 / inf) : 0;

            drl->magic = rte_cpu_to_be_32(DRL_MAGIC_NUMBER);
            drl->seq_num = rte_cpu_to_be_32(drl_seq_num++);
            drl->version = 1;
            drl->flags = 0;
            drl->idle_pol_rat = 0; // TODO in future
            drl->anomaly_rate = current_anom_rate & 0x3FFF;
            drl->active_cores = data->queue_per_port;
            // Handle safely if data->ring is somehow NULL (e.g. read offline pcap)
            drl->mempool_free = data->ring ? (rte_ring_free_count(data->ring) & 0xFFFFFF) : 0;
            drl->rx_pps = rte_cpu_to_be_32(current_pps);
            drl->imissed_pps = rte_cpu_to_be_32(current_imissed_pps);
            drl->tsc_timestamp = rte_cpu_to_be_64(rte_rdtsc());

            m->data_len = sizeof(struct rte_ether_hdr) + sizeof(struct drl_global_hdr);
            m->pkt_len = m->data_len;

            rte_eth_tx_burst(data->port_list[0], 0, &m, 1);
        }
    }

    // --- 2. Terminal UI Refresh (Runs every TERMINAL_UPDATE_MS) ---
    if ((nb_updates * STATS_PERIOD_MS) % TERMINAL_UPDATE_MS == 0) {
        clear();
        /* Move the windows */
        mv_windows();

        /* Write into the buffers */
        int ui_tick = (nb_updates * STATS_PERIOD_MS) / TERMINAL_UPDATE_MS;
        mvprintw(0,0,"%c - Press q to quit | Sending DRL-Stack telemetry @ %dms", 
                 ROTATING_CHAR[ui_tick % 4], STATS_PERIOD_MS);
        
        box(border_global,0,0);
        mvwprintw(border_global,0,2,"Global ML Inference Stats");
        
        // Comment out other detailed outputs as requested
        // box(border_write,0,0);
        // mvwprintw(border_write,0,2,"Write stats");
        // box(border_capture,0,0);
        // mvwprintw(border_capture,0,2,"Capture stats");

        wglobal_stats(window_global, data);
        // wwrite_stats(window_write, data);
        // wcapture_stats(window_capture, data);

        /* Print on screen */
        refresh();
    }

    return 0;
}

static struct rte_timer stats_timer;

void start_stats_display(struct stats_data * data) {
  signal(SIGINT,signal_handler);
  int ch;

  initscr();
  cbreak();
  noecho();
  keypad(stdscr, TRUE);
  curs_set(0);

  //Init windows
  init_windows();

  // Non blocking inputs
  timeout(0);

  init_learner_mac();
  drl_mempool = rte_pktmbuf_pool_create("DRL_TELEMETRY_POOL", 1024,
      32, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
  if (!drl_mempool) {
      RTE_LOG(WARNING, DPDKCAP, "Could not create DRL_TELEMETRY_POOL map. Telemetry disabled.\n");
  }

  //Initialize timers
  rte_timer_subsystem_init();
  //Timer launch
  rte_timer_init (&(stats_timer));
  rte_timer_reset(&(stats_timer), rte_get_timer_hz() * STATS_PERIOD_MS / 1000,
      PERIODICAL, rte_lcore_id(), (void*) printscreen, data);

  //Wait for ctrl+c
  for (;;) {
    if (unlikely(should_stop)) {
      break;
    }
    ch = getch();
    switch(ch) {
      case KEY_DOWN:
        break;
      case KEY_UP:
        break;
      case 'q':
        should_stop = true;
        break;
    }

    rte_timer_manage();
  }
  rte_timer_stop(&(stats_timer));

  endwin();

  signal(SIGINT,SIG_DFL);
}

