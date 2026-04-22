#include "generate_query.h"


void generate_create_table_sql(char *sql, const char *table_name, int pdu_num) {
    char sql_head[1024] = "time BIGINT UNSIGNED NOT NULL, " 
                          "sip INT UNSIGNED NOT NULL, " 
                          "dip INT UNSIGNED NOT NULL, "
                          "sport SMALLINT UNSIGNED NOT NULL, "
                          "dport SMALLINT UNSIGNED NOT NULL, "
                          "protocol TINYINT UNSIGNED NOT NULL, "
                          "pkts INT UNSIGNED NOT NULL, "
                          "bytes INT UNSIGNED NOT NULL, "
                          "duration INT UNSIGNED NOT NULL, "
                          "labelOfService TINYINT UNSIGNED, "
                          "labelOfAnomaly BOOLEAN, ";
    
    char pdu[32];
    for (int i = 1; i <= pdu_num; i++) {
        sprintf(pdu, "PDU%d SMALLINT UNSIGNED, ", i);
        strcat(sql_head, pdu);
    }

    strcat(sql_head, "PRIMARY KEY (time, sip, dip, sport, dport, protocol)");

    sprintf(sql, "CREATE TABLE IF NOT EXISTS %s(%s);", table_name, sql_head);
}


int generate_insert_sql(char *sql, const char *table_name, int pdu_num, const struct IPv4FlowFeature flows_features[], int flows_nums, int index, int  insert_batch_size) {
    char table_head[1024] = "time, sip, dip, sport, dport, protocol, pkts, bytes, duration";
    char pdu[32];
    for (int i = 1; i <= pdu_num; i++) {
        sprintf(pdu, ", PDU%d", i);
        strcat(table_head, pdu);
    }

    sprintf(sql, "INSERT INTO %s(%s) VALUES\n", table_name, table_head);

    int insert_size = insert_batch_size < flows_nums - index ? insert_batch_size : flows_nums - index;
    char table_value[1024];
    for (int i = index; i < index + insert_size; i++) {
        if (flows_features[i].first_pkt_time == 0) {
            continue;
        }

        uint32_t flow_duration = (flows_features[i].last_pkt_time - flows_features[i].first_pkt_time) * 1000 / rte_get_timer_hz();

        sprintf(table_value, "(%lu, %u, %u, %hu, %hu, %hu, %lu, %lu, %u", 
                flows_features[i].start_time, flows_features[i].flow.src_ip, flows_features[i].flow.dst_ip, flows_features[i].flow.src_port, flows_features[i].flow.dst_port, flows_features[i].flow.proto_id,
                flows_features[i].pkt_count, flows_features[i].bytes_count, flow_duration);
        
        int pdu_count = flows_features[i].pkt_count < pdu_num ? flows_features[i].pkt_count : pdu_num;

        // for (int j = 0; j < pdu_count; j++) {
        //     sprintf(pdu, ", %hu", flows_features[i].pdu_lens[j]);
        //     strcat(table_value, pdu);
        // }

        for (int j = pdu_count; j < pdu_num; j++) {
            strcat(table_value, ", NULL");
        }

        strcat(table_value, "),\n");
        strcat(sql, table_value);
    }
    sql[strlen(sql) - 2] = ';';

    return insert_size;
}