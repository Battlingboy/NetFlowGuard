#include "mysql_op.h"


/* 连接MySQL数据库 */
int collect_mysql(MYSQL *mysql_conn, const char *mysql_host, const char *mysql_user, const char *mysql_pass, const char *mysql_db) {
    if (mysql_init(mysql_conn) == NULL) {           // 初始化句柄MySQL
        printf("初始化MySQL失败: %s\n", mysql_error(mysql_conn));
        return -1;
    }

    if (mysql_library_init(0, NULL, NULL)) {    // 初始化MySQL库
        printf("初始化MySQL库失败: %s\n", mysql_error(mysql_conn));
        return -2;
    }

    // Enable LOCAL INFILE
    unsigned int local_infile = 1;
    if (mysql_options(mysql_conn, MYSQL_OPT_LOCAL_INFILE, &local_infile)) {
        printf("设置 LOCAL INFILE 选项失败: %s\n", mysql_error(mysql_conn));
    }

    if (mysql_real_connect(mysql_conn, mysql_host, mysql_user, mysql_pass, mysql_db, 0, NULL, 0) == NULL) {    // 连接MySQL数据库
        printf("连接MySQL数据库失败: %s\n", mysql_error(mysql_conn));
        return -3;
    }

    if (mysql_set_character_set(mysql_conn, "utf8")) {    // 设置字符集
        printf("设置字符集失败: %s\n", mysql_error(mysql_conn));
        return -3;
    }

    printf("连接MySQL数据库成功\n");

    return 0;
}


/* 新建表 */
int create_table(MYSQL *mysql_conn, const char *table_name) {
    char sql[2048] = {0};
    // generate_create_table_sql(sql, table_name, DEFAULT_FLOW_SEQ_LEN);

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
                          "labelOfAnomaly BOOLEAN";
    
    char pdu[32];
    for (int i = 1; i <= DEFAULT_FLOW_SEQ_LEN; i++) {
        sprintf(pdu, ", PDU%d SMALLINT UNSIGNED", i);
        strcat(sql_head, pdu);
    }

    // strcat(sql_head, "PRIMARY KEY (time, sip, dip, sport, dport, protocol)");
    
    sprintf(sql, "CREATE TABLE IF NOT EXISTS %s(%s);", table_name, sql_head);      // 如果表不存在，则新建

    if (mysql_query(mysql_conn, sql)) {    // 执行SQL语句
        printf("创建表失败: %s\n", mysql_error(mysql_conn));
        return -1;
    }

    printf("创建表: %s 成功\n", table_name);

    return 0;
}


/* 处理MySQL命令执行的返回结果 */
int deal_result(MYSQL *mysql_conn, MYSQL_RES *result) {
    MYSQL_ROW res_row;
    int row, col;           // 函数与列数

    col = mysql_num_fields(result);              // 获取结果集中的列数
    for (row = 0; row < mysql_num_rows(result); row++) {
        res_row = mysql_fetch_row(result);          // 获取一行数据
        if (res_row < 0) {
            printf("获取一行数据失败: %s\n", mysql_error(mysql_conn));
            return -1;
        }

        for (int i = 0; i < col; i++) {
            printf("%s\t", res_row[i]);
        }
        printf("\n");
    }

    return 0;
}


/* 查看所有表格 */
int show_tables(MYSQL *mysql_conn) {
    MYSQL_RES *result = NULL;

    if (mysql_query(mysql_conn, "SHOW TABLES")) {    // 执行SQL语句
        printf("查看所有表格失败: %s\n", mysql_error(mysql_conn));
        return -1;
    }

    result = mysql_store_result(mysql_conn);    // 获取结果集
    if (result == NULL) {
        printf("获取结果集失败: %s\n", mysql_error(mysql_conn));
        return -2;
    }

    if (deal_result(mysql_conn, result) != 0) {
        printf("处理结果集失败: %s\n", mysql_error(mysql_conn));
        return -3;
    }

    mysql_free_result(result);    // 释放结果集

    return 0;
}


/* 向表格中插入数据 */
int insert_data(MYSQL *mysql_conn, const char *table_name, const struct IPv4FlowFeature flow_features[], int flow_num) {
    char sql[1024 * INSERT_BATCH_SIZE] = {0};

    for (int i = 0; i < flow_num;) {
        i += generate_insert_sql(sql, table_name, DEFAULT_FLOW_SEQ_LEN, flow_features, flow_num, i, INSERT_BATCH_SIZE);
        if (mysql_query(mysql_conn, sql)) {    // 执行SQL语句
            printf("插入数据失败: %s\n", mysql_error(mysql_conn));
            return -1;
        }
    }

    printf("插入数据成功\n");

    return 0;
}


/* 直接向表格中插入数据(PDU的数目固定为24) */
int insert_data_direct(MYSQL *mysql_conn, const char *table_name, const struct IPv4FlowFeature flow_features[], int flow_num) {
    // char *sql = malloc(256 * INSERT_BATCH_SIZE);
    char sql[256 * INSERT_BATCH_SIZE] = {0};
    const char table_head[] = "time, sip, dip, sport, dport, protocol, pkts, bytes, duration, pdu1, pdu2, pdu3, pdu4, pdu5, pdu6, pdu7, pdu8, pdu9, pdu10, pdu11, pdu12, pdu13, pdu14, pdu15, pdu16, pdu17, pdu18, pdu19, pdu20, pdu21, pdu22, pdu23, pdu24";

    char table_value[256] = {0};
    int insert_count = 0;
    sprintf(sql, "INSERT INTO %s(%s) VALUES\n", table_name, table_head);
    for (int index = 0; index < flow_num; index++) {
        if (flow_features[index].first_pkt_tsc == 0) {
            continue;
        }

        uint32_t flow_duration = (flow_features[index].last_pkt_tsc > flow_features[index].first_pkt_tsc) ? (flow_features[index].last_pkt_tsc - flow_features[index].first_pkt_tsc) : 0;

        sprintf(table_value, "(%lu, %u, %u, %hu, %hu, %hu, %u, %u, %u), ", 
            flow_features[index].first_pkt_tsc, flow_features[index].flow.src_ip, flow_features[index].flow.dst_ip, flow_features[index].flow.src_port, flow_features[index].flow.dst_port, flow_features[index].flow.proto_id, 
            flow_features[index].fwd_pkt_count, flow_features[index].fwd_payload_tot_len, flow_duration);
            //,
            // flow_features[index].pdu_lens[0], flow_features[index].pdu_lens[1], flow_features[index].pdu_lens[2], flow_features[index].pdu_lens[3], flow_features[index].pdu_lens[4], 
            // flow_features[index].pdu_lens[5], flow_features[index].pdu_lens[6], flow_features[index].pdu_lens[7], flow_features[index].pdu_lens[8], flow_features[index].pdu_lens[9], 
            // flow_features[index].pdu_lens[10], flow_features[index].pdu_lens[11], flow_features[index].pdu_lens[12], flow_features[index].pdu_lens[13], flow_features[index].pdu_lens[14], 
            // flow_features[index].pdu_lens[15], flow_features[index].pdu_lens[16], flow_features[index].pdu_lens[17], flow_features[index].pdu_lens[18], flow_features[index].pdu_lens[19], 
            // flow_features[index].pdu_lens[20], flow_features[index].pdu_lens[21], flow_features[index].pdu_lens[22], flow_features[index].pdu_lens[23]);
        strcat(sql, table_value);

        insert_count += 1;

        if (insert_count % INSERT_BATCH_SIZE == 0 && insert_count != 0) {
            sql[strlen(sql) - 2] = ';';
            if (mysql_query(mysql_conn, sql)) {    // 执行SQL语句
                printf("插入数据失败: %s\n", mysql_error(mysql_conn));
                return -1;
            }
            sprintf(sql, "INSERT INTO %s(%s) VALUES\n", table_name, table_head);

        }
    }
    return 0;
}


/* 直接将CSV文件导入数据库 */
int load_file_into_mysql(MYSQL *mysql_conn, const char *table_name, const char *file_name, int pdu_num) {
    char sql[1024] = {0};
    sprintf(sql, "LOAD DATA LOCAL INFILE '%s' INTO TABLE %s FIELDS TERMINATED BY ',' LINES TERMINATED BY '\\n' IGNORE 1 ROWS (time, sip, dip, sport, dport, protocol, pkts, bytes, duration,", file_name, table_name);
    for (int i = 0; i < pdu_num; i++) {
        sprintf(sql + strlen(sql), " PDU%d,", i + 1);
    }
    sql[strlen(sql) - 1] = ')';
    strcat(sql, ";");

    if (mysql_query(mysql_conn, sql)) {    // 执行SQL语句
        printf("插入数据失败: %s\n", mysql_error(mysql_conn));
        return -1;
    }

    return 0;
}


// int main() {
//     MYSQL mysql_conn;

//     if (collect_mysql(&mysql_conn) != 0) {
//         return -1;
//     }

//     if (create_table(&mysql_conn, "Device_3544302408") != 0) {
//         return -1;
//     }

//     if (show_tables(&mysql_conn) != 0) {
//         return -1;
//     }

//     static struct IPv4FlowFeature flows_features[flow_num];
//     srand((unsigned)time(NULL));
//     for (int i = 0; i < flow_num; i++) {
//         flows_features[i].flow.src_ip = 3544302408;
//         flows_features[i].flow.dst_ip = rand();
//         flows_features[i].flow.src_port = rand();
//         flows_features[i].flow.dst_port = rand();
//         flows_features[i].flow.proto_id = rand();
//         flows_features[i].first_pkt_time = rand();
//         flows_features[i].last_pkt_time = rand();
//         flows_features[i].pkt_count = rand() % 32;
//         flows_features[i].bytes_count = rand();
//         flows_features[i].pdu_lens[0] = rand();
//         flows_features[i].pdu_lens[1] = rand();
//         flows_features[i].pdu_lens[2] = rand();
//         flows_features[i].pdu_lens[3] = rand();
//         flows_features[i].pdu_lens[4] = rand();
//         flows_features[i].pdu_lens[5] = rand();
//         flows_features[i].pdu_lens[6] = rand();
//         flows_features[i].pdu_lens[7] = rand();
//         flows_features[i].pdu_lens[8] = rand();
//         flows_features[i].pdu_lens[9] = rand();
//         flows_features[i].pdu_lens[10] = rand();
//         flows_features[i].pdu_lens[11] = rand();
//         flows_features[i].pdu_lens[12] = rand();
//         flows_features[i].pdu_lens[13] = rand();
//         flows_features[i].pdu_lens[14] = rand();
//         flows_features[i].pdu_lens[15] = rand();
//         flows_features[i].pdu_lens[16] = rand();
//         flows_features[i].pdu_lens[17] = rand();
//         flows_features[i].pdu_lens[18] = rand();
//         flows_features[i].pdu_lens[19] = rand();
//         flows_features[i].pdu_lens[20] = rand();
//         // flows_features[i].pdu_lens[21] = rand();
//         // flows_features[i].pdu_lens[22] = rand();
//         // flows_features[i].pdu_lens[23] = rand();
//     }

//     // if (insert_data(&mysql_conn, "Device_3544302408", flows_features) != 0) {
//     //     return -1;
//     // }

//     if (insert_data_direct(&mysql_conn, "Device_3544302408", flows_features) != 0) {
//         return -1;
//     }

//     mysql_close(&mysql_conn);    // 关闭连接
//     mysql_library_end();         // 关闭MySQL库

//     return 0;
// }
