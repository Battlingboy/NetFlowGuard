#ifndef GENERATE_QUERY_H
#define GENERATE_QUERY_H

#include <stdio.h>
#include <string.h>

#include "flow_extractor.h"

void generate_create_table_sql(char *sql, const char *table_name, int pdu_num);
int generate_insert_sql(char *sql, const char *table_name, int pdu_num, const struct IPv4FlowFeature flows_features[], int flows_nums, int index, int  insert_batch_size);

#endif