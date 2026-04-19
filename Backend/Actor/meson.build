# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

# meson file, for building this example as part of a main DPDK build.
#
# To build this example as a standalone application with an already-installed
# DPDK instance, use 'make'

project('dpdkcap', 'C',)

allow_experimental_apis = true
incdir = include_directories('/usr/include')
dpdk = dependency('libdpdk')
mysql = dependency('mysqlclient')
pthread =dependency('threads')
cc = meson.get_compiler('c')
m = cc.find_library('m', required : false)
onnxruntime = cc.find_library('onnxruntime', required : false)
sources = files(
        'src/dpdkcap.c',
        'src/core_write.c',
        'src/core_capture.c', 
        'src/statistics.c', 
        'src/pcap.c', 
        'src/utils.c',
        'src/flow_extractor.c',
        'src/generate_query.c',
        'src/mysql_op.c',
        'src/dpdk_lgbm_c_model/main.c',
        'src/dpdk_lgbm_c_model/tu0.c',
        'src/lzo/minilzo/minilzo.c', 
        'src/lzo/lzowrite.c', 
)
executable('dpdk_anomaly_flow_detector', sources, include_directories : incdir, dependencies: [dpdk, mysql, pthread, m, onnxruntime])