# Learner 节点 BFF 网关 API 接口规范

本文档定义了调度机（Learner Node）提供的 FastAPI 聚合网关接口规范。网关运行在被反向代理的 `12353` 端口，承担着对下分布式控制 4台 Actor执行机，对上为 Vue 动态实时大屏提供高密度、零延时的高频数字孪生数据服务的核心职能。

---

## 1. 核心高速通道

### 1.1 数字孪生全息遥测流 (WebSocket)
- **协议**: `WebSocket`
- **路径**: `/ws/telemetry`
- **频率**: `1Hz` (每秒强制推送一次)
- **描述**: 直接穿透到底层共享内存（SHM）结合 HTTP 状态聚合，将 RL的即时奖励、各个从机的流量、以及安全告警情况打包推送，支撑大屏动态图表。
- **推送体格式**:
```json
{
  "timestamp": 1712765893.1245,
  "learner": {
    "reward": 3.45,
    "reta_bucket_migrations": 12,
    "total_fwd_pps": 4501239,
    "packet_loss_rate": 0.0001
  },
  "actors": [
    {
      "node_id": 17,
      "jfi": 0.95,
      "pps": 110123,
      "bps": 89012341,
      "anomaly_rate": 0,
      "mempool_free": 1540,
      "compute_margin": 120
    }
  ]
}
```

---

## 2. 集群拓扑与生命周期控制

### 2.1 获取集群拓扑图谱
- **请求方式**: `GET /api/cluster/info`
- **描述**: 网关主动向下层的所有机器发送握手协议包，检查所有硬件探活状态，并强制覆写正确的下层网卡物理 ID 数据对齐暴露给前端。

### 2.2 一键暴力点火启动
- **请求方式**: `POST /api/cluster/start`
- **描述**: 全局发号施令，多线程并发拉起所有 Actor 从机，清理历史残留的强化学习奖励，并在隔离环境（Process Group）拉起本地长驻的 DPDK 数据流和 RL Python 分析脚本。

### 2.3 全网联合优雅停机 (含自动归档)
- **请求方式**: `POST /api/cluster/stop`
- **描述**: 除了下发 `SIGINT` 中断子网并清理大页内存外，该接口被设计为**阻塞调用**——它会静默等待所有硬件队列释放，然后立刻强制抽取全网数据进行 Pandas 数据清洗合并，形成一次实验闭环归档入册。

---

## 3. 高级态势日志与数据清洗集

### 3.1 跨节点警告实时透传聚合
- **请求方式**: `GET /api/cluster/anomalies/latest`
- **描述**: 为大屏的异动警告轮播表提供服务。它并行向全部执行机抓捕最新告警字符串日志，在内存级剔除多余脏数据与冗余表头，强行植入统一标准 `Source IP` 表头并整合返回大跨度文本。
- **单机透传版本**: `GET /api/node/{dpdk_id}/anomalies` 仅返回某一台制定节点的末尾日志。

### 3.2 离线并行 Pandas 去重清洗
- **请求方式**: `POST /api/anomalies/sync_all_and_merge`
- **描述**: 并发下载 4 个机器生成的所有被网络抓包留存下的攻击日志。通过 Python Numpy/Pandas 级别依据「五元组结构」和「系统级时间戳」进行严格并表与硬排重。
- *备注: 一般由 POST /stop 自动触发，无须前端干预。*

### 3.3 数据集原生获取通道
- **汇总归档下载**: `GET /api/anomalies/download/merged` (用于获取上面步骤 3.2 洗出来的全局纯洁数据)
- **单兵追踪下载**: `GET /api/anomalies/download/node/{dpdk_id}` (用于定向查杀分析针对特定的单节点日志)

---

## 4. 科研自动化台账系统 (History Archive)

### 4.1 获取往期绝版实验列表
- **请求方式**: `GET /api/history/logs`
- **描述**: 浏览本系统留存的科研档案记录，每次发版实验的运行时长和绝对时间皆在表内。
- **返回响应**:
```json
[
  {
    "seq_num": 1,
    "start_time": "2026-04-10 22:34:10",
    "end_time": "2026-04-10 23:25:12",
    "duration_formatted": "51m 2s",
    "filename": "anomalies_exp_1.csv"
  }
]
```

### 4.2 调取绝版实验历史副本下载
- **请求方式**: `GET /api/history/download/{seq_num}`
- **描述**: 直接由浏览器发起请求，获取并下载对应实验批次的归档合并清洗日志表。

---

## 5. RL 模型 OTA 热装载

### 5.1 模型替换升级
- **请求方式**: `POST /api/learner/upload_model`
- **形式**: `multipart/form-data`
- **字段**: `file` (必须为 .zip)
- **描述**: 前端将最新的 Stable-Baselines3 强化学习模型参数包传给后端，后端会自动解析当前的最新步数并 +1 重命名入库，促使环境监控器平滑热换血并加载最新大模型。
