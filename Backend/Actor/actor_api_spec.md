# Actor Control Plane API Specification

本文档整理了部署在 Actor 执行机上（端口 `12353`）的管理面 API 接口说明。该 API 旨在提供对 DPDK 数据面进程的非阻塞控制及实时状态监控。

---

## 1. 基础接口 (General)

### 1.1 节点握手 (Handshake)
*   **路由**: `GET /api/handshake`
*   **功能**: 获取当前节点的详细静态硬件与软件配置信息。
*   **返回值**: `node_config.json` 的完整 JSON 内容。
    ```json
    {
      "node_id": "181",
      "hardware": {
        "cpu": {
          "model": "Intel(R) Xeon(R) Gold 5220R CPU @ 2.20GHz",
          "base_frequency": "2.20 GHz",
          "numa_nodes": 2
        },
        "nic": {
          "model": "Ethernet Controller X710 for 10GbE",
          "simplified": "10 Gbps"
        },
        "memory": {
          "full": "128GB DDR4 3200MT/s",
          "simplified": "128GB"
        }
      },
      "software": {
        "os_full": "Debian GNU/Linux 11 (bullseye)",
        "os_simplified": "Debian Linux",
        "kernel": "5.10.0-33-amd64",
        "gcc": "10.2.1",
        "dpdk": "24.03.0",
        "python": "3.9.2"
      },
      "network": {
        "comm_mac": "6C:FE:54:41:F5:51"
      },
      "status": "alive"
    }
    ```

---

## 2. 进程控制接口 (Process Control)

### 2.1 启动 DPDK 进程 (Start)
*   **路由**: `POST /api/dpdk/start`
*   **功能**: 异步执行 `./run.sh` 脚本。
*   **注意**: 
    - 使用 `subprocess.Popen` 实现非阻塞，输出重定向至 `/dev/null` 以保证 0 性能损耗。
    - 若进程已在运行，返回 `400` 错误。
*   **返回值**:
    ```json
    {
      "message": "DPDK process started.",
      "pid": 12345
    }
    ```

### 2.2 停止 DPDK 进程 (Stop)
*   **路由**: `POST /api/dpdk/stop`
*   **功能**: 向 DPDK 进程组发送 `SIGINT` (信号 2) 信号。
*   **注意**: 
    - 触发 C 程序的 `signal_handler` 以优雅释放大页内存。
    - 采用进程组终止机制，确保脚本及其派生的二进制程序同步退出。
*   **返回值**:
    ```json
    {
      "message": "SIGINT sent to DPDK process and process group."
    }
    ```

---

## 3. 日志与分析接口 (Logs & Data)

### 3.1 获取最新异常流快照 (Latest Anomalies)
*   **路由**: `GET /api/anomalies/latest`
*   **功能**: 高效读取 `csv/anomalies.csv` 的最后 100 行。
*   **实现**: 基于 OS 级 `tail` 命令，不占用额外内存。
*   **返回值**:
    ```json
    {
      "data": "timestamp,src_ip,dst_ip...\n(last 100 lines content)"
    }
    ```

### 3.2 离线分析文件下载 (Download CSV)
*   **路由**: `GET /api/anomalies/download`
*   **功能**: 完整下载 `anomalies.csv` 文件。
*   **返回值**: 附件形式的 `.csv` 文件流。

---

## 4. 实时遥测接口 (Telemetry)

### 4.1 负载均衡指数 (JFI Stats)
*   **路由**: `GET /api/dpdk/jfi`
*   **功能**: 计算并返回当前各个 Capture Cores 的 Jain's Fairness Index。
*   **算法**: $JFI = \frac{(\sum x_i)^2}{n \cdot \sum x_i^2}$ (其中 $x_i$ 为第 $i$ 个核心的实时 PPS)。
*   **返回值**:
    ```json
    {
      "jfi": 0.985,
      "raw_loads": [1024, 980, 1050, 1010]
    }
    ```

---

## 错误代码说明
*   **400 Bad Request**: 尝试启动已在运行的进程，或尝试停止未运行的进程。
*   **404 Not Found**: 配置文件或 CSV 结果文件尚未生成。
*   **405 Method Not Allowed**: 使用了错误的 HTTP 方法（例如用 GET 访问 /start 接口）。
*   **500 Internal Server Error**: 系统调用失败或文件权限问题。
