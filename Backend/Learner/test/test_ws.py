import asyncio
import websockets
import json

async def test_telemetry():
    # 注意：如果你在其他机器运行，请把 127.0.0.1 换成 183 服务器的内网 IP
    uri = "ws://127.0.0.1:12353/ws/telemetry"
    print(f"[*] 准备连接至大动脉: {uri}...")
    try:
        async with websockets.connect(uri) as websocket:
            print("[✓] 握手成功！正在持续窃听 1Hz 每秒高频雷达扫描线...\n")
            while True:
                response = await websocket.recv()
                data = json.loads(response)
                print("\n================== 态势雷达 (1 Hz 更新) ==================")
                print(f"⏱️ 绝对时间戳: {data['timestamp']}")
                print(f"🧠 [调度机(Learner)]")
                print(f"   ► 即时 Reward (来源于RL快照): {data['learner']['reward']:>7.2f}")
                print(f"   ► RETA 表格物理迁移数       : {data['learner']['reta_bucket_migrations']:>7}")
                print(f"   ► 全网转发吞吐标量 (PPS)    : {data['learner']['total_fwd_pps']:>7}")
                print(f"   ► 瞬时丢包率评估            : {data['learner']['packet_loss_rate']:>7.3%}")
                
                print(f"💻 [执行机(Actor) 真值阵列]")
                for actor in data["actors"]:
                    print(f"   [Node {actor['node_id']:<2}]"
                          f" JFI:{actor['jfi']:<4.2f} |"
                          f" PPS:{actor['pps']:>9} |"
                          f" BPS:{actor['bps']:>11} |"
                          f" Margin:{actor['compute_margin']:>6} |"
                          f" MemFree:{actor['mempool_free']:>6} |"
                          f" 告警:{actor['anomaly_rate']:>2}"
                    )
    except Exception as e:
        print(f"[X] 连接断开或失败，原因: {e}")

if __name__ == "__main__":
    asyncio.run(test_telemetry())
