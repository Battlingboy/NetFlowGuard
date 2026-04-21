import time
import os
import sys
import mmap
import ctypes
import numpy as np
import gymnasium as gym
from gymnasium import spaces
from stable_baselines3 import PPO
from stable_baselines3.common.vec_env import DummyVecEnv, VecNormalize
from stable_baselines3.common.callbacks import CheckpointCallback
from stable_baselines3.common.logger import configure
import signal
import atexit
import csv
import glob
import re

global_m_action = None
global_shm_action_fd = None

def cleanup_action_shm():
    global global_m_action, global_shm_action_fd
    if global_m_action is not None:
        try:
            action_struct = DRLActionSHM.from_buffer(global_m_action)
            action_struct.magic = 0x00000000 
            action_struct.action_seq = 0
            global_m_action.close()
        except Exception as e:
            print(f"Error during Action SHM cleanup: {e}")
    
    if global_shm_action_fd is not None:
        try:
            os.close(global_shm_action_fd)
        except:
            pass
    print("\n[Cleanup] Action SHM strictly neutralized. Safe to exit.")

atexit.register(cleanup_action_shm)
signal.signal(signal.SIGINT, lambda sig, frame: sys.exit(0))
signal.signal(signal.SIGTERM, lambda sig, frame: sys.exit(0))

MAX_ACTOR_NODES = 64
DRL_STATE_SHM_NAME = "/dev/shm/drl_state_shm"
DRL_ACTION_SHM_NAME = "/dev/shm/drl_action_shm"
RETA_SIZE = 512

class NodeStateSHM(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("seq_num", ctypes.c_uint32),
        ("idle_pol_rat", ctypes.c_uint16),
        ("anomaly_rate", ctypes.c_uint16),
        ("rx_pps", ctypes.c_uint32),
        ("imissed_pps", ctypes.c_uint32),
        ("mempool_free", ctypes.c_uint32),
        ("total_flows", ctypes.c_uint32),
        ("rx_bps", ctypes.c_uint64),
        ("tsc_timestamp", ctypes.c_uint64),
        ("pad", ctypes.c_uint8 * 24),
    ]

class DRLStateSHM(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("magic", ctypes.c_uint32),
        ("active_nodes", ctypes.c_uint32),
        ("update_count", ctypes.c_uint64),
        ("pad0", ctypes.c_uint8 * 48), 
        ("nodes", NodeStateSHM * MAX_ACTOR_NODES),
        ("initial_reta", ctypes.c_uint8 * 512),
        ("bucket_totals", ctypes.c_uint64 * 512)
    ]

class DRLActionSHM(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("magic", ctypes.c_uint32),
        ("pad0", ctypes.c_uint32),
        ("action_seq", ctypes.c_uint64),
        ("reta_buckets", ctypes.c_uint8 * 512),
        ("pad1", ctypes.c_uint8 * 48)
    ]


class DPDKTrafficEnv(gym.Env):

    def __init__(self, active_nodes, active_node_ids):
        super(DPDKTrafficEnv, self).__init__()
        self.active_nodes = active_nodes
        self.active_node_ids = active_node_ids
        self.action_seq = 0
        self.is_first_action = True
        self.bad_steps = 0
        
        
        self.csv_log_path = "./rl_logs/dpdk_env_log.csv"
        os.makedirs("./rl_logs/", exist_ok=True)
        if not os.path.exists(self.csv_log_path):
            with open(self.csv_log_path, "w", newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["Tick", "Reward", "Fairness_Net", "Mempool", "Fairness_Comp", "Quotas_Pct", "Mvd", "Mean_CV_Net", "Min_Headroom", "Bucket_Change_Counts_Array", "State_Obs_Array"])
        
        
        self.last_target_buckets = np.zeros(512, dtype=np.uint8)
        self.bucket_age_map = np.zeros(512, dtype=np.int32)
        self.historic_bucket_totals = np.zeros(512, dtype=np.uint64)
        self.bucket_change_counts = np.zeros(512, dtype=np.int32)
        
        
        self.action_space = spaces.Box(low=-1.0, high=1.0, shape=(self.active_nodes,), dtype=np.float32)
        
        
        self.observation_space = spaces.Box(low=0, high=np.inf, shape=(self.active_nodes, 7), dtype=np.float32)
        
        
        self.fd = os.open(DRL_STATE_SHM_NAME, os.O_RDONLY)
        self.m = mmap.mmap(self.fd, ctypes.sizeof(DRLStateSHM), mmap.MAP_SHARED, mmap.PROT_READ)
        
        
        global global_m_action, global_shm_action_fd
        try:
            self.shm_action_fd = os.open(DRL_ACTION_SHM_NAME, os.O_RDWR | os.O_CREAT, 0o666)
            os.ftruncate(self.shm_action_fd, ctypes.sizeof(DRLActionSHM))
            self.m_action = mmap.mmap(self.shm_action_fd, ctypes.sizeof(DRLActionSHM), mmap.MAP_SHARED, mmap.PROT_WRITE | mmap.PROT_READ)
            
            
            global_m_action = self.m_action
            global_shm_action_fd = self.shm_action_fd
            
            
            init_action = DRLActionSHM.from_buffer(self.m_action)
            init_action.magic = 0x00000000
            init_action.action_seq = 0
        except Exception as e:
            print(f"Failed to create Action SHM: {e}")
            sys.exit(1)
            
        
        self.historic_totals = {
            "flows": np.zeros(self.active_nodes, dtype=np.int64),
            "drops": np.zeros(self.active_nodes, dtype=np.int64)
        }
        
        
        self.last_action_probs = np.ones(self.active_nodes) / self.active_nodes

    def _read_shm_state(self):
        
        while True:
            self.m.seek(8)
            count1 = int.from_bytes(self.m.read(8), sys.byteorder)
            if count1 % 2 != 0:
                continue
            self.m.seek(0)
            snapshot = self.m.read(ctypes.sizeof(DRLStateSHM))
            self.m.seek(8)
            count2 = int.from_bytes(self.m.read(8), sys.byteorder)
            if count1 == count2:
                return DRLStateSHM.from_buffer_copy(snapshot)

    def step(self, action):
        
        shm_data = self._read_shm_state()
        current_bucket_totals = np.ctypeslib.as_array(shm_data.bucket_totals, shape=(512,))
        
        
        current_bucket_pps = current_bucket_totals - self.historic_bucket_totals
        current_bucket_pps[current_bucket_pps > 100000000] = 0
        self.historic_bucket_totals = current_bucket_totals.copy()
        
        total_pps = np.sum(current_bucket_pps)
        if total_pps == 0:
            total_pps = 1

        
        target_buckets = np.copy(self.last_target_buckets)
        moved = 0
        
        
        if self.is_first_action:
            
            hardware_buckets = np.ctypeslib.as_array(shm_data.initial_reta, shape=(512,))
            self.last_target_buckets = np.copy(hardware_buckets)
            target_buckets = np.copy(hardware_buckets)
            
            
            counts = np.bincount(hardware_buckets, minlength=self.active_nodes)[:self.active_nodes]
            if np.sum(counts) > 0 and np.max(counts) < 512:
                action_probs = counts / np.sum(counts)
            else:
                print("\n[RL-WARNING] Received malformed initial RETA. Fallbacking to uniform SWRR.")
                action_probs = np.ones(self.active_nodes) / self.active_nodes
                for b in range(512):
                    target_buckets[b] = b % self.active_nodes
                self.last_target_buckets = np.copy(target_buckets)
                
            self.last_action_probs = action_probs
            self.is_first_action = False
        else:
            
            base_quotas = np.ones(self.active_nodes) / self.active_nodes
            offsets = action * 0.05
            new_probs = base_quotas + offsets
            
            
            action_probs = 0.5 * getattr(self, 'last_action_probs', new_probs) + 0.5 * new_probs
            
            
            action_probs = np.clip(action_probs, 0.01, 0.99)
            action_probs = action_probs / np.sum(action_probs)
            self.last_action_probs = action_probs
            
            
            target_capacity = action_probs * total_pps
            
            
            current_capacity = np.zeros(self.active_nodes)
            for b in range(512):
                qid = target_buckets[b]
                if qid < self.active_nodes:
                    current_capacity[qid] += current_bucket_pps[b]
                    
            
            deficits = target_capacity - current_capacity
            
            max_moves = 512
            receivers = np.argsort(deficits)[::-1]
            
            for r in receivers:
                if deficits[r] <= 0 or moved >= max_moves: break
                
                donors = np.argsort(deficits)
                for d in donors:
                    if deficits[d] >= 0 or deficits[r] <= 0 or moved >= max_moves: break
                    
                    d_buckets = np.where(target_buckets == d)[0]
                    if len(d_buckets) <= 1: continue
                    
                    
                    d_ages = self.bucket_age_map[d_buckets]
                    sorted_idxs = np.argsort(d_ages)
                    
                    for idx in sorted_idxs:
                        b = d_buckets[idx]
                        b_pps = current_bucket_pps[b]
                        
                        target_buckets[b] = r
                        deficits[r] -= b_pps
                        deficits[d] += b_pps
                        moved += 1
                        
                        if deficits[r] <= 0 or moved >= max_moves:
                            break
                            
        
        for b in range(512):
            if target_buckets[b] == self.last_target_buckets[b]:
                self.bucket_age_map[b] += 1
            else:
                self.bucket_age_map[b] = 0
                self.bucket_change_counts[b] += 1
                
        self.last_target_buckets = np.copy(target_buckets)
        
        
        self.action_seq += 1
        action_struct = DRLActionSHM.from_buffer(self.m_action)
        ctypes.memmove(action_struct.reta_buckets, target_buckets.ctypes.data, 512)
        
        
        if action_struct.magic == 0x00000000:
            action_struct.magic = 0xAC710055
            
        action_struct.action_seq = self.action_seq
        
        
        time.sleep(1.0)
        
        
        obs_buffer = []
        pps_buffer, headroom_buffer, mempool_buffer = [], [], []
        
        
        initial_shm = self._read_shm_state()
        active_idx = 0
        for i in range(MAX_ACTOR_NODES):
            if initial_shm.nodes[i].tsc_timestamp > 0 and active_idx < self.active_nodes:
                self.historic_totals["flows"][active_idx] = initial_shm.nodes[i].total_flows
                
                active_idx += 1
        
        sample_count = 40 # 【超长曝光抗噪声】：每 100ms 一帧，集齐 4 秒 (40帧) 观测期，加上前面的 sleep(1.0)，一步耗时 5 秒
        for _ in range(sample_count):
            shm_data = self._read_shm_state()
            frame_obs = np.zeros((self.active_nodes, 7), dtype=np.float32)
            frame_pps, frame_headroom, frame_mempool = 0, [], []
            
            active_idx = 0
            for i in range(MAX_ACTOR_NODES):
                node = shm_data.nodes[i]
                if node.tsc_timestamp > 0 and active_idx < self.active_nodes:
                    # [关键科研修正 Phase 6] 累加型指标转瞬时 Delta 速率，算力余量取瞬时绝对值
                    current_flows = node.total_flows
                    headroom = node.imissed_pps # [异构核心创新] 该字段已被 Actor 侧替换为 Compute Headroom
                    delta_flows = max(0, current_flows - self.historic_totals["flows"][active_idx])
                    
                    self.historic_totals["flows"][active_idx] = current_flows

                    frame_obs[active_idx][0] = node.idle_pol_rat / 1000.0    
                    frame_obs[active_idx][1] = node.anomaly_rate / 10000.0   
                    frame_obs[active_idx][2] = node.rx_pps / 100000.0        
                    frame_obs[active_idx][3] = node.rx_bps / 10000000.0      
                    frame_obs[active_idx][4] = node.mempool_free / 30000.0   
                    frame_obs[active_idx][5] = delta_flows / 1000.0
                    frame_obs[active_idx][6] = headroom / 100000.0
                    
                    frame_pps += node.rx_pps
                    frame_headroom.append(headroom)
                    frame_mempool.append(node.mempool_free)
                    active_idx += 1
                    
            obs_buffer.append(frame_obs)
            pps_buffer.append(frame_pps)
            headroom_buffer.append(frame_headroom)
            mempool_buffer.append(frame_mempool)
            time.sleep(0.1)
            
        
        obs_array = np.array(obs_buffer)
        final_obs = np.mean(obs_array, axis=0)
        max_obs = np.max(obs_array, axis=0)
        
        
        min_headroom = np.min(headroom_buffer) 
        
        
        def get_cv(arr, smooth=0.1):
            mean_val = np.mean(arr) + smooth
            return np.std(arr) / mean_val
            
        
        cv_pps = get_cv(final_obs[:, 2], 0.1)
        cv_bps = get_cv(final_obs[:, 3], 0.1)
        cv_flows = get_cv(final_obs[:, 5], 0.1)
        cv_net = (cv_pps + cv_bps + cv_flows) / 3.0
        
        reward_net_fairness = -5.0 * cv_net
        
        
        cv_comp = get_cv(final_obs[:, 6], 0.1)
        reward_comp_fairness = -40.0 * cv_comp
        
        
        mempool_arr = final_obs[:, 4]
        reward_mempool = -2.0 * get_cv(mempool_arr, 0.1)
        
        
        reward = reward_net_fairness + reward_comp_fairness + reward_mempool
        
        
        mvd = moved if 'moved' in locals() else 0
        probs_str = "/".join([f"{p*100:.1f}" for p in self.last_action_probs])
        print(f"TICK ({self.action_seq:4}) | R: {reward:7.2f} | Fn:{reward_net_fairness:6.2f} Fc:{reward_comp_fairness:6.2f} M:{reward_mempool:5.2f} | Quotas: [{probs_str}] | Mvd: {mvd}")
        
        
        try:
            with open(self.csv_log_path, "a", newline='') as f:
                writer = csv.writer(f)
                bucket_change_str = " ".join(map(str, self.bucket_change_counts))
                state_obs_str = " ".join([f"{x:.4f}" for x in final_obs.flatten()])
                writer.writerow([self.action_seq, f"{reward:.4f}", f"{reward_net_fairness:.4f}", 
                                 f"{reward_mempool:.4f}", f"{reward_comp_fairness:.4f}", probs_str, mvd, f"{cv_net:.4f}", min_headroom, bucket_change_str, state_obs_str])
        except Exception as e:
            pass
        
        
        if cv_net > 0.6:
            self.bad_steps += 1
        else:
            self.bad_steps = 0
            
        done = self.bad_steps >= 5
        if done:
            print("\n[RL-JUDGE] Tipping point reached! Environment declared DEAD (Accumulated Extreme Inequality). Triggering Rebirth...\n")
            
        truncated = False
        info = {}
        
        return final_obs, reward, done, truncated, info

    def reset(self, seed=None):
        super().reset(seed=seed)
        self.bad_steps = 0
        self.is_first_action = True
        
        
        print("\n[RL-RESET] Formatting hardware RETA to Unified Round-Robin...")
        target_buckets = np.zeros(512, dtype=np.uint8)
        for b in range(512):
            target_buckets[b] = b % self.active_nodes
            
        self.last_target_buckets = np.copy(target_buckets)
        self.bucket_age_map.fill(0)
        
        self.action_seq += 1
        action_struct = DRLActionSHM.from_buffer(self.m_action)
        ctypes.memmove(action_struct.reta_buckets, target_buckets.ctypes.data, 512)
        if action_struct.magic == 0x00000000:
            action_struct.magic = 0xAC710055
        action_struct.action_seq = self.action_seq
        
        
        time.sleep(3.0)
        
        shm_data = self._read_shm_state()
        obs = np.zeros((self.active_nodes, 7), dtype=np.float32)
        
        active_idx = 0
        for i in range(MAX_ACTOR_NODES):
            node = shm_data.nodes[i]
            if node.tsc_timestamp > 0 and active_idx < self.active_nodes:
                obs[active_idx][0] = node.idle_pol_rat / 1000.0    
                obs[active_idx][1] = node.anomaly_rate / 10000.0   
                obs[active_idx][2] = node.rx_pps / 100000.0        
                obs[active_idx][3] = node.rx_bps / 10000000.0      
                obs[active_idx][4] = node.mempool_free / 30000.0   
                obs[active_idx][5] = node.total_flows / 10000.0    
                obs[active_idx][6] = node.imissed_pps / 1.0
                active_idx += 1
            
        return obs, {}

def detect_active_nodes():

    
    ini_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "forward.ini")
    queue_node_ids = []
    
    try:
        with open(ini_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith("mac_"):
                    
                    mac_str = line.split('=')[1].strip()
                    last_byte = int(mac_str.split(':')[-1], 16)
                    node_id = last_byte & 0x3F
                    queue_node_ids.append(node_id)
        print(f"[INI] Parsed forward.ini Queue→Node mapping: {['Q'+str(i)+'→N'+str(n) for i,n in enumerate(queue_node_ids)]}")
    except Exception as e:
        print(f"[WARNING] Cannot parse forward.ini ({e}), falling back to SHM scan order")
        queue_node_ids = []
    
    
    print(f"Waiting for DPDK to start and create SHM segment {DRL_STATE_SHM_NAME}...")
    while True:
        try:
            fd = os.open(DRL_STATE_SHM_NAME, os.O_RDONLY)
            break
        except FileNotFoundError:
            time.sleep(1)
            
    shm_size = ctypes.sizeof(DRLStateSHM)
    m = mmap.mmap(fd, shm_size, mmap.MAP_SHARED, mmap.PROT_READ)
    
    print("SHM found. Waiting for Actor nodes to send telemetry data...")
    
    
    while True:
        m.seek(8)
        count1 = int.from_bytes(m.read(8), sys.byteorder)
        if count1 % 2 != 0:
            continue
        m.seek(0)
        snapshot = m.read(shm_size)
        m.seek(8)
        count2 = int.from_bytes(m.read(8), sys.byteorder)
        
        if count1 == count2:
            shm_data = DRLStateSHM.from_buffer_copy(snapshot)
            if shm_data.magic == 0xD8A7A7A5:
                if queue_node_ids:
                    
                    all_alive = all(shm_data.nodes[nid].tsc_timestamp > 0 for nid in queue_node_ids)
                    if all_alive:
                        break
                else:
                    
                    for i in range(MAX_ACTOR_NODES):
                        if shm_data.nodes[i].tsc_timestamp > 0:
                            queue_node_ids.append(i)
                    if queue_node_ids:
                        break
        time.sleep(1)
            
    m.close()
    os.close(fd)
    
    active_count = len(queue_node_ids)
    return active_count, queue_node_ids

if __name__ == '__main__':
    
    active_nodes, active_node_ids = detect_active_nodes()
    print(f"\n+++ System Detected {active_nodes} Active Actor Nodes: {active_node_ids} +++\n")

    print("Wait for Actor and DPDK subsystem to firmly stabilize...")
    for i in range(4, 0, -1): # Changed from 10 to 4
        print(f"Starting DRL Observer in {i} seconds...", end='\r')
        time.sleep(1)
    print("\nStarting DRL Observer now!                       ")
    
    
    raw_env = DPDKTrafficEnv(active_nodes, active_node_ids)
    
    
    vec_env = DummyVecEnv([lambda: raw_env])
    
    
    env = VecNormalize(vec_env, norm_obs=False, norm_reward=True, gamma=0.99)
    
    
    model_dir = "./rl_models/"
    os.makedirs(model_dir, exist_ok=True)
    
    
    list_of_models = glob.glob(os.path.join(model_dir, "ppo_dpdk_model_*_steps.zip"))
    latest_model_path = None
    latest_vecnorm_path = None
    max_steps = -1
    
    if list_of_models:
        for m_path in list_of_models:
            match = re.search(r'ppo_dpdk_model_(\d+)_steps\.zip', m_path)
            if match:
                steps = int(match.group(1))
                if steps > max_steps:
                    max_steps = steps
                    latest_model_path = m_path
    
                    latest_vecnorm_path = os.path.join(model_dir, f"ppo_dpdk_model_vecnormalize_{steps}_steps.pkl")
    
    if latest_model_path and latest_vecnorm_path and os.path.exists(latest_vecnorm_path):
        print(f"\n[INFO] 发现断点！正在从 {max_steps} 步恢复训练...")
        print(f"=> 模型权重: {latest_model_path}")
        print(f"=> 状态标尺: {latest_vecnorm_path}")
        
        
        env = VecNormalize.load(latest_vecnorm_path, vec_env)
        env.training = True 
        env.norm_reward = True
        
        
        custom_objects = {
            "learning_rate": 3e-4,
            "n_steps": 64,
            "batch_size": 64,
        }
        model = PPO.load(latest_model_path, env=env, custom_objects=custom_objects, device="cpu")
        print("[INFO] 断点环境与模型已成功挂载！")
    else:
        print("\n[INFO] 未发现历史 Checkpoint，正在全新初始化 PPO Agent (MlpPolicy)...")
        model = PPO(
            "MlpPolicy", 
            env, 
            n_steps=64,       
            batch_size=64,     
            n_epochs=10,
            learning_rate=3e-4,
            verbose=1,
            device="cpu"
        )
    
    
    new_logger = configure("./rl_logs/", ["stdout", "csv", "tensorboard"])
    model.set_logger(new_logger)
    
    print("Starting Training / Observation Loop...")
    
    
    checkpoint_callback = CheckpointCallback(
        save_freq=500,
        save_path=model_dir,
        name_prefix='ppo_dpdk_model',
        save_replay_buffer=False,
        save_vecnormalize=True, 
    )
    
    
    model.learn(total_timesteps=100000, callback=checkpoint_callback, reset_num_timesteps=False)
    
    
    print("\nTraining Finished! Saving final model...")
    model.save("ppo_dpdk_final")
    env.save("vec_normalize_final.pkl")
    print("Models and Normalization stats saved successfully. Ready for Inference!")
