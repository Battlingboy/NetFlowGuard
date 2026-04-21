import mmap
import ctypes
import os
import time
import sys

MAX_ACTOR_NODES = 64
DRL_STATE_SHM_NAME = "/dev/shm/drl_state_shm"  # shm_open maps to /dev/shm on Linux

class NodeStateSHM(ctypes.Structure):
    _pack_ = 1  # Packed to prevent Python ctypes from breaking the 64-byte alignment
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
        # Pad to 64 bytes total. Fields above take 40 bytes.
        ("pad", ctypes.c_uint8 * 24),
    ]

class DRLStateSHM(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("magic", ctypes.c_uint32),
        ("active_nodes", ctypes.c_uint32),
        ("update_count", ctypes.c_uint64),
        # CRITICAL FIX: C Compiler added 48 bytes of implicit padding here!
        # Because `node_state_shm` has `__attribute__((aligned(64)))`, 
        # the array must start at a 64-byte aligned boundary.
        # magic + active_nodes + update_count = 16 bytes.
        # Next 64-byte boundary is at offset 64.
        # 64 - 16 = 48 bytes of padding.
        ("pad0", ctypes.c_uint8 * 48), 
        ("nodes", NodeStateSHM * MAX_ACTOR_NODES),
    ]

def read_state():
    try:
        fd = os.open(DRL_STATE_SHM_NAME, os.O_RDONLY)
    except FileNotFoundError:
        print(f"Waiting for SHM segment {DRL_STATE_SHM_NAME} to be created by DPDK...")
        return
        
    shm_size = ctypes.sizeof(DRLStateSHM)
    m = mmap.mmap(fd, shm_size, mmap.MAP_SHARED, mmap.PROT_READ)
    
    init_snap = DRLStateSHM.from_buffer_copy(m)
    if init_snap.magic != 0xD8A7A7A5:
        print("Invalid magic number! SHM might not be fully initialized.")
        m.close()
        os.close(fd)
        return

    while True:
        # Seqlock tear-free reading
        m.seek(8)
        count1 = int.from_bytes(m.read(8), sys.byteorder)
        if count1 % 2 != 0:
            continue
        
        m.seek(0)
        snapshot_bytes = m.read(shm_size)
        
        m.seek(8)
        count2 = int.from_bytes(m.read(8), sys.byteorder)
        
        if count1 == count2:
            local_shm = DRLStateSHM.from_buffer_copy(snapshot_bytes)
            break
            
    os.system('clear' if os.name == 'posix' else 'cls')
    print(f"--- Python DRL State SHM Monitor (Update Count: {local_shm.update_count}) ---")
    active_count = 0
    for i in range(MAX_ACTOR_NODES):
        node = local_shm.nodes[i]
        if node.tsc_timestamp > 0:
            active_count += 1
            print(f"Node {i:2} | Seq: {node.seq_num:<8} | Anomaly: {node.anomaly_rate / 100.0:5.2f}% | " 
                  f"MemFree: {node.mempool_free:<8} | RxPPS: {node.rx_pps:<8} | Flow: {node.total_flows} | BPS: {node.rx_bps}")
                  
    if active_count == 0:
        print("No active nodes detected yet.")
    
    m.close()
    os.close(fd)

if __name__ == "__main__":
    print("Starting POSIX SHM Python Zero-Copy Observer...")
    try:
        while True:
            read_state()
            time.sleep(1) # Monitor at 1Hz
    except KeyboardInterrupt:
        print("\nStopped.")
