import asyncio
import os
import signal
import subprocess
import json
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
import uvicorn

app = FastAPI()

DPDK_PROCESS = None
CONFIG_PATH = "node_config.json"

def load_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"error": "Config file not found."}

@app.get("/api/handshake")
async def handshake():
    config = load_config()
    return config

@app.post("/api/dpdk/start")
async def start_dpdk():
    global DPDK_PROCESS
    if DPDK_PROCESS and DPDK_PROCESS.poll() is None:
        raise HTTPException(status_code=400, detail="DPDK process is already running.")
    
    try:
        # Run run.sh non-blocking, discard stdout/stderr to completely decouple from python IO
        # We use preexec_fn=os.setsid to start it in its own process group
        DPDK_PROCESS = subprocess.Popen(
            ["sudo", "./run.sh"], 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
        
    return {"message": "DPDK process started.", "pid": DPDK_PROCESS.pid}

@app.post("/api/dpdk/stop")
async def stop_dpdk():
    global DPDK_PROCESS
    if not DPDK_PROCESS or DPDK_PROCESS.poll() is not None:
        raise HTTPException(status_code=400, detail="DPDK process is not running.")
    
    try:
        # Send SIGINT to the process group because run.sh spawns the actual binary
        # We need sudo privileges to kill process group if python doesn't have it
        # Assuming python runs with sudo, this will work. If not, fallback to sudo kill
        os.killpg(os.getpgid(DPDK_PROCESS.pid), signal.SIGINT)
        
        # Wait up to 5 seconds for graceful shutdown
        try:
            DPDK_PROCESS.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
            
    except ProcessLookupError:
        pass # Process already dead
    except Exception as e:
        # fallback if os.killpg fails due to permissions without sudo
        try:
            subprocess.run(["sudo", "kill", "-INT", f"-{os.getpgid(DPDK_PROCESS.pid)}"], check=False)
        except Exception:
            pass
        
    DPDK_PROCESS = None
    return {"message": "SIGINT sent to DPDK process and process group."}

@app.get("/api/anomalies/latest")
async def latest_anomalies():
    file_path = "csv/anomalies.csv"
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found.")
    
    try:
        # highly efficient OS-level tail command
        out = subprocess.check_output(["tail", "-n", "100", file_path])
        return {"data": out.decode("utf-8", errors="replace")}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/anomalies/download")
async def download_anomalies():
    file_path = "csv/anomalies.csv"
    if not os.path.exists(file_path):
         raise HTTPException(status_code=404, detail="File not found.")
    return FileResponse(file_path, filename="anomalies.csv")

@app.get("/api/dpdk/jfi")
async def get_jfi():
    jfi_path = "csv/jfi_stats.txt"
    if not os.path.exists(jfi_path):
        return {"jfi": 1.0, "message": "JFI stats not yet available."}
        
    try:
        with open(jfi_path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            
        if not content:
            return {"jfi": 1.0}
            
        # Parse the comma separated loads
        loads = [float(x) for x in content.split(",") if x.strip()]
        
        n = len(loads)
        if n == 0:
            return {"jfi": 1.0}
            
        sum_loads = sum(loads)
        sum_sq_loads = sum(x*x for x in loads)
        
        if sum_sq_loads == 0:
            return {"jfi": 1.0}
            
        jfi = (sum_loads * sum_loads) / (n * sum_sq_loads)
        
        # We also expose raw loads so the frontend/learner can display per-core stats if it wants
        return {"jfi": jfi, "raw_loads": loads}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run("actor_api:app", host="0.0.0.0", port=12353, reload=False)
