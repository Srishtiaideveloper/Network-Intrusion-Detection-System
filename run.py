"""
Master Launcher for Network Intrusion Detection System (NIDS) SOC Command Center.
Performs pre-flight integrity checks, trains models if absent, and launches the Streamlit SOC UI.
"""

import sys
import os
import subprocess
import webbrowser
import time

def check_dependencies():
    print("[*] Checking system dependencies...")
    required = ["streamlit", "pandas", "numpy", "sklearn", "xgboost", "shap", "plotly", "scapy", "joblib"]
    missing = []
    for pkg in required:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"[-] Missing dependencies: {missing}")
        print(f"[*] Installing requirements...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    print("[+] All dependencies satisfied.")

def ensure_models_trained():
    if not os.path.exists("models/nids_classifier.joblib") or not os.path.exists("models/data_processor.joblib"):
        print("[*] Model artifacts not found. Starting automated training on real NSL-KDD benchmark...")
        subprocess.check_call([sys.executable, "train_models.py"])
    else:
        print("[+] Trained model artifacts verified.")

def main():
    print("=" * 70)
    print("🛡️  NETWORK INTRUSION DETECTION SYSTEM (NIDS) - SOC MASTER LAUNCHER")
    print("=" * 70)
    
    check_dependencies()
    ensure_models_trained()
    
    port = 8501
    url = f"http://localhost:{port}"
    print(f"\n🚀 Launching SOC Dashboard at {url} ...")
    
    cmd = [
        sys.executable, "-m", "streamlit", "run", "app.py",
        f"--server.port={port}",
        "--server.headless=true",
        "--theme.base=dark"
    ]
    
    try:
        proc = subprocess.Popen(cmd)
        time.sleep(2)
        print("[+] NIDS SOC Command Center is live and operational!")
        print(f"[+] Access the UI at: {url}")
        print("[*] Press Ctrl+C in this terminal to shutdown.")
        proc.wait()
    except KeyboardInterrupt:
        print("\n[*] Shutting down NIDS SOC Command Center.")
        proc.terminate()

if __name__ == "__main__":
    main()
