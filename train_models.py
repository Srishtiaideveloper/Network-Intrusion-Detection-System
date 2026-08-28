"""
Model Training & Benchmark Evaluation CLI Pipeline for Real NSL-KDD Dataset.
Downloads real NSL-KDD benchmark data, trains multi-class XGBoost/Random Forest and
Zero-Day Isolation Forest anomaly detector, saves artifacts to models/, and produces
evaluation metrics and sample test datasets.
"""

import sys
import os
import json
import time

if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

import numpy as np
import pandas as pd
from datetime import datetime

from src.data_loader import load_raw_dataset, NIDSDataProcessor, FEATURE_NAMES
from src.models import NIDSMultiClassifier, NIDSAnomalyDetector

def generate_sample_pcap(filepath: str = "data/sample_attacks.pcap"):
    """Creates an authentic sample PCAP file for testing offline PCAP inspection."""
    try:
        from scapy.all import IP, TCP, UDP, wrpcap
        packets = []
        # Normal HTTP request/response
        packets.append(IP(src="192.168.1.50", dst="142.250.190.46")/TCP(sport=52140, dport=80, flags="S")/b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
        packets.append(IP(src="142.250.190.46", dst="192.168.1.50")/TCP(sport=80, dport=52140, flags="SA")/b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!")
        # DNS Query
        packets.append(IP(src="192.168.1.50", dst="8.8.8.8")/UDP(sport=43210, dport=53)/b"DNS QUERY")
        # DoS SYN Flood Packets
        for _ in range(25):
            packets.append(IP(src=f"10.0.0.{np.random.randint(1, 250)}", dst="192.168.1.1")/TCP(sport=np.random.randint(1024, 65535), dport=80, flags="S"))
        # Port Scan Probe Packets
        for port in [21, 22, 23, 25, 80, 443, 8080, 3306]:
            packets.append(IP(src="172.16.0.99", dst="192.168.1.15")/TCP(sport=49152, dport=port, flags="S"))
            
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        wrpcap(filepath, packets)
        print(f"[+] Sample PCAP generated at {filepath} ({len(packets)} packets).")
    except Exception as e:
        print(f"[-] PCAP generation notice: {e}")

def main():
    print("=" * 70)
    print("[*] NETWORK INTRUSION DETECTION SYSTEM (NIDS) - MODEL TRAINER")
    print("=" * 70)
    start_time = time.time()
    
    # 1. Ingestion of Authentic Real Benchmark Data
    print("\n[Step 1/5] Loading authentic NSL-KDD real dataset...")
    df_train, df_test = load_raw_dataset(data_dir="data")
    print(f"  -> Real Training Samples: {len(df_train):,}")
    print(f"  -> Real Test Samples:     {len(df_test):,}")
    print("  -> Attack Category Distribution (Train):")
    for cat, count in df_train['attack_category'].value_counts().items():
        print(f"     * {cat:<10}: {count:>6,} ({count/len(df_train)*100:.1f}%)")

    # 2. Fit Feature Preprocessing Pipeline
    print("\n[Step 2/5] Fitting Feature Transformation & Scaling Pipeline...")
    processor = NIDSDataProcessor()
    X_train_scaled, y_train_multi, y_train_binary = processor.fit_transform(df_train)
    X_test_scaled = processor.transform(df_test)
    y_test_multi = processor.target_encoder.transform(df_test['attack_category'])
    
    os.makedirs("models", exist_ok=True)
    processor.save("models/data_processor.joblib")

    # 3. Train Multi-Class Threat Classifier
    print("\n[Step 3/5] Training Multi-Class Threat Classifier (Random Forest)...")
    clf = NIDSMultiClassifier(model_type='rf', n_estimators=150, max_depth=14)
    clf.fit(X_train_scaled, y_train_multi, class_names=processor.class_names)
    clf.save("models/nids_classifier.joblib")

    # 4. Train Zero-Day Anomaly Detector (Isolation Forest)
    print("\n[Step 4/5] Training Zero-Day Anomaly Detector (Isolation Forest)...")
    normal_mask = (y_train_binary == 0)
    X_normal = X_train_scaled[normal_mask]
    anomaly_detector = NIDSAnomalyDetector(contamination=0.04, n_estimators=100)
    anomaly_detector.fit(X_normal)
    anomaly_detector.save("models/nids_anomaly_detector.joblib")

    # 5. Evaluate on Authentic Real Test Set
    print("\n[Step 5/5] Evaluating on Real Unseen Test Benchmark...")
    eval_metrics = clf.evaluate(X_test_scaled, y_test_multi)
    
    print("-" * 50)
    print(f"  [+] Overall Test Accuracy: {eval_metrics['accuracy']*100:.2f}%")
    print(f"  [+] Weighted Precision:   {eval_metrics['precision']*100:.2f}%")
    print(f"  [+] Weighted Recall:      {eval_metrics['recall']*100:.2f}%")
    print(f"  [+] Weighted F1-Score:    {eval_metrics['f1_score']*100:.2f}%")
    print("-" * 50)

    # Save Metrics & Metadata
    metadata = {
        'training_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'dataset': 'NSL-KDD Real Benchmark',
        'train_samples': len(df_train),
        'test_samples': len(df_test),
        'features_count': len(processor.feature_columns),
        'classes': processor.class_names,
        'metrics': eval_metrics
    }
    with open("models/metrics.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print("[+] Model metadata and test benchmarks saved to models/metrics.json")

    # Generate sample test CSV for immediate upload testing in UI
    print("\n[*] Generating sample real test traffic CSV for UI demo...")
    sample_df = df_test.sample(n=100, random_state=42).copy()
    sample_df.to_csv("data/sample_traffic.csv", index=False)
    print("[+] Saved 100-sample real traffic trace to data/sample_traffic.csv")

    # Generate sample PCAP
    generate_sample_pcap("data/sample_attacks.pcap")

    elapsed = time.time() - start_time
    print(f"\n[+] Full Training & Benchmark Pipeline Completed in {elapsed:.2f}s!")

if __name__ == "__main__":
    main()
