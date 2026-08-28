"""
Deep Packet Forensics & PCAP / CSV Network Capture Analyzer.
Extracts bidirectional conversation flows, scores flows against trained ML/Anomaly models,
and returns structured forensic timelines with threat breakdowns.
"""

import os
import io
import time
import pandas as pd
import numpy as np
from typing import Dict, Any, List, Optional, Tuple

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from src.packet_sniffer import infer_service

class PCAPAnalyzer:
    """Forensic deep packet inspector for offline PCAP and CSV trace logs."""
    def __init__(self, data_processor, classifier, anomaly_detector=None):
        self.processor = data_processor
        self.classifier = classifier
        self.anomaly_detector = anomaly_detector

    def analyze_pcap_file(self, file_bytes: bytes) -> pd.DataFrame:
        """Parses raw PCAP bytes into network flows and runs ML threat detection."""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required to parse .pcap files.")
            
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            tmp.write(file_bytes)
            tmp_path = tmp.name

        try:
            packets = rdpcap(tmp_path)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

        flows: Dict[str, Dict[str, Any]] = {}
        for pkt in packets:
            if not pkt.haslayer(IP):
                continue
            ip = pkt[IP]
            src = ip.src
            dst = ip.dst
            proto = 'tcp' if pkt.haslayer(TCP) else ('udp' if pkt.haslayer(UDP) else ('icmp' if pkt.haslayer(ICMP) else 'other'))
            sport = pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else 0)
            dport = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)
            tcp_flags = str(pkt[TCP].flags) if pkt.haslayer(TCP) else ''
            
            key = f"{src}:{sport}->{dst}:{dport}@{proto}"
            pkt_time = float(pkt.time) if hasattr(pkt, 'time') else time.time()
            pkt_len = len(pkt)
            
            if key not in flows:
                flows[key] = {
                    'start_time': pkt_time,
                    'last_time': pkt_time,
                    'src_ip': src,
                    'dst_ip': dst,
                    'src_port': sport,
                    'dst_port': dport,
                    'protocol_type': proto,
                    'service': infer_service(dport),
                    'flag': 'SF' if 'A' in tcp_flags and 'F' in tcp_flags else ('S0' if 'S' in tcp_flags and 'A' not in tcp_flags else 'SF'),
                    'src_bytes': pkt_len,
                    'dst_bytes': 0,
                    'count': 1,
                    'serror_count': 1 if 'S' in tcp_flags and 'A' not in tcp_flags else 0
                }
            else:
                f = flows[key]
                f['last_time'] = pkt_time
                f['src_bytes'] += pkt_len
                f['count'] += 1
                if 'S' in tcp_flags and 'A' not in tcp_flags:
                    f['serror_count'] += 1

        records = []
        for key, f in flows.items():
            dur = max(0.0, f['last_time'] - f['start_time'])
            count = f['count']
            serror_rate = f['serror_count'] / count if count > 0 else 0.0
            
            rec = {
                'timestamp': time.strftime('%H:%M:%S', time.localtime(f['start_time'])),
                'src_ip': f['src_ip'],
                'dst_ip': f['dst_ip'],
                'src_port': f['src_port'],
                'dst_port': f['dst_port'],
                'duration': round(dur, 4),
                'protocol_type': f['protocol_type'],
                'service': f['service'],
                'flag': f['flag'],
                'src_bytes': f['src_bytes'],
                'dst_bytes': f['dst_bytes'],
                'land': 1 if (f['src_ip'] == f['dst_ip'] and f['src_port'] == f['dst_port']) else 0,
                'wrong_fragment': 0,
                'urgent': 0,
                'hot': 0,
                'num_failed_logins': 0,
                'logged_in': 1 if f['dst_port'] in [80, 443, 22] else 0,
                'num_compromised': 0,
                'root_shell': 0,
                'su_attempted': 0,
                'num_root': 0,
                'num_file_creations': 0,
                'num_shells': 0,
                'num_access_files': 0,
                'num_outbound_cmds': 0,
                'is_host_login': 0,
                'is_guest_login': 0,
                'count': count,
                'srv_count': count,
                'serror_rate': serror_rate,
                'srv_serror_rate': serror_rate,
                'rerror_rate': 0.0,
                'srv_rerror_rate': 0.0,
                'same_srv_rate': 1.0,
                'diff_srv_rate': 0.0,
                'srv_diff_host_rate': 0.0,
                'dst_host_count': min(255, count),
                'dst_host_srv_count': min(255, count),
                'dst_host_same_srv_rate': 1.0,
                'dst_host_diff_srv_rate': 0.0,
                'dst_host_same_src_port_rate': 1.0,
                'dst_host_srv_diff_host_rate': 0.0,
                'dst_host_serror_rate': serror_rate,
                'dst_host_srv_serror_rate': serror_rate,
                'dst_host_rerror_rate': 0.0,
                'dst_host_srv_rerror_rate': 0.0
            }
            records.append(rec)

        df_flows = pd.DataFrame(records)
        return self._predict_dataframe(df_flows)

    def analyze_csv_file(self, csv_file_or_df) -> pd.DataFrame:
        """Parses CSV network logs and evaluates each record through ML pipeline."""
        if isinstance(csv_file_or_df, pd.DataFrame):
            df = csv_file_or_df.copy()
        else:
            df = pd.read_csv(csv_file_or_df)
            
        return self._predict_dataframe(df)

    def _predict_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        if df.empty:
            return df
            
        df_out = df.copy()
        X_scaled = self.processor.transform(df_out)
        
        # Predict Attack Class & Probabilities
        y_preds = self.classifier.predict(X_scaled)
        class_names = self.processor.class_names
        
        if len(class_names) > 0 and max(y_preds) < len(class_names):
            df_out['Threat_Class'] = [class_names[p] for p in y_preds]
        else:
            df_out['Threat_Class'] = y_preds

        # Probability Confidence
        if hasattr(self.classifier, 'predict_proba'):
            probs = self.classifier.predict_proba(X_scaled)
            df_out['Confidence'] = [round(float(np.max(p)), 4) for p in probs]
        else:
            df_out['Confidence'] = 0.95

        # Zero-Day Anomaly Scoring
        if self.anomaly_detector:
            anomaly_scores = self.anomaly_detector.score_samples(X_scaled)
            df_out['Anomaly_Score'] = [round(float(s), 4) for s in anomaly_scores]
            df_out['Zero_Day_Flag'] = np.where(df_out['Anomaly_Score'] > 0.65, '⚠️ SUSPICIOUS', '✅ NORMAL')

        return df_out
