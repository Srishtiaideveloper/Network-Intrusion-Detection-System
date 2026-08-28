"""
Real-time Network Packet Sniffer & Dynamic Flow Feature Extractor.
Uses Scapy for live packet capture and bidirectional flow aggregation,
with a built-in safe Attack Simulator / Traffic Replay engine for demonstration.
"""

import time
import socket
import threading
import random
from queue import Queue, Empty
from typing import Dict, Any, List, Optional
import pandas as pd

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

COMMON_PORTS = {
    80: 'http', 443: 'http', 21: 'ftp', 22: 'ssh', 25: 'smtp',
    53: 'domain_u', 110: 'pop_3', 143: 'imap4', 23: 'telnet',
    67: 'dhcp', 68: 'dhcp', 123: 'ntp', 3389: 'rdp', 8080: 'http_8001'
}

def infer_service(port: int) -> str:
    return COMMON_PORTS.get(port, 'private' if port > 1024 else 'other')

class LivePacketSniffer:
    """Threaded live packet sniffer and real-time flow feature extractor."""
    def __init__(self, interface: Optional[str] = None):
        self.interface = interface
        self.is_running = False
        self.sniffer_thread: Optional[threading.Thread] = None
        self.flow_table: Dict[str, Dict[str, Any]] = {}
        self.live_queue: Queue = Queue(maxsize=2000)
        self.lock = threading.Lock()
        self.total_packets_sniffed = 0

    def _packet_callback(self, pkt):
        if not pkt.haslayer(IP):
            return
        
        self.total_packets_sniffed += 1
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        pkt_len = len(pkt)
        proto = 'tcp' if pkt.haslayer(TCP) else ('udp' if pkt.haslayer(UDP) else ('icmp' if pkt.haslayer(ICMP) else 'other'))
        
        src_port = 0
        dst_port = 0
        tcp_flags = ''
        
        if pkt.haslayer(TCP):
            tcp_layer = pkt[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            tcp_flags = str(tcp_layer.flags)
        elif pkt.haslayer(UDP):
            udp_layer = pkt[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            
        flow_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}@{proto}"
        now = time.time()
        
        with self.lock:
            if flow_key not in self.flow_table:
                self.flow_table[flow_key] = {
                    'start_time': now,
                    'last_time': now,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol_type': proto,
                    'service': infer_service(dst_port),
                    'flag': 'SF' if 'A' in tcp_flags and 'F' in tcp_flags else ('S0' if 'S' in tcp_flags and 'A' not in tcp_flags else 'SF'),
                    'src_bytes': pkt_len,
                    'dst_bytes': 0,
                    'count': 1,
                    'serror_count': 1 if 'S' in tcp_flags and 'A' not in tcp_flags else 0
                }
            else:
                f = self.flow_table[flow_key]
                f['last_time'] = now
                f['src_bytes'] += pkt_len
                f['count'] += 1
                if 'S' in tcp_flags and 'A' not in tcp_flags:
                    f['serror_count'] += 1
                    
            flow_data = self.flow_table[flow_key]
            
            # Construct NSL-KDD Compatible Flow Record
            duration = max(0.0, flow_data['last_time'] - flow_data['start_time'])
            count = flow_data['count']
            serror_rate = flow_data['serror_count'] / count if count > 0 else 0.0
            
            flow_record = {
                'timestamp': time.strftime('%H:%M:%S', time.localtime(now)),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'duration': float(duration),
                'protocol_type': proto,
                'service': flow_data['service'],
                'flag': flow_data['flag'],
                'src_bytes': int(flow_data['src_bytes']),
                'dst_bytes': int(flow_data['dst_bytes']),
                'land': 1 if (src_ip == dst_ip and src_port == dst_port) else 0,
                'wrong_fragment': 0,
                'urgent': 0,
                'hot': 0,
                'num_failed_logins': 0,
                'logged_in': 1 if dst_port in [80, 443, 22] else 0,
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
                'count': int(count),
                'srv_count': int(count),
                'serror_rate': float(serror_rate),
                'srv_serror_rate': float(serror_rate),
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
                'dst_host_serror_rate': float(serror_rate),
                'dst_host_srv_serror_rate': float(serror_rate),
                'dst_host_rerror_rate': 0.0,
                'dst_host_srv_rerror_rate': 0.0
            }
            
            if not self.live_queue.full():
                self.live_queue.put(flow_record)

    def start(self):
        if not SCAPY_AVAILABLE:
            print("[-] Scapy not available for raw sniffing. Using replay engine.")
            return
        if self.is_running:
            return
        self.is_running = True
        
        def run_sniff():
            try:
                sniff(prn=self._packet_callback, store=False, stop_filter=lambda p: not self.is_running)
            except Exception as e:
                print(f"[-] Sniffer thread error: {e}")
                self.is_running = False
                
        self.sniffer_thread = threading.Thread(target=run_sniff, daemon=True)
        self.sniffer_thread.start()
        print("[+] Live packet sniffer started.")

    def stop(self):
        self.is_running = False
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=1.0)
        print("[+] Live packet sniffer stopped.")

    def get_batch(self, max_items: int = 50) -> List[Dict[str, Any]]:
        items = []
        while len(items) < max_items:
            try:
                item = self.live_queue.get_nowait()
                items.append(item)
            except Empty:
                break
        return items

class SyntheticTrafficReplayer:
    """Safe high-fidelity simulated packet replay engine for instant testing."""
    def __init__(self, output_queue: Queue):
        self.output_queue = output_queue
        self.is_running = False
        self.thread: Optional[threading.Thread] = None

    def _generate_flow(self, attack_type: Optional[str] = None) -> Dict[str, Any]:
        now = time.strftime('%H:%M:%S')
        types = ['Normal', 'Normal', 'DoS', 'Probe', 'Normal', 'R2L', 'Normal']
        chosen = attack_type if attack_type else random.choice(types)
        
        if chosen == 'DoS':
            src_ip = f"192.168.1.{random.randint(100, 250)}"
            dst_ip = "192.168.1.1"
            dport = 80
            src_bytes = random.randint(0, 100)
            dst_bytes = 0
            count = random.randint(150, 500)
            serror_rate = random.uniform(0.85, 1.0)
            flag = 'S0'
            service = 'http'
        elif chosen == 'Probe':
            src_ip = f"10.0.0.{random.randint(50, 90)}"
            dst_ip = "192.168.1.15"
            dport = random.randint(20, 1024)
            src_bytes = random.randint(0, 40)
            dst_bytes = 0
            count = random.randint(50, 200)
            serror_rate = random.uniform(0.2, 0.6)
            flag = 'REJ'
            service = infer_service(dport)
        elif chosen == 'R2L':
            src_ip = f"172.16.4.{random.randint(10, 40)}"
            dst_ip = "192.168.1.50"
            dport = 21
            src_bytes = random.randint(300, 1200)
            dst_bytes = random.randint(100, 500)
            count = random.randint(5, 30)
            serror_rate = 0.0
            flag = 'SF'
            service = 'ftp'
        elif chosen == 'U2R':
            src_ip = "192.168.1.105"
            dst_ip = "192.168.1.5"
            dport = 23
            src_bytes = random.randint(2000, 6000)
            dst_bytes = random.randint(1500, 4000)
            count = random.randint(1, 10)
            serror_rate = 0.0
            flag = 'SF'
            service = 'telnet'
        else: # Normal
            src_ip = f"192.168.1.{random.randint(10, 80)}"
            dst_ip = f"142.250.{random.randint(1, 250)}.{random.randint(1, 250)}"
            dport = random.choice([80, 443, 53])
            src_bytes = random.randint(200, 4000)
            dst_bytes = random.randint(500, 20000)
            count = random.randint(1, 20)
            serror_rate = 0.0
            flag = 'SF'
            service = 'http' if dport in [80, 443] else 'domain_u'

        return {
            'timestamp': now,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': random.randint(1024, 65535),
            'dst_port': dport,
            'duration': round(random.uniform(0.01, 2.5), 3),
            'protocol_type': 'tcp' if dport != 53 else 'udp',
            'service': service,
            'flag': flag,
            'src_bytes': src_bytes,
            'dst_bytes': dst_bytes,
            'land': 0,
            'wrong_fragment': 0,
            'urgent': 0,
            'hot': 1 if chosen in ['R2L', 'U2R'] else 0,
            'num_failed_logins': random.randint(1, 4) if chosen == 'R2L' else 0,
            'logged_in': 1 if chosen == 'Normal' else 0,
            'num_compromised': 1 if chosen == 'U2R' else 0,
            'root_shell': 1 if chosen == 'U2R' else 0,
            'su_attempted': 1 if chosen == 'U2R' else 0,
            'num_root': 2 if chosen == 'U2R' else 0,
            'num_file_creations': 1 if chosen == 'U2R' else 0,
            'num_shells': 0,
            'num_access_files': 0,
            'num_outbound_cmds': 0,
            'is_host_login': 0,
            'is_guest_login': 1 if chosen == 'R2L' else 0,
            'count': count,
            'srv_count': count,
            'serror_rate': serror_rate,
            'srv_serror_rate': serror_rate,
            'rerror_rate': 0.0,
            'srv_rerror_rate': 0.0,
            'same_srv_rate': 1.0 if chosen != 'Probe' else 0.2,
            'diff_srv_rate': 0.0 if chosen != 'Probe' else 0.8,
            'srv_diff_host_rate': 0.0,
            'dst_host_count': min(255, count),
            'dst_host_srv_count': min(255, count if chosen != 'Probe' else 5),
            'dst_host_same_srv_rate': 1.0 if chosen != 'Probe' else 0.1,
            'dst_host_diff_srv_rate': 0.0 if chosen != 'Probe' else 0.9,
            'dst_host_same_src_port_rate': 1.0 if chosen == 'DoS' else 0.1,
            'dst_host_srv_diff_host_rate': 0.0,
            'dst_host_serror_rate': serror_rate,
            'dst_host_srv_serror_rate': serror_rate,
            'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0
        }

    def start_replay(self, delay: float = 0.8):
        if self.is_running:
            return
        self.is_running = True
        
        def run_loop():
            while self.is_running:
                flow = self._generate_flow()
                if not self.output_queue.full():
                    self.output_queue.put(flow)
                time.sleep(delay)
                
        self.thread = threading.Thread(target=run_loop, daemon=True)
        self.thread.start()

    def stop_replay(self):
        self.is_running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.0)
