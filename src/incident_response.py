"""
Automated Incident Response, MITRE ATT&CK Matrix Mapping, and Active Defense Firewall Synthesizer.
Generates automated firewall rules (Windows Defender Firewall & Linux iptables) to block malicious IPs,
computes risk assessment scores, and creates downloadable SOC audit reports.
"""

import json
import time
from typing import Dict, Any, List, Optional
from datetime import datetime

MITRE_ATTACK_MAPPING = {
    'DoS': {
        'technique_id': 'T1498',
        'technique_name': 'Network Denial of Service',
        'tactic': 'Impact',
        'sub_techniques': ['T1498.001 (Direct Network Flood)', 'T1498.002 (Reflection Amplification)'],
        'severity': 'HIGH',
        'color': '#ff4b4b',
        'remediation': 'Apply rate limiting, enable SYN Cookies, blackhole offending IP at border router, and activate upstream DDoS scrubbing.'
    },
    'Probe': {
        'technique_id': 'T1046',
        'technique_name': 'Network Service Discovery / Port Scan',
        'tactic': 'Discovery',
        'sub_techniques': ['T1046 (Network Service Scanning)', 'T1595 (Active Scanning)'],
        'severity': 'MEDIUM',
        'color': '#ffa500',
        'remediation': 'Block reconnaissance IP, inspect firewall rules, close unused ports, and enable honeypot deception monitoring.'
    },
    'R2L': {
        'technique_id': 'T1110',
        'technique_name': 'Brute Force / Unauthorized Access',
        'tactic': 'Initial Access / Credential Access',
        'sub_techniques': ['T1110.001 (Password Guessing)', 'T1190 (Exploit Public-Facing Application)'],
        'severity': 'HIGH',
        'color': '#e040fb',
        'remediation': 'Enforce MFA, lock compromised credentials, isolate target service endpoint, and audit auth logs.'
    },
    'U2R': {
        'technique_id': 'T1068',
        'technique_name': 'Exploitation for Privilege Escalation',
        'tactic': 'Privilege Escalation',
        'sub_techniques': ['T1068 (Exploitation for Privilege Escalation)', 'T1548 (Abuse Elevation Mechanism)'],
        'severity': 'CRITICAL',
        'color': '#d50000',
        'remediation': 'IMMEDIATE ISOLATION of affected host. Terminate root shells, run kernel memory integrity audit, and initiate forensic disk snapshot.'
    },
    'Normal': {
        'technique_id': 'N/A',
        'technique_name': 'Benign Operational Traffic',
        'tactic': 'None',
        'sub_techniques': [],
        'severity': 'LOW',
        'color': '#00e676',
        'remediation': 'No action required. Normal baseline traffic.'
    }
}

class IncidentResponseEngine:
    """Enterprise Active Defense and Incident Response orchestration engine."""
    def __init__(self):
        self.incidents: List[Dict[str, Any]] = []
        self.blocked_ips: set = set()

    def assess_threat(self, attack_type: str, confidence: float, src_ip: str, dst_ip: str, port: int, anomaly_score: float = 0.0) -> Dict[str, Any]:
        mitre = MITRE_ATTACK_MAPPING.get(attack_type, MITRE_ATTACK_MAPPING['Normal'])
        base_scores = {'CRITICAL': 95, 'HIGH': 80, 'MEDIUM': 55, 'LOW': 10}
        base = base_scores.get(mitre['severity'], 10)
        risk_score = min(100, int((base * confidence) + (anomaly_score * 20)))
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        incident_id = f"INC-{int(time.time()*1000)%1000000:06d}"
        
        win_rule = f'netsh advfirewall firewall add rule name="NIDS_BLOCK_{src_ip}_{incident_id}" dir=in action=block remoteip={src_ip}'
        linux_rule = f'iptables -A INPUT -s {src_ip} -j DROP'
        cisco_acl = f'access-list 101 deny ip host {src_ip} any'
        
        incident = {
            'incident_id': incident_id,
            'timestamp': timestamp,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'port': port,
            'attack_type': attack_type,
            'confidence': float(confidence),
            'anomaly_score': float(anomaly_score),
            'risk_score': risk_score,
            'severity': mitre['severity'],
            'technique_id': mitre['technique_id'],
            'technique_name': mitre['technique_name'],
            'tactic': mitre['tactic'],
            'remediation': mitre['remediation'],
            'rules': {
                'windows': win_rule,
                'linux': linux_rule,
                'cisco': cisco_acl
            },
            'status': 'ACTIVE_BLOCK' if attack_type != 'Normal' else 'LOGGED'
        }
        
        if attack_type != 'Normal':
            self.incidents.append(incident)
            self.blocked_ips.add(src_ip)
            
        return incident

    def export_firewall_script(self, target_os: str = 'windows') -> str:
        if target_os == 'windows':
            lines = ['@echo off', 'REM Automated NIDS Active Defense Windows Firewall Rules', 'REM Run this batch script in an Administrator Command Prompt', '']
            for inc in self.incidents:
                lines.append(inc['rules']['windows'])
            return '\n'.join(lines)
        else:
            lines = ['#!/bin/bash', '# Automated NIDS Active Defense iptables Rules', '# Run as root/sudo', '']
            for inc in self.incidents:
                lines.append(inc['rules']['linux'])
            return '\n'.join(lines)

    def generate_siem_cef_log(self, incident: Dict[str, Any]) -> str:
        return (
            f"CEF:0|NIDS-SOC|DeepInspectML|2.0|{incident['technique_id']}|{incident['technique_name']}|"
            f"{incident['risk_score']}|src={incident['src_ip']} dst={incident['dst_ip']} dpt={incident['port']} "
            f"msg={incident['remediation']}"
        )

    def generate_html_report(self) -> str:
        rows = ''
        for inc in self.incidents[-30:]:
            color = MITRE_ATTACK_MAPPING.get(inc['attack_type'], {}).get('color', '#fff')
            rows += f"""
            <tr>
                <td>{inc['timestamp']}</td>
                <td><span style="color:{color}; font-weight:bold;">{inc['attack_type']}</span></td>
                <td><span style="background-color:{color}33; color:{color}; padding:3px 8px; border-radius:4px; font-weight:600;">{inc['severity']}</span></td>
                <td><code>{inc['src_ip']}</code> &rarr; <code>{inc['dst_ip']}:{inc['port']}</code></td>
                <td><strong>{inc['risk_score']}/100</strong></td>
                <td><code>{inc['technique_id']}</code></td>
                <td><small>{inc['remediation']}</small></td>
            </tr>
            """
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>NIDS SOC Executive Incident Audit Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #0b0f19; color: #e2e8f0; margin: 0; padding: 30px; }}
        .header {{ border-bottom: 2px solid #00f2fe; padding-bottom: 15px; margin-bottom: 25px; }}
        h1 {{ color: #00f2fe; margin: 0 0 5px 0; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 25px; }}
        .stat-card {{ background-color: #151d30; border: 1px solid #1e293b; padding: 15px; border-radius: 8px; text-align: center; }}
        .stat-val {{ font-size: 24px; font-weight: bold; color: #38bdf8; }}
        .stat-lbl {{ font-size: 12px; color: #94a3b8; text-transform: uppercase; margin-top: 5px; }}
        table {{ width: 100%; border-collapse: collapse; background-color: #111827; border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #1f2937; }}
        th {{ background-color: #1e293b; color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 12px; }}
        tr:hover {{ background-color: #1e293b55; }}
        code {{ background-color: #1e293b; padding: 2px 5px; border-radius: 3px; font-family: Consolas, monospace; color: #38bdf8; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ NIDS SOC Security Forensics & Incident Audit Report</h1>
        <p style="color: #94a3b8; margin: 0;">Enterprise Network Intrusion Detection & Threat Intelligence System</p>
        <p style="color: #64748b; font-size: 12px; margin-top: 5px;">Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
    </div>
    
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-val">{len(self.incidents)}</div>
            <div class="stat-lbl">Total Incidents</div>
        </div>
        <div class="stat-card">
            <div class="stat-val" style="color: #ff4b4b;">{len(self.blocked_ips)}</div>
            <div class="stat-lbl">Blocked Threat Actors</div>
        </div>
        <div class="stat-card">
            <div class="stat-val" style="color: #00e676;">Active</div>
            <div class="stat-lbl">Firewall Defense Status</div>
        </div>
        <div class="stat-card">
            <div class="stat-val" style="color: #a855f7;">MITRE ATT&CK</div>
            <div class="stat-lbl">Framework Alignment</div>
        </div>
    </div>

    <h3>🚨 Incident Activity Log</h3>
    <table>
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Threat Category</th>
                <th>Severity</th>
                <th>Vector (Source &rarr; Target)</th>
                <th>Risk Score</th>
                <th>MITRE Technique</th>
                <th>Remediation Strategy</th>
            </tr>
        </thead>
        <tbody>
            {rows if rows else '<tr><td colspan="7" style="text-align:center; color:#94a3b8;">No threats recorded in this session.</td></tr>'}
        </tbody>
    </table>
</body>
</html>"""
        return html
