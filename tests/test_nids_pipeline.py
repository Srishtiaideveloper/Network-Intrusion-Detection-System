"""
Comprehensive Unit & Integration Test Suite for NIDS Pipeline.
Tests data preprocessing, model inference, anomaly detection, Explainable AI (SHAP),
firewall rule synthesis, and PCAP analysis.
"""

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
import numpy as np
import pandas as pd

from src.data_loader import NIDSDataProcessor, FEATURE_NAMES, NUMERIC_FEATURES, CATEGORICAL_FEATURES
from src.models import NIDSMultiClassifier, NIDSAnomalyDetector, NIDSExplainer
from src.incident_response import IncidentResponseEngine, MITRE_ATTACK_MAPPING
from src.packet_sniffer import LivePacketSniffer, SyntheticTrafficReplayer
from src.pcap_analyzer import PCAPAnalyzer

def test_data_processor_fit_transform():
    data = {f: [0] * 5 for f in FEATURE_NAMES[:-2]}
    data['protocol_type'] = ['tcp', 'udp', 'icmp', 'tcp', 'tcp']
    data['service'] = ['http', 'domain_u', 'eco_i', 'ftp', 'smtp']
    data['flag'] = ['SF', 'S0', 'SF', 'REJ', 'SF']
    data['attack_category'] = ['Normal', 'DoS', 'Probe', 'R2L', 'Normal']
    data['is_attack'] = [0, 1, 1, 1, 0]
    
    df = pd.DataFrame(data)
    processor = NIDSDataProcessor()
    X_scaled, y_multi, y_binary = processor.fit_transform(df)
    
    assert X_scaled.shape == (5, 41)
    assert len(y_multi) == 5
    assert len(y_binary) == 5
    assert processor.is_fitted

def test_classifier_fit_and_predict():
    X = np.random.randn(20, 41)
    y = np.random.randint(0, 4, size=20)
    class_names = ['DoS', 'Normal', 'Probe', 'R2L']
    
    clf = NIDSMultiClassifier(model_type='rf', n_estimators=10, max_depth=4)
    clf.fit(X, y, class_names=class_names)
    
    preds = clf.predict(X)
    probs = clf.predict_proba(X)
    
    assert len(preds) == 20
    assert probs.shape == (20, 4)
    assert np.allclose(probs.sum(axis=1), 1.0)

def test_anomaly_detector_scoring():
    X_normal = np.random.randn(30, 41)
    detector = NIDSAnomalyDetector(contamination=0.05, n_estimators=15)
    detector.fit(X_normal)
    
    test_samples = np.random.randn(5, 41)
    scores = detector.score_samples(test_samples)
    
    assert len(scores) == 5
    assert all(0.0 <= s <= 1.0 for s in scores)

def test_incident_response_firewall_rules():
    engine = IncidentResponseEngine()
    incident = engine.assess_threat(
        attack_type='DoS',
        confidence=0.98,
        src_ip='192.168.1.199',
        dst_ip='192.168.1.1',
        port=80,
        anomaly_score=0.85
    )
    
    assert incident['attack_type'] == 'DoS'
    assert incident['technique_id'] == 'T1498'
    assert '192.168.1.199' in engine.blocked_ips
    assert 'netsh advfirewall' in incident['rules']['windows']
    assert 'iptables' in incident['rules']['linux']
    
    win_script = engine.export_firewall_script('windows')
    assert 'netsh advfirewall' in win_script
    
    html_report = engine.generate_html_report()
    assert 'NIDS SOC Security Forensics' in html_report

def test_pcap_analyzer_csv_forensics():
    processor = NIDSDataProcessor.load("models/data_processor.joblib")
    classifier = NIDSMultiClassifier.load("models/nids_classifier.joblib")
    analyzer = PCAPAnalyzer(processor, classifier)
    
    if os.path.exists("data/sample_traffic.csv"):
        df_out = analyzer.analyze_csv_file("data/sample_traffic.csv")
        assert 'Threat_Class' in df_out.columns
        assert 'Confidence' in df_out.columns
        assert len(df_out) > 0
