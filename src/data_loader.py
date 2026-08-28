"""
Real NSL-KDD Dataset Loader, Preprocessor, and Feature Engineering Pipeline.
Handles automated downloading from authentic academic repositories, MITRE-aligned
category mapping, feature scaling, and categorical encoding for both training and real-time inference.
"""

import os
import urllib.request
import pandas as pd
import numpy as np
import joblib
from typing import Tuple, Dict, List, Optional
from sklearn.preprocessing import StandardScaler, LabelEncoder

# Authentic NSL-KDD 41 Feature Headers + Label + Difficulty Level
FEATURE_NAMES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty_level'
]

CATEGORICAL_FEATURES = ['protocol_type', 'service', 'flag']
NUMERIC_FEATURES = [f for f in FEATURE_NAMES[:-2] if f not in CATEGORICAL_FEATURES]

# Industry MITRE-Aligned Threat Classification for all NSL-KDD Signatures
ATTACK_CATEGORIES: Dict[str, str] = {
    'normal': 'Normal',
    # Denial of Service (DoS)
    'neptune': 'DoS', 'smurf': 'DoS', 'pod': 'DoS', 'teardrop': 'DoS',
    'land': 'DoS', 'back': 'DoS', 'apache2': 'DoS', 'udpstorm': 'DoS',
    'processtable': 'DoS', 'mailbomb': 'DoS', 'worm': 'DoS',
    # Reconnaissance / Probe
    'satan': 'Probe', 'ipsweep': 'Probe', 'portsweep': 'Probe',
    'nmap': 'Probe', 'mscan': 'Probe', 'saint': 'Probe',
    # Remote to Local (R2L)
    'guess_passwd': 'R2L', 'ftp_write': 'R2L', 'imap': 'R2L', 'phf': 'R2L',
    'multihop': 'R2L', 'warezmaster': 'R2L', 'warezclient': 'R2L', 'spy': 'R2L',
    'xlock': 'R2L', 'xsnoop': 'R2L', 'snmpguess': 'R2L', 'snmpgetattack': 'R2L',
    'httptunnel': 'R2L', 'sendmail': 'R2L', 'named': 'R2L',
    # User to Root (U2R)
    'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'rootkit': 'U2R',
    'perl': 'U2R', 'sqlattack': 'U2R', 'xterm': 'U2R', 'ps': 'U2R'
}

DATASET_URLS = {
    'train': [
        'https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt',
        'https://raw.githubusercontent.com/jimsun98/nsl-kdd/master/KDDTrain%2B.txt'
    ],
    'test': [
        'https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt',
        'https://raw.githubusercontent.com/jimsun98/nsl-kdd/master/KDDTest%2B.txt'
    ]
}

def download_dataset(data_dir: str = 'data') -> Tuple[str, str]:
    """Downloads authentic NSL-KDD dataset files if not already cached."""
    os.makedirs(data_dir, exist_ok=True)
    train_path = os.path.join(data_dir, 'KDDTrain+.txt')
    test_path = os.path.join(data_dir, 'KDDTest+.txt')
    
    for split, path, key in [('Train', train_path, 'train'), ('Test', test_path, 'test')]:
        if not os.path.exists(path) or os.path.getsize(path) < 1000:
            print(f'[*] Downloading authentic NSL-KDD {split} dataset...')
            success = False
            for url in DATASET_URLS[key]:
                try:
                    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req, timeout=30) as resp, open(path, 'wb') as out_file:
                        out_file.write(resp.read())
                    if os.path.exists(path) and os.path.getsize(path) > 1000:
                        print(f'[+] Downloaded {split} data ({os.path.getsize(path)/(1024*1024):.2f} MB).')
                        success = True
                        break
                except Exception as e:
                    print(f'[-] Warning from mirror {url}: {e}')
            if not success:
                raise RuntimeError(f'Could not download NSL-KDD {split} set.')
        else:
            print(f'[+] NSL-KDD {split} dataset already cached: {path}')
            
    return train_path, test_path

def map_attack_category(label: str) -> str:
    """Maps raw attack signature string to 5 core classes."""
    clean_label = str(label).strip().lower().rstrip('.')
    return ATTACK_CATEGORIES.get(clean_label, 'DoS')

def load_raw_dataset(data_dir: str = 'data', sample_train: Optional[int] = None, sample_test: Optional[int] = None) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Loads train and test NSL-KDD datasets into pandas DataFrames."""
    train_path, test_path = download_dataset(data_dir)
    
    df_train = pd.read_csv(train_path, names=FEATURE_NAMES, header=None)
    df_test = pd.read_csv(test_path, names=FEATURE_NAMES, header=None)
    
    df_train['attack_category'] = df_train['label'].apply(map_attack_category)
    df_test['attack_category'] = df_test['label'].apply(map_attack_category)
    
    df_train['is_attack'] = (df_train['attack_category'] != 'Normal').astype(int)
    df_test['is_attack'] = (df_test['attack_category'] != 'Normal').astype(int)
    
    if sample_train and sample_train < len(df_train):
        df_train = df_train.sample(n=sample_train, random_state=42).reset_index(drop=True)
    if sample_test and sample_test < len(df_test):
        df_test = df_test.sample(n=sample_test, random_state=42).reset_index(drop=True)
        
    return df_train, df_test

class NIDSDataProcessor:
    """Production feature transformer for standardizing inputs across ML & Live Sniffing."""
    def __init__(self):
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.target_encoder = LabelEncoder()
        self.feature_columns: List[str] = [c for c in FEATURE_NAMES[:-2]]
        self.class_names: List[str] = ['DoS', 'Normal', 'Probe', 'R2L', 'U2R']
        self.is_fitted = False

    def fit_transform(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        df_proc = df.copy()
        
        for col in CATEGORICAL_FEATURES:
            le = LabelEncoder()
            df_proc[col] = le.fit_transform(df_proc[col].astype(str))
            self.label_encoders[col] = le
            
        y_multi = self.target_encoder.fit_transform(df_proc['attack_category'])
        self.class_names = list(self.target_encoder.classes_)
        y_binary = df_proc['is_attack'].values
        
        X_raw = df_proc[self.feature_columns].values
        X_scaled = self.scaler.fit_transform(X_raw)
        
        self.is_fitted = True
        return X_scaled, y_multi, y_binary

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        if not self.is_fitted:
            raise ValueError('Processor has not been fitted yet.')
        
        df_proc = df.copy()
        for col in CATEGORICAL_FEATURES:
            if col in df_proc.columns:
                le = self.label_encoders[col]
                known = set(le.classes_)
                df_proc[col] = df_proc[col].astype(str).map(
                    lambda s: s if s in known else le.classes_[0]
                )
                df_proc[col] = le.transform(df_proc[col])
            else:
                df_proc[col] = 0
                
        for col in self.feature_columns:
            if col not in df_proc.columns:
                df_proc[col] = 0.0
                
        X_raw = df_proc[self.feature_columns].values
        return self.scaler.transform(X_raw)

    def save(self, filepath: str = 'models/data_processor.joblib'):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump(self, filepath)
        print(f'[+] Data processor saved to {filepath}')

    @classmethod
    def load(cls, filepath: str = 'models/data_processor.joblib') -> 'NIDSDataProcessor':
        if not os.path.exists(filepath):
            raise FileNotFoundError(f'Data processor artifact not found at {filepath}')
        return joblib.load(filepath)
