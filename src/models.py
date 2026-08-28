import os
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Optional, Tuple
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support
import xgboost as xgb
import shap

class NIDSMultiClassifier:
    def __init__(self, model_type: str = 'xgboost', n_estimators: int = 120, max_depth: int = 10):
        self.model_type = model_type
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.class_names: List[str] = []
        
        if model_type == 'xgboost':
            self.model = xgb.XGBClassifier(
                n_estimators=n_estimators,
                max_depth=max_depth,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=42,
                eval_metric='mlogloss',
                n_jobs=-1
            )
        else:
            self.model = RandomForestClassifier(
                n_estimators=n_estimators,
                max_depth=max_depth,
                random_state=42,
                n_jobs=-1
            )

    def fit(self, X: np.ndarray, y: np.ndarray, class_names: Optional[List[str]] = None):
        self.class_names = class_names if class_names else [str(i) for i in np.unique(y)]
        self.model.fit(X, y)
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict_proba(X)

    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, Any]:
        y_pred = self.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        prec, rec, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted', zero_division=0)
        cm = confusion_matrix(y_test, y_pred)
        
        report = classification_report(
            y_test, y_pred,
            target_names=self.class_names,
            output_dict=True,
            zero_division=0
        )
        
        return {
            'accuracy': float(acc),
            'precision': float(prec),
            'recall': float(rec),
            'f1_score': float(f1),
            'confusion_matrix': cm.tolist(),
            'classification_report': report
        }

    def get_feature_importances(self, feature_names: List[str]) -> pd.DataFrame:
        if hasattr(self.model, 'feature_importances_'):
            importances = self.model.feature_importances_
            df_imp = pd.DataFrame({
                'feature': feature_names[:len(importances)],
                'importance': importances
            }).sort_values(by='importance', ascending=False).reset_index(drop=True)
            return df_imp
        return pd.DataFrame()

    def save(self, filepath: str = 'models/nids_classifier.joblib'):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump({
            'model': self.model,
            'model_type': self.model_type,
            'class_names': self.class_names
        }, filepath)
        print(f'[+] Classifier saved to {filepath}')

    @classmethod
    def load(cls, filepath: str = 'models/nids_classifier.joblib') -> 'NIDSMultiClassifier':
        if not os.path.exists(filepath):
            raise FileNotFoundError(f'Model file not found: {filepath}')
        data = joblib.load(filepath)
        instance = cls(model_type=data.get('model_type', 'xgboost'))
        instance.model = data['model']
        instance.class_names = data['class_names']
        return instance

class NIDSAnomalyDetector:
    def __init__(self, contamination: float = 0.05, n_estimators: int = 100):
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=42,
            n_jobs=-1
        )
        self.is_fitted = False

    def fit(self, X_normal: np.ndarray):
        self.model.fit(X_normal)
        self.is_fitted = True
        return self

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        raw_scores = self.model.decision_function(X)
        norm_scores = 1.0 / (1.0 + np.exp(raw_scores * 5.0))
        return norm_scores

    def predict(self, X: np.ndarray) -> np.ndarray:
        preds = self.model.predict(X)
        return np.where(preds == -1, 1, 0)

    def save(self, filepath: str = 'models/nids_anomaly_detector.joblib'):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump(self.model, filepath)
        print(f'[+] Anomaly detector saved to {filepath}')

    @classmethod
    def load(cls, filepath: str = 'models/nids_anomaly_detector.joblib') -> 'NIDSAnomalyDetector':
        if not os.path.exists(filepath):
            raise FileNotFoundError(f'Model file not found: {filepath}')
        instance = cls()
        instance.model = joblib.load(filepath)
        instance.is_fitted = True
        return instance

class NIDSExplainer:
    def __init__(self, model, feature_names: List[str], class_names: List[str]):
        self.model = model
        self.feature_names = feature_names
        self.class_names = class_names
        self.explainer = None
        self._init_explainer()

    def _init_explainer(self):
        try:
            self.explainer = shap.TreeExplainer(self.model)
        except Exception as e:
            print(f'[-] Warning initializing SHAP TreeExplainer: {e}')

    def explain_instance(self, sample_scaled: np.ndarray, predicted_class_idx: int) -> List[Dict[str, Any]]:
        if self.explainer is None:
            return []
        try:
            shap_values = self.explainer.shap_values(sample_scaled)
            if isinstance(shap_values, list):
                class_shap = shap_values[predicted_class_idx][0]
            elif len(shap_values.shape) == 3:
                class_shap = shap_values[0, :, predicted_class_idx]
            else:
                class_shap = shap_values[0]
                
            impacts = []
            for feat, val in zip(self.feature_names, class_shap):
                impacts.append({
                    'feature': feat,
                    'shap_value': float(val),
                    'abs_impact': float(abs(val))
                })
            impacts.sort(key=lambda x: x['abs_impact'], reverse=True)
            return impacts[:10]
        except Exception as e:
            print(f'[-] SHAP instance explanation error: {e}')
            return []
