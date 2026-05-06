"""
베이스라인 모델: Random Forest + 메타데이터 피처만 사용
CodeBERT 없이 빠르게 성능 기준선(baseline)을 잡기 위한 모델
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score, classification_report
from sklearn.preprocessing import StandardScaler
from imblearn.over_sampling import SMOTE
from loguru import logger

from src.features.metadata_features import FEATURE_COLUMNS


class BaselineDetector:
    def __init__(self, n_estimators: int = 100, random_state: int = 42):
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            random_state=random_state,
            class_weight="balanced",  # 데이터 불균형 처리
        )
        self.scaler = StandardScaler()
        self.is_fitted = False

    def _prepare_features(self, df: pd.DataFrame) -> np.ndarray:
        available = [c for c in FEATURE_COLUMNS if c in df.columns]
        return df[available].fillna(0).values

    def train(self, df: pd.DataFrame) -> dict:
        """학습 및 검증 결과 반환"""
        X = self._prepare_features(df)
        y = df["label"].values

        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        # SMOTE로 클래스 불균형 해소
        smote = SMOTE(random_state=42)
        X_train_res, y_train_res = smote.fit_resample(X_train, y_train)
        logger.info(f"SMOTE 적용: {len(y_train)} → {len(y_train_res)}건")

        X_train_scaled = self.scaler.fit_transform(X_train_res)
        X_val_scaled = self.scaler.transform(X_val)

        self.model.fit(X_train_scaled, y_train_res)
        self.is_fitted = True

        y_pred = self.model.predict(X_val_scaled)
        f1 = f1_score(y_val, y_pred)
        report = classification_report(y_val, y_pred, target_names=["benign", "malicious"])
        logger.info(f"Baseline F1: {f1:.4f}\n{report}")
        return {"f1": f1, "report": report}

    def predict_score(self, df: pd.DataFrame) -> np.ndarray:
        """0~100 사이의 위험도 점수 반환"""
        if not self.is_fitted:
            raise RuntimeError("모델이 학습되지 않았습니다. train()을 먼저 실행하세요.")
        X = self._prepare_features(df)
        X_scaled = self.scaler.transform(X)
        # 악성 클래스(1)의 확률을 0~100으로 변환
        proba = self.model.predict_proba(X_scaled)[:, 1]
        return (proba * 100).round(1)

    def get_risk_level(self, score: float) -> str:
        """점수 → 위험 등급 변환"""
        if score >= 80:
            return "HIGH"
        elif score >= 50:
            return "MEDIUM"
        else:
            return "LOW"
