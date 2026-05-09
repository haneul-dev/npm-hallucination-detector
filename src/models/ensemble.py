"""
계층적 앙상블 모델
CodeBERT 임베딩 + 메타데이터 피처를 결합하여 XGBoost로 최종 위험도 점수 산출
"""

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import f1_score, mean_absolute_error
from sklearn.model_selection import train_test_split
from loguru import logger

from src.features.code_embedding import CodeEmbedder
from src.features.metadata_features import FEATURE_COLUMNS


class EnsembleDetector:
    """
    Layer 1: CodeBERT → 코드 패턴 임베딩 (768차원)
    Layer 2: 메타데이터 피처 (8차원)
    Layer 3: XGBoost → 두 레이어 결합 후 최종 위험도 점수
    """

    def __init__(self):
        self.embedder = CodeEmbedder()
        self.model = xgb.XGBClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.05,
            scale_pos_weight=10,  # 악성:정상 불균형 보정
            use_label_encoder=False,
            eval_metric="logloss",
            random_state=42,
        )
        self.is_fitted = False

    def _build_feature_matrix(self, df: pd.DataFrame, code_col: str = "install_script") -> np.ndarray:
        """코드 임베딩 + 메타데이터를 하나의 피처 행렬로 결합"""
        # CodeBERT 임베딩
        code_snippets = df[code_col].fillna("").tolist()
        embeddings = self.embedder.embed_batch(code_snippets)

        # 메타데이터 피처
        available = [c for c in FEATURE_COLUMNS if c in df.columns]
        meta = df[available].fillna(0).values

        return np.hstack([embeddings, meta])

    def train(self, df: pd.DataFrame) -> dict:
        X = self._build_feature_matrix(df)
        y = df["label"].values

        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        self.model.fit(
            X_train, y_train,
            eval_set=[(X_val, y_val)],
            verbose=50,
        )
        self.is_fitted = True

        y_pred = self.model.predict(X_val)
        y_proba = self.model.predict_proba(X_val)[:, 1]
        f1 = f1_score(y_val, y_pred)

        # MAE: 전문가 레이블(0 or 1)과 예측 점수(0~1) 차이
        mae = mean_absolute_error(y_val, y_proba)
        logger.info(f"Ensemble F1: {f1:.4f}, MAE: {mae:.4f}")
        return {"f1": f1, "mae": mae}

    def predict_score(self, df: pd.DataFrame) -> np.ndarray:
        """0~100 위험도 점수 반환"""
        if not self.is_fitted:
            raise RuntimeError("train()을 먼저 실행하세요.")
        X = self._build_feature_matrix(df)
        proba = self.model.predict_proba(X)[:, 1]
        return (proba * 100).round(1)
