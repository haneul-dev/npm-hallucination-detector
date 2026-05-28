"""
CodeBERT + XGBoost 계층적 앙상블 모델 학습 스크립트 (Phase 3-A)

실행 전 requirements.txt 설치 필요 (torch, transformers 포함):
    pip install -r requirements.txt

학습 시간 (패키지명 임베딩 기준):
    CPU : 약 30~60분 (7,160건 × CodeBERT 추론)
    MPS (Apple Silicon) : 약 5~10분
    CUDA GPU : 약 2~5분
"""

import os, csv, pickle, random, time
import numpy as np
import pandas as pd
from loguru import logger

# ─── 설정 ────────────────────────────────────────────────────
RANDOM_SEED = 42
DATA_SOURCES = {
    "maloss":       "data/processed/maloss_npm_malicious.csv",
    "backstabbers": "data/processed/backstabbers_npm.csv",
    "advisory":     "data/processed/npm_advisory.csv",
    "hallucination":"data/processed/llm_hallucinated_packages.csv",
    "benign":       "data/processed/benign_packages.csv",
}
MODEL_OUT = "models/ensemble_xgb.pkl"
MAX_SAMPLES_PER_CLASS = 4000  # 클래스 균형 유지용 상한


def load_dataset() -> pd.DataFrame:
    """처리된 CSV들을 합쳐 label 컬럼(0=정상, 1=악성) 포함 DataFrame 반환"""
    frames = []

    malicious_files = ["maloss", "backstabbers", "advisory", "hallucination"]
    for key in malicious_files:
        path = DATA_SOURCES[key]
        if not os.path.exists(path):
            logger.warning(f"{path} 없음 — 건너뜀")
            continue
        df = pd.read_csv(path)
        df["label"] = 1
        frames.append(df)
        logger.info(f"악성 로드: {path} ({len(df)}건)")

    benign_path = DATA_SOURCES["benign"]
    if os.path.exists(benign_path):
        df_b = pd.read_csv(benign_path)
        df_b["label"] = 0
        frames.append(df_b)
        logger.info(f"정상 로드: {benign_path} ({len(df_b)}건)")

    if not frames:
        raise FileNotFoundError("학습 데이터가 없습니다. data/processed/ 폴더를 확인하세요.")

    full = pd.concat(frames, ignore_index=True).drop_duplicates(subset=["name"])

    # 클래스 균형 맞추기 (상한 MAX_SAMPLES_PER_CLASS)
    mal = full[full["label"] == 1].sample(
        min(MAX_SAMPLES_PER_CLASS, (full["label"] == 1).sum()), random_state=RANDOM_SEED
    )
    ben = full[full["label"] == 0].sample(
        min(MAX_SAMPLES_PER_CLASS, (full["label"] == 0).sum()), random_state=RANDOM_SEED
    )
    balanced = pd.concat([mal, ben]).sample(frac=1, random_state=RANDOM_SEED)
    logger.info(f"최종 데이터셋: 악성 {len(mal)}건 / 정상 {len(ben)}건")
    return balanced


def build_meta_features(df: pd.DataFrame) -> np.ndarray:
    """메타데이터 9개 피처 행렬 (CodeBERT 없이도 단독 사용 가능)"""
    import re
    from difflib import SequenceMatcher

    POPULAR = ["react","express","lodash","axios","webpack","babel","eslint",
               "typescript","vue","angular","jquery","moment","chalk","commander",
               "dotenv","fastify","koa","next","vite","prisma"]

    def sim(name):
        return max(SequenceMatcher(None, str(name).lower(), p).ratio() for p in POPULAR)

    def sus(name):
        patterns = [r"\d{3,}$", r"_{2,}", r"-{2,}", r"^[a-z]{1,2}$"]
        return int(any(re.search(p, str(name)) for p in patterns))

    rows = []
    for _, row in df.iterrows():
        d = row.get("downloads", 0) or 0
        rows.append([
            np.log1p(float(d)),
            sim(row.get("name", "")),
            sus(row.get("name", "")),
            int(not row.get("author", "")),
            int(row.get("has_install_script", 0)),
            int(float(row.get("dependencies_count", 0)) > 20),
            min(float(row.get("maintainers_count", 0)), 20),
            min(float(row.get("dependencies_count", 0)), 50),
            int(not bool(row.get("exists", True))),
        ])
    return np.array(rows, dtype=np.float32)


def build_code_embeddings(df: pd.DataFrame) -> np.ndarray:
    """
    CodeBERT CLS 토큰으로 패키지명 임베딩 (768차원).
    install_script 컬럼이 있으면 스크립트 내용, 없으면 패키지명 사용.
    """
    from src.features.code_embedding import CodeEmbedder

    embedder = CodeEmbedder()

    if "install_script" in df.columns:
        texts = df["install_script"].fillna("").tolist()
        logger.info("install_script 컬럼 기반 임베딩")
    else:
        # 패키지명을 코드 토큰처럼 임베딩 (슬롭스쿼팅 이름 패턴 탐지)
        texts = df["name"].fillna("").tolist()
        logger.info("패키지명 기반 임베딩 (install_script 없음)")

    logger.info(f"CodeBERT 임베딩 시작: {len(texts)}건")
    embeddings = embedder.embed_batch(texts, batch_size=32)
    logger.info(f"임베딩 완료: shape={embeddings.shape}")
    return embeddings


def train_xgboost(X: np.ndarray, y: np.ndarray) -> dict:
    """XGBoost 학습 + 검증 결과 반환"""
    import xgboost as xgb
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import f1_score, roc_auc_score, mean_absolute_error
    from sklearn.preprocessing import StandardScaler

    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_SEED, stratify=y
    )

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_val_s = scaler.transform(X_val)

    neg, pos = (y_train == 0).sum(), (y_train == 1).sum()
    model = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        scale_pos_weight=neg / pos,  # 클래스 불균형 자동 보정
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric="logloss",
        random_state=RANDOM_SEED,
        verbosity=1,
    )

    model.fit(
        X_train, y_train,
        eval_set=[(X_val_s, y_val)],
        verbose=50,
    )

    y_pred  = model.predict(X_val_s)
    y_proba = model.predict_proba(X_val_s)[:, 1]

    metrics = {
        "f1":  round(f1_score(y_val, y_pred), 4),
        "auc": round(roc_auc_score(y_val, y_proba), 4),
        "mae": round(mean_absolute_error(y_val, y_proba), 4),
    }
    logger.info(f"Ensemble 결과: F1={metrics['f1']}, AUC={metrics['auc']}, MAE={metrics['mae']}")

    return {"model": model, "scaler": scaler, "metrics": metrics}


def main():
    random.seed(RANDOM_SEED)
    np.random.seed(RANDOM_SEED)

    print("=" * 60)
    print("  CodeBERT + XGBoost 앙상블 모델 학습 (Phase 3-A)")
    print("=" * 60)

    # 1. 데이터 로드
    df = load_dataset()
    y  = df["label"].values

    # 2. 메타데이터 피처
    logger.info("메타데이터 피처 추출 중...")
    meta_X = build_meta_features(df)          # (N, 9)

    # 3. CodeBERT 임베딩
    logger.info("CodeBERT 임베딩 중 (시간이 걸립니다)...")
    t0 = time.time()
    emb_X = build_code_embeddings(df)         # (N, 768)
    logger.info(f"임베딩 소요: {time.time()-t0:.1f}초")

    # 4. 결합 (768 + 9 = 777차원)
    X = np.hstack([emb_X, meta_X])
    logger.info(f"최종 피처 행렬: {X.shape}")

    # 5. XGBoost 학습
    result = train_xgboost(X, y)

    # 6. 저장
    os.makedirs("models", exist_ok=True)
    bundle = {
        "model":      result["model"],
        "scaler":     result["scaler"],
        "metrics":    result["metrics"],
        "model_type": "ensemble_codebert_xgboost",
        "feat_dim":   X.shape[1],
    }
    with open(MODEL_OUT, "wb") as f:
        pickle.dump(bundle, f)

    print("\n" + "=" * 60)
    print("  학습 완료")
    print("=" * 60)
    print(f"  F1-Score : {result['metrics']['f1']}")
    print(f"  AUC-ROC  : {result['metrics']['auc']}")
    print(f"  MAE      : {result['metrics']['mae']}")
    print(f"  저장 위치 : {MODEL_OUT}")
    print("=" * 60)


if __name__ == "__main__":
    main()
