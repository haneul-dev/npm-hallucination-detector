"""
기존 CSV 데이터로 RF 빠르게 재학습 (npm API 호출 없음, 약 1분 이내)
12개 피처: 기존 9개 + min_edit_dist / is_exact_popular / is_scoped
"""

import os, pickle, csv, random
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score, roc_auc_score, classification_report
from sklearn.preprocessing import StandardScaler
from imblearn.over_sampling import SMOTE

from src.features.metadata_features import (
    levenshtein, POPULAR_PACKAGES,
    name_similarity_score, has_suspicious_name_pattern,
)

RANDOM_SEED = 42
random.seed(RANDOM_SEED)

MAL_SOURCES = [
    "data/processed/maloss_npm_malicious.csv",
    "data/processed/backstabbers_npm.csv",
    "data/processed/npm_advisory.csv",
    "data/processed/llm_hallucinated_packages.csv",
]
BEN_SOURCE = "data/processed/benign_packages.csv"


def _min_edit_dist(name: str) -> int:
    core = str(name).lower().lstrip("@").split("/")[0]
    return min(levenshtein(core, p) for p in POPULAR_PACKAGES)


def extract_features(row: dict) -> list:
    name    = str(row.get("name", ""))
    d       = float(row.get("downloads", 0) or 0)
    edit_d  = _min_edit_dist(name)
    return [
        np.log1p(d),
        name_similarity_score(name),
        has_suspicious_name_pattern(name),
        int(not str(row.get("author", "")).strip()),
        int(float(row.get("has_install_script", 0) or 0)),
        int(float(row.get("dependencies_count", 0) or 0) > 20),
        min(float(row.get("maintainers_count", 0) or 0), 20),
        min(float(row.get("dependencies_count", 0) or 0), 50),
        int(not bool(row.get("exists", True))),
        min(edit_d, 10),            # min_edit_dist
        int(edit_d == 0),           # is_exact_popular
        int(name.startswith("@")),  # is_scoped
    ]


def load_csv(path: str, label: int, limit: int = 4000) -> list:
    rows = []
    try:
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(row)
    except FileNotFoundError:
        print(f"  [SKIP] {path}")
        return []
    random.shuffle(rows)
    return [(extract_features(r), label) for r in rows[:limit]]


def main():
    print("=" * 55)
    print("  RF 재학습 (12-피처 / 기존 CSV 사용)")
    print("=" * 55)

    # ── 데이터 로드 ───────────────────────────────────────────
    mal_data, ben_data = [], []

    for path in MAL_SOURCES:
        mal_data += load_csv(path, label=1, limit=2000)

    ben_data = load_csv(BEN_SOURCE, label=0, limit=4000)

    print(f"\n악성: {len(mal_data)}건 / 정상: {len(ben_data)}건")

    all_data = mal_data + ben_data
    random.shuffle(all_data)

    X = np.array([d[0] for d in all_data])
    y = np.array([d[1] for d in all_data])
    print(f"피처 행렬: {X.shape}")

    # ── 학습 ──────────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_SEED, stratify=y
    )

    scaler     = StandardScaler()
    X_train_s  = scaler.fit_transform(X_train)
    X_test_s   = scaler.transform(X_test)

    smote       = SMOTE(random_state=RANDOM_SEED)
    X_res, y_res = smote.fit_resample(X_train_s, y_train)

    clf = RandomForestClassifier(
        n_estimators=200, random_state=RANDOM_SEED, class_weight="balanced"
    )
    clf.fit(X_res, y_res)

    # ── 평가 ──────────────────────────────────────────────────
    y_pred  = clf.predict(X_test_s)
    y_proba = clf.predict_proba(X_test_s)[:, 1]

    f1  = f1_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_proba)
    fp  = ((y_pred == 1) & (y_test == 0)).sum()
    fpr = fp / (y_test == 0).sum() if (y_test == 0).sum() > 0 else 0

    print("\n" + "=" * 55)
    print(f"  F1-Score : {f1:.4f}")
    print(f"  AUC-ROC  : {auc:.4f}")
    print(f"  FPR      : {fpr:.4f}")
    print("=" * 55)
    print(classification_report(y_test, y_pred, target_names=["benign","malicious"]))

    # 피처 중요도
    feat_names = [
        "log_downloads","name_similarity","suspicious_name","no_author",
        "has_install_script","high_dependency","maintainers_count",
        "dependencies_count","not_exists","min_edit_dist","is_exact_popular","is_scoped",
    ]
    importances = sorted(zip(feat_names, clf.feature_importances_), key=lambda x: -x[1])
    print("  피처 중요도:")
    for n, imp in importances:
        bar = "█" * int(imp * 40)
        print(f"    {n:<22} {imp:.3f}  {bar}")

    # ── 저장 ──────────────────────────────────────────────────
    os.makedirs("models", exist_ok=True)
    with open("models/baseline_rf.pkl", "wb") as f:
        pickle.dump({"model": clf, "scaler": scaler}, f)
    print("\n  저장 완료: models/baseline_rf.pkl")


if __name__ == "__main__":
    main()
