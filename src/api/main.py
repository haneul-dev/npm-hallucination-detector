"""
FastAPI 실시간 위험도 평가 API  v0.4.0
POST /analyze      패키지명 → 위험도 점수 + SHAP 판단 근거
GET  /health       서버 상태
GET  /model-info   모델 메타데이터

v0.4.0 변경사항:
- 슬롭스쿼팅 특화 Levenshtein 피처 3개 추가 (12차원)
- 계층적 추론 (RF 확신 시 단독 / 불확실 시 앙상블 개입)
- 앙상블 pkl 존재 시 자동 로드
"""

import json, re, pickle, os
import numpy as np
import urllib.request
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from src.explainability.shap_explainer import ShapExplainer
from src.models.hierarchical_detector import hierarchical_score
from src.features.metadata_features import levenshtein, POPULAR_PACKAGES

app = FastAPI(
    title="npm Hallucination Detector API",
    description="LLM 환각 악용 npm 공급망 공격 탐지 — 계층적 추론 v0.4.0",
    version="0.4.0",
)

# ── 모델 경로 ──────────────────────────────────────────────────
_BASE_DIR   = os.path.dirname(__file__)
_RF_PATH    = os.path.join(_BASE_DIR, "../../models/baseline_rf.pkl")
_ENS_PATH   = os.path.join(_BASE_DIR, "../../models/ensemble_xgb.pkl")

_rf_bundle  = None
_ens_bundle = None
_shap       = None


def _load_models():
    global _rf_bundle, _ens_bundle, _shap
    if _rf_bundle is not None:
        return

    with open(_RF_PATH, "rb") as f:
        _rf_bundle = pickle.load(f)
    _shap = ShapExplainer(_rf_bundle["model"])

    if os.path.exists(_ENS_PATH):
        try:
            with open(_ENS_PATH, "rb") as f:
                _ens_bundle = pickle.load(f)
        except Exception:
            _ens_bundle = None


# ── 피처 함수 ──────────────────────────────────────────────────
POPULAR = ["react","express","lodash","axios","webpack","babel","eslint",
           "typescript","vue","angular","jquery","moment","chalk","commander",
           "dotenv","fastify","koa","next","vite","prisma"]

def _name_similarity(name: str) -> float:
    from difflib import SequenceMatcher
    return max(SequenceMatcher(None, name.lower(), p).ratio() for p in POPULAR)

def _suspicious(name: str) -> int:
    return int(any(re.search(p, name) for p in [r"\d{3,}$", r"_{2,}", r"-{2,}", r"^[a-z]{1,2}$"]))

def _min_edit_dist(name: str) -> int:
    core = name.lower().lstrip("@").split("/")[0]
    return min(levenshtein(core, p) for p in POPULAR_PACKAGES)

def _fetch_meta(name: str) -> dict:
    try:
        req = urllib.request.Request(
            f"https://registry.npmjs.org/{name}",
            headers={"User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=6) as r:
            data = json.loads(r.read())
        latest = data.get("dist-tags", {}).get("latest", "")
        ver    = data.get("versions", {}).get(latest, {})
        author = data.get("author", {})
        return {
            "exists":             True,
            "author":             author.get("name","") if isinstance(author, dict) else str(author or ""),
            "maintainers_count":  len(data.get("maintainers", [])),
            "dependencies_count": len(ver.get("dependencies", {})),
            "has_install_script": int("install" in ver.get("scripts", {})),
            "downloads":          0,
        }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"exists": False, "author": "", "maintainers_count": 0,
                    "dependencies_count": 0, "has_install_script": 0, "downloads": 0}
        return {"exists": True, "author": "", "maintainers_count": 1,
                "dependencies_count": 0, "has_install_script": 0, "downloads": 0}
    except Exception:
        return {"exists": True, "author": "", "maintainers_count": 1,
                "dependencies_count": 0, "has_install_script": 0, "downloads": 0}


def _build_meta_features(name: str, meta: dict) -> np.ndarray:
    """12차원 메타데이터 피처 벡터 반환"""
    d        = meta.get("downloads", 0) or 0
    edit_d   = _min_edit_dist(name)
    return np.array([[
        np.log1p(d),                                         # 0  log_downloads
        _name_similarity(name),                              # 1  name_similarity
        _suspicious(name),                                   # 2  suspicious_name
        int(not meta.get("author", "")),                     # 3  no_author
        meta.get("has_install_script", 0),                  # 4  has_install_script
        int(meta.get("dependencies_count", 0) > 20),        # 5  high_dependency
        min(meta.get("maintainers_count", 0), 20),          # 6  maintainers_count
        min(meta.get("dependencies_count", 0), 50),         # 7  dependencies_count
        int(not meta.get("exists", True)),                   # 8  not_exists
        min(edit_d, 10),                                     # 9  min_edit_dist
        int(edit_d == 0),                                    # 10 is_exact_popular
        int(name.startswith("@")),                           # 11 is_scoped
    ]])


def _build_reason(name: str, meta: dict, edit_d: int) -> str:
    reasons = []
    if not meta.get("exists", True):
        reasons.append("npm에 존재하지 않는 패키지(404)")
    if edit_d == 0 and name.lower() in POPULAR:
        reasons.append(f"인기 패키지 '{name}' 자체 — 정상")
    elif 1 <= edit_d <= 2:
        closest = min(POPULAR_PACKAGES, key=lambda p: levenshtein(name.lower(), p))
        reasons.append(f"'{closest}'과 편집거리 {edit_d} (슬롭스쿼팅 의심)")
    if not meta.get("author", ""):
        reasons.append("작성자 정보 없음")
    if meta.get("has_install_script"):
        reasons.append("postinstall 스크립트 존재")
    sim = _name_similarity(name)
    if sim > 0.7 and name.lower() not in POPULAR:
        reasons.append(f"인기 패키지와 이름 유사 ({sim:.0%})")
    if _suspicious(name):
        reasons.append("의심스러운 이름 패턴")
    if meta.get("maintainers_count", 1) <= 1 and meta.get("exists", True):
        reasons.append("관리자 1명 이하")
    return " | ".join(reasons) if reasons else "특이 패턴 없음"


# ── 스키마 ────────────────────────────────────────────────────
class PackageRequest(BaseModel):
    package_name: str

class RiskFactor(BaseModel):
    feature:   str
    label:     str
    impact:    float
    direction: str

class RiskResponse(BaseModel):
    package_name:     str
    risk_score:       float
    risk_level:       str
    reason:           str
    recommendation:   str
    exists_on_npm:    bool
    top_risk_factors: list[RiskFactor]
    inference_method: str


def _level(score: float) -> str:
    return "HIGH" if score >= 80 else "MEDIUM" if score >= 50 else "LOW"

def _recommendation(score: float) -> str:
    if score >= 80: return "즉시 설치 차단 권고"
    if score >= 50: return "수동 검토 후 설치 결정 권고"
    return "설치 허용 (정기 모니터링 유지)"


# ── 엔드포인트 ────────────────────────────────────────────────
@app.get("/health")
def health_check():
    _load_models()
    return {
        "status":   "ok",
        "version":  "0.4.0",
        "rf_model": "baseline_rf_v2 (12-feat, F1≥0.9565)",
        "ensemble": "loaded" if _ens_bundle else "not loaded",
    }


@app.get("/model-info")
def model_info():
    _load_models()
    rf = _rf_bundle["model"]
    return {
        "model_type":    type(rf).__name__,
        "n_features":    rf.n_features_in_,
        "feature_names": [
            "log_downloads", "name_similarity", "suspicious_name",
            "no_author", "has_install_script", "high_dependency",
            "maintainers_count", "dependencies_count", "not_exists",
            "min_edit_dist", "is_exact_popular", "is_scoped",
        ],
        "inference":  "hierarchical (RF → Ensemble fallback)",
        "ensemble":   _ens_bundle["metrics"] if _ens_bundle else None,
        "performance": {
            "f1_score": 0.9565,
            "auc_roc":  0.9917,
            "mae":      0.0773,
        },
    }


@app.post("/analyze", response_model=RiskResponse)
def analyze_package(req: PackageRequest):
    name = req.package_name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="package_name은 필수입니다.")

    _load_models()
    meta   = _fetch_meta(name)
    X_meta = _build_meta_features(name, meta)

    # ── 계층적 추론 ───────────────────────────────────────────
    X_meta_scaled = _rf_bundle["scaler"].transform(X_meta)
    score, method = hierarchical_score(
        rf_model=_rf_bundle["model"],
        rf_scaler=_rf_bundle["scaler"],
        X_meta=X_meta,
        ens_bundle=_ens_bundle,
        X_full=None,   # CodeBERT 임베딩은 실시간 무거움 → 메타 기반 fallback
    )

    top_factors  = _shap.top_factors(X_meta_scaled, k=3)
    edit_d       = _min_edit_dist(name)

    return RiskResponse(
        package_name=name,
        risk_score=score,
        risk_level=_level(score),
        reason=_build_reason(name, meta, edit_d),
        recommendation=_recommendation(score),
        exists_on_npm=meta.get("exists", True),
        top_risk_factors=top_factors,
        inference_method=method,
    )
