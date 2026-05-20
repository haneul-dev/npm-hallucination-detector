"""
FastAPI 실시간 위험도 평가 API
POST /analyze  패키지명 입력 → 위험도 점수 + SHAP 판단 근거 반환
GET  /model-info  현재 모델 메타데이터 반환
"""

import json, re, pickle, os, numpy as np, urllib.request
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from src.explainability.shap_explainer import ShapExplainer

app = FastAPI(
    title="npm Hallucination Detector API",
    description="LLM 환각 악용 npm 공급망 공격 탐지 API",
    version="0.3.0",
)

# ─── 모델 로드 ────────────────────────────────────────────────
_MODEL_PATH = os.path.join(os.path.dirname(__file__), "../../models/baseline_rf.pkl")
_bundle = None
_shap: ShapExplainer = None

def _load_model():
    global _bundle, _shap
    if _bundle is None:
        with open(_MODEL_PATH, "rb") as f:
            _bundle = pickle.load(f)
        _shap = ShapExplainer(_bundle["model"])

POPULAR = ["react","express","lodash","axios","webpack","babel","eslint",
           "typescript","vue","angular","jquery","moment","chalk","commander",
           "dotenv","fastify","koa","next","vite","prisma"]

def _name_similarity(name: str) -> float:
    from difflib import SequenceMatcher
    return max(SequenceMatcher(None, name.lower(), p).ratio() for p in POPULAR)

def _suspicious(name: str) -> int:
    return int(any(re.search(p, name) for p in [r"\d{3,}$", r"_{2,}", r"-{2,}", r"^[a-z]{1,2}$"]))

def _fetch_meta(name: str) -> dict:
    try:
        req = urllib.request.Request(
            f"https://registry.npmjs.org/{name}",
            headers={"User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=6) as r:
            data = json.loads(r.read())
        latest = data.get("dist-tags", {}).get("latest", "")
        ver = data.get("versions", {}).get(latest, {})
        author = data.get("author", {})
        return {
            "exists": True,
            "author": author.get("name","") if isinstance(author, dict) else str(author or ""),
            "maintainers_count": len(data.get("maintainers", [])),
            "dependencies_count": len(ver.get("dependencies", {})),
            "has_install_script": int("install" in ver.get("scripts", {})),
            "downloads": 0,
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

def _build_features(name: str, meta: dict) -> np.ndarray:
    d = meta.get("downloads", 0) or 0
    return np.array([[
        np.log1p(d),
        _name_similarity(name),
        _suspicious(name),
        int(not meta.get("author", "")),
        meta.get("has_install_script", 0),
        int(meta.get("dependencies_count", 0) > 20),
        min(meta.get("maintainers_count", 0), 20),
        min(meta.get("dependencies_count", 0), 50),
        int(not meta.get("exists", True)),
    ]])

def _build_reason(name: str, meta: dict, score: float) -> str:
    reasons = []
    if not meta.get("exists", True):
        reasons.append("npm에 존재하지 않는 패키지(404)")
    if not meta.get("author", ""):
        reasons.append("작성자 정보 없음")
    if meta.get("has_install_script"):
        reasons.append("postinstall 스크립트 존재")
    sim = _name_similarity(name)
    # 정확히 일치하면 진짜 인기 패키지 → 경고 제외
    if sim > 0.7 and name.lower() not in POPULAR:
        reasons.append(f"인기 패키지와 이름 유사 (유사도 {sim:.0%})")
    if _suspicious(name):
        reasons.append("의심스러운 이름 패턴")
    if meta.get("maintainers_count", 1) <= 1 and meta.get("exists", True):
        reasons.append("관리자 1명 이하")
    return " | ".join(reasons) if reasons else "특이 패턴 없음"


class PackageRequest(BaseModel):
    package_name: str

class RiskFactor(BaseModel):
    feature: str
    label: str
    impact: float
    direction: str

class RiskResponse(BaseModel):
    package_name: str
    risk_score: float
    risk_level: str
    reason: str
    recommendation: str
    exists_on_npm: bool
    top_risk_factors: list[RiskFactor]


def _level(score: float) -> str:
    return "HIGH" if score >= 80 else "MEDIUM" if score >= 50 else "LOW"

def _recommendation(score: float) -> str:
    if score >= 80: return "즉시 설치 차단 권고"
    if score >= 50: return "수동 검토 후 설치 결정 권고"
    return "설치 허용 (정기 모니터링 유지)"


@app.get("/health")
def health_check():
    return {"status": "ok", "version": "0.3.0", "model": "baseline_rf (F1=0.9565, AUC=0.9917)"}


@app.get("/model-info")
def model_info():
    """현재 로드된 모델의 메타데이터 반환"""
    _load_model()
    rf = _bundle["model"]
    return {
        "model_type": type(rf).__name__,
        "n_estimators": rf.n_estimators,
        "n_features": rf.n_features_in_,
        "feature_names": [
            "log_downloads", "name_similarity", "suspicious_name",
            "no_author", "has_install_script", "high_dependency",
            "maintainers_count", "dependencies_count", "not_exists",
        ],
        "performance": {
            "f1_score": 0.9565,
            "auc_roc": 0.9917,
            "mae": 0.0773,
        },
        "dataset_size": 7160,
        "explainability": "SHAP TreeExplainer",
    }


@app.post("/analyze", response_model=RiskResponse)
def analyze_package(req: PackageRequest):
    if not req.package_name.strip():
        raise HTTPException(status_code=400, detail="package_name은 필수입니다.")

    _load_model()
    meta = _fetch_meta(req.package_name)
    X = _build_features(req.package_name, meta)
    X_scaled = _bundle["scaler"].transform(X)
    score = round(float(_bundle["model"].predict_proba(X_scaled)[0, 1]) * 100, 1)
    top_factors = _shap.top_factors(X_scaled, k=3)

    return RiskResponse(
        package_name=req.package_name,
        risk_score=score,
        risk_level=_level(score),
        reason=_build_reason(req.package_name, meta, score),
        recommendation=_recommendation(score),
        exists_on_npm=meta.get("exists", True),
        top_risk_factors=top_factors,
    )
