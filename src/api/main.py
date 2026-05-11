"""
FastAPI 실시간 위험도 평가 API
POST /analyze  패키지명 입력 → 위험도 점수 + 판단 근거 반환
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(
    title="npm Hallucination Detector API",
    description="LLM 환각 악용 npm 공급망 공격 탐지 API",
    version="0.1.0",
)


class PackageRequest(BaseModel):
    package_name: str
    install_script: str = ""


class RiskResponse(BaseModel):
    package_name: str
    risk_score: float       # 0~100
    risk_level: str         # LOW / MEDIUM / HIGH
    reason: str             # SHAP 기반 판단 근거 (추후 연동)
    recommendation: str


def score_to_level(score: float) -> str:
    if score >= 80:
        return "HIGH"
    elif score >= 50:
        return "MEDIUM"
    return "LOW"


def score_to_recommendation(score: float) -> str:
    if score >= 80:
        return "즉시 설치 차단 권고"
    elif score >= 50:
        return "수동 검토 후 설치 결정 권고"
    return "설치 허용 (정기 모니터링 유지)"


@app.get("/health")
def health_check():
    return {"status": "ok", "version": "0.1.0"}


@app.post("/analyze", response_model=RiskResponse)
def analyze_package(req: PackageRequest):
    if not req.package_name.strip():
        raise HTTPException(status_code=400, detail="package_name은 필수입니다.")

    # TODO: 실제 모델 연동 (현재는 규칙 기반 더미 로직)
    score = _dummy_score(req.package_name)
    level = score_to_level(score)

    return RiskResponse(
        package_name=req.package_name,
        risk_score=score,
        risk_level=level,
        reason="[SHAP 연동 예정] 현재 규칙 기반 스코어",
        recommendation=score_to_recommendation(score),
    )


def _dummy_score(name: str) -> float:
    """임시 규칙 기반 스코어 (모델 학습 전 API 구조 검증용)"""
    from difflib import SequenceMatcher
    popular = ["react", "lodash", "express", "axios", "webpack"]
    max_sim = max(SequenceMatcher(None, name, p).ratio() for p in popular)
    return round(max_sim * 100, 1)
