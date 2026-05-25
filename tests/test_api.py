"""
/analyze, /health, /model-info 엔드포인트 통합 테스트.
npm 레지스트리 실호출 없이 응답 구조와 비즈니스 로직만 검증한다.

실행:
    pytest tests/test_api.py -v
"""

import numpy as np
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient


# ─── 공통 목(Mock) 설정 ──────────────────────────────────────

@pytest.fixture(autouse=True)
def mock_model(tmp_path):
    """RF 모델 + 스케일러 + SHAP 모두 목 처리 (네트워크·디스크 불필요)"""
    import pickle, os
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler

    clf = RandomForestClassifier(n_estimators=10, random_state=42)
    X_dummy = np.random.rand(20, 9)
    y_dummy = np.array([1]*10 + [0]*10)
    clf.fit(X_dummy, y_dummy)

    scaler = StandardScaler()
    scaler.fit(X_dummy)

    pkl_path = tmp_path / "baseline_rf.pkl"
    with open(pkl_path, "wb") as f:
        pickle.dump({"model": clf, "scaler": scaler}, f)

    with patch("src.api.main._MODEL_PATH", str(pkl_path)):
        yield


@pytest.fixture()
def client(mock_model):
    from src.api.main import app
    return TestClient(app)


def _mock_meta_exists(name: str) -> dict:
    return {
        "exists": True, "author": "test-author", "maintainers_count": 3,
        "dependencies_count": 2, "has_install_script": 0, "downloads": 1000,
    }

def _mock_meta_404(name: str) -> dict:
    return {
        "exists": False, "author": "", "maintainers_count": 0,
        "dependencies_count": 0, "has_install_script": 1, "downloads": 0,
    }


# ─── /health ─────────────────────────────────────────────────

def test_health_returns_ok(client):
    res = client.get("/health")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "ok"
    assert "version" in body
    assert "model" in body


# ─── /model-info ─────────────────────────────────────────────

def test_model_info_structure(client):
    res = client.get("/model-info")
    assert res.status_code == 200
    body = res.json()
    assert "model_type" in body
    assert "n_features" in body
    assert body["n_features"] == 9
    assert "performance" in body
    assert "f1_score" in body["performance"]


# ─── /analyze ────────────────────────────────────────────────

def test_analyze_response_schema(client):
    with patch("src.api.main._fetch_meta", side_effect=_mock_meta_exists):
        res = client.post("/analyze", json={"package_name": "express"})
    assert res.status_code == 200
    body = res.json()
    required = {"package_name", "risk_score", "risk_level", "reason",
                "recommendation", "exists_on_npm", "top_risk_factors"}
    assert required.issubset(body.keys())


def test_analyze_risk_score_range(client):
    with patch("src.api.main._fetch_meta", side_effect=_mock_meta_exists):
        res = client.post("/analyze", json={"package_name": "some-package"})
    score = res.json()["risk_score"]
    assert 0.0 <= score <= 100.0


def test_analyze_404_package_flagged(client):
    """npm에 없는 패키지는 reason에 404 문구 포함되어야 함"""
    with patch("src.api.main._fetch_meta", side_effect=_mock_meta_404):
        res = client.post("/analyze", json={"package_name": "react-hook-form-v2"})
    assert res.status_code == 200
    body = res.json()
    assert body["exists_on_npm"] is False
    assert "404" in body["reason"]


def test_analyze_top_risk_factors_count(client):
    """top_risk_factors는 최대 3개 반환"""
    with patch("src.api.main._fetch_meta", side_effect=_mock_meta_exists):
        res = client.post("/analyze", json={"package_name": "test-pkg"})
    factors = res.json()["top_risk_factors"]
    assert 1 <= len(factors) <= 3


def test_analyze_risk_factor_schema(client):
    """각 factor는 feature, label, impact, direction 필드를 가져야 함"""
    with patch("src.api.main._fetch_meta", side_effect=_mock_meta_exists):
        res = client.post("/analyze", json={"package_name": "test-pkg"})
    for factor in res.json()["top_risk_factors"]:
        assert {"feature", "label", "impact", "direction"}.issubset(factor.keys())
        assert factor["direction"] in ("위험", "안전")


def test_analyze_empty_name_returns_400(client):
    res = client.post("/analyze", json={"package_name": ""})
    assert res.status_code == 400


def test_analyze_risk_level_mapping(client):
    """risk_score 구간에 따라 risk_level이 올바르게 매핑되는지 확인"""
    from src.api.main import _level
    assert _level(85.0) == "HIGH"
    assert _level(65.0) == "MEDIUM"
    assert _level(30.0) == "LOW"
    assert _level(80.0) == "HIGH"
    assert _level(50.0) == "MEDIUM"
