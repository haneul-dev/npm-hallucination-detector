"""
계층적 추론 모듈 (Hierarchical Inference)

RF 메타데이터 모델이 확신할 때 → RF 단독 판단 (빠름)
RF 불확실 구간 (15~85점) → CodeBERT 앙상블 개입
두 모델 불일치 → 더 확신하는 쪽이 주도

이 구조 덕분에:
- 이름이 명백히 유명 패키지(edit_dist=0) → RF가 즉시 LOW 판정
- 오타 1~2개 수준의 애매한 케이스 → 앙상블이 description 임베딩으로 보완
"""

import numpy as np
from typing import Tuple

RF_HIGH = 0.85   # 이 이상이면 악성 확신 → RF 단독
RF_LOW  = 0.15   # 이 이하이면 정상 확신 → RF 단독
ENS_W   = 0.65   # 불확실 구간에서 앙상블 가중치


def hierarchical_score(
    rf_model,
    rf_scaler,
    X_meta: np.ndarray,          # (1, 11) 스케일 전 메타 피처
    ens_bundle=None,              # ensemble pkl (없으면 RF only)
    X_full: np.ndarray = None,   # (1, 779) CodeBERT + meta (앙상블용)
) -> Tuple[float, str]:
    """
    Returns
    -------
    score  : float  0~100 위험도 점수
    method : str    판단 경로 (발표/디버깅용)
    """
    X_meta_s = rf_scaler.transform(X_meta)
    rf_p = float(rf_model.predict_proba(X_meta_s)[0, 1])

    # 1단계: RF 확신 → 즉시 반환
    if rf_p >= RF_HIGH or rf_p <= RF_LOW:
        return round(rf_p * 100, 1), "rf_high_confidence"

    # 2단계: RF 불확실 + 앙상블 없음
    if ens_bundle is None or X_full is None:
        return round(rf_p * 100, 1), "rf_only"

    # 3단계: 앙상블 참조
    X_full_s = ens_bundle["scaler"].transform(X_full)
    ens_p = float(ens_bundle["model"].predict_proba(X_full_s)[0, 1])

    agreement = abs(rf_p - ens_p)

    if agreement < 0.25:
        # 두 모델 일치 → 앙상블 가중 평균
        final = (1 - ENS_W) * rf_p + ENS_W * ens_p
        method = "ensemble_weighted"
    else:
        # 불일치 → 더 확신하는 쪽 채택
        rf_conf  = abs(rf_p  - 0.5)
        ens_conf = abs(ens_p - 0.5)
        final  = ens_p if ens_conf > rf_conf else rf_p
        method = "ensemble_leading" if ens_conf > rf_conf else "rf_leading"

    return round(final * 100, 1), method
