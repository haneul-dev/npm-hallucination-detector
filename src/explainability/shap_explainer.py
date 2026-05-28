"""
SHAP 기반 위험도 판단 근거 설명 모듈
v2: 12개 피처 (Levenshtein 기반 슬롭스쿼팅 특화 3개 추가)
"""

import numpy as np
import shap


FEAT_NAMES = [
    "log_downloads",
    "name_similarity",
    "suspicious_name",
    "no_author",
    "has_install_script",
    "high_dependency",
    "maintainers_count",
    "dependencies_count",
    "not_exists",
    "min_edit_dist",
    "is_exact_popular",
    "is_scoped",
]

FEAT_LABELS = {
    "log_downloads":      "다운로드 수 (낮을수록 위험)",
    "name_similarity":    "인기 패키지 이름 유사도 (SequenceMatcher)",
    "suspicious_name":    "의심 이름 패턴 (숫자 끝·연속 기호 등)",
    "no_author":          "작성자 정보 없음",
    "has_install_script": "postinstall 스크립트 존재",
    "high_dependency":    "과다 의존성 (>20개)",
    "maintainers_count":  "관리자 수",
    "dependencies_count": "의존성 수",
    "not_exists":         "npm 미존재 (404)",
    "min_edit_dist":      "인기 패키지와 최소 편집거리 (1=오타 1개)",
    "is_exact_popular":   "인기 패키지 정확 일치 (react·express 등)",
    "is_scoped":          "스코프 패키지 여부 (@babel/core 형태)",
}


class ShapExplainer:
    def __init__(self, rf_model):
        self.explainer = shap.TreeExplainer(rf_model)

    def top_factors(self, X_scaled: np.ndarray, k: int = 3) -> list[dict]:
        """
        단일 샘플 SHAP 값 계산 → 위험도 기여 상위 k개 반환
        양수 = 악성 방향 기여, 음수 = 정상 방향 기여
        """
        explanation = self.explainer(X_scaled)
        vals = np.array(explanation.values)

        # (n_samples, n_features, n_classes) → class 1 (악성)
        if vals.ndim == 3:
            vals_sample = vals[0, :, 1]
        elif vals.ndim == 2:
            vals_sample = vals[0, :]
        else:
            vals_sample = vals

        n_feats = len(vals_sample)
        names = FEAT_NAMES[:n_feats]

        ranked = sorted(
            zip(names, vals_sample.tolist()),
            key=lambda x: abs(x[1]),
            reverse=True,
        )[:k]

        return [
            {
                "feature":   name,
                "label":     FEAT_LABELS.get(name, name),
                "impact":    round(val, 4),
                "direction": "위험" if val > 0 else "안전",
            }
            for name, val in ranked
        ]
