"""
SHAP 기반 위험도 판단 근거 설명 모듈 (Phase 3-B)
TreeExplainer로 RF 모델의 피처별 기여도를 계산한다.
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
]

FEAT_LABELS = {
    "log_downloads":      "다운로드 수 (낮을수록 위험)",
    "name_similarity":    "인기 패키지 이름 유사도",
    "suspicious_name":    "의심 이름 패턴",
    "no_author":          "작성자 정보 없음",
    "has_install_script": "postinstall 스크립트 존재",
    "high_dependency":    "과다 의존성 (>20개)",
    "maintainers_count":  "관리자 수",
    "dependencies_count": "의존성 수",
    "not_exists":         "npm 미존재 (404)",
}


class ShapExplainer:
    def __init__(self, rf_model):
        self.explainer = shap.TreeExplainer(rf_model)

    def top_factors(self, X_scaled: np.ndarray, k: int = 3) -> list[dict]:
        """
        단일 샘플(1×9)의 SHAP 값을 계산하여 위험도 기여 상위 k개 반환.
        양수 값 = 악성 쪽으로 기여, 음수 = 정상 쪽으로 기여.
        """
        shap_vals = self.explainer.shap_values(X_scaled)
        # RF binary: [class0_vals, class1_vals]
        if isinstance(shap_vals, list):
            vals = shap_vals[1][0]
        else:
            vals = shap_vals[0]

        ranked = sorted(
            zip(FEAT_NAMES, vals.tolist()),
            key=lambda x: abs(x[1]),
            reverse=True,
        )[:k]

        return [
            {
                "feature": name,
                "label":   FEAT_LABELS[name],
                "impact":  round(val, 4),
                "direction": "위험" if val > 0 else "안전",
            }
            for name, val in ranked
        ]
