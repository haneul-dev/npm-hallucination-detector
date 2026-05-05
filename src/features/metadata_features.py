"""
메타데이터 기반 피처 엔지니어링
작성자 신뢰도, 다운로드 수, 패키지 이름 패턴 등을 수치 피처로 변환
"""

import re
import numpy as np
import pandas as pd
from loguru import logger


# 슬롭스쿼팅 패턴: 인기 패키지와 유사한 이름 탐지용
POPULAR_PACKAGES = [
    "react", "express", "lodash", "axios", "moment",
    "webpack", "babel", "eslint", "typescript", "vue",
    "angular", "jquery", "underscore", "chalk", "commander"
]


def name_similarity_score(package_name: str) -> float:
    """인기 패키지와의 편집 거리 기반 유사도 (0~1, 높을수록 유심)"""
    from difflib import SequenceMatcher
    max_score = 0.0
    for popular in POPULAR_PACKAGES:
        score = SequenceMatcher(None, package_name.lower(), popular).ratio()
        max_score = max(max_score, score)
    return max_score


def has_suspicious_name_pattern(package_name: str) -> int:
    """이름에 의심 패턴이 있으면 1 반환 (숫자 끝, 언더스코어 과다 등)"""
    patterns = [
        r"\d{3,}$",          # 숫자로 끝나는 경우
        r"_{2,}",             # 언더스코어 2개 이상 연속
        r"-{2,}",             # 하이픈 2개 이상 연속
        r"^[a-z]{1,2}$",     # 너무 짧은 이름
    ]
    for p in patterns:
        if re.search(p, package_name):
            return 1
    return 0


def extract_metadata_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    DataFrame에서 수치 피처 컬럼 추가
    입력 컬럼: name, downloads, maintainers_count, dependencies_count,
               has_install_script, author
    """
    df = df.copy()

    # 다운로드 수 로그 스케일 (0이면 -1로 표시)
    df["log_downloads"] = df["downloads"].apply(
        lambda x: np.log1p(x) if x and x > 0 else -1.0
    )

    # 이름 유사도
    df["name_similarity"] = df["name"].apply(name_similarity_score)

    # 의심 이름 패턴
    df["suspicious_name"] = df["name"].apply(has_suspicious_name_pattern)

    # 작성자 없으면 의심
    df["no_author"] = df["author"].apply(lambda x: 1 if not x or x == "nan" else 0)

    # install 스크립트 존재 여부 (악성 패키지 특징)
    df["has_install_script"] = df["has_install_script"].astype(int)

    # 의존성 수 (너무 많으면 의심)
    df["high_dependency"] = (df["dependencies_count"] > 20).astype(int)

    logger.info(f"메타데이터 피처 추출 완료: {len(df)}행 x {len(df.columns)}열")
    return df


FEATURE_COLUMNS = [
    "log_downloads",
    "name_similarity",
    "suspicious_name",
    "no_author",
    "has_install_script",
    "high_dependency",
    "maintainers_count",
    "dependencies_count",
]
