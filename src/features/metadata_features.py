"""
메타데이터 기반 피처 엔지니어링
작성자 신뢰도, 다운로드 수, 패키지 이름 패턴 등을 수치 피처로 변환
v2: Levenshtein 기반 슬롭스쿼팅 특화 피처 3개 추가 (총 12개)
"""

import re
import numpy as np
import pandas as pd
from loguru import logger


POPULAR_PACKAGES = [
    "react", "express", "lodash", "axios", "moment",
    "webpack", "babel", "eslint", "typescript", "vue",
    "angular", "jquery", "underscore", "chalk", "commander",
    "dotenv", "fastify", "koa", "next", "vite", "prisma",
]


# ── Levenshtein 거리 (외부 라이브러리 없이 구현) ─────────────
def levenshtein(a: str, b: str) -> int:
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev, dp[0] = dp[0], i
        for j in range(1, n + 1):
            temp = dp[j]
            dp[j] = prev if a[i-1] == b[j-1] else 1 + min(prev, dp[j], dp[j-1])
            prev = temp
    return dp[n]


def min_edit_distance(package_name: str) -> int:
    """인기 패키지와의 최소 Levenshtein 거리 (슬롭스쿼팅 핵심 신호)"""
    # 스코프 패키지(@vue/cli)는 core name만 비교
    name = package_name.lower().lstrip("@").split("/")[0]
    return min(levenshtein(name, p) for p in POPULAR_PACKAGES)


def name_similarity_score(package_name: str) -> float:
    """SequenceMatcher 기반 유사도 (0~1)"""
    from difflib import SequenceMatcher
    return max(
        SequenceMatcher(None, package_name.lower(), p).ratio()
        for p in POPULAR_PACKAGES
    )


def has_suspicious_name_pattern(package_name: str) -> int:
    patterns = [r"\d{3,}$", r"_{2,}", r"-{2,}", r"^[a-z]{1,2}$"]
    return int(any(re.search(p, package_name) for p in patterns))


def extract_metadata_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["log_downloads"] = df["downloads"].apply(
        lambda x: np.log1p(x) if x and x > 0 else -1.0
    )
    df["name_similarity"]  = df["name"].apply(name_similarity_score)
    df["suspicious_name"]  = df["name"].apply(has_suspicious_name_pattern)
    df["no_author"]        = df["author"].apply(lambda x: 1 if not x or x == "nan" else 0)
    df["has_install_script"] = df["has_install_script"].astype(int)
    df["high_dependency"]  = (df["dependencies_count"] > 20).astype(int)

    # ── v2 슬롭스쿼팅 특화 피처 ──────────────────────────────
    edit_dists = df["name"].apply(min_edit_distance)
    df["min_edit_dist"]    = edit_dists.clip(upper=10)   # 0=완벽일치, 1=오타1개
    df["is_exact_popular"] = (edit_dists == 0).astype(int)  # 유명 패키지 자체
    df["is_scoped"]        = df["name"].str.startswith("@").astype(int)  # @babel/core 등

    logger.info(f"피처 추출 완료: {len(df)}행 x {len(df.columns)}열")
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
    "min_edit_dist",       # NEW v2
    "is_exact_popular",    # NEW v2
    "is_scoped",           # NEW v2
]
