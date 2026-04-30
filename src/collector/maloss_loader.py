"""
MalOSS 데이터셋 로더
출처: https://github.com/osssanitizer/maloss
악성 npm 패키지 700+ 건 로드 및 전처리
"""

import json
import os
import pandas as pd
from loguru import logger


MALOSS_FIELDS = ["name", "version", "description", "author", "license", "downloads"]


def load_maloss_dataset(data_dir: str) -> pd.DataFrame:
    """MalOSS JSON 파일들을 읽어서 DataFrame으로 반환"""
    records = []

    if not os.path.exists(data_dir):
        logger.warning(f"데이터 디렉토리가 없습니다: {data_dir}")
        return pd.DataFrame()

    for fname in os.listdir(data_dir):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(data_dir, fname)
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                pkg = json.load(f)
            record = {field: pkg.get(field, None) for field in MALOSS_FIELDS}
            record["label"] = 1  # 악성
            records.append(record)
        except Exception as e:
            logger.error(f"파일 로드 실패 {fname}: {e}")

    df = pd.DataFrame(records)
    logger.info(f"MalOSS 로드 완료: {len(df)}건")
    return df


def load_label_map(label_path: str) -> dict:
    """패키지명 → 레이블 매핑 딕셔너리 반환"""
    with open(label_path, "r") as f:
        data = json.load(f)
    # {"malicious": [...], "benign": [...]} 구조 가정
    label_map = {}
    for name in data.get("malicious", []):
        label_map[name] = 1
    for name in data.get("benign", []):
        label_map[name] = 0
    logger.info(f"레이블 맵 로드: 악성 {sum(v for v in label_map.values())}건 / "
                f"정상 {sum(1 - v for v in label_map.values())}건")
    return label_map
