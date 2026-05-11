import os
import json
import pandas as pd
from loguru import logger


def save_dataframe(df: pd.DataFrame, path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    df.to_csv(path, index=False)
    logger.info(f"저장 완료: {path} ({len(df)}행)")


def load_dataframe(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    logger.info(f"로드 완료: {path} ({len(df)}행)")
    return df


def load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
