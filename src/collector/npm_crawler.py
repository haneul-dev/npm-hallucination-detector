"""
npm Registry 크롤러
출처: https://registry.npmjs.org
패키지 메타데이터(이름, 버전, 다운로드 수, 작성자 등) 수집
"""

import time
import requests
import pandas as pd
from loguru import logger

NPM_REGISTRY = "https://registry.npmjs.org"
NPM_DOWNLOADS = "https://api.npmjs.org/downloads/point/last-month"


def fetch_package_metadata(package_name: str) -> dict | None:
    """단일 패키지 메타데이터 조회"""
    url = f"{NPM_REGISTRY}/{package_name}"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 404:
            # 존재하지 않는 패키지 → 환각 후보
            logger.debug(f"패키지 없음 (404): {package_name}")
            return {"name": package_name, "exists": False}
        resp.raise_for_status()
        data = resp.json()
        latest = data.get("dist-tags", {}).get("latest", "")
        version_info = data.get("versions", {}).get(latest, {})
        return {
            "name": package_name,
            "exists": True,
            "version": latest,
            "description": data.get("description", ""),
            "author": data.get("author", {}).get("name", "") if isinstance(data.get("author"), dict) else str(data.get("author", "")),
            "license": version_info.get("license", ""),
            "dependencies_count": len(version_info.get("dependencies", {})),
            "has_install_script": "install" in version_info.get("scripts", {}),
            "maintainers_count": len(data.get("maintainers", [])),
        }
    except requests.RequestException as e:
        logger.error(f"요청 실패 {package_name}: {e}")
        return None


def fetch_download_count(package_name: str) -> int:
    """최근 1달 다운로드 수 조회"""
    url = f"{NPM_DOWNLOADS}/{package_name}"
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        return resp.json().get("downloads", 0)
    except Exception:
        return 0


def crawl_packages(package_list: list[str], delay: float = 0.5) -> pd.DataFrame:
    """
    패키지 목록을 순회하며 메타데이터 수집
    delay: API rate limit 방지용 딜레이(초)
    """
    results = []
    for i, name in enumerate(package_list):
        meta = fetch_package_metadata(name)
        if meta and meta.get("exists"):
            meta["downloads"] = fetch_download_count(name)
        if meta:
            results.append(meta)
        if (i + 1) % 50 == 0:
            logger.info(f"진행 중: {i + 1}/{len(package_list)}")
        time.sleep(delay)

    df = pd.DataFrame(results)
    logger.info(f"크롤링 완료: {len(df)}건")
    return df
