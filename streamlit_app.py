import streamlit as st
import requests
import time

st.set_page_config(
    page_title="npm 위험도 평가기",
    page_icon="🔍",
    layout="wide",
)

# ── 상수 ──────────────────────────────────────────────────────────────────
POPULAR = [
    "react","lodash","express","axios","chalk","moment","webpack","typescript",
    "eslint","prettier","jest","mongoose","async","request","got","node-fetch",
    "commander","yargs","glob","rimraf","uuid","semver","debug","ms","qs",
    "cors","dotenv","jsonwebtoken","bcrypt","yaml","cheerio","puppeteer",
]

GRADE_CFG = {
    "LOW":     {"emoji":"🟢","label":"LOW — 낮은 위험",       "msg":"위험 신호 없음. 일반적으로 안전하게 설치 가능합니다."},
    "LOW-MED": {"emoji":"🟡","label":"LOW-MED — 비교적 낮음", "msg":"큰 위험 신호는 없으나 일부 항목을 확인해보세요."},
    "MEDIUM":  {"emoji":"🟠","label":"MEDIUM — 중간 위험",    "msg":"⚠️ 위험도 애매한 구간입니다. 설치 전 한 번 더 확인해보시길 권장합니다."},
    "HIGH":    {"emoji":"🔴","label":"HIGH — 높은 위험",      "msg":"🚨 위험 신호 다수. 사용 전 신중한 검토가 필요합니다."},
    "CRITICAL":{"emoji":"🚨","label":"CRITICAL — 매우 위험",  "msg":"🚨 슬롭스쿼팅 공격 패키지로 의심됩니다. 설치하지 마세요!"},
}

FACTOR_MAX = {
    "패키지 미존재(404)": 15,
    "타이포스쿼팅 위험도": 30,
    "슬롭스쿼팅 복합 보너스": 10,
    "설치 스크립트 존재": 20,
    "설명 없음": 8,
    "저장소 링크 없음": 5,
    "키워드 없음": 2,
    "낮은 다운로드 수": 10,
    "관리자 수 부족": 10,
}

# ── 유틸리티 ──────────────────────────────────────────────────────────────
def levenshtein(a, b):
    m, n = len(a), len(b)
    if m < n:
        a, b, m, n = b, a, n, m
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev, dp[0] = dp[0], i
        for j in range(1, n + 1):
            temp = dp[j]
            dp[j] = prev if a[i-1] == b[j-1] else 1 + min(prev, dp[j], dp[j-1])
            prev = temp
    return dp[n]

def min_edit_distance(name):
    if name in POPULAR:
        return 0, name
    dists = [(levenshtein(name, p), p) for p in POPULAR]
    return min(dists, key=lambda x: x[0])

@st.cache_data(ttl=300, show_spinner=False)
def fetch_npm(name):
    try:
        r = requests.get(f"https://registry.npmjs.org/{name}", timeout=10)
        if r.status_code == 404:
            return {"exists": False}
        if r.status_code != 200:
            return {"exists": False}
        d = r.json()
        latest = d.get("dist-tags", {}).get("latest", "")
        ver = d.get("versions", {}).get(latest, {})
        scripts = ver.get("scripts", {})
        return {
            "exists": True,
            "description": d.get("description", ""),
            "maintainers_count": len(d.get("maintainers", [])),
            "keywords": d.get("keywords", []),
            "repository": d.get("repository", {}),
            "has_install_script": any(
                k in scripts for k in ["preinstall", "install", "postinstall"]
            ),
        }
    except Exception:
        return {"exists": False}

@st.cache_data(ttl=300, show_spinner=False)
def fetch_downloads(name):
    try:
        r = requests.get(
            f"https://api.npmjs.org/downloads/point/last-week/{name}", timeout=8
        )
        if r.status_code == 200:
            return r.json().get("downloads", 0)
    except Exception:
        pass
    return 0

def compute_score(name):
    info = fetch_npm(name)
    dl = fetch_downloads(name) if info.get("exists") else 0
    min_dist, closest = min_edit_distance(name)

    score = 0
    comps = {}

    v = 15 if not info["exists"] else 0
    comps["패키지 미존재(404)"] = v
    score += v

    if min_dist == 0:   v = 0
    elif min_dist == 1: v = 30
    elif min_dist == 2: v = 20
    elif min_dist == 3: v = 10
    else:               v = 0
    comps["타이포스쿼팅 위험도"] = v
    score += v

    v = 10 if (not info["exists"] and min_dist == 1) else 0
    comps["슬롭스쿼팅 복합 보너스"] = v
    score += v

    v = 20 if info.get("has_install_script") else 0
    comps["설치 스크립트 존재"] = v
    score += v

    v = 8 if not info.get("description") else 0
    comps["설명 없음"] = v
    score += v

    repo = info.get("repository", {})
    has_repo = bool(
        repo and (isinstance(repo, dict) and repo.get("url"))
        or isinstance(repo, str)
    )
    v = 5 if not has_repo else 0
    comps["저장소 링크 없음"] = v
    score += v

    v = 2 if not info.get("keywords") else 0
    comps["키워드 없음"] = v
    score += v

    if dl == 0:       v = 10
    elif dl < 100:    v = 7
    elif dl < 1_000:  v = 4
    elif dl < 10_000: v = 1
    else:             v = 0
    comps["낮은 다운로드 수"] = v
    score += v

    m = info.get("maintainers_count", 0)
    if m == 0:   v = 10
    elif m == 1: v = 5
    elif m == 2: v = 2
    else:        v = 0
    comps["관리자 수 부족"] = v
    score += v

    score = min(score, 100)

    if score <= 20:   grade = "LOW"
    elif score <= 40: grade = "LOW-MED"
    elif score <= 60: grade = "MEDIUM"
    elif score <= 80: grade = "HIGH"
    else:             grade = "CRITICAL"

    return {
        "name": name, "score": score, "grade": grade,
        "components": comps, "exists": info["exists"],
        "downloads": dl, "min_dist": min_dist, "closest": closest,
        "maintainers": info.get("maintainers_count", 0),
        "has_install_script": info.get("has_install_script", False),
    }


# ════════════════════════════════════════════════════════════════════════════
# UI
# ════════════════════════════════════════════════════════════════════════════
st.title("🔍 npm 패키지 위험도 평가기")
st.caption("LLM 환각 악용 슬롭스쿼팅 공격 탐지 시스템  ·  단국대학교 32230120 강하늘")
st.divider()

# ── 데모 패키지 ───────────────────────────────────────────────────────────
st.subheader("📦 데모 패키지 4종 비교")
st.caption("버튼을 클릭하면 npm API에서 실시간으로 데이터를 수집해 위험도를 계산합니다.")

DEMO_PKGS = ["express", "expresss", "axos", "reqact"]

if st.button("🚀  데모 패키지 4종 분석 실행"):
    results = []
    bar = st.progress(0, text="분석 중...")
    for i, pkg in enumerate(DEMO_PKGS):
        bar.progress((i + 1) / len(DEMO_PKGS), text=f"'{pkg}' 분석 중...")
        results.append(compute_score(pkg))
        time.sleep(0.3)
    bar.empty()
    st.session_state["demo_results"] = results

# 결과를 session_state에서 꺼내서 별도 컨테이너에 렌더링
demo_container = st.container()
if "demo_results" in st.session_state:
    with demo_container:
        results = st.session_state["demo_results"]
        c1, c2, c3, c4 = st.columns(4)
        for col, res in zip([c1, c2, c3, c4], results):
            cfg = GRADE_CFG[res["grade"]]
            with col:
                st.metric(
                    label=f"`{res['name']}`",
                    value=f"{res['score']}점",
                )
                st.write(f"**{cfg['emoji']} {cfg['label']}**")
                exist = "❌ 404" if not res["exists"] else f"✅ {res['downloads']:,}회/주"
                st.caption(f"{exist}")
                st.caption(f"편집거리 {res['min_dist']} ← {res['closest']}")
                if res["grade"] in ("MEDIUM", "HIGH", "CRITICAL"):
                    st.warning(cfg["msg"])
                else:
                    st.success(cfg["msg"])

st.divider()

# ── 직접 분석 ─────────────────────────────────────────────────────────────
st.subheader("🔎 패키지 직접 분석")

pkg_name = st.text_input(
    "패키지명 입력",
    placeholder="예: lodash, axio, reqact, expresss",
    label_visibility="visible",
)
analyze = st.button("분석 실행")

# 결과를 별도 컨테이너에 격리
result_container = st.container()

if analyze and pkg_name.strip():
    name = pkg_name.strip().lower()
    with st.spinner(f"'{name}' 분석 중..."):
        res = compute_score(name)
    st.session_state["single_result"] = res

if "single_result" in st.session_state and pkg_name.strip():
    res = st.session_state["single_result"]
    if res["name"] == pkg_name.strip().lower():
        with result_container:
            st.subheader(f"`npm install {res['name']}`")
            cfg = GRADE_CFG[res["grade"]]

            col_a, col_b, col_c = st.columns([1, 1, 2])

            with col_a:
                st.metric("위험도 점수", f"{res['score']} / 100")
                st.write(f"**{cfg['emoji']} {cfg['label']}**")

            with col_b:
                st.write("**패키지 정보**")
                st.write("npm:" , "❌ 404" if not res["exists"] else "✅ 존재함")
                st.write("다운로드:", f"{res['downloads']:,}회/주")
                st.write("관리자:", f"{res['maintainers']}명")
                st.write("유사 패키지:", f"{res['closest']} (거리 {res['min_dist']})")
                st.write("설치스크립트:", "있음" if res["has_install_script"] else "없음")

            with col_c:
                st.write("**점수 구성 요소**")
                for fname, val in res["components"].items():
                    max_val = FACTOR_MAX.get(fname, 1)
                    pct = val / max_val if max_val > 0 else 0
                    st.progress(pct, text=f"{fname}  (+{val}/{max_val}점)")

            if res["grade"] in ("MEDIUM", "HIGH", "CRITICAL"):
                st.warning(f"{cfg['emoji']}  {cfg['msg']}")
            else:
                st.success(f"{cfg['emoji']}  {cfg['msg']}")

elif analyze and not pkg_name.strip():
    st.warning("패키지 이름을 입력해주세요.")

st.divider()
st.caption(
    "**점수 산정:** 타이포스쿼팅(최대 30) + 미존재(15) + 슬롭스쿼팅보너스(10) + "
    "설치스크립트(20) + 메타데이터(15) + 활동지표(20) = 최대 100점  |  "
    "모든 데이터는 npm Registry API에서 실시간 수집"
)
