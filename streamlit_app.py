import streamlit as st
import requests
import time

st.set_page_config(
    page_title="npm 위험도 평가기",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── CSS ───────────────────────────────────────────────────────────────────
st.markdown("""
<style>
  .main { background: #0F172A; color: #F1F5F9; }
  .stApp { background: #0F172A; }
  .block-container { padding-top: 1.5rem; }
  h1, h2, h3 { color: #F1F5F9 !important; }
  .score-box {
    background: #1E293B; border-radius: 12px;
    padding: 24px; text-align: center; border: 2px solid;
  }
  .score-num { font-size: 72px; font-weight: 900; line-height: 1; }
  .grade-badge {
    display: inline-block; border-radius: 8px;
    padding: 6px 20px; font-size: 16px; font-weight: 700;
    margin-top: 8px;
  }
  .factor-bar-bg {
    background: #334155; border-radius: 6px; height: 12px; margin: 4px 0;
  }
  .factor-bar-fill { border-radius: 6px; height: 12px; }
  .info-card {
    background: #1E293B; border-radius: 10px;
    padding: 16px; margin: 8px 0; border-left: 4px solid;
  }
  .stTextInput > div > div > input {
    background: #1E293B !important; color: #F1F5F9 !important;
    border: 1.5px solid #334155 !important; border-radius: 8px !important;
    font-size: 16px !important;
  }
  .stButton > button {
    background: #2563EB !important; color: white !important;
    border: none !important; border-radius: 8px !important;
    font-size: 15px !important; font-weight: 600 !important;
    padding: 10px 28px !important; width: 100% !important;
  }
  .stButton > button:hover { background: #1D4ED8 !important; }
  div[data-testid="metric-container"] {
    background: #1E293B; border-radius: 10px; padding: 12px;
  }
  .stExpander { background: #1E293B !important; border-radius: 10px !important; }
  hr { border-color: #334155 !important; }
</style>
""", unsafe_allow_html=True)

# ── 상수 ──────────────────────────────────────────────────────────────────
POPULAR = [
    "react","lodash","express","axios","chalk","moment","webpack","typescript",
    "eslint","prettier","jest","mongoose","async","request","got","node-fetch",
    "commander","yargs","glob","rimraf","uuid","semver","debug","ms","qs",
    "cors","dotenv","jsonwebtoken","bcrypt","yaml","cheerio","puppeteer",
]

GRADE_CFG = {
    "LOW":      {"color":"#22c55e","bg":"#14532D","label":"낮은 위험",      "msg":"위험 신호가 없습니다. 일반적으로 안전하게 설치 가능합니다."},
    "LOW-MED":  {"color":"#84cc16","bg":"#365314","label":"비교적 낮은 위험","msg":"큰 위험 신호는 없으나 일부 항목을 확인해보세요."},
    "MEDIUM":   {"color":"#f59e0b","bg":"#451A03","label":"중간 위험",      "msg":"⚠️ 위험도가 애매한 구간입니다. 설치 전 한 번 더 확인해보시길 권장합니다."},
    "HIGH":     {"color":"#f97316","bg":"#431407","label":"높은 위험",      "msg":"🚨 위험 신호가 다수 감지됩니다. 사용 전 신중한 검토가 필요합니다."},
    "CRITICAL": {"color":"#ef4444","bg":"#450A0A","label":"매우 높은 위험", "msg":"🚨🚨 슬롭스쿼팅 공격 패키지로 의심됩니다. 설치하지 마세요."},
}

# ── 유틸리티 ──────────────────────────────────────────────────────────────
def levenshtein(a, b):
    m, n = len(a), len(b)
    if m < n: a, b, m, n = b, a, n, m
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
            "has_install_script": any(k in scripts for k in ["preinstall","install","postinstall"]),
            "latest_version": latest,
        }
    except:
        return {"exists": False}

@st.cache_data(ttl=300, show_spinner=False)
def fetch_downloads(name):
    try:
        r = requests.get(f"https://api.npmjs.org/downloads/point/last-week/{name}", timeout=8)
        if r.status_code == 200:
            return r.json().get("downloads", 0)
    except:
        pass
    return 0

def compute_score(name):
    info = fetch_npm(name)
    dl = fetch_downloads(name) if info.get("exists") else 0
    min_dist, closest = min_edit_distance(name)

    score = 0
    comps = {}

    # A. 패키지 미존재
    v = 15 if not info["exists"] else 0
    comps["패키지 미존재 (404)"] = (v, 15)
    score += v

    # B. 타이포스쿼팅
    if min_dist == 0:   v = 0
    elif min_dist == 1: v = 30
    elif min_dist == 2: v = 20
    elif min_dist == 3: v = 10
    else:               v = 0
    comps["타이포스쿼팅 위험도"] = (v, 30)
    score += v

    # C. 슬롭스쿼팅 복합 보너스
    v = 10 if (not info["exists"] and min_dist == 1) else 0
    comps["슬롭스쿼팅 복합 보너스"] = (v, 10)
    score += v

    # D. 설치 스크립트
    v = 20 if info.get("has_install_script") else 0
    comps["설치 스크립트 존재"] = (v, 20)
    score += v

    # E. 설명 없음
    v = 8 if not info.get("description") else 0
    comps["설명 없음"] = (v, 8)
    score += v

    # F. 저장소 없음
    repo = info.get("repository", {})
    has_repo = bool(repo and (isinstance(repo, dict) and repo.get("url")) or isinstance(repo, str))
    v = 5 if not has_repo else 0
    comps["저장소 링크 없음"] = (v, 5)
    score += v

    # G. 키워드 없음
    v = 2 if not info.get("keywords") else 0
    comps["키워드 없음"] = (v, 2)
    score += v

    # H. 낮은 다운로드
    if dl == 0:       v = 10
    elif dl < 100:    v = 7
    elif dl < 1_000:  v = 4
    elif dl < 10_000: v = 1
    else:             v = 0
    comps["낮은 다운로드 수"] = (v, 10)
    score += v

    # I. 관리자 수
    m = info.get("maintainers_count", 0)
    if m == 0:   v = 10
    elif m == 1: v = 5
    elif m == 2: v = 2
    else:        v = 0
    comps["관리자 수 부족"] = (v, 10)
    score += v

    score = min(score, 100)

    if score <= 20:   grade = "LOW"
    elif score <= 40: grade = "LOW-MED"
    elif score <= 60: grade = "MEDIUM"
    elif score <= 80: grade = "HIGH"
    else:             grade = "CRITICAL"

    return {
        "name": name,
        "score": score,
        "grade": grade,
        "components": comps,
        "exists": info["exists"],
        "downloads": dl,
        "min_dist": min_dist,
        "closest": closest,
        "maintainers": info.get("maintainers_count", 0),
        "description": info.get("description", ""),
        "has_install_script": info.get("has_install_script", False),
    }

def render_result(res):
    g = res["grade"]
    cfg = GRADE_CFG[g]
    color = cfg["color"]

    col1, col2 = st.columns([1, 2])

    with col1:
        st.markdown(f"""
        <div class="score-box" style="border-color:{color};">
          <div class="score-num" style="color:{color};">{res['score']}</div>
          <div style="color:#94A3B8;font-size:14px;margin-top:4px;">/ 100점</div>
          <div class="grade-badge" style="background:{cfg['bg']};color:{color};">
            {cfg['label']}
          </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # 기본 정보
        exist_icon = "✅ 존재함" if res["exists"] else "❌ npm 미존재 (404)"
        st.markdown(f"""
        <div class="info-card" style="border-color:{color};">
          <div style="color:#94A3B8;font-size:12px;margin-bottom:8px;">패키지 정보</div>
          <div style="font-size:13px;line-height:2;">
            npm 존재: <b>{exist_icon}</b><br>
            주간 다운로드: <b>{res['downloads']:,}회</b><br>
            관리자 수: <b>{res['maintainers']}명</b><br>
            유사 패키지: <b>{res['closest']}</b> (편집거리 {res['min_dist']})<br>
            설치 스크립트: <b>{'있음' if res['has_install_script'] else '없음'}</b>
          </div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div style="background:#1E293B;border-radius:12px;padding:20px;margin-bottom:12px;">
          <div style="color:#94A3B8;font-size:12px;margin-bottom:12px;">점수 구성 요소</div>
        """, unsafe_allow_html=True)

        for fname, (val, max_val) in res["components"].items():
            pct = int(val / max_val * 100) if max_val > 0 else 0
            bar_color = color if val > 0 else "#334155"
            st.markdown(f"""
            <div style="margin-bottom:10px;">
              <div style="display:flex;justify-content:space-between;font-size:13px;">
                <span style="color:{'#F1F5F9' if val>0 else '#64748B'}">{fname}</span>
                <span style="color:{bar_color};font-weight:700;">+{val} / {max_val}</span>
              </div>
              <div class="factor-bar-bg">
                <div class="factor-bar-fill" style="width:{pct}%;background:{bar_color};"></div>
              </div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("</div>", unsafe_allow_html=True)

        # 최종 안내 메시지
        st.markdown(f"""
        <div style="background:{cfg['bg']};border:1.5px solid {color};border-radius:10px;
                    padding:14px;margin-top:4px;">
          <div style="color:{color};font-size:14px;font-weight:600;">{cfg['msg']}</div>
        </div>
        """, unsafe_allow_html=True)

# ════════════════════════════════════════════════════════════════════════════
# UI
# ════════════════════════════════════════════════════════════════════════════

st.markdown("""
<div style="text-align:center;padding:20px 0 10px;">
  <div style="font-size:36px;font-weight:900;color:#F1F5F9;">
    🔍 npm 패키지 위험도 평가기
  </div>
  <div style="color:#64748B;font-size:15px;margin-top:8px;">
    LLM 환각 악용 슬롭스쿼팅 공격 탐지 시스템  ·  단국대학교 32230120 강하늘
  </div>
</div>
<hr>
""", unsafe_allow_html=True)

# ── 데모 패키지 섹션 ─────────────────────────────────────────────────────
st.markdown("### 📦 데모 패키지 비교")
st.markdown("<div style='color:#64748B;font-size:13px;margin-bottom:12px;'>4가지 패키지의 위험도를 한눈에 비교하세요</div>", unsafe_allow_html=True)

demo_packages = ["express", "expresss", "axos", "reqact"]

if "demo_results" not in st.session_state:
    st.session_state.demo_results = None

if st.button("🚀  데모 패키지 4종 분석 실행", key="demo_btn"):
    with st.spinner("npm API에서 실시간으로 데이터를 수집 중..."):
        results = []
        for pkg in demo_packages:
            results.append(compute_score(pkg))
            time.sleep(0.3)
        st.session_state.demo_results = results

if st.session_state.demo_results:
    results = st.session_state.demo_results
    cols = st.columns(4)
    for i, res in enumerate(results):
        with cols[i]:
            g = res["grade"]
            cfg = GRADE_CFG[g]
            color = cfg["color"]
            st.markdown(f"""
            <div style="background:#1E293B;border-radius:10px;padding:16px;
                        text-align:center;border:2px solid {color};">
              <div style="font-size:13px;color:#94A3B8;margin-bottom:4px;">npm install</div>
              <div style="font-size:16px;font-weight:700;color:#F1F5F9;font-family:monospace;">
                {res['name']}
              </div>
              <div style="font-size:52px;font-weight:900;color:{color};margin:8px 0;">
                {res['score']}
              </div>
              <div style="background:{cfg['bg']};color:{color};border-radius:6px;
                          padding:4px 12px;font-size:12px;font-weight:700;">
                {cfg['label']}
              </div>
              <div style="font-size:11px;color:#64748B;margin-top:8px;">
                {'❌ 404' if not res['exists'] else f"✅ {res['downloads']:,}회/주"}<br>
                편집거리 {res['min_dist']} ← {res['closest']}
              </div>
            </div>
            """, unsafe_allow_html=True)

st.markdown("<hr>", unsafe_allow_html=True)

# ── 직접 분석 ────────────────────────────────────────────────────────────
st.markdown("### 🔎 직접 패키지 분석")

col_input, col_btn = st.columns([4, 1])
with col_input:
    pkg_name = st.text_input(
        "",
        placeholder="분석할 npm 패키지 이름을 입력하세요 (예: lodash, axio, reqact)",
        label_visibility="collapsed",
        key="pkg_input",
    )
with col_btn:
    analyze_clicked = st.button("분석", key="analyze_btn")

if analyze_clicked and pkg_name.strip():
    name = pkg_name.strip().lower()
    with st.spinner(f"'{name}' 분석 중..."):
        res = compute_score(name)
    st.markdown(f"<div style='margin:16px 0 8px;'><span style='font-size:20px;font-weight:700;color:#F1F5F9;font-family:monospace;'>npm install {name}</span></div>", unsafe_allow_html=True)
    render_result(res)
elif analyze_clicked:
    st.warning("패키지 이름을 입력해주세요.")

# ── 하단 설명 ─────────────────────────────────────────────────────────────
st.markdown("<hr>", unsafe_allow_html=True)
st.markdown("""
<div style="color:#475569;font-size:12px;text-align:center;line-height:2;">
  <b style="color:#64748B;">점수 산정 기준</b><br>
  타이포스쿼팅(최대 30) + 미존재(15) + 슬롭스쿼팅 보너스(10) + 설치스크립트(20) + 메타데이터(15) + 활동지표(10)  =  최대 100점<br>
  <br>
  위험도 구간: LOW 0–20  |  LOW-MED 21–40  |  <b style="color:#f59e0b;">MEDIUM 41–60 (추가 검토 필요)</b>  |  HIGH 61–80  |  <b style="color:#ef4444;">CRITICAL 81–100</b><br>
  <br>
  모든 데이터는 npm Registry API에서 실시간 수집됩니다.
</div>
""", unsafe_allow_html=True)
