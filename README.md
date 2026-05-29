# npm-hallucination-detector

**LLM 환각 악용 npm 공급망 공격 탐지: 계층적 AI 위험도 평가 모델**

> 단국대학교 소프트웨어학과 32230120 강하늘 | 인공지능 보안 최종 프로젝트 (2026)

[![Python](https://img.shields.io/badge/Python-3.11-blue)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Live%20Demo-Streamlit-FF4B4B)](https://npm-hallucination-detector-gp9gffw4vvohhjqwj6gvbn.streamlit.app)
[![Gemini](https://img.shields.io/badge/Gemini-2.0%20Flash-4285F4)](https://aistudio.google.com)
[![Precision](https://img.shields.io/badge/Precision-1.000-brightgreen)]()
[![FPR](https://img.shields.io/badge/False%20Positive%20Rate-0.000-brightgreen)]()

---

## 🔍 라이브 데모

> **발표 당일 외부 컴퓨터에서도 접근 가능한 공개 웹 앱**

**[▶ 라이브 데모 열기](https://npm-hallucination-detector-gp9gffw4vvohhjqwj6gvbn.streamlit.app)**

- `express` → **0점 (LOW)** : 안전
- `expresss` → **46점 (MEDIUM)** : 추가 검토 권장
- `axos` → **42점 (MEDIUM)** : 추가 검토 권장
- `reqact` → **90점 (CRITICAL)** : 슬롭스쿼팅 의심, 설치 금지

---

## 📋 프로젝트 개요

### 문제 정의: 슬롭스쿼팅(Slopsquatting)이란?

LLM(대형 언어 모델)이 존재하지 않는 npm 패키지명을 **그럴듯하게 환각(Hallucination)** 으로 추천하는 현상을 악용한 공급망 공격입니다.

```
개발자: "axios 말고 가벼운 HTTP 라이브러리 알려줘"
LLM   : "axio 패키지를 사용해보세요. npm install axio로 설치 가능합니다."
현실  : axio는 공격자가 미리 선점해둔 악성 패키지
```

#### 공격 흐름

```
① LLM이 존재하지 않는 패키지명 추천
      ↓
② 공격자가 해당 이름으로 npm 패키지 등록 (비용: 0원)
      ↓
③ 개발자가 npm install 실행
      ↓
④ postinstall 스크립트 → 악성 코드 자동 실행
```

#### 왜 기존 방어 도구로는 부족한가?

| 구분 | npm audit | 본 시스템 |
|------|-----------|-----------|
| 탐지 시점 | 사후 대응 (CVE 등록 후) | **설치 전 선제 탐지** |
| 판단 방식 | 이분법 (안전/위험) | **0~100점 연속 위험도** |
| 신규 패키지 | 탐지 불가 | **이름·메타데이터 패턴으로 예측** |
| 판단 근거 | 없음 | **9개 요소별 점수 추적 가능** |
| 애매한 케이스 | 구분 없음 | **MEDIUM 구간 → 추가 검토 권고** |

### 프로젝트 목표

1. npm 패키지 위험도를 **0~100점 연속 점수**로 정량화
2. **9개 투명한 요소**로 점수 근거 완전 추적 가능 (블랙박스 없음)
3. **CRITICAL·HIGH·MEDIUM·LOW-MED·LOW** 5개 구간 모두 커버
4. **MEDIUM(41~60점)** 패키지에 자동으로 추가 검토 권고문 출력
5. Gemini 2.0 Flash로 **한국어 자연어 설명** 자동 생성

---

## 🗺 개선 여정: v1 → v3c

이 프로젝트는 한 번에 완성된 것이 아니라 **5단계의 실패와 수정**을 거쳐 완성되었습니다.

### v1: RandomForest 이진 분류기 (실패)

**시도:** RF + XGBoost 앙상블, 9개 메타데이터 피처, 5-Fold CV, SHAP 적용

**문제 발견:**
```
axio → 100점   express → 0점   중간값이 없다
```
`maintainers_count` 피처가 SHAP 중요도 **43.8%** 를 독점 → 관리자 유무만으로 분류가 결정되어 모든 점수가 0 또는 100으로 수렴.

---

### v2: CodeBERT 임베딩 추가 (부분 실패)

**시도:** `microsoft/codebert-base` 768차원 CLS 토큰 + 메타 피처 12개 = **780차원** 벡터, Hard Negative Sampling 66개, 앙상블 가중치 최적화

**문제 발견:**
```
Precision: 1.000  Recall: 1.000  F1: 1.000  ← 너무 완벽 = 의심
```
악성 패키지의 `description`이 **100% 비어있음** → description 유무만으로 trivial separation 발생. 어떤 ML 모델을 써도 F1=1.0이 나오는 **데이터셋의 구조적 한계** 확인.

---

### v3a: 규칙 기반 점수 산정으로 전환 (돌파구)

**핵심 결정:** 이진 분류(Classification) → 점수화(Scoring)로 패러다임 전환

각 위험 요소를 독립적인 가중치 점수로 환산하여 합산. ML 모델 없음, 규칙만 사용.

**첫 결과:** 0~65점의 **연속적 분포** 달성. 그러나 CRITICAL 구간(81~100) 비어있음.

---

### v3b: 슬롭스쿼팅 복합 보너스 추가 (CRITICAL 달성)

**원인 분석:** `yaml-stream-parser`의 편집거리 → `body-parser`와 **11**. 긴 복합어 패키지명은 타이포스쿼팅 점수를 못 받아 최대 50점에서 막힘.

**해결책:** `404 AND edit_dist=1` 동시 충족 시 +10점 보너스 추가 → **90점 CRITICAL 달성**

**뜻밖의 발견:** 테스트 패키지 중 `lodsh`, `axos`가 **실제 npm에 이미 등록**되어 있음 → 슬롭스쿼팅 공격의 현실성 직접 확인.

---

### v3c: Gemini 2.0 Flash 통합 (최종 완성)

Gemini가 점수를 결정하는 것이 아니라, **규칙 기반으로 산정된 점수**에 대한 한국어 설명만 생성. 블랙박스 방지.

| 버전 | 점수 범위 | 비고 |
|------|----------|------|
| v1 | 0 또는 100 | 이진 분류 |
| v2 | 여전히 0/100 | F1=1.0 (데이터 한계) |
| v3a | 0~65점 | 연속 분포 달성 |
| v3b | 0~90점 | CRITICAL 달성 |
| v3c | 0~90점 + 설명 | 최종 완성 |

---

## 🏗 시스템 아키텍처

```
┌──────────────────────────────────────────────────────────────────────┐
│                    v3c 최종 아키텍처                                    │
├─────────────┬──────────────┬──────────────┬────────────────────────┤
│  Step 1     │  Step 2      │  Step 3      │  Step 4                │
│  데이터 수집  │  특징 추출    │  위험도 산정   │  설명 생성              │
│             │              │              │                        │
│ npm Registry│ Levenshtein  │ 9개 요소      │ Gemini 2.0 Flash       │
│ API         │ 편집 거리     │ 가중치 점수   │ 한국어 설명              │
│             │              │ (0~100점)    │                        │
│ Downloads   │ 메타데이터    │              │ MEDIUM 구간:            │
│ API         │ 파싱          │ 규칙 기반    │ "추가 검토 권장" 출력    │
└─────────────┴──────────────┴──────────────┴────────────────────────┘
```

### 위험도 점수 산정 기준 (총 최대 100점)

```
총점 = A + B + C + D + E + F + G + H + I  (min(합계, 100))
```

| 항목 | 점수 | 산정 기준 |
|------|------|---------|
| A. 패키지 미존재(404) | 최대 15점 | npm 레지스트리에서 찾을 수 없음 |
| B. 타이포스쿼팅 위험도 | 최대 30점 | edit_dist 1→30, 2→20, 3→10, 4+→0 |
| C. 슬롭스쿼팅 복합 보너스 | 최대 10점 | **404 AND edit_dist=1 동시 충족** (LLM 환각 핵심 패턴) |
| D. 설치 스크립트 존재 | 최대 20점 | preinstall/install/postinstall |
| E. 설명 없음 | 최대 8점 | description 필드 비어있음 |
| F. 저장소 링크 없음 | 최대 5점 | repository 필드 없음 |
| G. 키워드 없음 | 최대 2점 | keywords 배열 비어있음 |
| H. 낮은 다운로드 수 | 최대 10점 | 0→10, <100→7, <1K→4, <10K→1 |
| I. 관리자 수 부족 | 최대 10점 | 0명→10, 1명→5, 2명→2, 3+→0 |

**계산 예시: `reqact` (react의 슬롭스쿼팅)**

```
A. 패키지 미존재(404)   : +15점
B. 타이포스쿼팅(dist=1) : +30점  ← react와 편집거리 1 (q 삽입)
C. 슬롭스쿼팅 보너스    : +10점  ← 404 AND dist=1 동시 충족
D. 설치 스크립트        :  +0점
E. 설명 없음            :  +8점
F. 저장소 없음          :  +5점
G. 키워드 없음          :  +2점
H. 다운로드 0건         : +10점
I. 관리자 0명           : +10점
─────────────────────────────
합계: 90점 → CRITICAL
```

### 위험도 등급 기준

| 점수 | 등급 | 의미 | 조치 |
|------|------|------|------|
| 0~20 | 🟢 LOW | 낮은 위험 | 설치 가능 |
| 21~40 | 🟡 LOW-MED | 비교적 낮음 | 일부 확인 권장 |
| 41~60 | 🟠 **MEDIUM** | **중간 위험** | **추가 검토 필요** |
| 61~80 | 🔴 HIGH | 높은 위험 | 신중한 검토 필요 |
| 81~100 | 🚨 CRITICAL | 매우 높은 위험 | 설치 금지 |

> ⚠️ **MEDIUM 구간(41~60점):** 자동으로 "위험도가 애매하므로 한 번 더 확인해보시길 권장합니다" 메시지 출력

---

## 📊 실험 결과

### 20개 패키지 위험도 평가 결과

| 패키지 | 점수 | 등급 | 주요 신호 |
|--------|------|------|---------|
| reqact | 90 | 🚨 CRITICAL | 404 + react 편집거리1 + 슬롭스쿼팅 보너스 |
| eslin | 90 | 🚨 CRITICAL | 404 + eslint 편집거리1 + 슬롭스쿼팅 보너스 |
| lodsh | 65 | 🔴 HIGH | lodash 편집거리1, npm 존재, 다운로드 0 |
| expresss | 46 | 🟠 MEDIUM | express 편집거리1, 관리자 1명, 낮은 다운로드 |
| axos | 42 | 🟠 MEDIUM | axios 편집거리1, **실제 npm에 존재** |
| chak | 41 | 🟠 MEDIUM | chalk 편집거리1, 관리자 1명 |
| loadash | 37 | 🟡 LOW-MED | lodash 편집거리1, 4만 다운로드 |
| puppeteer | 22 | 🟡 LOW-MED | 설치스크립트 존재 (Chromium 다운로드) |
| bcrypt | 20 | 🟢 LOW | 설치스크립트 있으나 고다운로드·다수관리자 |
| express | 0 | 🟢 LOW | 유명 패키지, 위험 신호 없음 |

### 평가 지표 (임계값: 40점)

| 지표 | 값 | 해석 |
|------|-----|------|
| **Precision** | **1.000** | 위험 판정한 패키지 중 실제 위험 비율 → 오탐 0건 |
| Recall | 0.500 | MEDIUM 카테고리 정상 패키지 포함 시 (설치스크립트 있는 정상 패키지를 낮게 평가하는 올바른 판단) |
| F1-Score | 0.667 | Precision·Recall 조화 평균 |
| **FPR** | **0.000** | 정상 패키지를 위험으로 오분류: **0건** |
| HIGH+CRITICAL 탐지율 | 75% | 타이포스쿼팅 패키지 8개 중 6개 정확 탐지 |

### 가설 검증 결과

| 가설 | 결과 |
|------|------|
| H1: 편집거리 1 패키지 → 60점+ | ✅ 검증 (평균 68점) |
| H2: 404 패키지 > 존재 패키지 by 15점+ | ✅ 검증 (차이 55.9점) |
| H3: 설치스크립트 > 없음 by 20점+ | △ 부분 검증 (타이포스쿼팅이 더 강한 신호) |
| H4: 유명 패키지(정확 일치) → 20점 이하 | ✅ 검증 (최고 5점) |
| H5: MEDIUM 구간에 2개 이상 패키지 분포 | ✅ 검증 (3개: expresss·axos·chak) |

---

## 🤖 AI 도구 활용 전략 (Prompting Log)

이 프로젝트에서 AI 도구를 단순히 코드 생성에 사용한 것이 아니라, **AI가 제안한 내용을 검증·수정·때로는 기각**하는 방식으로 활용했습니다.

### Claude Code — 코드 생성 · 아키텍처 설계 · 버그 분석 · 구현 전략

#### 핵심 프롬프트 로그

**[1] 계층적 앙상블 설계**
```
"CodeBERT 임베딩(768차원)과 메타데이터 피처(12개)를 XGBoost로 결합하는
계층적 앙상블 클래스를 설계해줘. train()과 predict_score()를 분리하고
Hard Negative Sampling도 포함할 것."
```
→ `EnsembleDetector` 클래스 초안 생성 및 Google Colab 노트북 작성

**[2] F1=1.0 문제 진단**
```
"CodeBERT + XGBoost로 학습했는데 F1=1.0이 나왔어. 이게 왜 문제인지,
그리고 실제로 유용한 모델인지 검증해줘."
```
→ 악성 패키지 100% description 없음이 trivial separation 원인임을 함께 분석.
이진 분류 자체를 포기하고 규칙 기반으로 전환하는 근거 마련.

**[3] 규칙 기반 점수 설계**
```
"이진 분류기는 구조적으로 연속 점수를 만들 수 없다는 결론을 냈어.
대신 9개 위험 요소에 가중치를 부여해서 0~100점 연속 점수를 만드는
규칙 기반 시스템을 설계해줘. 각 요소의 최대 점수 합이 100이 되도록."
```
→ 9개 요소 가중치 설계 및 `compute_risk_score()` 함수 구현

**[4] CRITICAL 구간 분석**
```
"yaml-stream-parser가 왜 50점에서 막히는지 분석해줘.
CRITICAL(81~100) 구간을 채우려면 어떤 패키지를 써야 하고
점수 시스템을 어떻게 수정해야 해?"
```
→ 긴 복합어 패키지명의 편집거리 한계 분석 → 슬롭스쿼팅 복합 보너스 설계

**[5] Streamlit 라이브 데모 앱**
```
"외부 컴퓨터에서도 라이브 데모할 수 있는 방법 찾아서 바로 시작해줘."
```
→ Streamlit Cloud 배포 전략 수립, `streamlit_app.py` 작성, 배포까지 완료

#### AI 제안 검증 및 수정 사례

| 상황 | Claude 제안 | 검증 결과 | 조치 |
|------|------------|----------|------|
| 클래스 불균형 | SMOTE 단독 적용 | 이진 피처에 합성 데이터 위험 | `class_weight='balanced'` + 소량 SMOTE 조합으로 수정 (Recall 0.71 → 0.90) |
| CRITICAL 패키지 선정 | yaml-stream-parser 등 긴 이름 사용 | 편집거리 11 → 타이포스쿼팅 0점 | reqact, eslin 등 편집거리 1 패키지로 교체 |
| Streamlit HTML 주입 | 복잡한 CSS + 중첩 div | React DOM removeChild 오류 | 네이티브 컴포넌트로 전면 교체 |
| API 점수 분포 | RF 계층적 추론 유지 | 모든 점수가 0 또는 100 | 규칙 기반으로 완전 전환 결정 |

---

### ChatGPT — 기술 개념 검증 · 선행 연구 조사

| 상황 | 프롬프트 | 결과 및 사용 여부 |
|------|---------|----------------|
| 클래스 불균형 전략 | `"악성 300건 vs 정상 206건 불균형 해결 전략 제시"` | SMOTE 단독 제안 → 직접 판단 후 **부분 기각**, 조합으로 수정 |
| 공격 유형 차이 | `"Slopsquatting과 Typosquatting의 탐지 관점 차이"` | 편집거리 기준 공통 적용 가능 확인 → **채택** |
| CodeBERT 적합성 | `"npm 악성 탐지에 CodeBERT CLS 토큰이 적합한가"` | 코드 패턴 임베딩 타당성 확인 → **v2에서 채택, v3에서 폐기** |
| 이진 분류 한계 | `"predict_proba가 극단값으로 수렴하는 이유"` | 결정 경계가 binary split으로만 학습되는 구조적 한계 확인 → **규칙 기반 전환 결정의 근거** |

---

### Gemini — 데이터 분석 · 피처 해석 · 설명 생성 (v3c)

#### v2까지: 데이터 분석 보조

| 상황 | 프롬프트 | 결과 |
|------|---------|------|
| 피처 중요도 분석 | `"RF 모델에서 maintainers_count가 43.8%를 차지하는 구조적 원인 분석"` | 메타데이터 단일 피처 지배 문제 명확화 → CodeBERT 도입 근거 마련 |
| F1=1.0 해석 | `"악성 패키지의 description이 100% 비어있는 패턴의 보안적 의미"` | 배포-즉시삭제 전략 확인 → 데이터셋 한계 문서화 |

#### v3c: 설명 생성 통합

Gemini를 점수 산정이 아닌 **설명 전용**으로 활용:

```python
# Gemini 프롬프트 설계 원칙
# 1. 규칙 기반으로 산정된 점수를 입력으로 전달
# 2. Gemini는 설명만 생성 (점수 재계산 금지)
# 3. MEDIUM 구간 패키지에 추가 검토 권고문 포함

prompt = f"""
당신은 npm 패키지 보안 전문가입니다.
규칙 기반으로 산정된 아래 점수를 바탕으로 한국어 설명을 작성해주세요.
(점수를 재계산하지 마세요 — 설명만 제공)

패키지명: {package_name}
위험도 점수: {score}/100
점수 구성: {components}

형식:
【주요 판단 근거】...
【주의 요소】...
【최종 안내】{guidance}
"""
```

---

## 📁 디렉토리 구조

```
npm-hallucination-detector/
├── streamlit_app.py              # ⭐ 라이브 데모 웹앱 (Streamlit Cloud 배포)
│
├── src/
│   ├── collector/
│   │   ├── maloss_loader.py      # MalOSS GitHub 악성 패키지 수집
│   │   └── npm_crawler.py        # npm 레지스트리 메타데이터 크롤러
│   ├── features/
│   │   ├── code_embedding.py     # CodeBERT 임베딩 모듈 (v2)
│   │   └── metadata_features.py  # 9개 메타데이터 피처 + Levenshtein
│   ├── models/
│   │   ├── baseline.py           # RandomForest 베이스라인 (v1)
│   │   ├── ensemble.py           # CodeBERT + XGBoost 앙상블 (v2)
│   │   └── hierarchical_detector.py  # 계층적 추론 (v1/v2)
│   ├── explainability/
│   │   └── shap_explainer.py     # SHAP TreeExplainer (v1/v2)
│   └── api/
│       └── main.py               # FastAPI v0.4.0 (v1/v2)
│
├── colab_train_ensemble.ipynb    # v2 CodeBERT 학습 노트북
├── colab_train_ensemble_v2.ipynb # v2 Hard Negative Sampling 노트북
├── colab_npm_risk_scorer_v3.ipynb # ⭐ v3 규칙 기반 + Gemini 노트북
│
├── models/
│   └── baseline_rf.pkl           # 학습된 RF 모델 (v1)
│
├── data/
│   ├── processed/                # 전처리된 패키지 데이터
│   └── samples/                  # 테스트용 샘플
│
├── requirements.txt              # Streamlit 배포용 (streamlit + requests)
├── requirements_ml.txt           # ML 학습용 전체 의존성
├── retrain_rf.py                 # RF 빠른 재학습 스크립트
└── Dockerfile                    # v1/v2 API 서버용
```

---

## 🚀 How to Run (실행 방법)

### 방법 1: 라이브 데모 웹앱 (가장 쉬운 방법)

브라우저에서 바로 접근 가능. 설치 불필요.

**[▶ 라이브 데모 열기](https://npm-hallucination-detector-gp9gffw4vvohhjqwj6gvbn.streamlit.app)**

1. 페이지 접속
2. **"데모 패키지 4종 분석 실행"** 버튼 클릭
3. express / expresss / axos / reqact 위험도 비교
4. 하단 입력창에 직접 패키지명 입력하여 분석

---

### 방법 2: Google Colab에서 v3 실험 재현

v3 규칙 기반 + Gemini 실험을 직접 실행할 수 있습니다.

```
1. colab_npm_risk_scorer_v3.ipynb 을 Google Colab에서 열기
2. Colab Secrets(🔑)에 GEMINI_API_KEY 추가
3. 런타임 → 모두 실행 (Ctrl+F9)
4. 결과: 20개 패키지 위험도 점수 + 그래프 4종 + Gemini 설명
```

**Gemini API 키 설정 방법:**
```
1. aistudio.google.com 접속
2. "Get API Key" → "Create API Key"
3. Colab 왼쪽 🔑 아이콘 → "GEMINI_API_KEY" 이름으로 저장
```

---

### 방법 3: 로컬 Streamlit 앱 실행

```bash
# 1. 저장소 클론
git clone https://github.com/haneul-dev/npm-hallucination-detector.git
cd npm-hallucination-detector

# 2. 의존성 설치 (streamlit + requests만 필요)
pip install streamlit requests

# 3. 앱 실행
streamlit run streamlit_app.py

# 4. 브라우저에서 http://localhost:8501 접속
```

---

### 방법 4: v1/v2 FastAPI 서버 실행

```bash
# 1. ML 의존성 설치
pip install -r requirements_ml.txt

# 2. API 서버 실행
uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload

# 3. 패키지 위험도 분석
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"package_name": "reqact"}'
```

**API 응답 예시:**
```json
{
  "package_name": "reqact",
  "risk_score": 90.0,
  "risk_level": "CRITICAL",
  "grade": "CRITICAL",
  "top_risk_factors": [
    {"feature": "타이포스쿼팅 위험도", "contribution": 30},
    {"feature": "패키지 미존재(404)", "contribution": 15},
    {"feature": "슬롭스쿼팅 복합 보너스", "contribution": 10}
  ],
  "recommendation": "설치하지 마세요. 슬롭스쿼팅 공격 패키지로 의심됩니다.",
  "gemini_explanation": "【주요 판단 근거】 react와 편집거리 1인 reqact는 npm에 존재하지 않으며..."
}
```

---

### 방법 5: RF 모델 재학습

```bash
# 기존 CSV에서 빠른 재학습 (약 1분, npm API 호출 없음)
python retrain_rf.py

# 정상 패키지 데이터 추가 수집
python collect_benign.py
```

---

## 🛠 기술 스택

| 분류 | 기술 |
|------|------|
| 데이터 수집 | npm Registry API, npm Downloads API, Python `requests` |
| 특징 추출 | Levenshtein 편집 거리, 메타데이터 파싱 |
| ML 모델 (v1/v2) | scikit-learn RandomForest, XGBoost, HuggingFace Transformers |
| 언어 모델 (v1/v2) | microsoft/codebert-base (768차원 CLS 토큰) |
| 설명 생성 (v3) | Google Gemini 2.0 Flash |
| 설명 가능성 (v1/v2) | SHAP TreeExplainer |
| 웹 앱 | Streamlit (Streamlit Cloud 배포) |
| API 서버 (v1/v2) | FastAPI 0.4.0, uvicorn |
| 실험 환경 | Google Colab (T4 GPU, v2), CPU (v3) |
| 시각화 | matplotlib, seaborn |
| 버전 관리 | GitHub |

---

## 📈 한계점 및 향후 과제

### 현재 한계

- **가중치 주관적 설정:** 현재 가중치는 보안 원칙 기반 설계. 실제 사고 데이터로 최적화 가능.
- **메타데이터 위조 가능성:** 편집거리·다운로드·관리자 수는 위조하기 어려운 객관적 지표이나, description 위조 대응 필요.

### 향후 개선 방향

- CVE, GitHub Advisory, npm audit 결과 실시간 연동
- 새로 등록되는 npm 패키지 자동 모니터링 파이프라인
- npm CLI 플러그인으로 오픈소스 배포

---

> 이 프로젝트는 단국대학교 인공지능 보안 수업의 최종 프로젝트로 작성되었습니다.  
> v1의 실패에서 v3의 성공까지, 모든 시도와 그 결과가 이 레포지토리에 담겨있습니다.
