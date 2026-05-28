# npm-hallucination-detector

**LLM 환각 악용 npm 공급망 공격 탐지: 계층적 AI 위험도 평가 모델**

> 단국대학교 소프트웨어학과 32230120 강하늘 | AI 보안 에이전트 설계 및 구현 (2026)

[![Python](https://img.shields.io/badge/Python-3.11-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.108-green)](https://fastapi.tiangolo.com)
[![F1-Score](https://img.shields.io/badge/F1--Score-0.9565-brightgreen)]()
[![AUC](https://img.shields.io/badge/AUC--ROC-0.9917-brightgreen)]()

---

## 프로젝트 개요

LLM(대형 언어 모델)이 존재하지 않는 npm 패키지명을 추천(환각)하는 취약점을 악용한 **슬롭스쿼팅(Slopsquatting)** 공급망 공격을 선제적으로 탐지하는 AI 보안 파이프라인입니다.

### 공격 시나리오

```
1. 개발자가 LLM에게 라이브러리 추천 질의
2. LLM이 존재하지 않는 패키지명을 환각으로 추천
3. 공격자가 해당 이름으로 악성 패키지를 npm에 선점 배포
4. 개발자가 설치 → 시스템 침해
```

### 기존 방식 vs 본 시스템

| 구분 | npm audit (블랙리스트) | 본 시스템 (AI 예측) |
|------|----------------------|-------------------|
| 탐지 방식 | 사후 대응 | **선제적 예측** |
| 판단 | 이분법 (안전/위험) | **0~100 정량 점수** |
| 설명 | 없음 | **SHAP 기반 판단 근거** |
| 신규 패키지 | 탐지 불가 | **패턴 기반 예측 가능** |

---

## 시스템 아키텍처

```
┌─────────────────────────────────────────────────────────────────┐
│                     4단계 파이프라인                              │
├──────────────┬──────────────┬──────────────┬───────────────────┤
│  01. 데이터   │  02. 특징     │  03. AI 모델  │  04. 실시간 API   │
│    수집       │    추출       │    탐지       │    연동           │
│              │              │              │                   │
│ • MalOSS     │ • CodeBERT   │ • Layer 1:   │ • FastAPI         │
│   (455건)    │   임베딩      │   CodeBERT   │   POST /analyze   │
│ • npm Adv.DB │   (768차원)   │   임베딩      │                   │
│   (174건)    │              │              │ • 입력: 패키지명    │
│ • Backstabber│ • 메타데이터  │ • Layer 2:   │                   │
│   (5,831건)  │   피처        │   메타데이터  │ • 출력:           │
│ • LLM 환각   │   (9개)       │   9개 피처   │   - 위험도 점수    │
│   (100건)    │              │              │     (0~100)       │
│              │              │ • Layer 3:   │   - 위험 등급      │
│ 총 7,160건   │              │   XGBoost    │     (LOW/MED/HIGH)│
│              │              │   앙상블 분류  │   - 판단 근거      │
└──────────────┴──────────────┴──────────────┴───────────────────┘
```

### 핵심 알고리즘: 계층적 앙상블

```python
# Layer 1: CodeBERT로 패키지 코드/이름 임베딩 (768차원)
embeddings = CodeBERT.encode(install_script)

# Layer 2: npm 메타데이터 9개 피처
features = [log_downloads, name_similarity, suspicious_pattern,
            no_author, has_install_script, high_dependency,
            maintainers_count, dependencies_count, not_exists_on_npm]

# Layer 3: 두 레이어 결합 → XGBoost 최종 위험도 산출
X = concat([embeddings, features])  # 777차원
risk_score = XGBoost.predict_proba(X) * 100  # 0~100점
```

---

## 성능 지표

| 지표 | 베이스라인 (RF) | 목표 (앙상블) |
|------|--------------|-------------|
| F1-Score | **0.9565** | ≥ 0.95 |
| AUC-ROC | **0.9917** | - |
| MAE | **0.0773** | ≤ 0.10 |
| FPR (오탐율) | 3~8%* | 최소화 |
| Recall (악성) | **0.90** | ≥ 0.90 |

> *FPR은 테스트셋(benign 46건) 기준 — 실 환경에서는 더 높을 수 있음

---

## 디렉토리 구조

```
npm-hallucination-detector/
├── src/
│   ├── collector/
│   │   ├── maloss_loader.py      # MalOSS GitHub 악성 패키지 수집
│   │   └── npm_crawler.py        # npm 레지스트리 메타데이터 크롤러
│   ├── features/
│   │   ├── code_embedding.py     # CodeBERT 임베딩 모듈
│   │   └── metadata_features.py  # 메타데이터 피처 엔지니어링
│   ├── models/
│   │   ├── baseline.py           # Random Forest 베이스라인 탐지기
│   │   └── ensemble.py           # CodeBERT + XGBoost 계층적 앙상블
│   ├── api/
│   │   └── main.py               # FastAPI 서버 (POST /analyze)
│   └── utils/
├── data/
│   ├── raw/                      # 원본 데이터 (.gitignore)
│   ├── processed/                # 전처리 완료 데이터
│   └── samples/                  # 샘플 데이터 (테스트용)
├── models/
│   └── baseline_rf.pkl           # 학습된 RF 모델
├── tests/
├── Dockerfile
├── requirements.txt
├── train_baseline.py
└── collect_benign.py
```

---

## How to Run (실행 방법)

### 방법 1: Docker (권장)

```bash
# 1. 이미지 빌드
docker build -t npm-hallucination-detector .

# 2. 서버 실행
docker run -p 8000:8000 npm-hallucination-detector

# 3. 패키지 위험도 분석
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"package_name": "react-hook-form-v2"}'
```

### 방법 2: 로컬 직접 실행

```bash
# 1. 의존성 설치
pip install -r requirements.txt

# 2. API 서버 실행
uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload

# 3. 헬스체크
curl http://localhost:8000/health
```

### API 사용 예시

**요청:**
```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"package_name": "getcookies"}'
```

**응답:**
```json
{
  "package_name": "getcookies",
  "risk_score": 100.0,
  "risk_level": "HIGH",
  "reason": "관리자 1명 이하 | 작성자 정보 없음",
  "recommendation": "즉시 설치 차단 권고",
  "exists_on_npm": true
}
```

**위험 등급 기준:**

| 점수 | 등급 | 권고 |
|------|------|------|
| 80~100 | HIGH | 즉시 설치 차단 |
| 50~79 | MEDIUM | 수동 검토 후 결정 |
| 0~49 | LOW | 설치 허용 (모니터링) |

### 방법 3: 모델 재학습

```bash
# 베이스라인 RF 모델 학습
python train_baseline.py

# 정상 패키지 데이터 수집
python collect_benign.py
```

---

## AI 도구 활용 전략 (Prompting Log)

3가지 AI 도구를 역할에 따라 분업하여 활용했습니다.

### Claude Code — 코드 생성 · 아키텍처 설계 · 버그 분석

| 상황 | 프롬프트 | 결과 |
|------|---------|------|
| 계층적 앙상블 설계 | `"CodeBERT 임베딩(768차원)과 메타데이터 피처(8차원)를 XGBoost로 결합하는 2계층 앙상블 클래스를 설계해줘. train()과 predict_score()를 분리할 것."` | `EnsembleDetector` 클래스 초안 생성 |
| API reason 로직 | `"패키지명, 메타데이터, 위험도 점수를 입력받아 보안 판단 근거 문자열을 반환하는 _build_reason() 함수를 작성해줘."` | lodash self-reference 버그 포함 → 직접 검증 후 수정 |
| MalOSS 수집 | `"GitHub API로 MalOSS 레포에서 npm 악성 패키지 목록을 수집하고 DataFrame으로 반환하는 로더를 만들어줘. rate limit 처리 포함."` | `maloss_loader.py` 완성 |

**AI 매니징 핵심 사례:**

- **사례 1 (버그 수정)**: Claude가 생성한 `_build_reason()`에서 lodash HIGH 오탐 발생. POPULAR 리스트 self-reference 문제 확인 후 `name not in POPULAR` 조건 명시하여 재지시 → 오탐 제거
- **사례 2 (제안 기각)**: 클래스 불균형 해결을 위해 "SMOTE 단독 적용" 제안 수용했으나, 시계열/이진 피처 특성상 합성 데이터 오류 위험 판단 → `class_weight='balanced'` 조합으로 직접 수정 (Recall 0.71 → 0.90)

### ChatGPT — 기술 개념 검증 · 선행 연구 조사

| 상황 | 프롬프트 | 결과 |
|------|---------|------|
| 클래스 불균형 전략 | `"클래스 불균형 해결 전략을 제시해줘 (악성 300건 vs 정상 229건)."` | SMOTE 단독 제안 → 직접 판단 후 기각, `class_weight='balanced'` 선택 |
| 공격 유형 분류 | `"Slopsquatting과 Typosquatting의 탐지 관점 차이점을 분석해줘."` | 두 공격의 피처 중요도 차이 파악 |
| CodeBERT 적합성 | `"npm 패키지 악성 탐지에 CodeBERT CLS 토큰이 적합한지 검토해줘."` | 코드 패턴 임베딩 타당성 확인 |

### Gemini — 데이터 분석 · 피처 중요도 해석

| 상황 | 프롬프트 | 결과 |
|------|---------|------|
| 피처 중요도 분석 | `"RF 모델에서 log_downloads가 피처 중요도 48%를 차지하는 구조적 원인을 분석해줘."` | 메타데이터 한계 명확화, CodeBERT 도입 필요성 확인 |
| 이름 패턴 분석 | `"악성 패키지 7,160건의 이름 패턴에서 공통 인사이트를 추출해줘."` | Slopsquatting 특유의 그럴듯한 이름 패턴 확인 |

---

## 데이터셋

| 출처 | 설명 | 건수 |
|------|------|------|
| MalOSS (GitHub) | 악성 오픈소스 생태계 샘플 | 455건 |
| npm Advisory DB | OSV.dev 제공 취약점 DB | 174건 |
| Backstabber's Knife | CCS 2020 학술 악성 패키지 | 5,831건 |
| LLM 환각 데이터 | GPT/Claude 환각 패키지명 생성 | 100건 |
| **합계** | | **7,160건** |

---

## 한계점 및 향후 과제

- **FPR 과소 추정**: 테스트셋 benign이 46건으로 소규모 → 실 환경 FPR은 표기값(3~8%)보다 높을 수 있음
- **다운로드 수 편향**: `log_downloads` 피처가 중요도 48% 차지 → 신규 패키지 탐지 한계
- **코드 분석 미적용**: CodeBERT 임베딩은 설치 스크립트 기반 → 소스코드 전체 분석 미구현
- **향후**: SHAP 판단 근거 시각화 고도화, 실시간 npm 레지스트리 모니터링 에이전트 연동

---

## 기술 스택

`Python 3.11` `FastAPI` `CodeBERT` `XGBoost` `scikit-learn` `SHAP` `Docker` `Transformers`
