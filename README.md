# npm-hallucination-detector

**LLM 환각 악용 npm 공급망 공격 탐지: 계층적 AI 위험도 평가 모델**

> 단순 차단을 넘어선 정량적 리스크 관리 시스템 (EAI 활용)

---

## 개요

LLM(대형 언어 모델)이 존재하지 않는 npm 패키지명을 추천(환각)하는 취약점을 악용한
슬롭스쿼팅(Slopsquatting) 공격을 선제적으로 탐지하는 AI 보안 파이프라인입니다.

기존 `npm audit` 등 블랙리스트 기반 방식의 한계(사후 대응, 이분법적 판단, 설명 불가)를
극복하고, **0~100점의 정량적 위험도 점수**와 **SHAP 기반 판단 근거**를 제공합니다.

---

## 핵심 기능

| 기능 | 설명 |
|------|------|
| 예측 기반 선제 탐지 | 알려지지 않은 신규 악성 패키지도 AI가 예측 |
| 정량적 위험도 점수 | 0~100점 스코어로 유연한 보안 정책 수립 가능 |
| 설명 가능한 보안 | SHAP으로 위험 판단 근거 시각화 |
| 실시간 REST API | CI/CD 파이프라인 연동 지원 |

---

## 시스템 아키텍처

```
데이터 수집 → 특징 추출 → AI 탐지 모델 → 실시간 API
 npm 메타데이터   CodeBERT     CodeBERT         FastAPI
 악성 패키지 DB   메타데이터    + XGBoost/RF     CI/CD 연동
 LLM 생성 패키지  피처 엔지니어링  위험도 점수 산출  경보 시스템
```

---

## 기술 스택

- **Feature Extraction**: CodeBERT (코드 임베딩), 메타데이터 피처 엔지니어링
- **ML Models**: XGBoost, Random Forest (계층적 앙상블)
- **Explainability**: SHAP (XAI)
- **API**: FastAPI + Docker
- **Dataset**: MalOSS, npm Advisory DB, Backstabber's Knife

---

## 디렉토리 구조

```
npm-hallucination-detector/
├── data/
│   ├── raw/          # 원본 데이터 (git 제외)
│   ├── processed/    # 전처리된 데이터
│   └── samples/      # 샘플 데이터
├── src/
│   ├── collector/    # 데이터 수집
│   ├── features/     # 특징 추출
│   ├── models/       # ML 모델
│   ├── api/          # FastAPI 서버
│   └── utils/        # 공통 유틸
├── notebooks/        # EDA & 실험
└── tests/
```

---

## 평가 목표

- F1-Score ≥ 0.90
- MAE ≤ 0.1 (위험도 점수)
- False Positive Rate: 기존 대비 최소화

---

단국대학교 소프트웨어학과 32230120 강하늘
