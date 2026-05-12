"""
베이스라인 RF 모델 학습 스크립트
정상 패키지 수집 → 피처 추출 → RF 학습 → 결과 출력
"""

import csv, json, re, time, os, random
import urllib.request
import numpy as np

# ─── 1. 정상 패키지 목록 (인기 npm 패키지) ───────────────────
BENIGN_PACKAGES = [
    "react","react-dom","lodash","express","axios","moment","webpack","babel-core",
    "eslint","typescript","chalk","commander","yargs","minimist","semver","debug",
    "glob","mkdirp","rimraf","async","bluebird","request","node-fetch","got",
    "cheerio","puppeteer","mongoose","sequelize","knex","pg","mysql2","redis",
    "socket.io","passport","bcryptjs","jsonwebtoken","cors","helmet","dotenv",
    "nodemailer","sharp","multer","archiver","tar","uuid","nanoid","zod","yup",
    "joi","fastify","koa","hapi","next","nuxt","vite","rollup","esbuild","prisma",
    "typeorm","jest","mocha","chai","sinon","supertest","prettier","husky",
    "lint-staged","cross-env","concurrently","nodemon","ts-node","tsx","tsup",
    "dayjs","date-fns","luxon","numeral","currency.js","bignumber.js","decimal.js",
    "lodash-es","ramda","underscore","rxjs","immer","zustand","redux","mobx",
    "recoil","jotai","tanstack","swr","react-query","graphql","apollo-server",
    "prisma","drizzle-orm","typeorm","mikro-orm","objection","bookshelf",
    "winston","pino","morgan","bunyan","loglevel","log4js","signale","consola",
    "inquirer","ora","cli-progress","boxen","figlet","gradient-string","ansi-colors",
    "mime","mime-types","content-type","busboy","formidable","multiparty","form-data",
    "got","ky","wretch","ofetch","undici","node-fetch","cross-fetch","isomorphic-fetch",
    "zod","io-ts","superstruct","class-validator","ajv","jsonschema","joi",
    "csv-parse","csv-stringify","fast-csv","papaparse","xlsx","exceljs","pdfkit",
    "marked","showdown","markdown-it","highlight.js","prismjs","shiki",
    "sharp","jimp","canvas","fabric","konva","pixi.js","three","babylon.js",
    "socket.io-client","ws","sockjs","centrifuge","pusher-js","ably",
    "stripe","paypal-rest-sdk","braintree","square","klarna-checkout",
    "aws-sdk","@aws-sdk/client-s3","firebase","@google-cloud/storage","azure-storage",
    "mongoose","mongodb","@prisma/client","typeorm","sequelize","knex",
    "ioredis","redis","memcached","lru-cache","node-cache","cache-manager",
    "bull","bullmq","agenda","node-cron","cron","node-schedule",
    "passport-local","passport-jwt","passport-google-oauth20","oauth2-server",
    "helmet","csurf","express-rate-limit","express-slow-down","hpp",
    "compression","express-static-gzip","serve-static","serve","http-server",
    "pm2","forever","supervisor","nodemon","ts-node-dev","tsx",
    "webpack-cli","webpack-dev-server","webpack-bundle-analyzer","speed-measure-webpack-plugin",
    "babel-loader","css-loader","style-loader","file-loader","url-loader","sass-loader",
    "postcss","postcss-loader","autoprefixer","tailwindcss","styled-components","emotion",
]

# 악성 패키지 로드
MALICIOUS_SOURCES = [
    "data/processed/maloss_npm_malicious.csv",
    "data/processed/backstabbers_npm.csv",
]

def fetch_npm_metadata(name: str) -> dict:
    """npm Registry에서 패키지 메타데이터 가져오기"""
    url = f"https://registry.npmjs.org/{name}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read())
        latest = data.get("dist-tags", {}).get("latest", "")
        ver_info = data.get("versions", {}).get(latest, {})
        author = data.get("author", {})
        author_name = author.get("name", "") if isinstance(author, dict) else str(author or "")
        return {
            "name": name,
            "exists": True,
            "author": author_name,
            "maintainers_count": len(data.get("maintainers", [])),
            "dependencies_count": len(ver_info.get("dependencies", {})),
            "has_install_script": int("install" in ver_info.get("scripts", {})),
        }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"name": name, "exists": False, "author": "", "maintainers_count": 0,
                    "dependencies_count": 0, "has_install_script": 0}
        return None
    except Exception:
        return None

def fetch_downloads(name: str) -> int:
    url = f"https://api.npmjs.org/downloads/point/last-month/{name}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read()).get("downloads", 0)
    except Exception:
        return 0

# ─── 피처 추출 ────────────────────────────────────────────────
POPULAR = ["react","express","lodash","axios","webpack","babel","eslint",
           "typescript","vue","angular","jquery","moment","chalk","commander",
           "dotenv","fastify","koa","next","vite","prisma"]

def name_similarity(name: str) -> float:
    from difflib import SequenceMatcher
    return max(SequenceMatcher(None, name.lower(), p).ratio() for p in POPULAR)

def suspicious_pattern(name: str) -> int:
    patterns = [r"\d{3,}$", r"_{2,}", r"-{2,}", r"^[a-z]{1,2}$"]
    return int(any(re.search(p, name) for p in patterns))

def extract_features(pkg: dict) -> list:
    downloads = pkg.get("downloads", 0) or 0
    return [
        np.log1p(downloads),                          # log_downloads
        name_similarity(pkg["name"]),                 # name_similarity
        suspicious_pattern(pkg["name"]),              # suspicious_name
        int(not pkg.get("author", "")),               # no_author
        pkg.get("has_install_script", 0),             # has_install_script
        int(pkg.get("dependencies_count", 0) > 20),  # high_dependency
        min(pkg.get("maintainers_count", 0), 20),    # maintainers_count
        min(pkg.get("dependencies_count", 0), 50),   # dependencies_count
        int(not pkg.get("exists", True)),             # not_exists (404)
    ]

# ─── 메인 ────────────────────────────────────────────────────
def main():
    print("=" * 55)
    print("  npm 악성 패키지 탐지 베이스라인 모델 학습")
    print("=" * 55)

    # 1. 악성 패키지 로드
    malicious_names = set()
    for path in MALICIOUS_SOURCES:
        with open(path) as f:
            for row in csv.DictReader(f):
                malicious_names.add(row["name"])
    print(f"\n[1] 악성 패키지 로드: {len(malicious_names)}건")

    # 2. 샘플링 (각 300건)
    mal_sample = random.sample(list(malicious_names), min(300, len(malicious_names)))
    ben_sample = random.sample(BENIGN_PACKAGES, min(300, len(BENIGN_PACKAGES)))
    print(f"[2] 샘플링: 악성 {len(mal_sample)}건 / 정상 {len(ben_sample)}건")

    # 3. npm 메타데이터 수집
    print("\n[3] npm 메타데이터 수집 중...")
    all_data = []

    print("  정상 패키지 수집:")
    for i, name in enumerate(ben_sample):
        meta = fetch_npm_metadata(name)
        if meta:
            meta["downloads"] = fetch_downloads(name)
            meta["label"] = 0
            all_data.append(meta)
        if (i + 1) % 30 == 0:
            print(f"    {i+1}/{len(ben_sample)} 완료")
        time.sleep(0.15)

    print("  악성 패키지 수집:")
    for i, name in enumerate(mal_sample):
        meta = fetch_npm_metadata(name)
        if meta:
            meta["downloads"] = fetch_downloads(name) if meta.get("exists") else 0
            meta["label"] = 1
            all_data.append(meta)
        else:
            # API 실패 → 존재하지 않는 패키지로 처리
            all_data.append({"name": name, "exists": False, "author": "",
                             "maintainers_count": 0, "dependencies_count": 0,
                             "has_install_script": 0, "downloads": 0, "label": 1})
        if (i + 1) % 30 == 0:
            print(f"    {i+1}/{len(mal_sample)} 완료")
        time.sleep(0.1)

    print(f"\n  수집 완료: 총 {len(all_data)}건")

    # 4. 피처 행렬 구성
    X = np.array([extract_features(d) for d in all_data])
    y = np.array([d["label"] for d in all_data])
    print(f"\n[4] 피처 행렬: {X.shape} | 악성 {y.sum()}건 / 정상 {(y==0).sum()}건")

    # 5. 학습
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import f1_score, classification_report, confusion_matrix
    from sklearn.preprocessing import StandardScaler
    try:
        from imblearn.over_sampling import SMOTE
        use_smote = True
    except ImportError:
        use_smote = False

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    if use_smote:
        smote = SMOTE(random_state=42)
        X_train_s, y_train = smote.fit_resample(X_train_s, y_train)
        print(f"[5] SMOTE 적용: {len(y_train)}건으로 균형 조정")

    clf = RandomForestClassifier(n_estimators=200, random_state=42, class_weight="balanced")
    clf.fit(X_train_s, y_train)

    # 6. 평가
    y_pred = clf.predict(X_test_s)
    y_proba = clf.predict_proba(X_test_s)[:, 1]

    f1 = f1_score(y_test, y_pred)
    from sklearn.metrics import roc_auc_score, mean_absolute_error
    auc = roc_auc_score(y_test, y_proba)
    mae = mean_absolute_error(y_test, y_proba)
    fp = ((y_pred == 1) & (y_test == 0)).sum()
    fpr = fp / (y_test == 0).sum()

    print("\n" + "=" * 55)
    print("  학습 결과")
    print("=" * 55)
    print(f"  F1-Score  : {f1:.4f}")
    print(f"  AUC-ROC   : {auc:.4f}")
    print(f"  MAE       : {mae:.4f}")
    print(f"  FPR (오탐율): {fpr:.4f}")
    print("\n" + classification_report(y_test, y_pred,
          target_names=["benign", "malicious"]))

    # 피처 중요도
    feat_names = ["log_downloads","name_similarity","suspicious_name",
                  "no_author","has_install_script","high_dependency",
                  "maintainers_count","dependencies_count","not_exists"]
    importances = sorted(zip(feat_names, clf.feature_importances_),
                         key=lambda x: -x[1])
    print("  피처 중요도:")
    for name, imp in importances:
        bar = "█" * int(imp * 40)
        print(f"    {name:<22} {imp:.3f}  {bar}")

    # 7. 샘플 예측 (시연용)
    print("\n" + "=" * 55)
    print("  위험도 점수 샘플 예측 (0~100)")
    print("=" * 55)
    demo_packages = [
        {"name": "expres", "exists": True, "author": "", "maintainers_count": 1,
         "dependencies_count": 1, "has_install_script": 1, "downloads": 5},
        {"name": "lodash", "exists": True, "author": "John-David Dalton",
         "maintainers_count": 5, "dependencies_count": 0, "has_install_script": 0,
         "downloads": 40000000},
        {"name": "axio", "exists": False, "author": "", "maintainers_count": 1,
         "dependencies_count": 0, "has_install_script": 1, "downloads": 3},
        {"name": "react", "exists": True, "author": "Facebook",
         "maintainers_count": 6, "dependencies_count": 3, "has_install_script": 0,
         "downloads": 50000000},
    ]
    X_demo = scaler.transform(np.array([extract_features(p) for p in demo_packages]))
    scores = clf.predict_proba(X_demo)[:, 1] * 100
    for pkg, score in zip(demo_packages, scores):
        level = "🔴 HIGH" if score >= 80 else "🟡 MEDIUM" if score >= 50 else "🟢 LOW"
        print(f"  {pkg['name']:<25} {score:5.1f}점  {level}")

    # 8. 모델 저장
    import pickle, os
    os.makedirs("models", exist_ok=True)
    with open("models/baseline_rf.pkl", "wb") as f:
        pickle.dump({"model": clf, "scaler": scaler}, f)
    print(f"\n  모델 저장: models/baseline_rf.pkl")
    print("\n  완료!")

    return {"f1": f1, "auc": auc, "mae": mae, "fpr": fpr}

if __name__ == "__main__":
    random.seed(42)
    main()
