"""
정상 패키지 메타데이터 수집 → benign_packages.csv 저장
한 번만 실행하면 됨
"""

import json, csv, time, os, urllib.request

BENIGN_PACKAGES = [
    "react","react-dom","lodash","express","axios","moment","webpack","babel-core",
    "eslint","typescript","chalk","commander","yargs","minimist","semver","debug",
    "glob","mkdirp","rimraf","async","bluebird","request","node-fetch","got",
    "cheerio","puppeteer","mongoose","sequelize","knex","pg","mysql2","redis",
    "socket.io","passport","bcryptjs","jsonwebtoken","cors","helmet","dotenv",
    "nodemailer","sharp","multer","archiver","tar","uuid","nanoid","zod","yup",
    "joi","fastify","koa","next","nuxt","vite","rollup","esbuild","prisma",
    "typeorm","jest","mocha","chai","sinon","supertest","prettier","husky",
    "cross-env","concurrently","nodemon","ts-node","dayjs","date-fns","luxon",
    "lodash-es","ramda","underscore","rxjs","immer","zustand","redux","mobx",
    "recoil","jotai","swr","graphql","winston","pino","morgan","bunyan",
    "inquirer","ora","mime","mime-types","form-data","csv-parse","papaparse",
    "xlsx","marked","highlight.js","socket.io-client","ws","stripe","aws-sdk",
    "ioredis","lru-cache","bull","bullmq","node-cron","compression","pm2",
    "webpack-cli","webpack-dev-server","postcss","tailwindcss","styled-components",
    "body-parser","cookie-parser","express-session","multer","mongoose-paginate-v2",
    "dotenv-safe","cross-env","npm-run-all","rimraf","del","glob","chokidar",
    "execa","chalk","ora","inquirer","conf","update-notifier","boxen","figures",
    "p-limit","p-queue","p-retry","bottleneck","async-retry","got","ky",
    "serialize-javascript","js-yaml","toml","ini","nconf","config","convict",
]

def fetch_meta(name):
    try:
        req = urllib.request.Request(
            f"https://registry.npmjs.org/{name}",
            headers={"User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read())
        latest = data.get("dist-tags", {}).get("latest", "")
        ver = data.get("versions", {}).get(latest, {})
        author = data.get("author", {})
        return {
            "name": name,
            "label": 0,
            "author": author.get("name","") if isinstance(author, dict) else str(author or ""),
            "maintainers_count": len(data.get("maintainers", [])),
            "dependencies_count": len(ver.get("dependencies", {})),
            "has_install_script": int("install" in ver.get("scripts", {})),
            "exists": True,
        }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        return {"name": name, "label": 0, "author": "", "maintainers_count": 1,
                "dependencies_count": 0, "has_install_script": 0, "exists": True}
    except Exception:
        return None

def fetch_downloads(name):
    try:
        req = urllib.request.Request(
            f"https://api.npmjs.org/downloads/point/last-month/{name}",
            headers={"User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read()).get("downloads", 0)
    except Exception:
        return 0

os.makedirs("data/processed", exist_ok=True)
output = "data/processed/benign_packages.csv"

results = []
print(f"정상 패키지 {len(BENIGN_PACKAGES)}건 수집 시작...")

for i, name in enumerate(BENIGN_PACKAGES):
    meta = fetch_meta(name)
    if meta:
        meta["downloads"] = fetch_downloads(name)
        results.append(meta)
    if (i + 1) % 20 == 0:
        print(f"  {i+1}/{len(BENIGN_PACKAGES)} 완료")
    time.sleep(0.15)

with open(output, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["name","label","author","maintainers_count",
                                           "dependencies_count","has_install_script",
                                           "exists","downloads"])
    writer.writeheader()
    writer.writerows(results)

print(f"\n완료: {len(results)}건 → {output}")
