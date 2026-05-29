# AISEC App

`AISEC App`은 1-day binary vulnerability를 자동 탐지하고, 그 결과를 검증 가능한 근거와 함께 리포트로 제공하는 것을 목표로 하는 프로젝트입니다.

현재 저장소는 PPT 제안서를 코드로 옮기기 위한 첫 번째 뼈대입니다. 핵심 아이디어인 `Triage -> Patch Analysis -> Binary Match -> Verification -> Report` 흐름을 먼저 코드 구조로 고정해두고, 이후 데이터셋 수집과 실제 LLM/분석기 연동을 단계적으로 붙일 수 있게 구성했습니다.

## 현재 들어있는 것

- 프로젝트 목표와 MVP 범위를 정리한 문서
- 분석 파이프라인의 도메인 모델
- 샘플 케이스를 기반으로 한 데모 실행 코드
- 검증 레이어가 포함된 리포트 생성 흐름
- 최소 단위 테스트

## 추천 시작 순서

1. `docs/project-plan.md`를 읽고 범위와 평가 지표를 고정합니다.
2. `src/aisec_app/models.py`와 `src/aisec_app/pipeline.py`를 기준으로 실제 입력/출력 포맷을 확정합니다.
3. `data/`에 Magma 기반 CVE 샘플을 쌓고 baseline 단일 LLM 파이프라인을 먼저 만듭니다.
4. 그 다음 verifier와 웹 리포트를 붙입니다.

## 실행

Python 3.10+ 기준입니다.

```bash
pip install -e .[llm]
PYTHONPATH=src python3 -m aisec_app.cli
PYTHONPATH=src python3 -m aisec_app.evaluation data/cases
PYTHONPATH=src python3 -m aisec_app.cve_metadata data/cases --write
PYTHONPATH=src python3 -m aisec_app.final_evaluation --output-dir output/evaluation --max-llm-calls 3
python3 -m unittest discover -s tests -v
```

## Claude Sonnet 설정

실제 LLM 기반 source 분석은 Anthropic Claude API key가 필요합니다.

```bash
cp .env.example .env
```

`.env`에 값을 채웁니다.

```env
ANTHROPIC_API_KEY=sk-ant-...
ANTHROPIC_MODEL=claude-sonnet-4-6
```

소스 파일 분석:

```bash
PYTHONPATH=src python3 -m aisec_app.source_cli path/to/source.c
```

ZIP 프로젝트 분석:

```bash
PYTHONPATH=src python3 -m aisec_app.zip_cli input/project.zip
```

백엔드 API 실행:

```bash
pip install -e .[api,llm]
uvicorn aisec_app.api:app --app-dir src --reload
```

프론트 개발 서버 실행:

```bash
cd frontend
npm install
npm run dev
```

프론트 빌드 후 FastAPI에서 함께 serving:

```bash
cd frontend
npm run build
cd ..
uvicorn aisec_app.api:app --app-dir src --reload
```

터미널에서 ZIP 업로드:

```bash
curl -X POST \
  -F "file=@path/to/project.zip" \
  -F "max_files=20" \
  http://127.0.0.1:8000/analyze/zip
```

API key 없이 리포트 형식만 확인하려면 local heuristic mode를 사용할 수 있습니다.

```bash
PYTHONPATH=src python3 -m aisec_app.source_cli path/to/source.c --allow-heuristic
PYTHONPATH=src python3 -m aisec_app.zip_cli input/project.zip --allow-heuristic
```

API에서도 heuristic fallback을 명시적으로 허용할 수 있습니다.

```bash
curl -X POST \
  -F "file=@path/to/project.zip" \
  -F "allow_heuristic=true" \
  http://127.0.0.1:8000/analyze/zip
```

LLM finding은 `evidence_quote`가 실제 입력 source에 존재할 때만 accepted finding으로 남고, 근거가 입력에 없으면 rejected finding으로 분리됩니다.

## 실험 명령

Claude key 설정 후 실제 ZIP 분석:

```bash
PYTHONPATH=src python3 -m aisec_app.zip_cli input/project.zip --max-files 20 --output-dir output
```

`input/`에 ZIP 파일이 하나만 있으면 파일명을 생략해도 됩니다.

```bash
PYTHONPATH=src python3 -m aisec_app.zip_cli --max-files 20 --output-dir output
```

결과는 아래 구조로 저장됩니다.

```text
output/
  project-<hash>/
    report.json
    report.md
    report.pdf
    llm_logs/
      <source-file>.md
```

`report.pdf`는 발표/확인용 요약 리포트이고, `report.md`와 `report.json`은 상세 결과 확인용입니다. `llm_logs/`에는 파일별 agent decision log가 Markdown으로 저장됩니다.

## CVE Database 연동

NVD CVE API를 사용해 case 내부의 실제 `CVE-YYYY-NNNN` 문자열을 찾고, 해당 CVE의 설명, CWE, CVSS, published/modified date, reference URL을 `manifest.json`의 `cve_metadata`에 저장할 수 있습니다.

```bash
PYTHONPATH=src python3 -m aisec_app.cve_metadata data/cases --write
```

API key가 있으면 `NVD_API_KEY` 환경변수로 전달합니다.

ZIP 분석 경로에서는 NVD `keywordSearch` 기반 candidate mapping을 수행합니다.

```text
NVD Mapping Agent
  -> source 파일명, 프로젝트명, 함수명, 위험 키워드로 NVD keywordSearch

CVE Candidate Evaluation Agent
  -> NVD description/CWE/CVSS/reference와 source token overlap 점수화

CVE Candidate Verifier Agent
  -> NVD metadata와 source match reason이 있는 후보만 verified candidate로 표시
```

분석 리포트의 `cve_candidates`에는 CVE ID, score, match reason, description, CWE, CVSS, reference URL, verifier rationale이 포함됩니다.

## 최종 평가 산출물 생성

Demo Day 제출용 평가 결과는 아래 명령으로 생성합니다.

```bash
PYTHONPATH=src python3 -m aisec_app.final_evaluation --output-dir output/evaluation --max-llm-calls 3
```

생성 결과:

```text
output/evaluation/evaluation.json
output/evaluation/evaluation.md
output/evaluation/ai_sample_reports/*.json
```

Magma 전체는 deterministic/baseline으로 전수 평가하고, 비용이 드는 LLM 평가는 대표 샘플 최대 3개로 제한합니다. 캐시된 LLM sample report가 있으면 API를 다시 호출하지 않습니다. Magma patch-derived evidence는 analyzer 입력으로 사용하지 않고, Magma label은 scoring/readiness 판단에만 사용합니다.

## Multi-Agent 분석 구조

Source/ZIP 분석은 아래 agent 흐름을 따릅니다.

```text
Triage Agent -> Finding Agent -> Skeptic Verifier Agent -> Reporter Agent
```

- `Triage Agent`: 분석할 함수와 위험 신호를 고릅니다.
- `Finding Agent`: 취약점 후보와 source evidence quote를 생성합니다.
- `Skeptic Verifier Agent`: 근거가 입력 source에 실제로 있는지, claim을 지지하는지, 라인 범위와 confidence가 타당한지 검증합니다.
- `Reporter Agent`: accepted finding과 rejected finding을 분리해 최종 report를 만듭니다.

Reject 기준:

- evidence quote가 없음
- evidence quote가 제출된 source에 없음
- finding verdict가 `vulnerable`이 아님
- deterministic confidence가 threshold보다 낮음
- root cause 또는 remediation이 없음
- line reference가 source 범위를 벗어남
- high/critical finding인데 evidence에 dangerous operation이 없음
- evidence 주변에 bounds check나 mitigation pattern이 있음
- Claude verifier가 quote와 claim이 직접 연결되지 않는다고 판단함

Confidence는 LLM이 제출한 자기평가 값을 그대로 쓰지 않고, evidence grounding, line range, dangerous operation, root cause/remediation, nearby mitigation 여부를 기준으로 deterministic rule로 재계산합니다. 따라서 같은 source와 같은 finding이면 항상 같은 confidence가 산출됩니다.

## 저장소 구조

```text
data/                CVE 케이스셋 적재 위치와 구조 안내
docs/                프로젝트 범위, 설계, 초기 로드맵
src/aisec_app/       도메인 모델과 파이프라인 스켈레톤
tests/               최소 회귀 테스트
```

## 다음 단계

- Magma에서 CVE 15~20개 후보를 정리해 `vulnerable/fixed binary pair`를 수집
- 단일 LLM baseline과 multi-agent pipeline의 공통 입력 스키마 정의
- 함수 위치 추정과 verifier reject rate를 측정할 로그 포맷 확정
- 데모용 웹 UI는 분석 엔진이 안정화된 뒤 2차로 연결
