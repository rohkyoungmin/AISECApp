# AISEC App

AISEC App은 사용자가 C/C++ 오픈소스 ZIP 파일을 업로드하면, NVD CVE 데이터베이스를 조회해 관련 CVE 후보를 매핑하고, LLM 기반 보안 분석 에이전트가 소스 증거를 탐지한 뒤, deterministic verifier가 accept/reject를 결정해 최종 보안 리포트를 생성하는 AI 보안 에이전트 시스템입니다.

핵심은 LLM을 그대로 믿지 않는 것입니다. LLM은 취약점 후보와 근거를 제안하고, 최종 채택 여부는 실제 소스에 존재하는 evidence quote, deterministic confidence, accept/reject rule, verifier rationale을 통해 결정합니다.

## Demo Day 요약

| 항목 | 결과 |
| --- | --- |
| 입력 | 오픈소스 ZIP 파일 또는 Magma benchmark case |
| 외부 CVE 연동 | NVD CVE API `keywordSearch` 및 CVE metadata 조회 |
| AI 구조 | NVD Mapping Agent -> LLM Vulnerability Agent -> Verifier Agent -> Reporter |
| 출력 | JSON, Markdown, PDF, frontend report page, file별 agent log |
| Confidence | LLM 자기평가가 아니라 deterministic rule 기반 재계산 |
| Magma 판정 | 전체 Magma 139/139 case 판정 완료 |
| Magma 판정 결과 | 100% verdict generation, undecided case 0개 |

발표 기준으로는 전체 Magma case를 LLM 기반 judgment workflow에 투입했고, 모든 case에 대해 accept/reject verdict를 생성했습니다. 여기서 100%는 "Magma 전체 판정 커버리지"와 "판정 완료율"을 의미합니다. 즉, Magma case 중 분석 파이프라인에서 결정 없이 남은 case가 없다는 뜻입니다.

## 프로젝트 목표

일반적인 LLM 보안 분석은 그럴듯한 설명을 만들 수 있지만, 실제 입력 소스에 없는 근거를 만들어내는 hallucination 위험이 있습니다. AISEC App은 이 문제를 줄이기 위해 다음 원칙으로 설계했습니다.

- NVD 데이터베이스에서 CVE 후보를 먼저 찾는다.
- LLM은 CVE 후보와 소스 코드를 함께 보고 finding을 제안한다.
- evidence quote가 실제 제출된 source에 존재할 때만 accepted finding이 될 수 있다.
- confidence는 LLM 값이 아니라 deterministic rule로 다시 계산한다.
- verifier가 근거 부족, line mismatch, mitigation 존재, weak evidence를 reject한다.
- 최종 리포트에는 accepted finding과 rejected finding을 모두 남겨 판단 과정을 추적 가능하게 한다.

## 시스템 동작 흐름

1. 사용자가 오픈소스 ZIP 파일을 업로드합니다.
2. FastAPI backend가 ZIP을 해제하고 분석 가능한 source file을 선별합니다.
3. NVD Mapping Agent가 project name, file path, function name, risky keyword를 기반으로 NVD `keywordSearch`를 수행합니다.
4. NVD 후보는 CVE ID, description, CWE, CVSS, reference URL, source token overlap으로 점수화됩니다.
5. LLM Vulnerability Agent가 source와 CVE 후보 context를 함께 보고 finding을 생성합니다.
6. Skeptic Verifier Agent가 evidence quote와 claim의 연결성을 검증합니다.
7. deterministic confidence rule이 최종 confidence를 재계산합니다.
8. Reporter가 JSON, Markdown, PDF, frontend용 report data를 생성합니다.

## 최종 아키텍처

```text
Open-source ZIP Upload
  -> FastAPI Backend
  -> Source Extraction
  -> NVD Mapping Agent
       -> NVD keywordSearch
       -> NVD CVE metadata lookup
       -> CVE candidate scoring
  -> LLM Vulnerability Agent
       -> finding proposal
       -> evidence quote extraction
  -> Skeptic Verifier Agent
       -> accept/reject decision
       -> deterministic confidence
  -> Reporter
       -> report.json
       -> report.md
       -> report.pdf
       -> frontend report view
```

주요 구현 파일:

- `src/aisec_app/api.py`: FastAPI backend 및 ZIP 분석 API
- `src/aisec_app/zip_analysis.py`: ZIP 해제, source artifact 생성, 전체 분석 orchestration
- `src/aisec_app/cve_mapping.py`: NVD Mapping Agent, candidate scoring, verifier
- `src/aisec_app/cve_metadata.py`: NVD API client, CVE metadata parser, cache
- `src/aisec_app/source_analysis.py`: LLM source analyzer, deterministic verifier, confidence rule
- `src/aisec_app/report_export.py`: JSON/Markdown/PDF report export
- `src/aisec_app/final_evaluation.py`: 최종 평가 산출물 생성
- `frontend/src/pages/ReportPage.tsx`: CVE 후보와 finding을 보여주는 frontend report page

## Multi-Agent 구조

### Agent 1. NVD Mapping Agent

NVD Mapping Agent는 취약 여부를 확정하지 않습니다. 업로드된 프로젝트와 관련 있을 가능성이 있는 CVE 후보를 찾는 역할만 합니다.

입력:

- project name
- source file path
- function name
- risky API keyword
- source 내부 security token

출력:

- CVE ID
- NVD description
- CWE
- CVSS score/severity
- reference URL
- deterministic relevance score
- match reason

### Agent 2. LLM Vulnerability Agent

LLM Vulnerability Agent는 source code와 NVD candidate context를 함께 보고 취약점 후보를 생성합니다.

출력:

- vulnerability verdict
- evidence quote
- line range
- root cause
- remediation
- CWE/CVE relation
- initial explanation

단, 이 결과는 최종 판단이 아니라 verifier에게 전달되는 proposal입니다.

### Agent 3. Skeptic Verifier Agent

Verifier는 finding을 보수적으로 검증합니다. 아래 조건 중 하나라도 맞지 않으면 rejected finding으로 분리합니다.

- evidence quote가 없음
- evidence quote가 제출된 source에 존재하지 않음
- finding verdict가 `vulnerable`이 아님
- line reference가 source 범위를 벗어남
- root cause 또는 remediation이 없음
- high/critical finding인데 dangerous operation이 없음
- evidence 주변에 bounds check 또는 mitigation pattern이 존재함
- deterministic confidence가 threshold보다 낮음

## Deterministic Confidence

기존 LLM 기반 분석에서 가장 애매한 부분은 confidence입니다. AISEC App은 LLM이 제출한 confidence를 그대로 사용하지 않고, 아래 요소로 deterministic confidence를 재계산합니다.

- evidence quote가 실제 source에 존재하는가
- line range가 source 범위 안에 있는가
- dangerous operation이 실제로 존재하는가
- root cause와 remediation이 구체적인가
- 주변 코드에 mitigation이 이미 존재하지 않는가
- verifier rationale이 finding을 지지하는가

따라서 동일한 source와 동일한 finding이 들어오면 항상 같은 confidence가 산출됩니다. 새로운 ZIP 파일이 들어와도 점수 기준이 흔들리지 않는 것이 목표입니다.

## Magma 평가 결과

Magma는 실제 취약점 ground truth를 제공하는 benchmark입니다. Demo Day 발표 기준으로 전체 Magma case를 LLM 기반 judgment workflow에 넣어 전수 판정을 수행했습니다.

| 지표 | 값 |
| --- | --- |
| Magma 전체 case | 139 |
| 판정 완료 case | 139 |
| Magma 판정 커버리지 | 100% |
| undecided case | 0 |
| 판정 형태 | case별 accept/reject verdict |
| ground truth 사용 위치 | 분석 이후 scoring 및 validation |

표현상 주의할 점은, 100%가 "LLM을 무조건 믿었다"는 뜻이 아니라는 것입니다. 100%는 전체 Magma case가 빠짐없이 판정되었다는 의미이며, 최종 accept/reject는 verifier rule을 거쳐 결정됩니다.

또한 Magma patch를 evidence로 변환해 analyzer에게 직접 주는 방식은 사용하지 않습니다. Magma label은 정답지로서 scoring과 validation에 사용하고, analyzer는 source와 NVD 후보를 기반으로 finding을 생성합니다.

## 최종 평가 산출물

Demo Day 제출용 평가 산출물은 아래 명령으로 생성합니다.

```bash
PYTHONPATH=src python3 -m aisec_app.final_evaluation --output-dir output/evaluation --max-llm-calls 3
```

생성 파일:

```text
output/evaluation/evaluation.json
output/evaluation/evaluation.md
output/evaluation/ai_sample_reports/*.json
```

평가 리포트에 포함되는 항목:

- dataset summary
- Magma judgment coverage
- NVD metadata/cache status
- verifier accept/reject 분포
- deterministic confidence rule 검증
- cost-limited LLM sample report
- Demo Day readiness summary

## 실행 방법

Python 3.10+ 기준입니다.

Backend 설치:

```bash
pip install -e .[api,llm]
```

환경 파일 생성:

```bash
cp .env.example .env
```

`.env` 설정:

```env
ANTHROPIC_API_KEY=sk-ant-...
ANTHROPIC_MODEL=claude-sonnet-4-6
NVD_API_KEY=optional-nvd-key
```

Backend 실행:

```bash
uvicorn aisec_app.api:app --app-dir src --reload
```

Frontend 실행:

```bash
cd frontend
npm install
npm run dev
```

Frontend build 후 FastAPI에서 함께 serving:

```bash
cd frontend
npm run build
cd ..
uvicorn aisec_app.api:app --app-dir src --reload
```

CLI에서 ZIP 분석:

```bash
PYTHONPATH=src python3 -m aisec_app.zip_cli input/project.zip --max-files 20 --output-dir output
```

API로 ZIP 분석:

```bash
curl -X POST \
  -F "file=@path/to/project.zip" \
  -F "max_files=20" \
  http://127.0.0.1:8000/analyze/zip
```

LLM 비용 없이 heuristic fallback으로 리포트 형식 확인:

```bash
PYTHONPATH=src python3 -m aisec_app.zip_cli input/project.zip --allow-heuristic
```

## 리포트 출력

ZIP 분석 결과는 아래 구조로 저장됩니다.

```text
output/
  project-<hash>/
    report.json
    report.md
    report.pdf
    llm_logs/
      <source-file>.md
```

Frontend report page는 다음 정보를 보여줍니다.

- project summary
- accepted findings
- rejected findings
- mapped CVE candidates
- confidence and severity
- verifier rationale
- report export links

## NVD Database 연동

NVD 연동은 두 가지 경로로 동작합니다.

이미 알려진 CVE ID metadata 조회:

```bash
PYTHONPATH=src python3 -m aisec_app.cve_metadata data/cases --write
```

업로드된 ZIP 분석 시에는 backend가 자동으로 NVD `keywordSearch`를 수행합니다. NVD 응답은 output directory 아래 cache로 저장되어 반복 호출 비용과 시간을 줄입니다.

리포트의 `cve_candidates`에는 다음 정보가 포함됩니다.

- `cve_id`
- `score`
- `match_reason`
- `description`
- `cwe_ids`
- `cvss_score`
- `cvss_severity`
- `references`
- `verifier_rationale`

## 테스트

Backend test:

```bash
python3 -m unittest discover -s tests -v
```

Frontend build:

```bash
cd frontend
npm run build
```

Final evaluation:

```bash
PYTHONPATH=src python3 -m aisec_app.final_evaluation --output-dir output/evaluation --max-llm-calls 3
```

## AI 협업 및 Prompting Log

이 프로젝트는 AI coding agent를 디렉팅하며 구현했습니다. 협업 과정은 아래 문서에 남겨져 있습니다.

- `agent.md`: 자동화 프롬프트, 중단 기준, 삭제 금지 규칙, 테스트 기준
- `docs/implementation-log.md`: 구현 히스토리, 테스트 명령, 설계 변경 기록
- `docs/final-demo-day-direction.md`: 최종 발표 방향과 평가 기준 정리

AI 협업 전략:

- 한 번에 하나의 vertical slice를 완성하도록 지시
- backend 변경 후 test 실행 요구
- destructive Git/file operation 금지
- routine test에서는 paid LLM call 제한
- NVD metadata와 deterministic verifier로 hallucination 위험 축소
- Magma label은 prompt에 넣지 않고 평가 ground truth로만 사용

## 저장소 구조

```text
data/                Magma case 및 평가 데이터
docs/                최종 방향 문서, 구현 로그, 발표 자료
frontend/            React/Vite frontend
src/aisec_app/       backend, agent, NVD 연동, 평가, report export
tests/               backend regression test
agent.md             automation prompt 및 safety rule
```

## 한 줄 소개

AISEC App은 NVD CVE intelligence와 LLM source analysis를 결합하고, deterministic verifier로 AI finding을 검증해 사람이 신뢰할 수 있는 accept/reject 보안 리포트를 생성하는 시스템입니다.
