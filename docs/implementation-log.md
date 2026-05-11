# AISEC App Implementation Log

이 문서는 발표자료의 아이디어를 실제 구현으로 옮기는 과정에서, 결정 사항과 작업 로그를 누적하기 위한 기록입니다.

## 2026-05-10 KST - 구현 방향 정리

### 기준 자료

- `docs/32211411_노경민_인공지능보안응용_프로젝트발표.pdf`
- `docs/project-plan.md`
- 현재 코드 스켈레톤:
  - `src/aisec_app/models.py`
  - `src/aisec_app/pipeline.py`
  - `src/aisec_app/sample_data.py`
  - `tests/test_pipeline.py`

### 구현 목표

발표자료의 핵심 흐름인 `Triage -> Patch Analysis -> Binary Match -> Verification -> Report`를 실제 CVE 케이스셋 기반으로 실행 가능한 분석 파이프라인으로 만든다.

목표는 단순히 LLM이 취약 여부를 맞히는 것이 아니라, patch diff 근거와 binary/decompiler 근거가 함께 있을 때만 결과를 채택하는 검증 가능한 1-day 취약점 분석 시스템을 만드는 것이다.

### 현재 상태

- Python 패키지 구조는 이미 존재한다.
- 도메인 모델과 5단계 파이프라인 인터페이스가 있다.
- 현재 구현은 demo case 기반의 rule-like prototype이다.
- 최소 테스트는 통과한다.
- 아직 실제 `data/cases/` 기반 loader, baseline, evaluation, LLM agent, Web UI는 없다.

### 구현 우선순위

1. Dataset contract 고정
   - `data/cases/{case_id}/manifest.json` 구조 확정
   - advisory, patch diff, vulnerable/fixed decompiler excerpt, binary path를 같은 방식으로 읽도록 정리

2. Dataset loader 구현
   - `src/aisec_app/dataset.py`
   - `load_case(case_dir) -> CVECase`
   - `load_cases(cases_root) -> list[CVECase]`

3. Baseline 구현
   - rule-based matcher baseline
   - single LLM baseline은 나중에 같은 입력 계약 위에 추가

4. Evaluation 구현
   - Detection F1
   - Function Localization Accuracy
   - Verifier Reject Rate
   - PASS / REJECT / NEEDS_REVIEW 분포

5. Multi-agent 구현
   - Patch Analysis agent
   - Binary Match agent
   - Verification layer 강화
   - Reporter 구조화

6. Report JSON 저장
   - CLI 실행 결과를 JSON 파일로 저장
   - Web UI가 이 JSON을 그대로 표시할 수 있도록 schema 안정화

7. Web App 구현
   - FastAPI API
   - 간단한 report viewer
   - binary upload는 마지막 단계에서 연결

### 바로 해야 할 일

1. `data/cases/` 아래에 sample case 1개를 만든다.
2. `manifest.json` schema를 확정한다.
3. `dataset.py` loader를 구현한다.
4. CLI가 demo case뿐 아니라 실제 case directory를 받아 실행할 수 있게 한다.
5. loader와 CLI에 대한 테스트를 추가한다.

### MVP 성공 기준

- 최소 1개 case directory를 읽어서 pipeline을 실행할 수 있다.
- 분석 결과가 기존 `AnalysisReport` schema로 나온다.
- 테스트로 loader와 pipeline 흐름이 검증된다.
- 이후 실제 Magma CVE case를 추가해도 코드 구조를 바꾸지 않아도 된다.

### 작업 로그 규칙

- 구현 방향, 파일 구조 변경, 중요한 의사결정은 이 파일에 날짜별로 기록한다.
- 코드 변경을 시작하기 전에 무엇을 바꿀지 짧게 기록한다.
- 구현 후에는 변경 파일, 테스트 결과, 남은 이슈를 기록한다.

## 2026-05-10 KST - 파일 기반 case 실행 구현 시작

### 이번 작업 목표

하드코딩된 `demo_case()`만 실행하는 상태에서 벗어나, `data/cases/{case_id}/` 디렉터리에 정리된 CVE case를 읽어 pipeline을 실행할 수 있게 만든다.

### 구현 예정

- `data/cases/demo-parse-header/` 샘플 case 추가
- `manifest.json` schema 초안 추가
- `src/aisec_app/dataset.py` loader 추가
- CLI가 optional case path를 받도록 확장
- loader와 CLI 흐름을 검증하는 테스트 추가

### 구현 결과

추가/변경 파일:

- `data/cases/demo-parse-header/manifest.json`
- `data/cases/demo-parse-header/advisory.txt`
- `data/cases/demo-parse-header/patch.diff`
- `data/cases/demo-parse-header/vulnerable/decompiler.txt`
- `data/cases/demo-parse-header/fixed/decompiler.txt`
- `data/cases/demo-parse-header/vulnerable/binary`
- `data/cases/demo-parse-header/fixed/binary`
- `src/aisec_app/dataset.py`
- `src/aisec_app/cli.py`
- `tests/test_dataset.py`

이제 CLI는 인자를 생략하면 기존 built-in demo case를 실행하고, case directory를 넘기면 해당 manifest 기반 case를 읽어서 pipeline snapshot을 출력한다.

실행 예:

```bash
PYTHONPATH=src python3 -m aisec_app.cli data/cases/demo-parse-header
```

### 검증 결과

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

결과:

- 5 tests passed
- `demo-parse-header` manifest case가 pipeline을 통과해 `vulnerable`, `parse_header`, verifier `pass` 결과를 생성함

### 다음 작업 후보

1. `manifest.json`의 label 정보를 읽는 별도 metadata 모델 추가
2. evaluation script 구현
3. rule-based baseline을 pipeline과 분리해서 비교 가능하게 구현
4. 실제 Magma 기반 CVE case 1개를 `data/cases/`에 추가

## 2026-05-10 KST - 데이터 출처와 GitHub 버전 관리 방침

### 실제 데이터 출처

실제 case 데이터는 하나의 완성된 JSON 데이터셋을 받는 것이 아니라, 아래 원천을 조합해 `data/cases/{case_id}/` 구조로 정리한다.

- Magma benchmark: ground-truth bug, target, build script, bug/fix patch의 1차 출처
- NVD CVE API: CVE description, CWE, CVSS, reference metadata 출처
- Upstream project repository: vulnerable/fixed commit과 실제 patch diff 확인용
- GitHub Advisory Database: GHSA/vendor advisory 보조 출처

상세 수집 계획은 `docs/dataset-acquisition.md`에 정리했다.

### GitHub 버전 관리 방침

앞으로 의미 있는 코드/문서 변경이 생기면 다음 순서로 관리한다.

1. `docs/implementation-log.md`에 작업 의도와 결과 기록
2. 테스트 실행
3. commit 생성
4. `https://github.com/rohkyoungmin/AISECApp.git`에 push

현재 실행 환경의 기본 `.git` 디렉터리는 비어 있는 read-only placeholder라서 일반적인 `git init`이 실패한다. 이번 세션에서는 별도 git directory를 사용해 local commit을 만들고 원격 저장소에 push한다.

### GitHub push 시도 결과

로컬 commit 생성:

```text
e323228 Initialize AISEC pipeline scaffold
```

테스트:

```text
PYTHONPATH=src python3 -m unittest discover -s tests -v
5 tests passed
```

원격 저장소 확인:

```text
https://github.com/rohkyoungmin/AISECApp.git
```

push는 GitHub HTTPS 인증 정보가 없어 실패했다.

```text
fatal: could not read Username for 'https://github.com': No such device or address
```

다음 push를 완료하려면 이 환경에 GitHub 인증을 연결해야 한다. 가능한 방법:

- `gh` 설치 후 `gh auth login`
- Git credential helper 설정
- push 권한이 있는 personal access token 사용

### GitHub 인증 후 push 완료

GitHub CLI device login으로 `rohkyoungmin` 계정 인증을 완료한 뒤 push에 성공했다.

원격:

```text
https://github.com/rohkyoungmin/AISECApp.git
```

push된 커밋:

```text
e323228 Initialize AISEC pipeline scaffold
9f47aa2 Document GitHub push requirements
```

이후부터는 의미 있는 변경마다 `implementation-log.md` 기록, 테스트, commit, push 순서로 관리한다.

## 2026-05-10 KST - 첫 Magma case 수집 시작

### 이번 작업 목표

사용자가 clone해둔 `external/magma`에서 실제 patch 후보 하나를 골라, 우리 `data/cases/{case_id}/` 포맷으로 변환한다.

### 작업 원칙

- `external/magma` 전체는 외부 소스라 repository에 commit하지 않는다.
- 필요한 advisory/patch/excerpt만 `data/cases/` 아래로 복사한다.
- 아직 실제 binary/decompiler build가 없으면 placeholder 또는 source-level excerpt로 시작하고, 이후 build 단계에서 교체한다.

### 선택한 첫 case

- Source: `external/magma/targets/libpng/patches/bugs/PNG003.patch`
- Case ID: `magma-libpng-png003`
- Project: `libpng`
- Function: `png_handle_PLTE`
- Issue summary: PLTE chunk 처리 중 `num`이 `max_palette_length`를 초과할 수 있으며, fixed path는 `num`을 `max_palette_length`로 clamp한다.

### 구현 결과

추가/변경 파일:

- `.gitignore`
  - `external/`을 ignore하여 Magma clone 전체가 repository에 들어가지 않게 함
- `data/cases/magma-libpng-png003/manifest.json`
- `data/cases/magma-libpng-png003/advisory.txt`
- `data/cases/magma-libpng-png003/patch.diff`
- `data/cases/magma-libpng-png003/vulnerable/decompiler.txt`
- `data/cases/magma-libpng-png003/fixed/decompiler.txt`
- `data/cases/magma-libpng-png003/vulnerable/binary`
- `data/cases/magma-libpng-png003/fixed/binary`
- `src/aisec_app/pipeline.py`
  - `max_palette_length` / `png_handle_PLTE` 계열 patch와 excerpt를 인식하는 최소 rule 추가
- `tests/test_dataset.py`
  - 실제 Magma-derived case가 loader와 pipeline을 통과하는지 검증

### 검증 결과

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

결과:

- 6 tests passed
- `magma-libpng-png003`가 `vulnerable`, function `png_handle_PLTE`, verifier `pass` 결과를 생성함

CLI 확인:

```bash
PYTHONPATH=src python3 -m aisec_app.cli data/cases/magma-libpng-png003
```

### 남은 한계

- 현재 `vulnerable/binary`와 `fixed/binary`는 placeholder이다.
- `decompiler.txt`는 실제 binary decompile 결과가 아니라 Magma patch를 기준으로 만든 source-level excerpt이다.
- 다음 단계에서 Magma build를 수행하고 실제 build artifact와 decompiler/static-analysis output으로 교체해야 한다.

## 2026-05-11 KST - Evaluation layer 구현 시작

### 이번 작업 목표

`manifest.json`의 `labels`를 읽어 전체 `data/cases/`를 평가하는 script를 추가한다.

### 구현 예정

- 정답 label 모델 추가
- dataset loader가 `CVECase`와 labels를 함께 반환할 수 있도록 확장
- `src/aisec_app/evaluation.py` 추가
- 전체 case 수, detection accuracy, function localization accuracy, verifier status 분포 출력
- 테스트 추가

### 구현 결과

추가/변경 파일:

- `src/aisec_app/models.py`
  - `CaseLabels`, `CaseRecord` 추가
- `src/aisec_app/dataset.py`
  - `load_case_record`, `load_case_records` 추가
  - 기존 `load_case`, `load_cases`는 호환 유지
- `src/aisec_app/evaluation.py`
  - 전체 cases 평가 CLI 추가
  - text 출력과 `--json` 출력 지원
- `tests/test_dataset.py`
  - manifest label loader 테스트 추가
- `tests/test_evaluation.py`
  - evaluation summary와 text formatting 테스트 추가

### 실행 방법

```bash
PYTHONPATH=src python3 -m aisec_app.evaluation data/cases
PYTHONPATH=src python3 -m aisec_app.evaluation data/cases --json
```

### 검증 결과

```text
Cases: 2
Detection Accuracy: 2/2 (100.00%)
Function Localization Accuracy: 2/2 (100.00%)
Verifier Status:
  needs_review: 0
  pass: 2
  reject: 0
```

테스트:

```text
PYTHONPATH=src python3 -m unittest discover -s tests -v
10 tests passed
```

### 다음 작업 후보

- 실제 Magma build artifact 생성
- placeholder binary를 실제 vulnerable/fixed binary로 교체
- objdump 또는 decompiler output 생성 자동화
- verifier가 confidence 외에 evidence coverage를 더 세밀하게 평가하도록 개선

## 2026-05-11 KST - Magma patch dataset skeleton 전체 생성

### 구현 결과

- `src/aisec_app/magma_import.py`를 추가했다.
  - `external/magma/targets/*/patches/bugs/*.patch`를 읽어 `data/cases/magma-{target}-{bug}/` 구조로 변환한다.
  - 기존 case는 기본적으로 덮어쓰지 않는다.
  - `--overwrite`를 주면 재생성할 수 있다.
- `external/magma`에서 발견된 bug patch는 총 138개였다.
- 기존 수동 case `magma-libpng-png003`을 제외하고 137개 case skeleton을 새로 생성했다.
- 현재 `data/cases` 전체 case 수는 demo case 포함 139개다.
- 이전에 만들다 중단한 source upload API 초안 파일은 제거했다. LLM/API 연결은 dataset baseline 이후 다시 설계한다.

### 실행 방법

```bash
PYTHONPATH=src python3 -m aisec_app.magma_import external/magma data/cases
PYTHONPATH=src python3 -m aisec_app.magma_import external/magma data/cases --overwrite
```

### 검증 결과

```text
PYTHONPATH=src python3 -m unittest discover -s tests -v
10 tests passed
```

Evaluation baseline:

```text
Cases: 139
Detection Accuracy: 2/139 (1.44%)
Function Localization Accuracy: 2/139 (1.44%)
Verifier Status:
  needs_review: 0
  pass: 2
  reject: 137
```

### 해석

현재 deterministic pipeline은 demo case와 `magma-libpng-png003`만 맞추고 나머지 Magma skeleton case는 대부분 reject한다. 이 낮은 점수는 실패가 아니라, Claude Sonnet 기반 agent를 붙였을 때 비교할 baseline으로 사용한다.

### 남은 한계

- 생성된 Magma case 대부분은 source-level patch 기반 skeleton이다.
- `vulnerable/binary`와 `fixed/binary`는 placeholder이다.
- 실제 Magma build artifact와 decompiler/static-analysis output은 다음 단계에서 교체해야 한다.
- Claude Sonnet API를 붙이기 전까지는 semantic reasoning 성능이 제한적이다.

## 2026-05-11 KST - Claude Sonnet source report 구조 추가

### 구현 결과

- `.env.example` 추가
  - `ANTHROPIC_API_KEY`
  - `ANTHROPIC_MODEL`
  - `ANTHROPIC_MAX_TOKENS`
  - `ANTHROPIC_TEMPERATURE`
  - `AISEC_REQUIRE_LLM`
- `.env`를 `.gitignore`에 추가했다.
- `pyproject.toml`의 `llm` extra를 Claude용으로 변경했다.
  - `anthropic`
  - `python-dotenv`
- `src/aisec_app/config.py` 추가
  - `.env` 로드
  - Claude 설정 로드
- `src/aisec_app/source_analysis.py` 추가
  - `ClaudeSourceAnalyzer`
  - `HeuristicSourceAnalyzer`
  - source analysis report 모델 검증
  - evidence quote가 실제 source에 없으면 finding을 reject
- `src/aisec_app/source_cli.py` 추가
  - `PYTHONPATH=src python3 -m aisec_app.source_cli path/to/source.c`
  - API key 없이 형식 확인 시 `--allow-heuristic`
- `src/aisec_app/models.py`에 source report 모델 추가
  - `SourceArtifact`
  - `SourceFinding`
  - `SourceAnalysisReport`
- `tests/test_source_analysis.py` 추가
- `README.md`에 Claude 설정과 source 분석 실행법 추가

### Reject 정책

Sonnet의 hallucination 여부와 별개로, finding의 `evidence_quote`가 실제 업로드 source 안에 존재하지 않으면 reject한다. 즉 reject는 모델의 자기 확신이 아니라 입력 근거 검증으로 결정한다.

### 검증 결과

```text
PYTHONPATH=src python3 -m unittest discover -s tests -v
14 tests passed
```

local heuristic smoke test:

```text
PYTHONPATH=src python3 -m aisec_app.source_cli /tmp/sample.c --allow-heuristic
verifier_status: pass
```

## 2026-05-11 KST - ZIP archive backend/CLI 분석 추가

### 구현 결과

- ZIP 프로젝트 분석 모델을 추가했다.
  - `ProjectAnalysisReport`
- `src/aisec_app/zip_analysis.py` 추가
  - ZIP 내부에서 C/C++ source 파일만 수집
  - path traversal 방지
  - 분석 파일 수, 파일 크기, 전체 byte 제한 적용
  - 파일별 `SourceAnalysisReport`를 project-level report로 묶음
- `src/aisec_app/zip_cli.py` 추가
  - 터미널에서 ZIP 파일을 직접 분석 가능
  - `--allow-heuristic`으로 Claude key 없이 report 형식 확인 가능
- `src/aisec_app/api.py` 추가
  - `GET /health`
  - `POST /analyze/zip`
  - 프론트엔드 UI는 만들지 않음
- `pyproject.toml`의 `api` extra에 `python-multipart` 추가
- `README.md`에 ZIP CLI와 curl 업로드 예시 추가
- `tests/test_zip_analysis.py` 추가

### 실행 방법

터미널 직접 분석:

```bash
PYTHONPATH=src python3 -m aisec_app.zip_cli path/to/project.zip
```

Claude key 없이 형식 확인:

```bash
PYTHONPATH=src python3 -m aisec_app.zip_cli path/to/project.zip --allow-heuristic
```

백엔드 실행:

```bash
pip install -e .[api,llm]
uvicorn aisec_app.api:app --app-dir src --reload
```

curl 업로드:

```bash
curl -X POST \
  -F "file=@path/to/project.zip" \
  -F "max_files=20" \
  http://127.0.0.1:8000/analyze/zip
```

### 검증 결과

```text
PYTHONPATH=src python3 -m unittest discover -s tests -v
17 tests passed
```

ZIP CLI smoke test:

```text
PYTHONPATH=src python3 -m aisec_app.zip_cli /tmp/project.zip --allow-heuristic
verifier_status: pass
analyzed_files: 1
```

## 2026-05-11 KST - Source 분석 multi-agent 리팩터링

### 구현 결과

- `src/aisec_app/source_analysis.py`를 multi-agent 구조로 리팩터링했다.
- Source/ZIP 분석은 이제 아래 흐름을 따른다.

```text
Triage Agent -> Finding Agent -> Skeptic Verifier Agent -> Reporter Agent
```

- Claude 사용 시 agent별 역할:
  - `ClaudeTriageAgent`: 분석 우선순위, 후보 함수, risk signal 선정
  - `ClaudeFindingAgent`: 취약점 후보와 exact evidence quote 생성
  - `ClaudeSkepticVerifierAgent`: deterministic evidence policy 통과 후 claim/evidence 관계를 재검토
  - `SourceReporterAgent`: accepted/rejected finding 분리
- Claude key가 없을 때 `--allow-heuristic`을 쓰면 같은 agent 계약을 따르는 local heuristic agents가 동작한다.
- 기존 `verify_source_report()` 호환 경로는 유지하되, 내부적으로 evidence policy verifier를 사용하도록 바꿨다.

### Reject 정책

Finding은 아래 조건 중 하나라도 실패하면 reject된다.

- evidence quote가 없음
- evidence quote가 제출된 source에 없음
- finding verdict가 `vulnerable`이 아님
- confidence가 threshold보다 낮음
- root cause가 없음
- remediation이 없음
- line reference가 source 범위를 벗어남
- Claude verifier가 quote와 claim이 직접 연결되지 않거나 주변 mitigation이 있다고 판단함

### 검증 결과

```text
PYTHONPATH=src python3 -m unittest discover -s tests -v
18 tests passed
```

ZIP heuristic smoke test:

```text
model: heuristic-multi-agent
summary: Triage signals: strcpy. Accepted findings: 1. Rejected findings: 0.
```

## 2026-05-11 KST - Experiment output export 추가

### 구현 결과

- `output/`을 `.gitignore`에 추가했다.
- `src/aisec_app/report_export.py` 추가
  - project report JSON 저장
  - Markdown report 저장
  - PDF summary report 저장
  - 파일별 agent decision log를 `llm_logs/*.md`로 저장
- `src/aisec_app/zip_cli.py` 확장
  - 기본적으로 `output/project-<hash>/`에 실험 결과 저장
  - `--output-dir` 지원
  - `--no-export`로 stdout JSON만 출력 가능
- `tests/test_report_export.py` 추가
- `README.md`에 실제 실험 명령과 output 구조 추가

### 실험 명령

```bash
PYTHONPATH=src python3 -m aisec_app.zip_cli path/to/project.zip --max-files 20 --output-dir output
```

Claude key 없이 형식 확인:

```bash
PYTHONPATH=src python3 -m aisec_app.zip_cli path/to/project.zip --allow-heuristic --output-dir output
```

### Output 구조

```text
output/project-<hash>/
  report.json
  report.md
  report.pdf
  llm_logs/
    <source-file>.md
```

### 검증 결과

```text
PYTHONPATH=src python3 -m unittest discover -s tests -v
19 tests passed
```

Smoke test 결과:

```text
Saved JSON: output/project-0a9bf8f4d665/report.json
Saved Markdown: output/project-0a9bf8f4d665/report.md
Saved PDF: output/project-0a9bf8f4d665/report.pdf
Saved agent logs: output/project-0a9bf8f4d665/llm_logs
```

## 2026-05-11 KST - Input directory 기반 ZIP 실행 추가

### 구현 결과

- `input/`을 `.gitignore`에 추가했다.
- `zip_cli`에서 ZIP path 인자를 optional로 변경했다.
- ZIP path를 생략하면 기본 `input/` 폴더에서 `*.zip`을 찾도록 했다.
- `input/`에 ZIP이 하나만 있으면 자동 선택한다.
- ZIP이 없거나 여러 개면 명시적으로 경로를 넘기도록 에러를 출력한다.
- README 실험 명령을 `input/` 기준으로 업데이트했다.

### 실험 명령

```bash
PYTHONPATH=src python3 -m aisec_app.zip_cli --max-files 20 --output-dir output
```

명시적으로 파일 지정:

```bash
PYTHONPATH=src python3 -m aisec_app.zip_cli input/project.zip --max-files 20 --output-dir output
```

## 2026-05-11 KST - Python packaging backend 수정

### 구현 결과

- editable install 오류를 해결하기 위해 build backend를 `setuptools.build_meta`에서 `hatchling.build`로 변경했다.
- Python 요구 버전을 실제 실행 환경에 맞춰 `>=3.10`으로 낮췄다.
- hatchling wheel package target을 `src/aisec_app`으로 명시했다.
- README 실행 섹션에 `pip install -e .[llm]` 명령을 추가했다.

### 배경

`pip install -e .[llm]` 실행 시 build backend가 `build_editable` hook을 제공하지 않는다는 오류가 발생했다. 또한 non-editable 설치에서도 metadata가 `UNKNOWN-0.0.0`으로 잡혀 optional dependency가 적용되지 않았다.
