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
