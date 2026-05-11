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

Python 3.11+ 기준입니다.

```bash
PYTHONPATH=src python3 -m aisec_app.cli
PYTHONPATH=src python3 -m aisec_app.evaluation data/cases
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
ANTHROPIC_MODEL=claude-3-5-sonnet-latest
```

소스 파일 분석:

```bash
PYTHONPATH=src python3 -m aisec_app.source_cli path/to/source.c
```

ZIP 프로젝트 분석:

```bash
PYTHONPATH=src python3 -m aisec_app.zip_cli path/to/project.zip
```

백엔드 API 실행:

```bash
pip install -e .[api,llm]
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
PYTHONPATH=src python3 -m aisec_app.zip_cli path/to/project.zip --allow-heuristic
```

API에서도 heuristic fallback을 명시적으로 허용할 수 있습니다.

```bash
curl -X POST \
  -F "file=@path/to/project.zip" \
  -F "allow_heuristic=true" \
  http://127.0.0.1:8000/analyze/zip
```

LLM finding은 `evidence_quote`가 실제 입력 source에 존재할 때만 accepted finding으로 남고, 근거가 입력에 없으면 rejected finding으로 분리됩니다.

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
