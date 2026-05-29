# AISEC App Final Demo Day Direction

## 1. 최종 발표 목표

최종 발표의 핵심 메시지는 다음과 같다.

> AISEC App은 사용자가 C/C++ 오픈소스 ZIP을 업로드하면, NVD 기반 CVE 후보를 찾고, LLM multi-agent가 소스 증거를 분석한 뒤, deterministic verifier가 근거 기반으로 accept/reject를 결정하여 JSON/Markdown/PDF 리포트를 생성하는 AI 보안 분석 시스템이다.

이번 Demo Day에서는 “모든 CVE를 완벽히 탐지한다”가 아니라, 아래 네 가지를 실제 작동으로 증명한다.

- ZIP 업로드 기반 C/C++ source 분석이 동작한다.
- LLM 또는 heuristic agent가 취약점 후보와 evidence quote를 생성한다.
- verifier가 hallucination, weak evidence, mitigation이 있는 finding을 reject한다.
- 최종 결과가 Web UI와 PDF report로 재현 가능하게 남는다.

## 2. 최종 시스템 방향

중간 발표에서는 source-level vulnerability report pipeline까지 구현했다. 최종 방향은 여기에 NVD 기반 CVE candidate mapping과 deterministic confidence calibration을 붙여, 1-day vulnerability analysis에 더 가까운 구조로 정리한다.

```text
Open-source ZIP Upload
  -> Extract C/C++ Files
  -> Project / Function / Risk Keyword Extraction
  -> NVD CVE Candidate Mapping
  -> AI Mapping + Finding Agent
  -> Deterministic Confidence Calibration
  -> Evidence-grounded Verifier
  -> Report Export + Web UI
```

### 핵심 설계 원칙

- CVE mapping은 “확정”이 아니라 “후보 추천”으로 표현한다.
- LLM confidence는 그대로 믿지 않고 deterministic rule로 재계산한다.
- evidence quote가 실제 source에 없으면 무조건 reject한다.
- 주변에 bounds check, mitigation pattern이 있으면 accept하지 않는다.
- 최종 accept는 CVE 후보 근거와 source evidence가 함께 있을 때만 가능하도록 확장한다.

## 3. 최종 아키텍처

### 1. Extract Stage

ZIP 파일을 받아 C/C++ 파일만 추출한다.

- 허용 확장자: `.c`, `.cpp`, `.cc`, `.cxx`, `.h`, `.hpp`
- path traversal 차단
- file size 제한
- 분석 파일 수 제한
- non-UTF-8 입력은 lossy decode 처리

평가 포인트:

- Live Demo 안정성
- 악성 ZIP 입력에 대한 기본 방어
- 실제 오픈소스 프로젝트 ZIP을 입력으로 받을 수 있음

### 2. CVE Candidate Mapping Stage

업로드된 source archive에서 다음 단서를 추출한다.

- 프로젝트명 또는 파일 경로 키워드
- 위험 API: `strcpy`, `memcpy`, `gets`, `sprintf`, `recv`, `fread`
- 함수명: 예: `ssl3_read_bytes`, `png_handle_PLTE`
- README, header, config 파일의 버전 문자열

이 단서를 기반으로 NVD CVE API를 조회해 후보 CVE를 만든다.

```text
NVD keywordSearch / cveIds
  -> CVE description
  -> CWE
  -> CVSS score
  -> published / lastModified
  -> references
```

중요한 표현:

> ZIP만으로 CVE를 100% 확정할 수 없기 때문에, AISEC App은 NVD 기반 candidate CVE를 생성하고, 이후 source evidence와 verifier를 통해 관련성을 검증한다.

현재 구현 상태:

- NVD CVE API 연동 모듈 구현 완료
- case 내부의 실제 CVE ID를 찾고 metadata를 manifest에 저장 가능
- `CVE-2016-6304`, `CVE-2016-6305` 실제 NVD metadata 연동 완료

최종 보강 방향:

- ZIP 분석 경로에 candidate CVE mapping stage 연결
- Report UI에 “Mapped CVE Candidates” 섹션 추가

### 3. AI Finding Stage

LLM agent는 NVD 후보와 source 내용을 함께 보고 취약점 후보를 만든다.

입력:

- source file content
- triage risk signals
- candidate CVE metadata
- CWE/CVSS/reference summary

출력:

- vulnerability title
- verdict
- severity
- affected function
- line range
- exact evidence quote
- root cause
- remediation

중요한 제약:

- evidence quote는 source의 정확한 substring이어야 한다.
- 함수명, 라인 번호, 코드 조각을 invent하면 안 된다.
- evidence가 약하면 `needs_review`로 남긴다.

### 4. Deterministic Confidence Calibration

기존에는 LLM이 confidence를 생성했기 때문에 기준이 모호했다. 최종 방향에서는 confidence를 deterministic rule로 재계산한다.

점수 기준:

- finding verdict가 `vulnerable`인지
- evidence quote가 실제 source에 존재하는지
- line reference가 source 범위 안에 있는지
- root cause가 있는지
- remediation이 있는지
- evidence 안에 dangerous operation이 있는지
- function name이 실제 source에 존재하는지
- 주변에 mitigation 또는 bounds check가 있는지

예시:

```text
same source + same finding -> same confidence
```

발표용 핵심 문장:

> Confidence는 LLM의 자기 확신 값이 아니라, source evidence 구조를 기반으로 한 deterministic score이다. 따라서 새로운 ZIP 파일이 들어와도 같은 코드와 같은 finding에는 항상 같은 점수가 부여된다.

현재 구현 상태:

- `calibrate_finding_confidence()` 구현 완료
- LLM이 `confidence: 0.01` 또는 `0.99`를 반환해도 최종 confidence는 동일하게 재계산됨
- mitigation 주변 finding은 confidence가 감점되고 reject됨

### 5. Evidence-grounded Verifier

Verifier는 최종 보안 판단을 통제한다.

Reject 기준:

- evidence quote가 없음
- evidence quote가 실제 source에 없음
- verdict가 `vulnerable`이 아님
- deterministic confidence가 threshold보다 낮음
- root cause 또는 remediation이 없음
- line reference가 source 범위를 벗어남
- high/critical finding인데 dangerous operation이 없음
- 주변 mitigation 또는 bounds check가 있음
- Claude verifier가 quote와 claim이 직접 연결되지 않는다고 판단함

Accept 조건:

- source evidence가 실제로 존재함
- 위험 동작이 evidence에 포함됨
- root cause와 remediation이 설명됨
- deterministic confidence threshold를 통과함
- 주변 mitigation이 없어야 함

## 4. Live Demo 시나리오

10분 발표에서는 아래 순서로 시연한다.

### Demo 1. Web UI ZIP 분석

1. AISEC App 실행
2. Project 생성
3. 취약한 C/C++ sample ZIP 업로드
4. progress stream 확인
5. Report Page 확인
6. PDF 다운로드

보여줄 것:

- 분석 stage가 순서대로 진행됨
- accepted finding이 source evidence와 함께 표시됨
- PDF report가 생성됨

### Demo 2. Reject Case

mitigation이 있는 코드를 업로드하거나 테스트 fixture를 사용한다.

예시:

```c
void f(char *s, size_t n) {
  if (n < sizeof(buf)) {
    strcpy(buf, s);
  }
}
```

보여줄 것:

- 단순히 `strcpy`가 있다고 accept하지 않음
- 주변 bounds check 때문에 reject 또는 needs_review 처리
- verifier rationale에 reject 이유가 남음

### Demo 3. NVD CVE Metadata

CLI 또는 report 화면에서 NVD 연동 결과를 보여준다.

```bash
PYTHONPATH=src python3 -m aisec_app.cve_metadata data/cases --json --delay 0
```

보여줄 것:

- NVD API로 CVE description, CWE, CVSS, references를 가져옴
- 현재 실제 연동된 case:
  - `CVE-2016-6304`
  - `CVE-2016-6305`

## 5. 발표 자료 구성

발표 시간은 10분 내외이므로, 9~11장 정도로 압축한다.

### Slide 1. Title

- AISEC App
- NVD-grounded C/C++ Vulnerability Analysis Reporting System
- 이름, 학과

### Slide 2. Problem & Goal

핵심 문제:

- LLM은 보안 분석을 잘 설명하지만 hallucination 위험이 있다.
- CVE/NVD 정보만으로는 실제 source가 취약한지 알 수 없다.
- 따라서 CVE metadata, source evidence, deterministic verifier를 결합해야 한다.

### Slide 3. Final Architecture

```text
ZIP -> Extract -> NVD Candidate Mapping -> AI Finding -> Deterministic Verify -> Report
```

### Slide 4. CVE Candidate Mapping

- NVD API 사용
- CVE description, CWE, CVSS, references 수집
- 확정 매핑이 아니라 candidate mapping으로 설계

### Slide 5. AI Agent Pipeline

- Triage Agent
- Finding Agent
- Skeptic Verifier Agent
- Reporter Agent

### Slide 6. Deterministic Confidence & Reject Policy

- LLM confidence를 그대로 사용하지 않음
- 같은 source/finding이면 같은 confidence
- accept/reject rule 표로 정리

### Slide 7. Live Demo

- Web UI
- ZIP upload
- Report
- PDF

### Slide 8. Evaluation & Test Result

현재 검증 결과:

```text
27 tests passed
139 Magma skeleton cases
2 NVD-linked OpenSSL CVE cases
JSON / Markdown / PDF report export
```

설명 방식:

- Magma benchmark 자체는 ground truth dataset이므로, 실제 artifact가 완비된 completed Magma case에서는 탐지율이 높아야 한다.
- 현재 repository의 139개 case는 대부분 source-level skeleton이므로 최종 성능 평가용이 아니라 pipeline contract 평가용이다.
- verifier가 weak evidence를 reject하는 것이 현재 시스템의 핵심 안전성이다.

### Slide 9. Evaluation Method

평가는 한 개의 accuracy 숫자로 설명하지 않고, 시스템 단계를 나누어 평가한다.

```text
CVE Candidate Mapping
  -> Top-1 Accuracy, Top-3 Recall

Vulnerability Detection
  -> Precision, Recall, F1

Function Localization
  -> Function Accuracy, Line Range Overlap

Verifier Reliability
  -> Reject Rate, False Accept Rate, Mitigation Reject Accuracy

Report Quality
  -> Evidence Grounding, Root Cause Quality, Remediation Usefulness
```

발표 핵심:

> AISEC App은 CVE를 바로 확정하는 시스템이 아니라 NVD 기반 후보 CVE를 만들고, source evidence와 verifier로 검증하는 시스템이므로 Top-k candidate recall과 verifier false accept rate가 중요하다.

### Slide 10. AI & Git Collaboration

포함할 내용:

- Claude/Codex를 역할 분리해서 사용
- prompt 설계, code review, test, documentation 반복
- implementation-log 기반 개발 이력 관리
- Git commit history 요약

### Slide 11. Limitations & Future Work

한계:

- ZIP만으로 CVE를 완전히 확정하기 어렵다.
- 실제 exploitability 판단은 source만으로 제한적이다.
- Magma skeleton 대부분은 실제 built binary가 아니다.
- NVD keyword mapping은 false positive 가능성이 있다.

향후 과제:

- NVD candidate mapping을 ZIP analysis flow에 완전 통합
- function-level CVE matching 강화
- 실제 Magma binary/decompiler artifact 확보
- CVE mapping precision/recall 평가셋 구축
- UI에 candidate CVE ranking과 reject rationale 시각화

## 6. 최종 평가 기준 대응 전략

### Creativity

강조할 점:

- 단순 LLM 취약점 탐지가 아니라 NVD CVE candidate와 source evidence를 결합
- LLM hallucination을 deterministic verifier로 통제
- confidence를 모델 자기평가가 아닌 rule-based score로 재계산

발표 문장:

> AISEC App의 독창성은 LLM을 최종 판단자로 쓰지 않고, CVE metadata와 source evidence를 연결하는 후보 생성기로 제한한 뒤, verifier가 보안 판단을 통제한다는 점이다.

### Completeness

강조할 점:

- ZIP upload
- source filtering
- LLM/heuristic analysis
- accept/reject verifier
- JSON/Markdown/PDF export
- React UI + FastAPI backend
- unittest 27개 통과

Live Demo에서 반드시 보여줄 것:

- 실제 ZIP 분석
- report 화면
- PDF 다운로드
- reject rationale

### AI-Collaboration

강조할 점:

- AI IDE를 단순 코드 생성이 아니라 설계, 구현, 테스트, 문서화에 사용
- implementation-log로 session continuity 확보
- GitHub commit history로 개발 과정 증명
- 사람이 보안 판단 기준과 범위를 결정하고, AI는 구현/검증을 보조

### Professionalism

강조할 점:

- 과장하지 않고 한계를 명확히 말한다.
- CVE mapping은 candidate라고 표현한다.
- 낮은 baseline 성능은 skeleton dataset 한계와 strict verifier 정책 때문이라고 설명한다.
- Magma ground truth case가 완성되면 탐지율은 높게 나와야 하며, 현재 skeleton baseline과 completed-case 성능 평가는 분리해서 말한다.
- accept보다 reject를 보수적으로 택한 이유를 보안 관점에서 설명한다.

## 7. Evaluation Plan

최종 시스템 평가는 `CVE 매핑`, `취약점 탐지`, `함수 위치 추정`, `Verifier 신뢰도`, `리포트 품질`로 나누어 수행하는 것이 가장 적절하다. 이 프로젝트는 LLM이 단독으로 정답을 내는 구조가 아니라, NVD 후보 생성과 evidence-grounded verification을 결합한 구조이기 때문이다.

### 1. Magma Ground Truth Evaluation

Magma는 실제 취약점 ground truth를 제공하는 benchmark이므로, 최종 성능 평가는 Magma completed case를 기준으로 해야 한다.

중요 원칙:

> Magma patch/advisory를 미리 분석해서 만든 evidence를 analyzer 입력으로 넣지 않는다. Magma는 정답 라벨과 평가 기준으로만 사용하고, AISEC App은 ZIP source와 NVD 후보만 보고 evidence quote와 finding을 스스로 생성해야 한다.

이유:

- Magma patch를 evidence로 변환해 입력하면 정답 힌트를 주는 data leakage가 된다.
- 실제 사용자는 patch diff나 vulnerable function label을 함께 주지 않고 오픈소스 ZIP만 업로드한다.
- 평가에서는 시스템이 source 안에서 취약 evidence를 직접 찾는 능력을 봐야 한다.

공정한 평가 흐름:

```text
Magma vulnerable/fixed source or artifact
  -> ZIP input으로만 제공
  -> AISEC App이 NVD candidate mapping 수행
  -> AI/heuristic analyzer가 source evidence 직접 생성
  -> verifier가 accept/reject
  -> Magma ground truth label과 비교해 점수 계산
```

사용하지 말아야 할 입력:

- Magma patch를 요약한 handcrafted evidence
- vulnerable function label
- vulnerable address label
- expected verdict label
- 정답 라인을 그대로 알려주는 decompiler excerpt

사용 가능한 평가용 정보:

- scoring 단계의 expected verdict
- scoring 단계의 vulnerable function
- scoring 단계의 CVE/bug mapping
- source/fixed pair 구분

중요한 구분:

```text
Magma benchmark itself
  -> ground truth bug/fix information exists
  -> completed case에서는 탐지율이 높아야 함

Current imported repository cases
  -> 대부분 source-level skeleton
  -> real built binary / decompiler artifact / PoC가 부족함
  -> 현재 139개 전체 점수는 최종 탐지 성능이 아니라 contract baseline
```

따라서 최종 보고에서는 두 숫자를 분리한다.

```text
Skeleton Contract Evaluation
  - 139 cases load and run through the pipeline
  - strict verifier rejects weak evidence

Completed Magma Evaluation
  - artifact가 완비된 selected cases만 따로 평가
  - vulnerable/fixed pair 기준으로 Precision / Recall / F1 산출
```

발표 문장:

> Magma는 ground truth benchmark이므로 완성된 Magma case에서는 높은 탐지율이 나와야 한다. 다만 Magma patch를 evidence로 바꿔 analyzer에게 주면 data leakage가 되므로, 평가는 ZIP source만 입력하고 Magma label은 scoring에만 사용한다. 현재 repository의 139개 case는 대부분 skeleton이기 때문에, 전체 139개 결과는 최종 탐지율이 아니라 strict verifier와 data contract가 동작하는지 보는 baseline으로 해석한다.

### 2. CVE Candidate Mapping Evaluation

목표:

- 업로드된 ZIP/source project가 어떤 CVE 후보와 연결될 수 있는지 평가한다.

입력:

- open-source project ZIP
- source/fixed pair case
- Magma 또는 CVE-linked sample

정답:

- 해당 case와 실제로 연결된 CVE ID

지표:

- `Top-1 Accuracy`: 1순위 후보가 정답 CVE인가
- `Top-3 Recall`: 상위 3개 후보 안에 정답 CVE가 포함되는가
- `Top-5 Recall`: 상위 5개 후보 안에 정답 CVE가 포함되는가
- `Average Candidate Count`: case당 평균 후보 CVE 수

해석:

- ZIP만으로 CVE를 확정하기 어렵기 때문에 Top-1 Accuracy보다 Top-k Recall이 더 중요하다.
- 후보를 너무 많이 내면 사용성이 떨어지므로 Average Candidate Count도 함께 본다.

발표 문장:

> CVE mapping은 최종 판정이 아니라 후보 생성 단계이므로, 정확도는 Top-1뿐 아니라 Top-3/Top-5 Recall로 평가한다.

### 3. Vulnerability Detection Evaluation

목표:

- candidate CVE와 source evidence를 기반으로 실제 vulnerable/fixed 여부를 얼마나 잘 판단하는지 평가한다.

정답:

- vulnerable 또는 fixed label

지표:

- `Precision`: accept한 finding 중 실제 취약한 비율
- `Recall`: 실제 취약한 case 중 accept한 비율
- `F1`: Precision과 Recall의 조화 평균
- `False Positive`: fixed 또는 mitigated code를 vulnerable로 accept한 수
- `False Negative`: vulnerable code를 reject 또는 miss한 수

보안 관점 해석:

- 보안 리포팅 시스템에서는 unsupported finding을 accept하면 신뢰도가 떨어진다.
- 따라서 초기 버전에서는 Recall보다 Precision과 False Accept 감소를 더 중요하게 본다.
- 단, Magma completed vulnerable case에서는 ground truth가 명확하므로 Recall도 충분히 높아야 한다.

발표 문장:

> AISEC App은 보수적인 보안 분석 시스템이므로, 단순히 많이 탐지하는 것보다 근거 없는 finding을 accept하지 않는 것을 우선한다. 그러나 Magma completed case처럼 ground truth가 완비된 평가셋에서는 높은 Recall과 F1을 목표로 한다.

### 4. Function Localization Evaluation

목표:

- 취약점이 어느 함수 또는 라인 근처에 있는지 맞히는지 평가한다.

정답:

- vulnerable function name
- 가능하면 vulnerable line range

지표:

- `Function Accuracy`: 예측 함수명이 정답 함수명과 일치하는가
- `Line Range Overlap`: 예측 라인 범위가 정답 라인 범위와 겹치는가
- `Evidence Quote Grounding`: evidence quote가 실제 source에 존재하는가

현실적인 초기 평가:

- 현재는 line-level ground truth가 부족하므로 function name 기준으로 먼저 평가한다.
- line range는 향후 CVE-linked source dataset을 보강한 뒤 평가한다.

### 5. Verifier Reliability Evaluation

목표:

- Verifier가 LLM hallucination과 weak evidence를 얼마나 잘 걸러내는지 평가한다.

지표:

- `Accept Rate`: 전체 finding 중 accept 비율
- `Reject Rate`: 전체 finding 중 reject 비율
- `False Accept Rate`: reject해야 할 finding을 accept한 비율
- `Ungrounded Evidence Reject Accuracy`: source에 없는 quote를 reject하는 비율
- `Invalid Line Reject Accuracy`: source 범위를 벗어난 line reference를 reject하는 비율
- `Mitigation Reject Accuracy`: bounds check 또는 mitigation이 있는 finding을 reject하는 비율
- `Deterministic Confidence Consistency`: 같은 source/finding에 항상 같은 confidence가 나오는지

현재 구현된 verifier 테스트:

- source에 없는 evidence quote reject
- source 범위를 벗어난 line reference reject
- mitigation 주변 finding reject
- LLM이 준 confidence와 무관하게 deterministic confidence 재계산

발표 문장:

> Verifier 평가는 단순 탐지 정확도보다 중요하다. LLM이 그럴듯한 finding을 만들어도 source evidence가 없거나 mitigation이 있으면 reject해야 하기 때문이다.

### 6. Report Quality Evaluation

목표:

- 최종 리포트가 사람이 검토하기에 충분히 설명 가능한지 평가한다.

Rubric:

```text
Evidence Grounding
  1: evidence 없음
  3: source quote는 있으나 claim과 약하게 연결됨
  5: source quote가 root cause를 직접 설명함

Root Cause Quality
  1: 일반적인 설명
  3: 위험 API 또는 함수 수준 설명
  5: CVE/CWE와 연결된 구체적 원인 설명

Remediation Usefulness
  1: "fix it" 수준
  3: bounds check 등 일반적 수정 방향
  5: 함수/코드 맥락에 맞는 구체적 수정 가이드

Reject Explainability
  1: reject 이유 없음
  3: rule 이름만 제시
  5: 어떤 evidence/rule 때문에 reject됐는지 설명
```

### 7. System Robustness Evaluation

목표:

- 실제 Demo Day에서 시스템이 안정적으로 동작하는지 평가한다.

지표:

- unittest 통과 수
- ZIP path traversal 방어 여부
- max file/max size 제한 동작 여부
- JSON/Markdown/PDF report export 성공 여부
- Web UI에서 project 생성, upload, progress, report view, PDF download 성공 여부

현재 결과:

```text
27 tests passed
139 Magma skeleton cases loaded
2 NVD-linked OpenSSL CVE cases
JSON / Markdown / PDF report export supported
```

### 8. 현재 제출 시 사용할 수 있는 평가

현재 코드와 dataset 기준으로 즉시 제시 가능한 평가는 다음과 같다.

```text
Dataset Contract Evaluation
  - 139 Magma skeleton cases loaded
  - manifest/advisory/patch/decompiler contract 검증

Baseline Detection Evaluation
  - Detection Accuracy
  - Function Localization Accuracy
  - Verifier pass/reject distribution

Verifier Unit Evaluation
  - ungrounded evidence reject
  - invalid line reference reject
  - mitigation nearby reject
  - deterministic confidence consistency

NVD Metadata Evaluation
  - 2 OpenSSL CVE cases linked to NVD
  - CVE description/CWE/CVSS/reference parsed

System Robustness Evaluation
  - 27 unittest passed
  - ZIP filtering/path traversal defense
  - report export success
```

주의:

> `Detection Accuracy 2/139`만 단독으로 강조하면 안 된다. Magma benchmark는 ground truth가 맞지만, 현재 import된 139개 case 대부분은 실제 built artifact와 decompiler evidence가 없는 skeleton이다. 따라서 이 숫자는 최종 Magma 탐지율이 아니라 skeleton 상태에서 strict verifier가 weak evidence를 reject한다는 baseline으로 설명해야 한다.

### 9. 최종 평가 표

발표자료에는 아래 표를 그대로 사용할 수 있다.

```text
Evaluation Axis              Metric
---------------------------------------------------------------
Magma Ground Truth            Detection F1 on completed cases
CVE Candidate Mapping         Top-1 Accuracy, Top-3/Top-5 Recall
Vulnerability Detection       Precision, Recall, F1
Function Localization         Function Accuracy, Line Overlap
Verifier Reliability          Reject Rate, False Accept Rate,
                               Mitigation Reject Accuracy
Report Quality                Evidence Grounding, Root Cause,
                               Remediation Usefulness
System Robustness             Tests Passed, ZIP Filtering,
                               PDF Export Success
```

## 8. 제출 전 체크리스트

### README 필수 항목

- 프로젝트 개요
- 시스템 아키텍처
- AI 도구 활용 전략 또는 prompting/development log
- 실행 방법
- Demo command
- 테스트 방법
- 한계 및 향후 과제

### 발표자료 필수 항목

- 최종 시스템 아키텍처
- 핵심 알고리즘
- Live Demo 흐름
- AI/Git 협업 성과
- 한계점 및 향후 과제
- GitHub repository URL

### 코드/데모 체크

```bash
python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m aisec_app.evaluation data/cases
PYTHONPATH=src python3 -m aisec_app.cve_metadata data/cases --json --delay 0
```

Frontend build:

```bash
cd frontend
npm run build
cd ..
```

Backend:

```bash
uvicorn aisec_app.api:app --app-dir src --reload
```

## 8. 발표 Q&A 대비

### Q. 왜 CVE를 확정하지 않고 candidate라고 하나?

ZIP source만으로는 정확한 product version, patch level, build configuration을 완전히 알 수 없기 때문이다. 그래서 NVD는 후보 CVE를 찾는 데 사용하고, 최종 판단은 source evidence와 verifier가 결정한다.

### Q. LLM confidence를 믿을 수 있나?

그대로 믿지 않는다. LLM confidence는 버리고, evidence grounding, dangerous operation, line reference, mitigation 여부를 기준으로 deterministic confidence를 재계산한다.

### Q. 왜 reject가 많은가?

보안 시스템에서는 unsupported finding을 accept하는 것이 더 위험하다. 현재 시스템은 false positive를 줄이기 위해 evidence가 약하거나 mitigation이 있는 경우 reject한다.

### Q. 실제 exploit 가능성까지 판단하나?

현재는 source-level evidence 기반의 취약 가능성 판단이다. exploitability를 더 정확히 판단하려면 PoC input, build artifact, runtime trace, sanitizer result가 추가로 필요하다.

### Q. Fine-tuning은 했나?

최종 구현에서는 fine-tuning보다 evidence-grounded pipeline과 deterministic verifier를 우선했다. 보안 판단에서 더 중요한 것은 모델 성능보다 재현 가능한 근거와 reject policy라고 판단했다.

## 9. 최종 한 줄 피치

> AISEC App은 NVD CVE metadata와 C/C++ source evidence를 연결하고, LLM의 분석 결과를 deterministic verifier로 검증해, 사람이 신뢰할 수 있는 취약점 분석 리포트를 생성하는 AI 보안 에이전트 시스템이다.
