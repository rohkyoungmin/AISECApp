# AISEC App 초기 프로젝트 계획

## 1. 문제 정의

이 프로젝트는 공개된 patch diff와 advisory를 바탕으로, 실제 운영 바이너리가 해당 1-day 취약점에 영향을 받는지 자동으로 탐지하는 것을 목표로 합니다.

제안서 기준 핵심 문제는 다음 두 가지입니다.

- 기존 구문 기반 binary patch matching은 정확하지만 컴파일러 옵션, 인라이닝, 리팩토링 변화에 취약함
- 단일 LLM 접근은 의미적 이해는 가능하지만 hallucination과 근거 부족 때문에 보안 판단에 그대로 쓰기 어려움

따라서 목표는 `의미적 추론`과 `근거 검증`을 동시에 갖춘 binary vulnerability detection pipeline을 만드는 것입니다.

## 2. MVP 범위

### 대상

- Open-source C/C++ binary
- Memory corruption 계열 취약점
- Heap overflow
- Stack overflow
- Use-after-free

### 입력

- 분석 대상 binary metadata
- CVE advisory 요약
- vulnerable/fixed commit 기반 patch diff
- 가능하면 decompiler excerpt 또는 함수 단위 분석 결과

### 출력

- 취약 여부
- 취약 함수 위치
- 근거 문장과 artifact reference
- confidence
- verifier의 통과 여부
- 리포트용 수정 가이드

## 3. 제안 아키텍처

파이프라인은 아래 순서를 따릅니다.

1. `Triage`
   binary 메타데이터와 advisory를 보고 CVE 후보를 좁힙니다.
2. `Patch Analysis`
   patch diff에서 취약 원인과 수정 의도를 추출합니다.
3. `Binary Match`
   디컴파일 결과 또는 함수 특징과 patch pattern을 매칭합니다.
4. `Verification`
   binary 근거와 patch 근거가 모두 있을 때만 결과를 accept합니다.
5. `Report`
   사람이 읽을 수 있는 write-up과 UI용 구조화 결과를 생성합니다.

핵심 원칙은 다음 한 줄로 정리할 수 있습니다.

> 검증되지 않은 LLM 출력은 결과로 채택하지 않는다.

## 4. 왜 지금 이 구조로 시작하는가

초기 단계에서 가장 중요한 것은 UI가 아니라 `실험 가능한 입력/출력 계약`입니다.

먼저 아래 세 가지를 고정해야 나중에 모델이나 도구를 바꿔도 실험이 흔들리지 않습니다.

- CVE 케이스를 표현하는 데이터 구조
- 파이프라인 각 단계의 산출물 형식
- 평가에 필요한 로그와 리포트 스키마

이번 초기 스캐폴드는 바로 그 세 가지를 먼저 만들어두는 방향입니다.

## 5. 1차 구현 우선순위

### Phase 1. 데이터 파이프라인

- Magma 기반 후보 프로그램 선정
- CVE별 vulnerable/fixed binary pair 수집
- patch diff, PoC input, 함수 라벨 정리

### Phase 2. Baseline

- single LLM prompting baseline
- rule-based diff matcher baseline
- 공통 평가 스크립트 준비

### Phase 3. Multi-agent + verifier

- Patch Analysis agent
- Binary Match agent
- Verification layer
- Reporter

### Phase 4. Demo UI

- binary 업로드
- 분석 요청
- 취약 함수/근거/patch write-up 시각화

## 6. 평가 지표

- `Detection F1`: vulnerable/fixed 분류 정확도
- `Function Localization`: 취약 함수 위치 정확도
- `Verifier Reject Rate`: 근거가 약한 결과를 얼마나 잘 걸러내는지
- `Write-up Quality`: 재현 가능성, 근거 충실성, 수정 가이드 유용성

## 7. 바로 다음 액션

프로젝트를 실제로 진행할 때 가장 먼저 해야 할 일은 아래 순서가 좋습니다.

1. Magma 기반으로 3개 프로그램만 먼저 선택합니다.
2. 각 프로그램에서 CVE 1~2개씩 골라 총 5개 내외 샘플 세트를 만듭니다.
3. 이 저장소의 파이프라인 스키마에 맞춰 샘플 케이스를 JSON으로 적재합니다.
4. baseline과 multi-agent가 같은 입력을 쓰도록 고정합니다.
5. 마지막에 UI를 붙여도 늦지 않습니다.

즉, 이 프로젝트의 진짜 시작점은 `웹`보다 `재현 가능한 CVE 케이스셋`입니다.
