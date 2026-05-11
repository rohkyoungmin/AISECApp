# Reporter — 구현 기록

## 개요

기존 AISEC App 프로젝트를 **Reporter**라는 이름의 완성형 보안 분석 플랫폼으로 발전시킨 작업 기록입니다.
프론트엔드 디자인 전면 개편, 멀티 에이전트 파이프라인 최적화, 취약점 검증 정책 강화가 주요 내용입니다.

---

## 1. 디자인 시스템 전면 교체

### 변경 전
- 사이버펑크 다크 테마 (검정 배경, 네온 블루/그린)
- 단순 테이블 기반 레이아웃

### 변경 후
Anthropic Claude.com 스타일의 워밍 크림 캔버스 디자인으로 전면 교체했습니다.

**색상 토큰**

| 토큰 | 값 | 용도 |
|------|-----|------|
| `--canvas` | `#faf9f5` | 페이지 배경 |
| `--surface-card` | `#efe9de` | 카드 배경 |
| `--surface-dark` | `#181715` | 다크 섹션 |
| `--primary` | `#014029` | 브랜드 다크그린 |
| `--ink` | `#141413` | 본문 텍스트 |
| `--muted` | `#6c6a64` | 보조 텍스트 |
| `--error` | `#c64545` | Critical/에러 |
| `--amber` | `#e8a55a` | High |
| `--warning` | `#d4a017` | Medium |
| `--teal` | `#5db8a6` | Low |

**폰트**
- Display: Cormorant Garamond (숫자, 제목)
- Body: Inter (본문)
- Mono: JetBrains Mono (코드)

---

## 2. 페이지별 변경 내용

### HeroPage
히어로 섹션을 좌우 분할(split) 레이아웃으로 재설계했습니다.
- 왼쪽: 앱 소개 카피, 체크리스트, CTA 버튼, 통계 바
- 오른쪽: macOS 스타일 터미널 목업 (실제 분석 결과 예시)
- 아래: The Pipeline (4단계 설명), What's in every report (3개 기능 카드), 다크 CTA 밴드

### ReportPage — 통계 섹션 재구성
기존에 Accepted / Rejected / Files / High / Medium / Low가 같은 레벨로 나열돼 있어 숫자 의미가 불명확했습니다. 두 그룹으로 분리했습니다.

**Findings overview** (3칸 고정 그리드)
- Accepted — confirmed findings (파일당 여러 finding 가능, Files보다 클 수 있음)
- Rejected — filtered by verifier
- Files — source files scanned

**By severity** (accepted findings only)
- Critical / High / Medium / Low별 카운트
- 각 카드 상단에 severity 색상 border
- "accepted findings only" 명시로 Accepted 합계와 일치함을 표시

### ProgressPage
5단계 진행 표시기, 로그 패널, 다크 테마 진행 화면

---

## 3. 멀티 에이전트 파이프라인 최적화

### 변경 전 (파일당 Claude API 3회 호출)
```
ClaudeTriageAgent     → API call 1
ClaudeFindingAgent    → API call 2
ClaudeSkepticVerifier → API call 3
```

### 변경 후 (파일당 Claude API 1회 호출)
```
HeuristicTriageAgent   → 정규식 기반, API 없음
ClaudeFindingAgent     → API call 1 (유지)
EvidencePolicyVerifier → 결정론적 검사, API 없음
```

`ClaudeSourceAnalyzer.__init__`에서 triage와 verify를 교체했습니다.

**HeuristicTriageAgent**: `gets`, `strcpy`, `malloc` 등 위험 API 패턴을 정규식으로 감지해 분석 우선순위를 결정합니다. LLM 없이 빠르게 동작합니다.

**EvidencePolicyVerifier**: Claude가 생성한 finding을 결정론적 규칙으로 검증합니다.

---

## 4. EvidencePolicyVerifier — 검증 정책

### 기본 체크 (모든 severity 공통)
| 체크 항목 | 실패 조건 |
|-----------|-----------|
| evidence_quote 존재 | 빈 문자열 |
| evidence grounded | 소스에서 찾을 수 없음 |
| root_cause 존재 | 빈 문자열 |
| remediation 존재 | 빈 문자열 |
| line_range 유효 | line_start가 소스 범위 초과 |

### Evidence Grounding 알고리즘
Claude가 생성한 `evidence_quote`는 종종 `...`로 중간을 생략하거나 공백이 다릅니다. 단순 substring 매칭으로는 과도하게 reject됩니다.

개선된 알고리즘:
1. `...` / `…` / `[...]` 기준으로 quote를 fragment로 분리
2. 각 fragment (≥8자)가 소스에 있으면 통과
3. 12자 sliding window: fragment 내 임의 12자 구간이 소스에 있으면 통과

### Exploitability Policy (severity별 차등)

| Severity | 최소 confidence | Verdict 요건 | 증거 요건 |
|----------|----------------|-------------|-----------|
| CRITICAL | 70% | VULNERABLE | dangerous op 필수 |
| HIGH | 60% | VULNERABLE | dangerous op 필수 |
| MEDIUM | 50% | VULNERABLE | 없음 |
| LOW | 40% | VULNERABLE / NEEDS_REVIEW | 없음 |

**Dangerous operations** (HIGH/CRITICAL 증거에 필수):
- 무조건 위험: `gets`, `strcpy`, `strcat`, `sprintf`, `vsprintf`
- 조건부 위험: `memcpy`, `malloc`, `recv`, `read`, `scanf`, `free`
- Integer overflow 신호: `int x = a * b` 형태의 산술 연산

**Mitigation 감지**: `strncpy`, `snprintf`, `fgets`, 길이 검사 `if (len < ...)` 등이 증거에 있고 dangerous call이 없으면 HIGH/CRITICAL은 reject — 이미 완화된 코드 패스는 실제 exploitable하지 않다고 판단합니다.

---

## 5. PDF 리포트 재설계

### 변경 전
- 다크 네이비 배경 (`#0a0c18`)
- 네온 청록 악센트
- "AISEC" 브랜딩

### 변경 후
웹 UI 디자인 토큰과 동일한 색상 팔레트 사용

**폰트 (DejaVu 시스템 폰트 임베딩)**
- Body: DejaVu Sans (Inter 대용)
- Display: DejaVu Serif (Cormorant Garamond 대용)
- Code: DejaVu Sans Mono (JetBrains Mono 대용)
- 폴백: Helvetica / Courier (DejaVu 없는 환경)

**레이아웃 구조**
```
[다크그린 헤더 바] Reporter + Security Analysis Report + status badge
[크림 배경]
  프로젝트 메타 정보 (Archive, Project ID, 파일 수 등)
  ─ hairline divider ─
  SUMMARY 섹션
  통계 4칸 (Files / Accepted / Rejected / Skipped)

[파일별 섹션]
  ┌─ 파일명 헤더 바 (카드 배경, 다크그린 left stripe)
  │  파일 요약
  │
  │  [Finding 블록]
  │  Finding 제목 (severity left stripe)
  │  SEVERITY · L{line} · function · confidence%
  │  Root cause: ...
  │  ┌─────────────────────────────────┐
  │  │ code                            │  ← 코드 블록 (카드 배경 + mono)
  │  │ evidence_quote                  │
  │  └─────────────────────────────────┘
  │  Fix: ...
  │  ─ hairline divider ─
```

---

## 6. 파일 변경 목록

| 파일 | 변경 내용 |
|------|-----------|
| `frontend/index.html` | Google Fonts 교체 (Cormorant Garamond + Inter + JetBrains Mono) |
| `frontend/src/global.css` | 디자인 토큰 전면 교체, hero-split 레이아웃, 반응형 |
| `frontend/src/components/Header.tsx` | "Reporter" 로고, top-nav 스타일 |
| `frontend/src/components/StatusBadge.tsx` | 워밍 시맨틱 색상 |
| `frontend/src/pages/HeroPage.tsx` | 분할 레이아웃, 터미널 목업, 섹션 3개 |
| `frontend/src/pages/ProgressPage.tsx` | 5단계 진행 표시기, 다크 로그 패널 |
| `frontend/src/pages/ProjectDetailPage.tsx` | 새 디자인 시스템 적용 |
| `frontend/src/pages/ProjectsPage.tsx` | 새 디자인 시스템 적용 |
| `frontend/src/pages/ReportPage.tsx` | 통계 그룹 분리, severity breakdown |
| `src/aisec_app/source_analysis.py` | ClaudeSourceAnalyzer 최적화, EvidencePolicyVerifier exploitability policy, evidence grounding 개선 |
| `src/aisec_app/report_export.py` | PDF 디자인 전면 교체, DejaVu 폰트 임베딩, 노트 스타일 레이아웃 |
