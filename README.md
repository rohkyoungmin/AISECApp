# Reporter

C/C++ 소스코드의 취약점을 자동으로 탐지하고 PDF 리포트로 출력하는 보안 분석 플랫폼입니다.
Claude AI를 기반으로 한 4단계 멀티 에이전트 파이프라인이 ZIP 아카이브를 받아 취약점 후보를 추출하고, 증거 기반 검증을 거쳐 최종 리포트를 생성합니다.

## 빠른 시작

### 사전 준비

- Python 3.10+
- Node.js 18+
- Anthropic API Key

### 환경 설정

```bash
cp .env.example .env
# .env에 ANTHROPIC_API_KEY 입력
```

### 백엔드 실행

```bash
pip install -e ".[api,llm]"
uvicorn aisec_app.api:app --app-dir src --host 0.0.0.0 --port 8000 --reload
```

### 프론트엔드 실행

```bash
cd frontend
npm install
npm run dev
```

브라우저에서 [http://localhost:5173](http://localhost:5173) 접속

---

API Key 없이 동작 확인만 하려면 `.env`에서 `ALLOW_HEURISTIC=true` 설정 후 분석 시 **Allow heuristic** 옵션을 켜세요.

## 주요 기능

- ZIP 아카이브 업로드 → 자동 C/C++ 파일 추출 및 분석
- 4단계 AI 파이프라인: Extract → Triage → Finding → Verify → Report
- Severity별(Critical / High / Medium / Low) 취약점 분류
- 증거 코드 스니펫 포함 PDF 리포트 자동 생성
- 프로젝트별 분석 히스토리 관리

## 구조

```
src/aisec_app/    백엔드 (FastAPI + 분석 파이프라인)
frontend/         프론트엔드 (React + Vite)
docs/             설계 문서 및 작업 기록
```

상세 아키텍처 및 구현 내용은 [docs/implementation.md](docs/implementation.md)를 참고하세요.
