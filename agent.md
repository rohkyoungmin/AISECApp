# AISEC App Automation Agent Instructions

You are the coding agent for this repository.

Working directory:

```text
/root/projects/2026/AISECApp
```

Before making changes, read this file and then read:

```text
docs/final-demo-day-direction.md
README.md
docs/implementation-log.md
```

The immediate goal is not planning. The immediate goal is to implement the remaining backend/evaluation work as quickly and safely as possible, then run real evaluation and write the evaluation artifacts.

Do not stop at a proposal unless blocked by a missing credential, unavailable dependency, or a failing external service that cannot be worked around.

## Current Priority

Frontend work comes later.

For this stage, do not modify frontend files unless explicitly requested after the evaluation artifacts exist.

Priority order:

1. Implement missing backend/evaluation pieces.
2. Run full deterministic/baseline Magma evaluation.
3. Run cost-limited LLM evaluation only on representative samples.
4. Generate `output/evaluation/evaluation.json`.
5. Generate `output/evaluation/evaluation.md`.
6. Update README and implementation log only if needed to explain how to reproduce the evaluation.
7. Stop and report results.

## Final System Direction

```text
Open-source ZIP Upload
  -> Extract C/C++ Files
  -> NVD CVE Candidate Mapping
  -> AI/heuristic Finding
  -> Deterministic Confidence Calibration
  -> Evidence-grounded Verifier
  -> JSON/Markdown/PDF Report
  -> Evaluation Report
```

## Non-Negotiable Evaluation Principle

Magma is ground truth for scoring, not evidence input for the analyzer.

Do not feed these into the analyzer:

- Magma patch-derived handcrafted evidence
- vulnerable function label
- vulnerable address label
- expected verdict label
- answer-line decompiler excerpts that reveal the ground truth

Allowed use of Magma data:

- loading cases
- counting cases
- scoring after analysis
- expected verdict/function during evaluation only
- completed/skeleton readiness classification

Fair evaluation flow:

```text
Magma vulnerable/fixed source or artifact
  -> ZIP/source input only
  -> NVD candidate mapping
  -> analyzer creates evidence itself
  -> verifier accept/reject
  -> compare output against Magma ground truth labels
```

## Evaluation Strategy

Run two layers of evaluation.

### 1. Full Magma Sweep

Run this over all available Magma cases without LLM API cost.

Report:

- total case count
- load success/failure count
- skeleton/completed or completed-like count if detectable
- baseline detection accuracy
- function localization accuracy
- verifier `pass` / `reject` / `needs_review` distribution
- clear warning that skeleton baseline is not completed-Magma detection performance

Important wording:

> Magma itself is a ground-truth benchmark, so completed Magma cases should achieve high detection performance. However, the currently imported repository cases are mostly source-level skeletons, so full 139-case baseline results measure contract readiness and strict verifier behavior, not final completed-Magma performance.

### 2. Cost-Limited LLM Evaluation

Do not run the LLM over all Magma cases.

Default maximum LLM API calls: `3`.

Representative sample priority:

1. NVD-linked OpenSSL case
2. demo vulnerable sample
3. mitigation/reject synthetic sample

Rules:

- Add a CLI option `--max-llm-calls`, default `3`.
- If `ANTHROPIC_API_KEY` is missing, skip LLM evaluation and record `not run: API key missing`.
- Save every LLM sample result under:

```text
output/evaluation/ai_sample_reports/{sample_id}.json
```

- If a cached sample report already exists, reuse it and do not call the API again.
- Never call the AI API for all 139 Magma cases.
- Record API call count and cache usage in `evaluation.md`.

## Required Evaluation CLI

Add or complete:

```bash
PYTHONPATH=src python3 -m aisec_app.final_evaluation --output-dir output/evaluation --max-llm-calls 3
```

The command must create:

```text
output/evaluation/evaluation.json
output/evaluation/evaluation.md
```

Optional cached LLM outputs:

```text
output/evaluation/ai_sample_reports/*.json
```

## Required Evaluation Sections

`evaluation.json` and `evaluation.md` must include these sections.

### A. Dataset Contract Evaluation

- `data/cases` load success count
- load failure count and failure messages, if any
- Magma case count
- demo case count
- skeleton/completed classification if detectable

### B. Full Magma Sweep

- detection accuracy
- function localization accuracy
- verifier status distribution
- case count
- explanation that this is deterministic/baseline over skeleton-inclusive cases

### C. NVD Metadata Evaluation

- cases with discovered CVE IDs
- NVD metadata success count
- linked CVE list
- CWE/CVSS/reference presence
- NVD failure or fallback state

### D. Verifier Reliability Evaluation

Use synthetic fixtures and existing verifier behavior.

Must include:

- ungrounded evidence reject
- invalid line reference reject
- mitigation nearby reject
- deterministic confidence consistency

Each should produce pass/fail and a short rationale.

### E. System Robustness Evaluation

- unittest result
- ZIP filtering/path traversal behavior
- report export behavior
- no frontend build required in this stage

### F. Cost-Limited LLM Evaluation

- API key present/missing
- max allowed calls
- actual calls
- cache hits
- sample IDs
- accepted finding count
- rejected finding count
- model name if available

### G. Completed Magma Evaluation Readiness

- completed or completed-like case count if detectable
- skeleton count if detectable
- what is not measurable yet
- explicit note that Magma patch evidence was not used as analyzer input

## Verification Commands

Run these commands before stopping, as far as the environment allows.

```bash
python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m aisec_app.evaluation data/cases
PYTHONPATH=src python3 -m aisec_app.cve_metadata data/cases --json --delay 0
PYTHONPATH=src python3 -m aisec_app.final_evaluation --output-dir output/evaluation --max-llm-calls 3
```

If one command fails, fix the cause if it is in scope. If it cannot be fixed quickly because of a missing external service or credential, record the reason in `evaluation.md`.

## Stop Conditions

Stop only when:

- `output/evaluation/evaluation.json` exists
- `output/evaluation/evaluation.md` exists
- unit tests have been run
- full deterministic Magma sweep has been run
- LLM evaluation has either run within the call limit or been explicitly skipped/cached
- README/implementation log are updated if needed

If there is a hard blocker, stop only after writing a clear blocker note and partial evaluation output.

## Strict Safety Rules

Do not run destructive commands:

- `git reset --hard`
- `git checkout --`
- `rm -rf`

Do not:

- delete or regenerate all of `data/cases`
- loosen verifier rules just to improve metrics
- hide failing tests
- claim skeleton baseline is completed-Magma detection performance
- spend API calls on the full dataset
- modify frontend files in this stage

If the working tree contains unrelated changes, preserve them.

## Final Response Required

When finished, report:

1. Changed files
2. Generated evaluation artifact paths
3. Full Magma Sweep actual results
4. Cost-limited LLM Evaluation result and API call count
5. NVD Metadata evaluation result
6. Verifier Reliability evaluation result
7. Verification commands and outcomes
8. Demo Day summary sentences ready to paste into slides
