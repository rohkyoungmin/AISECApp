# Dataset Layout

초기에는 Magma 기반 CVE 샘플을 아래 구조로 정리하는 것을 권장합니다.

```text
data/
  cases/
    CVE-2021-XXXX/
      manifest.json
      advisory.txt
      patch.diff
      vulnerable/
        binary
        decompiler.txt
      fixed/
        binary
        decompiler.txt
      poc/
        input.bin
```

## manifest.json에 넣을 필드 예시

- `case_id`
- `cve_id`
- `project`
- `language`
- `binary_arch`
- `compiler`
- `optimization`
- `vulnerable_function`
- `vulnerable_binary_path`
- `fixed_binary_path`
- `patch_diff_path`
- `advisory_path`
- `poc_path`

## 첫 수집 목표

- 프로그램 3개
- CVE 총 5개 내외
- 각 CVE마다 vulnerable/fixed binary pair 확보
- 함수 단위 라벨 최소 1개 이상

이 구조만 먼저 통일해도 baseline, multi-agent, verifier가 같은 입력을 공유할 수 있습니다.
