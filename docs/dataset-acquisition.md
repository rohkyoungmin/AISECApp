# Dataset Acquisition Plan

이 프로젝트의 실제 데이터는 하나의 완성된 데이터셋을 그대로 받는 방식이 아니라, 여러 원천을 조합해 `data/cases/{case_id}/` 구조로 정리한다.

## Primary Source: Magma

우선순위 1순위는 Magma benchmark이다.

Magma는 실제 open-source library의 과거 보안 버그를 최신 target에 front-port하고, ground-truth bug reached/triggered 정보를 수집할 수 있게 instrumentation을 제공한다.

초기 후보 target:

- libpng
- libsndfile
- libtiff
- libxml2
- lua
- poppler
- openssl
- sqlite3
- php

가져올 항목:

- target project
- bug identifier
- vulnerable/fixed behavior
- patch or bug injection diff
- build script
- PoV/PoC input이 있으면 함께 저장

프로젝트에서 필요한 변환:

- Magma target/bug 정보를 `manifest.json`으로 정리
- patch 정보를 `patch.diff`로 저장
- vulnerable/fixed build 결과를 각각 `vulnerable/binary`, `fixed/binary`에 저장
- decompiler나 static analysis 결과를 `vulnerable/decompiler.txt`, `fixed/decompiler.txt`로 저장

## CVE Metadata Source: NVD

CVE 설명, CWE, severity, reference URL은 NVD CVE API에서 가져온다.

사용 방식:

```text
https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={CVE-ID}
```

가져올 항목:

- CVE description
- CWE
- CVSS score
- published / last modified date
- references

주의:

- NVD는 advisory metadata용으로 사용한다.
- 실제 patch diff와 vulnerable/fixed commit은 upstream repository에서 확인한다.

## Patch Source: Upstream Repository

patch diff는 가능하면 해당 project의 upstream Git repository에서 가져온다.

가져올 항목:

- vulnerable commit
- fixed commit
- patch commit
- changed function
- regression test나 PoC가 있으면 함께 저장

Magma를 사용할 경우에는 Magma가 제공하는 bug/fix patch를 먼저 사용하고, 필요하면 upstream CVE reference와 연결한다.

## Advisory Source: GitHub Advisory Database

GitHub-originated advisory나 open-source package advisory는 GitHub Advisory Database를 보조 출처로 사용한다.

가져올 항목:

- GHSA ID
- linked CVE
- affected package/version
- patched version
- references

## Initial Collection Strategy

처음부터 15~20개 CVE를 수집하지 않는다.

1. Magma target 중 하나를 고른다.
2. PoV/PoC 또는 재현 정보가 있는 bug를 우선 선택한다.
3. 1개 case를 우리 `manifest.json` schema로 변환한다.
4. pipeline/evaluation이 돌아가는지 확인한다.
5. 같은 방식으로 3~5개까지 늘린다.

## Case Completion Criteria

하나의 실제 case는 아래 항목이 있어야 완료로 본다.

- `manifest.json`
- `advisory.txt`
- `patch.diff`
- `vulnerable/binary`
- `fixed/binary`
- `vulnerable/decompiler.txt`
- `fixed/decompiler.txt`
- 정답 label:
  - expected verdict
  - vulnerable function
  - vulnerable address, 가능할 때만

## References

- Magma homepage: https://hexhive.epfl.ch/magma/
- Magma GitHub repository: https://github.com/HexHive/magma
- NVD CVE API documentation: https://nvd.nist.gov/developers/vulnerabilities
- GitHub Advisory Database: https://github.com/advisories
