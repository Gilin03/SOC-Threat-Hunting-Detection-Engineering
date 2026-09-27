# 참고자료

## Dataset

- [Dataset Specification: SSH Interactive Honeypot Logs](dataset-README.md)
- 사용 데이터: `raw/ssh_attacks_full.csv`
- 데이터셋 문서에 기록된 전체 규모: 145,425 events
- 사용 목적: 데이터 출처, 컬럼 의미, 수집 범위 및 Honeypot 환경 설명
- 주의: Dataset 문서와 CSV의 실제 이벤트를 구분하고, 본 Case의 판단은 저장소에 있는 CSV와 Evidence에 한정합니다.

## MITRE ATT&CK

- [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
- [T1059.004 Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
- [T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- 실제 유효 계정 사용이 확인되지 않아 Valid Account 계열 매핑은 Case 02에서 제외했습니다.

## Evidence

- [Evidence screenshots](../evidence/screenshots/)
- 핵심 Evidence: E03, E06, E10, E13, E15, E18
- Evidence 링크는 실제 저장된 파일명 기준으로 작성했습니다.

## 참고 범위

이 문서에 기록한 분석 결과는 외부 자료의 일반론이 아니라 `ssh_attacks_full.csv`, `dataset-README.md`, Case 02 Evidence 및 분석 메모에서 확인한 내용에 기반합니다.
