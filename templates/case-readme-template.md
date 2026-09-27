# CASE-XX: [Case Title]

> GitHub에서 처음 보는 사람이 Case의 범위, 핵심 Evidence, 최종 판단을 빠르게 이해할 수 있도록 작성합니다. 긴 명령어와 원본 로그는 상세 문서로 분리합니다.

## Case 요약

| 항목 | 내용 |
|---|---|
| Case ID | `CASE-XX` |
| 주제 | [작성] |
| Dataset 또는 로그 출처 | [작성] |
| 데이터 유형 | [PCAP / 인증 로그 / Endpoint 로그 / 기타] |
| 분석 도구 | [작성] |
| 분석 상태 | [작성] |
| 주요 Entity | [선택: Source/Destination, User, Process, Host, Domain, File 등] |
| 최종 판단 | [작성 또는 확인 필요] |

## 대표 이미지

<!-- Case를 가장 잘 보여주는 Evidence 1개만 선택합니다. -->

![대표 Evidence](evidence/screenshots/대표-evidence.png)

[이 이미지가 보여주는 내용과 최종 판단에서 중요한 이유를 1~2문장으로 작성]

## 분석 목표

- [이번 Case에서 확인하려는 질문]
- [분석 범위와 제외 범위]

## 데이터와 분석 흐름

[어떤 데이터에서 시작해 어떤 기준으로 범위를 좁혔는지 요약]

## 핵심 발견

- [관찰된 사실 1]
- [관찰된 사실 2]
- [관찰된 사실 3]

## 핵심 증거

| Evidence | 확인 내용 | 판단에서의 역할 |
|---|---|---|
| [E01] | [무엇을 확인했는가] | [왜 중요한가] |
| [E02] | [무엇을 확인했는가] | [왜 중요한가] |
| [E03] | [무엇을 확인했는가] | [왜 중요한가] |

Case에 직접 사용한 핵심 Evidence만 남기고, 전체 자료는 `evidence/`에 보관합니다.

## MITRE ATT&CK

| Technique ID | Technique Name | 적용 근거 |
|---|---|---|
| [작성] | [작성] | [관찰된 Evidence와 연결] |

## Detection Rule 요약

- 탐지 목표: [작성]
- 핵심 조건: [Case별 필드와 관계를 작성]
- Threshold / Time Window: [Case별 정상·공격 분포를 확인한 뒤 작성]
- Allowlist / 예외: [작성 또는 확인 필요]

## 최종 판단

- Observation: [직접 관찰한 사실]
- Assessment: [관찰 사실에 대한 분석 판단]
- Confirmed Fact: [직접 검증된 범위]
- Limitations: [확인하지 못한 내용]

## 상세 문서

- [상세 기술 분석](analysis.md)
- [최종 결론](conclusion.md)
- [IOC 목록](ioc.csv)
- [조사 메모](notes/investigation-notes.md)
- [탐지 규칙](detection/detection-rule.md)
- [필터·쿼리 문서](detection/filters-or-queries.md)
- [참고자료](references/sources.md)

## 공통 형식과 Case별 유연성

형식은 일정하게 유지하되, 분석 내용은 공격 유형과 데이터에 맞게 바꿉니다.

- 공통: Overview, Objective, Evidence, Assessment, MITRE, False Positive, Detection, Response, Lessons Learned
- 가변: 데이터, 후보 선정 기준, 세부 분석 단계, 필터·쿼리, IOC, Threshold, Evidence 종류
- 주요 Entity는 Case에 맞게 Source/Destination, User, Process, Host, Domain, File 등으로 선택합니다.
