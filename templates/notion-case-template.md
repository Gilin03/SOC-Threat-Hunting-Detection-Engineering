# Case XX · [Title]

> Notion은 채용 담당자가 빠르게 읽을 수 있는 요약과 판단 중심으로 작성합니다. 명령어, 긴 로그, 전체 재현 절차는 GitHub에 두고 핵심 Evidence와 판단 근거만 연결합니다.

## 한눈에 보는 Case

| 항목 | 내용 |
|---|---|
| Case ID | `CASE-XX` |
| Dataset 또는 로그 출처 | [작성] |
| Data Type | [작성] |
| Key Entity | [선택: Source/Destination, User, Process, Host, Domain, File 등] |
| Key Finding | [작성] |
| Assessment | [작성] |
| MITRE ATT&CK | [작성 또는 확인 필요] |
| Status | [작성] |

## 분석 목표

[무엇을 확인하려는지 2~3문장으로 작성]

## 핵심 발견

- [직접 확인한 핵심 사실 1]
- [직접 확인한 핵심 사실 2]
- [최종 판단을 지지하는 사실 3]

## 분석 흐름

[왜 다음 분석 단계로 넘어갔는지 보이도록 3~7단계로 요약]

## 핵심 Evidence

3~5개의 핵심 Evidence만 배치합니다.

### E## — [Evidence 제목]

![Evidence](evidence/screenshots/대표-evidence.png)

- 무엇을 보여주는가: [작성]
- 무엇을 확인했는가: [작성]
- 왜 중요한가: [최종 판단과 연결]

## 상세 분석

Case 유형에 맞는 하위 섹션만 선택합니다.

### [네트워크 / 인증 / 프로세스 / DNS·HTTP / 파일 등]

- 분석 이유: [작성]
- 관찰 결과: [작성]
- 판단: [작성]
- Evidence: [작성]

## 최종 판단

- Observation: [직접 관찰한 사실]
- Assessment: [분석 판단]
- Confirmed Fact: [직접 검증된 범위]
- Limitations: [확인하지 못한 내용]

## MITRE ATT&CK

| Technique ID | Technique Name | 적용 근거 |
|---|---|---|
| [작성] | [작성] | [핵심 Evidence와 연결] |

매핑은 관찰된 행위의 성격을 설명하는 근거이며, 매핑만으로 공격 성공이나 악성 의도를 확정하지 않습니다.

## Detection Rule

- 탐지 목표: [작성]
- 핵심 조건: [작성]
- Threshold / Time Window: [Case별 정상·공격 분포 확인 후 작성]
- 필수 필드: [작성]
- 운영 검증 상태: [작성 또는 확인 필요]

## False Positive / Tuning

- 가능한 정상 행위: [작성]
- Allowlist / 예외: [작성 또는 확인 필요]
- 튜닝 방향: [작성]

## Response

- 확인할 Entity와 소유자: [작성]
- 승인된 정상 행위 여부: [작성]
- 비인가 또는 후속 이상행위 시 권고: [작성]

실제로 수행한 조치와 권고사항을 구분합니다.

## Lessons Learned

- [판단 기준]
- [분석 과정에서 배운 점]
- [다음 Case에 재사용할 절차]

## GitHub 상세 분석 링크

- [상세 분석](analysis.md)
- [최종 결론](conclusion.md)
- [IOC](ioc.csv)
- [조사 메모](notes/investigation-notes.md)
- [Detection Rule](detection/detection-rule.md)
- [필터·쿼리 문서](detection/filters-or-queries.md)
- [참고자료](references/sources.md)

## 공통 형식과 Case별 유연성

- 공통으로 고정할 것: Overview, Objective, Evidence, Assessment, MITRE, False Positive, Detection, Response, Lessons Learned
- Case별로 바꿀 것: 분석 데이터, 후보 선정 기준, 세부 분석 단계, 필터·쿼리, IOC, Threshold, Evidence 종류
- 예시: 네트워크는 흐름·포트·플래그, 인증은 실패 로그인·계정·빈도, Endpoint는 프로세스·부모 프로세스·명령줄, C2는 DNS·HTTP·주기성 등으로 확장합니다.
