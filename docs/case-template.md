# SOC Case Template Index

이 문서는 기존의 단일 Case 템플릿을 대체하는 안내 페이지입니다. 재사용 가능한 원본은 [`templates/`](../templates/) 아래의 여섯 개 파일로 분리해 관리합니다.

## Canonical templates

| 파일 | 역할 |
|---|---|
| [`case-readme-template.md`](../templates/case-readme-template.md) | GitHub 첫 화면용 1분 요약 |
| [`analysis-template.md`](../templates/analysis-template.md) | 상세 분석 과정과 판단 흐름 |
| [`conclusion-template.md`](../templates/conclusion-template.md) | 최종 판단, 한계, 대응 권고 |
| [`detection-rule-template.md`](../templates/detection-rule-template.md) | 탐지 로직, 오탐, 튜닝 기록 |
| [`investigation-notes-template.md`](../templates/investigation-notes-template.md) | 조사 중간 기록과 가설 검증 로그 |
| [`notion-case-template.md`](../templates/notion-case-template.md) | Notion 포트폴리오용 요약 구조 |

## 공통 형식과 Case별 유연성

모든 Case는 Overview, Objective, Evidence, Assessment, MITRE ATT&CK, False Positive, Detection, Response, Lessons Learned를 공통 축으로 사용합니다.

다음 내용은 Case 유형에 따라 달라질 수 있습니다.

- 데이터와 로그 형식
- 후보 선정 기준과 핵심 Entity
- 세부 분석 단계
- 필터와 쿼리
- IOC와 Evidence 종류
- Threshold와 Time Window

Source/Destination은 네트워크 Case에서 선택적으로 사용하고, 다른 Case에서는 User, Process, Host, Domain, File 등 실제 분석 대상에 맞는 Entity로 바꿉니다.

## 새 Case 시작 방법

1. `cases/case-XX/` 아래에 Case 디렉터리를 만듭니다.
2. 여섯 개 템플릿을 Case의 README, 분석, 결론, 탐지, 메모, Notion 초안으로 복사합니다.
3. 실제로 확인한 내용만 채우고, 확인하지 못한 값은 `[확인 필요]` 또는 `[작성]`으로 남깁니다.
4. GitHub에는 명령어, 필터, 긴 로그, 재현 절차를 기록하고 Notion에는 판단 과정과 대표 Evidence만 옮깁니다.
5. Case 유형에 맞지 않는 섹션은 삭제하거나 선택 항목으로 표시하되, 공통 판단 축은 유지합니다.

## 현재 저장소의 상세 산출물 경로

Case별로 다음 경로를 필요에 따라 사용합니다.

- `analysis.md`
- `conclusion.md`
- `ioc.csv`
- `notes/investigation-notes.md`
- `detection/detection-rule.md`
- `detection/` 아래의 필터·쿼리 문서
- `references/` 아래의 참고자료
- `evidence/` 아래의 원본 및 Screenshot

이 인덱스에는 특정 Case의 IP, Dataset, 포트, 패킷 수, 시간값, Screenshot 이름을 기록하지 않습니다.
