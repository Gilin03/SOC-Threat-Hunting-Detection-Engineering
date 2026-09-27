# CASE-XX 기술 분석 보고서

> 상세 분석에서는 결과보다 판단 흐름을 남깁니다. 각 주요 섹션에 가능하면 `왜 확인했는가 → 무엇을 확인했는가 → 어떻게 판단했는가 → Evidence`를 기록합니다.

## 1. Case Overview

| 항목 | 내용 |
|---|---|
| Case ID | `CASE-XX` |
| Case 제목 | [작성] |
| 데이터 유형 | [PCAP / 인증 로그 / Endpoint 로그 / 기타] |
| 분석 상태 | [작성] |
| 분석 기간 | [작성 또는 확인 필요] |
| 핵심 Entity | [선택: Source/Destination, User, Process, Host, Domain, File 등] |

## 2. Objective

### 분석 질문

- [무엇을 확인하려는가]
- [무엇은 이번 범위에서 확인하지 않는가]

### 성공 기준

- [판단에 필요한 직접 Evidence]
- [정상 행위와 비교할 기준]

## 3. Data Source

- 출처: [작성]
- 파일 또는 로그명: [작성]
- 데이터 범위: [작성]
- 수집·다운로드 시각: [확인 필요]
- 파일 크기 또는 이벤트 규모: [작성 또는 확인 필요]
- 해시·버전·환경 정보: [작성 또는 확인 필요]

## 4. Analysis Strategy

### 왜 이 순서로 분석했는가

[데이터 규모와 분석 목표를 고려해 범위를 좁힌 이유]

### 분석 단계

1. [초기 범위와 데이터 품질 확인]
2. [후보를 좁힌 기준]
3. [시간·빈도·관계 또는 속성 비교]
4. [상세 Evidence 검증]
5. [최종 판단과 한계 기록]

## 5. Initial Observation

### 왜 확인했는가

[초기 상태를 확인한 이유]

### 확인한 내용

[직접 관찰한 사실만 작성]

### 초기 가설

[가설 또는 미확정 상태를 구분해 작성]

## 6. Candidate Identification

### 왜 확인했는가

[Source, User, Process, Host, Domain, File 등 후보를 선정할 필요]

### 후보 선정 기준

- Entity: [선택]
- 필드 또는 속성: [작성]
- 비교 기준: [작성]
- 제외 기준: [작성]

### 확인한 내용과 판단

[어떤 후보가 남았고, 다음 단계로 넘어간 이유]

Evidence: [E## 또는 경로]

## 7. Pattern / Timeline Analysis

### 분석 대상

[시간대, 빈도, 반복, 분포, 관계 중 해당 항목 선택]

### 확인한 내용

[관찰된 시간·빈도·반복·분포·관계]

### 판단

[정상 기준과 비교한 해석]

Evidence: [E## 또는 경로]

## 8. Detailed Evidence Analysis

Case에 맞는 하위 섹션만 선택해 사용합니다. 예: Network Packet Analysis, Authentication Analysis, Process Analysis, Command Line Analysis, DNS Analysis, HTTP Analysis, File Analysis.

### [Case별 세부 분석 제목]

#### 확인 이유

[왜 이 세부 항목을 확인했는가]

#### 확인한 내용

[필터, 쿼리, 명령어 결과 또는 로그·패킷 관찰]

#### 판단

[관찰 사실에서 도출한 판단]

#### Evidence

[Screenshot, 로그 범위, 패킷 번호, 이벤트 ID 또는 기타 재현 가능한 근거]

## 9. Validation and Scope

### 직접 확인한 것

- [작성]

### 확인하지 못한 것

- [작성]

### 추정하지 않은 것

- [공격자·사용자·프로세스의 실제 주체 등 확인되지 않은 속성]

최종 판단은 직접 확인한 데이터와 범위 안에서만 작성합니다.

## 10. MITRE ATT&CK Mapping

| Technique ID | Technique Name | 적용 근거 |
|---|---|---|
| [작성] | [작성] | [관찰된 Evidence와 연결] |

ATT&CK 매핑은 관찰된 행위의 성격을 설명하는 용도로 사용하며, 매핑만으로 공격 성공이나 악성 의도를 확정하지 않습니다.

## 11. False Positive Analysis

### 가능한 정상 원인

- [작성]

### 구분에 필요한 추가 확인

- [자산·계정·변경·승인·운영 맥락 등]

### 현재 판단의 한계

[정상 행위를 배제했는지 여부와 근거]

## 12. Detection Engineering

- 탐지 목표: [작성]
- 필요한 필드: [작성]
- 초기 로직: [작성]
- Threshold / Time Window: [Case별 정상·공격 분포 확인 후 작성]
- Allowlist / 예외: [작성 또는 확인 필요]
- 튜닝 계획: [작성]

고정 숫자를 보편적인 정답으로 사용하지 않습니다. Threshold는 해당 Case의 정상 트래픽 또는 이벤트 분포를 확인한 뒤 정하고 운영 검증으로 조정합니다.

상세 규칙은 `detection/detection-rule.md`에 기록합니다.

## 13. Response Recommendation

이번 분석에서 실제로 수행한 조치와 향후 권고를 구분합니다.

1. [자산·계정·프로세스·도메인 등 핵심 Entity 확인]
2. [승인된 정상 행위 여부 확인]
3. [비인가 또는 추가 이상행위가 확인될 때의 제한·차단 검토]
4. [후속 로그와 주변 시스템 조사]

## 14. Lessons Learned

- 판단에 가장 유용했던 기준: [작성]
- 분석에서 제외하거나 보류한 내용: [작성]
- 다음 Case에 재사용할 절차: [작성]
- 개선할 점: [작성]

## Case별 유연성 가이드

- 고정할 것: Overview, Objective, Evidence, Assessment, MITRE, False Positive, Detection, Response, Lessons Learned
- 바꿀 것: 데이터, 후보 선정 기준, 세부 분석 단계, 필터·쿼리, IOC, Threshold, Evidence 종류
- 예시 방향: 네트워크는 흐름·포트·플래그, 인증은 실패 로그인·계정·빈도, Endpoint는 프로세스·부모 프로세스·명령줄, C2는 DNS·HTTP·주기성 등으로 확장합니다.
