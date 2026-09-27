# Detection Rule

> 이 문서는 탐지 목적, 필요한 데이터, 초기 로직, 오탐, 튜닝, 운영 검증을 분리해 기록합니다. Threshold는 Case마다 정상·공격 분포를 확인한 뒤 설정합니다.

## Detection Objective

- 탐지하려는 행위: [작성]
- 탐지 시점과 목적: [작성]
- 탐지하지 못하는 범위: [작성]

## Data Source / Required Fields

- 데이터 출처: [작성]
- 필수 필드: [예: timestamp, source entity, destination entity, event type, process, user, domain 등]
- 필드 품질 또는 누락: [확인 필요]

## Detection Logic

자연어로 먼저 작성한 뒤, 사용 환경에 맞는 쿼리·룰 문법을 별도 기록합니다.

1. [조건 1]
2. [조건 2]
3. [상관관계·순서·반복 조건]

예시 문법 또는 SIEM 쿼리: [선택]

## Threshold / Time Window

- Threshold: [Case별 분포 확인 후 작성]
- Time Window: [Case별 시간 패턴 확인 후 작성]
- 설정 근거: [정상·공격 샘플과 비교한 근거]

Threshold와 Time Window는 보편적인 고정 정답으로 복사하지 않습니다. 운영 환경의 정상 트래픽·이벤트 분포를 측정한 뒤 조정합니다.

## Initial Rule

[분석 결과에서 출발한 초기 탐지 로직]

## False Positive

- 예상 정상 행위: [작성]
- 오탐을 확인할 필드: [작성]
- 오탐과 정탐을 구분하는 추가 Evidence: [작성]

## Allowlist / Exception

- 허용할 Entity 또는 조건: [작성 또는 없음]
- 승인 근거: [작성]
- 만료·재검토 조건: [작성]

Allowlist가 탐지 누락을 만들 수 있으므로 범위와 만료 조건을 함께 기록합니다.

## Tuning Strategy

1. [정상 데이터에서 초기 Rule의 발생량 확인]
2. [오탐 사례의 공통 속성 확인]
3. [필드·Threshold·Time Window·예외 조정]
4. [조정 전후 결과 비교]

## Improved Rule

[튜닝 후 룰. 아직 운영 검증 전이면 `[확인 필요]`로 표시]

## Operational Considerations

- Alert에 포함할 정보: [작성]
- 분석가가 확인할 추가 Context: [작성]
- 심각도·에스컬레이션 기준: [작성 또는 확인 필요]
- 유지보수와 재검토 주기: [작성]

## Validation Result

- 검증 데이터 범위: [작성]
- 초기 Alert 결과: [작성 또는 미집계]
- 튜닝 후 결과: [작성 또는 운영 검증 전]
- 최종 False Positive: [작성 또는 확인 필요]
- 남은 한계: [작성]
