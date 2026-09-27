# TCP SYN Port Scan 탐지 규칙 설계

이번 Case에서 확인한 패턴을 운영 탐지로 일반화하기 위한 초기 설계입니다. 아래 기준은 실험 기반 시작점이며, 운영환경에 바로 적용하기 전에 정상 트래픽과 승인된 점검을 기준으로 검증·튜닝해야 합니다.

## Detection Objective

동일한 Source가 동일한 Destination에 짧은 시간 동안 여러 TCP 목적지 포트로 SYN을 전송하는 포트 탐색 후보를 식별합니다. 탐지 결과는 정찰 후보 이벤트이며, 그 자체로 악성 또는 후속 침해를 확정하지 않습니다.

## Detection Logic

다음 조건을 하나의 집계 키로 묶습니다.

1. `src_ip`와 `dst_ip`가 동일한 흐름
2. TCP SYN 플래그가 설정되고 ACK 플래그가 설정되지 않음
3. 관찰 시간 범위가 60초 이내
4. 서로 다른 `dst_port`가 100개 이상
5. 승인된 스캐너 Source는 allowlist 정책에 따라 별도 처리

SYN/ACK 또는 RST/ACK 응답은 탐지 조건의 필수값은 아니지만, 열린 포트 후보·닫힌 포트 후보와 Half-open 패턴을 설명하는 보조 필드로 수집하는 것이 좋습니다.

## Required Fields

- `timestamp`: 이벤트 시간
- `src_ip`: 관찰된 Source IP
- `dst_ip`: Destination IP
- `dst_port`: TCP 목적지 포트
- `protocol`: TCP 여부
- `tcp_flags`: SYN/ACK/RST 등 TCP 플래그
- `asset_id` 또는 자산 메타데이터: Source·Destination 자산 식별용
- `scanner_allowlist_match`: 승인된 스캐너 여부
- 가능하면 `src_mac`, NAT/방화벽 로그의 원본 주소, 사용자·호스트 정보

## Threshold

- 초기값: **서로 다른 Destination Port 100개 이상**
- 근거: 이번 Case에서 관찰된 999개 Unique Port 패턴을 운영 탐지 후보로 일반화하기 위한 실험 기반 시작값
- 주의: 100은 보편적인 악성 기준이 아니며, 환경별 정상 점검 범위에 따라 오탐이 발생할 수 있음

## Time Window

- 초기값: **60초**
- 집계 기준: 동일 `src_ip` + 동일 `dst_ip` 조합
- 구현 시 슬라이딩 윈도우 또는 고정 윈도우 여부를 운영 플랫폼에 맞게 결정

## False Positives

다음 정상 행위가 유사한 이벤트를 만들 수 있습니다.

- 승인된 취약점 스캐너
- Nmap 기반 내부 점검
- Nessus 등 보안 점검 도구
- 정기 네트워크 자산 점검
- 관리자 승인 테스트 또는 변경 작업

단순한 Port Scan 이벤트만으로 악성 의도를 확정하지 않고, Source 자산의 역할과 승인된 작업 여부를 함께 확인해야 합니다.

## Allowlist

allowlist는 IP 문자열만 고정해 두기보다 다음 정보를 함께 관리하는 것을 권장합니다.

- 승인된 스캐너 Source IP 또는 자산 ID
- 스캐너 소유 팀과 담당자
- 허용된 대상 범위
- 허용된 점검 시간대
- 승인 티켓 또는 변경 기록
- 만료일과 재검토 주기

허용 범위를 벗어난 Destination, 시간대 또는 포트 수가 관찰되면 allowlist 일치만으로 이벤트를 완전히 무시하지 않고 검토 대상으로 남길 수 있습니다.

## Tuning

- 서버·네트워크 장비 역할별로 정상적인 포트 탐색 패턴을 측정합니다.
- 내부 자산 점검과 외부 경계 구간을 구분해 threshold를 별도로 검토합니다.
- `dst_ip`별 포트 다양성뿐 아니라 짧은 시간의 SYN 비율과 RST/SYN-ACK 응답 분포를 보조 신호로 사용합니다.
- NAT 또는 방화벽으로 Source가 대표 주소로 보이는 환경에서는 원본 로그와 자산 매핑을 결합합니다.
- 초기 적용 후 알림량, 승인 작업 적중률, 미승인 스캔 탐지 사례를 확인해 100개·60초 값을 조정합니다.

## Example pseudo rule

```text
WHEN protocol == "TCP"
  AND tcp.syn == 1
  AND tcp.ack == 0
GROUP BY src_ip, dst_ip
WITHIN 60 seconds
HAVING COUNT(DISTINCT dst_port) >= 100
  AND scanner_allowlist_match != true
THEN alert("Possible TCP SYN / Half-open Port Scan")
```

응답 패턴을 보조 조건으로 추가하는 예시는 다음과 같습니다.

```text
ENRICH alert WITH
  COUNT(dst_port WHERE response_flags CONTAINS "SYN,ACK") AS open_port_candidates,
  COUNT(dst_port WHERE response_flags CONTAINS "RST") AS closed_port_candidates
```

위 의사 규칙은 특정 SIEM 또는 IDS 문법이 아니며, 운영 플랫폼의 실제 필드명과 상관분석 문법에 맞춰 변환해야 합니다.

## Operational Considerations

- 이 규칙은 정찰 후보를 생성하며, 실제 외부 주체 식별이나 후속 침해를 의미하지 않습니다.
- Source IP를 실제 외부 공격자 주소로 단정하지 말고 NAT·방화벽·프록시 구조를 확인합니다.
- 알림 발생 후 Source 자산 식별, 승인 스캐너 여부, 작업 시간대, 변경 기록을 우선 확인합니다.
- 비인가 Source이면 차단 또는 접근 제한을 검토하고, 대상 서버의 열린 포트 필요성과 접근 제어를 점검합니다.
- 동일 Source의 후속 공격 로그와 다른 내부 시스템 대상 스캔을 함께 조사합니다.
- 운영 적용 전에는 이번 Case의 Evidence([E05](../evidence/screenshots/05-unique-port-ranking.png), [E06](../evidence/screenshots/06-suspected-scan-target.png), [E14](../evidence/screenshots/14-syn-scan-half-open-pattern.png))와 동일한 신호가 재현되는지 검증합니다.
