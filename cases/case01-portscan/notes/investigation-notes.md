# CASE-01 Investigation Notes

실제 분석 흐름을 시간순 순서로 정리한 조사 메모입니다. 분석 수행 시각 자체는 기록된 근거가 없어 단계 번호로 표시합니다.

## 기록 규칙

- 관찰 사실과 해석을 분리합니다.
- `172.16.0.1`은 “관찰된 Source”로만 표현합니다.
- Port Scan 관찰과 악성·침해 확정을 구분합니다.
- Evidence는 실제 저장된 스크린샷 파일에 연결합니다.

## Step 01 — 전체 PCAP 로드

- 수행 내용: Wireshark로 `Friday-WorkingHours.pcap` 확인
- 관찰한 사실: 약 1천만 패킷 규모의 대용량 PCAP이며 화면 하단에 9,997,874개 패킷이 표시됨
- 해석: 전체 파일을 직접 상세 분석하면 작업 부담이 크므로 1차 집계가 필요함
- 다음 작업: Endpoint와 Conversation 통계 확인
- Evidence: [E01](../evidence/screenshots/01-pcap-overview.png)

## Step 02 — IPv4 Endpoints 확인

- 수행 내용: IPv4 Endpoint 통계 확인
- 관찰한 사실: 다수의 IPv4 Endpoint와 트래픽 분포가 보임
- 해석: 통신 주체 후보를 파악할 수 있으나, 패킷 수가 많은 IP만으로 Port Scan을 판별할 수 없음
- 다음 작업: TCP Conversation 확인
- Evidence: [E02](../evidence/screenshots/02-ipv4-endpoints.png)

## Step 03 — TCP Conversations 확인

- 수행 내용: TCP Conversation 통계 확인
- 관찰한 사실: 상위 대화에 80/443과 같은 일반 서비스 통신이 많이 보임
- 해석: 대화량만으로 정상 서비스 통신과 포트 스캔을 분리하기 어려움
- 다음 작업: SYN과 목적지 포트 다양성을 기준으로 분석 방향 변경
- Evidence: [E03](../evidence/screenshots/03-tcp-conversations-overview.png)

## Step 04 — SYN 기준으로 방향 변경

- 수행 내용: SYN이 설정되고 ACK가 없는 TCP 패킷을 기준으로 전체 트래픽을 집계
- 사용 기준:

  ```text
  tcp.flags.syn == 1 && tcp.flags.ack == 0
  ```

- 관찰한 사실: Source별 SYN 발생량에 차이가 나타남
- 해석: 연결 시도 패턴을 중심으로 후보를 좁히는 것이 적절함
- 다음 작업: SYN Source 순위 확인
- Evidence: [E04](../evidence/screenshots/04-syn-source-ranking.png)

## Step 05 — Source 후보 선정

- 수행 내용: SYN Source별 발생량 비교
- 관찰한 사실: `172.16.0.1`이 약 256,000건 수준으로 가장 두드러짐
- 해석: 관찰된 Source 후보로 선정하되, 이 값만으로 실제 외부 주체라고 단정하지 않음
- 다음 작업: Source별 Unique Destination Port 비교
- Evidence: [E04](../evidence/screenshots/04-syn-source-ranking.png)

## Step 06 — UniquePorts 분석

- 수행 내용: SYN 패킷의 Source별 목적지 포트를 중복 제거해 비교
- 관찰한 사실: `172.16.0.1`은 Unique Port 999개, 다른 주요 Source는 대부분 50~70개 수준
- 해석: 한 Source에서 다양한 포트로 연결을 시도한 패턴이 두드러짐
- 다음 작업: 해당 Source가 집중한 Destination 확인
- Evidence: [E05](../evidence/screenshots/05-unique-port-ranking.png)

## Step 07 — 대상 확인

- 수행 내용: `172.16.0.1`의 SYN을 Destination별로 그룹화
- 관찰한 사실: `192.168.10.50`에 SYN 약 256,000건과 Unique Port 999개가 집중됨. 다른 Destination은 대부분 Unique Port 1개 수준
- 해석: 포트 탐색 후보 대상은 `192.168.10.50`으로 좁혀짐
- 다음 작업: 시간대별 포트 다양성 확인
- Evidence: [E06](../evidence/screenshots/06-suspected-scan-target.png)

## Step 08 — 시간대 탐색

- 수행 내용: `172.16.0.1 → 192.168.10.50` SYN을 한국시간 기준 분 단위로 그룹화
- 관찰한 사실: 2017-07-08 02:51~02:56에 Unique Port 997~998개. 직전 구간은 약 5개 수준
- 해석: 포트 다양성이 특정 시간대에 급증하므로 working PCAP 후보 구간으로 선정
- 다음 작업: 후보 시간대 추출
- Evidence: [E08](../evidence/screenshots/08-minute-port-diversity.png)

## Step 09 — Working PCAP 생성

- 수행 내용: `editcap`으로 후보 시간대를 `case01-portscan-window.pcap`으로 추출
- 관찰한 사실: 축소 파일에서도 해당 Source/Destination 간 ICMP와 일반 TCP/HTTP가 함께 보임
- 해석: 두 주소 간 전체 통신이 아니라 SYN 조건으로 다시 좁혀야 함
- 다음 작업: Wireshark에서 SYN 패턴 확인
- Evidence: [E09](../evidence/screenshots/09-working-window-overview.png)

## Step 10 — SYN 패턴 확인

- 수행 내용: Source, Destination, SYN=1, ACK=0 필터 적용
- 관찰한 사실: 짧은 시간 동안 다양한 목적지 포트로 SYN이 연속 전송됨
- 해석: 특정 서비스에 대한 단일 연결보다 여러 포트 탐색 패턴에 가까움
- 다음 작업: 대상의 SYN/ACK 응답 확인
- Evidence: [E10](../evidence/screenshots/10-syn-port-scan-pattern.png)

## Step 11 — SYN/ACK 확인

- 수행 내용: `192.168.10.50 → 172.16.0.1` 방향의 SYN/ACK 필터 적용
- 관찰한 사실: 21, 22, 80, 139, 445에서 SYN/ACK 응답 확인
- 해석: 해당 포트들을 열린 TCP 포트 후보로 기록
- 다음 작업: RST 응답 확인
- Evidence: [E11](../evidence/screenshots/11-open-port-synack-responses.png)

## Step 12 — RST 확인

- 수행 내용: `192.168.10.50 → 172.16.0.1` 방향의 RST 필터 적용
- 관찰한 사실: 23, 53, 111, 3306, 3389 등을 포함한 다수 포트에서 RST/ACK 응답 확인
- 해석: 해당 응답 포트들을 닫힌 TCP 포트 후보로 기록
- 다음 작업: 열린 포트 후보 중 22번 포트의 전체 순서 확인
- Evidence: [E12](../evidence/screenshots/12-closed-port-rst-responses.png)

## Step 13 — 열린 포트 목록 정리

- 수행 내용: SYN/ACK 응답의 Source Port를 중복 제거
- 관찰한 사실: 21, 22, 80, 139, 445가 목록으로 정리됨
- 해석: 서비스 의미는 일반적인 포트 번호 수준에서만 기록하고 버전·취약점은 비워둠
- 다음 작업: 22번 포트에서 SYN→SYN/ACK→RST 순서 확인
- Evidence: [E13](../evidence/screenshots/13-open-port-list.png)

## Step 14 — SYN Scan 판정

- 수행 내용: 양쪽 주소와 TCP 22번 포트 추적
- 관찰한 사실: `SYN → SYN/ACK → RST`가 반복되고 마지막 ACK는 확인되지 않음
- 해석: TCP SYN / Half-open Scan 패턴으로 판단
- 최종 결과: PCAP 내부에서 Port Scan 정찰 행위가 관찰된 것으로 정리. 악성 의도, 실제 외부 주체, 후속 침해 여부는 별도 확인 필요
- Evidence: [E14](../evidence/screenshots/14-syn-scan-half-open-pattern.png)
