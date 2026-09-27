# CASE-01 최종 결론

## Incident Summary

CASE-01은 CIC-IDS2017의 `Friday-WorkingHours.pcap`에서 TCP SYN 기반 포트 탐색 정황을 확인한 분석 사례입니다. PCAP상 관찰된 Source `172.16.0.1`은 Destination `192.168.10.50`에 약 999개의 서로 다른 TCP 목적지 포트로 SYN을 전송했습니다.

한국시간 기준 `2017-07-08 02:51~02:56`에는 Unique Port가 997~998개로 급증했고, 22번 포트에서는 `SYN → SYN/ACK → RST` 순서가 반복되었습니다. 이 순서는 정상적인 TCP 3-way handshake의 마지막 ACK 없이 연결 시도를 종료하는 TCP SYN / Half-open Scan 패턴과 일치합니다.

## Key Evidence

| Evidence | 관찰 결과 | 의미 |
|---|---|---|
| [E05](evidence/screenshots/05-unique-port-ranking.png) | `172.16.0.1`의 Unique Port 999개 | Source별 포트 다양성에서 두드러짐 |
| [E06](evidence/screenshots/06-suspected-scan-target.png) | `172.16.0.1 → 192.168.10.50`, SYN 약 256,000건, Unique Port 999개 | 특정 대상에 대한 포트 탐색 후보 |
| [E08](evidence/screenshots/08-minute-port-diversity.png) | 특정 분 997~999개, 직전 약 5개 | 시간대별 급격한 포트 다양성 변화 |
| [E11](evidence/screenshots/11-open-port-synack-responses.png) | 21, 22, 80, 139, 445에 대한 SYN/ACK 응답 | 열린 TCP 포트 후보 |
| [E12](evidence/screenshots/12-closed-port-rst-responses.png) | 다수 포트에 대한 RST/ACK 응답 | 닫힌 TCP 포트 후보 |
| [E14](evidence/screenshots/14-syn-scan-half-open-pattern.png) | 22번 포트의 SYN→SYN/ACK→RST 반복 | Half-open Scan 패턴 |

## Final Assessment

**최종 판단: PCAP 내부에서 TCP SYN / Half-open Port Scan 정찰 행위가 관찰됨.**

판단 근거는 다음과 같습니다.

- 하나의 관찰된 Source가 특정 Destination의 매우 다양한 TCP 포트로 SYN을 전송함
- 동일 구간에서 Unique Port가 짧은 시간에 급증함
- 포트에 따라 SYN/ACK 또는 RST/ACK 응답이 확인됨
- 22번 포트에서 마지막 ACK 없이 RST로 종료되는 순서가 반복됨

다만 `172.16.0.1`은 PCAP상 Source일 뿐이며 실제 외부 주체의 주소로 단정하지 않습니다. 또한 이번 분석만으로 실제 외부 주체, 서비스 버전, 취약점 존재, 후속 침해 여부는 확인하지 않았습니다.

## Limitations

- Source 주소와 실제 자산·사용자를 매핑하지 않았습니다.
- NAT 또는 방화벽에 의한 주소 변환 여부를 확인하지 않았습니다.
- 승인된 스캐너, 내부 점검, 변경 작업 기록을 대조하지 않았습니다.
- 서비스 버전과 취약점 존재 여부를 확인하지 않았습니다.
- 독립적인 운영 로그 또는 데이터셋 라벨을 별도로 검증하지 않았습니다.
- 파일 해시, Wireshark/tshark 버전, 분석 수행 시각은 기록된 근거가 없어 문서에 넣지 않았습니다.

## False Positive

다음 정상 행위도 유사한 패턴을 만들 수 있습니다.

- 승인된 취약점 스캐너
- Nmap 기반 내부 점검
- Nessus 등 보안 점검 도구
- 정기 자산 점검 또는 관리자 승인 테스트

따라서 이 결과는 “Port Scan 정황”으로 우선 분류하고, 자산 소유자·승인 목록·작업 시간대·변경 기록을 확인한 뒤 악성 여부를 결정해야 합니다.

## Response Recommendation

1. `172.16.0.1`에 해당하는 자산과 네트워크 경로를 식별합니다.
2. 승인된 스캐너 또는 점검 작업인지 확인합니다.
3. 비인가 Source인 경우 차단 또는 접근 제한을 검토합니다.
4. `192.168.10.50`에서 열린 포트 후보 21, 22, 80, 139, 445의 실제 필요성과 접근 제어를 확인합니다.
5. 불필요한 서비스 종료와 SSH/FTP/SMB 접근 제어를 점검합니다.
6. 동일 Source의 후속 공격 로그와 다른 내부 시스템 대상 스캔 여부를 조사합니다.

위 항목은 대응 권고이며, 이 분석에서 실제 차단·격리 또는 서비스 변경을 수행했다는 의미는 아닙니다.

## Lessons Learned

- 전체 패킷 수와 TCP Conversation만으로는 포트 스캔을 충분히 설명하기 어려웠습니다.
- SYN과 Unique Port를 함께 집계하면 조사 대상을 빠르게 좁힐 수 있습니다.
- 시간대 분석과 working PCAP 추출은 대규모 원본의 상세 검증에 유용했습니다.
- 패킷 응답을 SYN/ACK와 RST/ACK로 분리하면 열린 포트 후보와 닫힌 포트 후보를 구분할 수 있습니다.
- 관찰된 Source IP와 실제 외부 주체 식별을 분리해 기록해야 과도한 판단을 피할 수 있습니다.
