# CASE-01 기술 분석 보고서

## 1. Case Overview

| 항목 | 내용 |
|---|---|
| Case ID | CASE-01 |
| 주제 | TCP SYN Port Scan 분석 |
| Dataset | CIC-IDS2017 |
| 원본 PCAP | `Friday-WorkingHours.pcap` |
| 분석용 PCAP | `case01-portscan-window.pcap` |
| 분석 도구 | Wireshark, tshark, editcap |
| 분석 상태 | 분석 완료 |
| 관찰된 Source | `172.16.0.1` |
| 관찰된 Destination | `192.168.10.50` |

`172.16.0.1`은 이 PCAP에서 관찰된 Source 주소를 의미합니다. NAT 또는 방화벽 구조가 있을 수 있으므로 실제 외부 주체의 주소나 단일 주체의 실체로 단정하지 않습니다.

## 2. Objective

이번 분석의 목적은 단순히 패킷 수가 많은 통신을 Port Scan으로 분류하는 것이 아니라, 다음 세 가지 근거를 연결해 포트 탐색 행위 여부를 판단하는 것이었습니다.

1. 동일 Source가 짧은 시간에 다양한 TCP 목적지 포트로 SYN을 보냈는가?
2. 대상이 특정 호스트에 집중되었는가?
3. 대상의 SYN/ACK·RST 응답과 후속 패킷이 TCP SYN / Half-open Scan 패턴을 뒷받침하는가?

서비스 버전, 취약점 존재, 실제 외부 공격자, 후속 침해 여부는 이번 분석 범위에서 확인하지 않았습니다.

## 3. Data Source

- Dataset: CIC-IDS2017
- 원본 파일: `Friday-WorkingHours.pcap`
- 분석용 파일: `case01-portscan-window.pcap`
- 원본 로컬 경로: `evidence/pcap/Friday-WorkingHours.pcap`
- 분석용 로컬 경로: `evidence/pcap/case01-portscan-window.pcap`
- 파일 규모: Wireshark 화면에서 원본이 약 1천만 패킷 규모로 확인되었고, 하단에는 9,997,874개 패킷이 표시됨 ([E01](evidence/screenshots/01-pcap-overview.png))
- 별도 확인하지 않은 항목: 파일 해시, 운영체제, 도구 버전, 다운로드 시각

## 4. Analysis Strategy

대규모 PCAP 전체를 Wireshark에서 직접 따라가면 분석 부담이 컸기 때문에 다음 순서로 범위를 축소했습니다.

1. tshark로 전체 트래픽의 Endpoint, SYN Source, 목적지 포트 분포를 집계
2. Endpoint와 TCP Conversation으로 전체 통신 구조를 확인
3. 단순 패킷 수 대신 `SYN`과 `Unique Destination Port`를 중심으로 후보 Source와 대상 선정
4. 한국시간 기준 분 단위 포트 다양성으로 의심 시간대 확인
5. `editcap`으로 `case01-portscan-window.pcap` 생성
6. Wireshark에서 SYN, SYN/ACK, RST 및 22번 포트의 순서를 패킷 수준으로 검증

이 흐름은 “많이 통신한 주소”를 바로 공격 주체로 판단하지 않고, 포트 탐색에 직접 연결되는 패킷 특성을 단계적으로 확인하기 위한 것입니다.

## 5. Initial Observation

### 왜 확인했는가

원본 PCAP의 전체 규모와 분석 가능 범위를 먼저 파악해야 이후 결과가 특정 부분만 본 것인지 판단할 수 있습니다.

### 확인한 내용

Wireshark로 원본 `Friday-WorkingHours.pcap`을 열었을 때 약 1천만 패킷이 포함된 대규모 캡처임을 확인했습니다. 화면에는 CDP, LDAP, TCP 등 다양한 일반 트래픽이 함께 표시되었습니다 ([E01](evidence/screenshots/01-pcap-overview.png)).

### 판단

전체 파일을 Wireshark에서 직접 필터링하며 추적하기보다, tshark 집계와 분석용 PCAP 추출을 먼저 수행하는 것이 재현성과 작업 효율 측면에서 적절하다고 판단했습니다.

## 6. Endpoint Analysis

### 왜 확인했는가

IPv4 Endpoint 통계는 캡처에 어떤 주소들이 등장하는지와 트래픽이 특정 주소에 집중되는지를 파악하는 출발점입니다.

### 확인한 내용

IPv4 Endpoint 통계에서 여러 주소가 관찰되었습니다 ([E02](evidence/screenshots/02-ipv4-endpoints.png)). 그러나 Endpoint의 패킷 수가 많다는 사실만으로 포트 스캔을 판별하기는 어려웠습니다. 일반 서비스 통신도 패킷 수가 커질 수 있기 때문입니다.

### 판단

Endpoint 통계는 후보 범위를 파악하는 보조 근거로 사용하고, 최종 판단 기준은 SYN 패킷과 목적지 포트 다양성으로 전환했습니다.

## 7. TCP Conversation Analysis

### 왜 확인했는가

TCP Conversation 통계는 주소 쌍과 포트별 대화량을 보여주므로, 특정 통신 쌍이 분석의 중심인지 확인하는 데 유용합니다.

### 확인한 내용

상위 TCP Conversation에는 80/443과 같은 일반 서비스 통신이 주로 보였습니다 ([E03](evidence/screenshots/03-tcp-conversations-overview.png)). 이 결과만으로는 정상적인 서비스 사용과 포트 스캔을 분리하기 어려웠습니다.

### 판단

대화량 순위 자체를 Port Scan의 판정 근거로 사용하지 않았습니다. 이후에는 연결 성공 여부보다 “한 Source가 얼마나 많은 목적지 포트에 SYN을 보냈는가”를 중심으로 확인했습니다.

## 8. SYN Source Analysis

### 왜 확인했는가

SYN은 TCP 연결을 시작하는 패킷이므로, SYN만 추려 Source별 발생량을 비교하면 연결 시도 패턴이 두드러지는 주소를 찾을 수 있습니다.

### 확인한 내용

분석에 사용한 기준은 다음과 같습니다.

```text
tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.src
```

Source별 결과에서 `172.16.0.1`이 약 256,000건 수준으로 가장 두드러졌습니다 ([E04](evidence/screenshots/04-syn-source-ranking.png)).

### 판단

`172.16.0.1`을 관찰 대상 Source 후보로 선정했습니다. 단, SYN 개수만으로 악성 또는 실제 외부 주체라고 판단하지 않고 목적지 포트와 대상 집중도를 추가로 확인했습니다.

## 9. Port Diversity Analysis

### 왜 확인했는가

Port Scan은 한 호스트 또는 여러 호스트의 서비스 노출 범위를 파악하기 위해 다양한 목적지 포트에 연결을 시도하는 형태로 나타날 수 있습니다. 따라서 Source별 Unique Destination Port를 비교했습니다.

### 확인한 내용

SYN 패킷에서 Source와 목적지 포트를 추출해 Source별로 중복을 제거했습니다. `172.16.0.1`은 Unique Port 999개를 보였고, 다른 주요 Source는 대부분 50~70개 수준이었습니다 ([E05](evidence/screenshots/05-unique-port-ranking.png)).

대표적으로 관찰된 목적지 포트에는 다음이 포함됩니다.

```text
256, 80, 139, 1723, 23, 135, 3306, 111, 53,
3389, 587, 25, 993, 21, 8080, 8888, 1720, 1025,
5900, 110, 995, 199, 443, 554, 143, 445, 22
```

목적지 포트가 시간 순서에 따라 바뀌는 샘플도 별도로 확인했습니다 ([E07](evidence/screenshots/07-port-sequence-sample.png)).

### 판단

`172.16.0.1`의 SYN 양과 Unique Port 수가 다른 주요 Source보다 함께 두드러져, 단순한 일반 서비스 통신보다 포트 탐색 후보에 가까운 패턴으로 판단했습니다.

## 10. Timeline Analysis

### 왜 확인했는가

포트 다양성이 캡처 전체에 고르게 나타나는지, 특정 시간대에 집중되는지 확인하면 점검·자동화 트래픽과 일시적인 탐색 활동을 구분하는 데 도움이 됩니다.

### 확인한 내용

`172.16.0.1 → 192.168.10.50` SYN을 분 단위로 그룹화했습니다. 한국시간 기준 대표 결과는 다음과 같습니다.

| 시각 | UniquePorts |
|---|---:|
| 2017-07-08 02:51 | 997 |
| 2017-07-08 02:52 | 997 |
| 2017-07-08 02:53 | 997 |
| 2017-07-08 02:54 | 998 |
| 2017-07-08 02:55 | 997 |
| 2017-07-08 02:56 | 997 |

직전 구간에서는 Unique Port가 약 5개 수준으로 나타났습니다 ([E08](evidence/screenshots/08-minute-port-diversity.png)).

### 판단

직전 구간의 낮은 다양성에서 특정 구간의 997~998개 수준으로 급격히 변한 점을 Port Scan 후보 시간대 선정 근거로 사용했습니다.

## 11. Working PCAP Extraction

### 왜 확인했는가

후보 시간대를 작은 분석용 파일로 분리하면 원본 전체의 일반 트래픽에 묻히지 않고, 동일한 패킷 패턴을 반복 검증할 수 있습니다.

### 확인한 내용

후보 시간대를 기준으로 `editcap`을 사용해 `case01-portscan-window.pcap`을 생성했습니다. working PCAP을 Source와 Destination으로 필터링했을 때 ICMP와 80번 포트의 일반 통신도 함께 보였으므로, 단순한 두 주소 간 통신 전체를 스캔으로 간주하지 않고 SYN 조건을 추가했습니다 ([E09](evidence/screenshots/09-working-window-overview.png)).

### 판단

working PCAP은 상세 패킷 분석의 범위를 줄이는 용도로 사용했으며, 최종 판단은 그 안에서 다시 SYN, SYN/ACK, RST 플래그를 확인한 결과에 기반합니다.

## 12. Packet-level Analysis

### 왜 확인했는가

Port Scan 여부는 집계 결과만으로 확정하기보다 실제 패킷의 방향, 목적지 포트, TCP 플래그를 확인해야 합니다.

### 확인한 내용

다음 필터로 `172.16.0.1 → 192.168.10.50`의 SYN만 표시했습니다.

```text
ip.src == 172.16.0.1 &&
ip.dst == 192.168.10.50 &&
tcp.flags.syn == 1 &&
tcp.flags.ack == 0
```

짧은 시간 동안 80, 256, 139, 1723, 23, 135, 3306, 111, 53, 3389, 21, 443, 445, 22 등 다양한 목적지 포트로 SYN이 연속 전송되는 패턴을 확인했습니다 ([E10](evidence/screenshots/10-syn-port-scan-pattern.png)).

### 판단

단일 서비스 연결이 아니라 하나의 관찰된 Source가 한 대상의 여러 TCP 목적지 포트로 연결을 시작하는 형태로 해석했습니다.

## 13. Open Port Analysis

### 왜 확인했는가

SYN에 대한 대상의 응답 플래그는 해당 포트가 연결 요청에 어떻게 반응했는지 구분하는 근거가 됩니다.

### 확인한 내용

다음 필터로 대상에서 관찰된 SYN/ACK 응답을 확인했습니다.

```text
ip.src == 192.168.10.50 &&
ip.dst == 172.16.0.1 &&
tcp.flags.syn == 1 &&
tcp.flags.ack == 1
```

SYN/ACK 응답에서 확인된 중복 제거 포트 후보는 다음과 같습니다.

| 포트 | 해석 |
|---:|---|
| 21 | FTP에 일반적으로 사용되는 포트 |
| 22 | SSH에 일반적으로 사용되는 포트 |
| 80 | HTTP에 일반적으로 사용되는 포트 |
| 139 | NetBIOS Session Service에 일반적으로 사용되는 포트 |
| 445 | SMB에 일반적으로 사용되는 포트 |

응답 패킷은 [E11](evidence/screenshots/11-open-port-synack-responses.png), 중복 제거 목록은 [E13](evidence/screenshots/13-open-port-list.png)에 기록되어 있습니다.

### 판단과 한계

위 포트는 SYN/ACK 응답에 근거한 **열린 TCP 포트 후보**입니다. 이 분석으로 서비스 버전, 실제 애플리케이션, 취약점 존재 여부는 확인하지 않았습니다.

## 14. Closed Port Analysis

### 왜 확인했는가

Port Scan은 열린 포트뿐 아니라 닫힌 포트에 대한 응답도 함께 남깁니다. RST/ACK 응답을 확인하면 대상이 포트 탐색에 응답한 범위를 보완할 수 있습니다.

### 확인한 내용

```text
ip.src == 192.168.10.50 &&
ip.dst == 172.16.0.1 &&
tcp.flags.reset == 1
```

다수 목적지 포트에 대해 `192.168.10.50 → 172.16.0.1` 방향의 RST/ACK 응답을 확인했습니다. 예시는 23, 53, 111, 3306, 3389입니다 ([E12](evidence/screenshots/12-closed-port-rst-responses.png)).

### 판단

이번 문서에서는 RST/ACK 응답을 **닫힌 TCP 포트 후보**로 해석했습니다. 모든 포트의 실제 운영 상태나 방화벽 정책을 별도로 검증한 것은 아닙니다.

## 15. Scan Type Identification

### 왜 확인했는가

SYN을 보냈다는 사실만으로는 스캔 방식까지 구분하기 어렵기 때문에, 특정 포트의 요청-응답-종료 순서를 확인했습니다.

### 확인한 내용

22번 포트 추적 필터는 다음과 같습니다.

```text
(ip.addr == 172.16.0.1 && ip.addr == 192.168.10.50) &&
tcp.port == 22
```

반복적으로 다음 순서를 확인했습니다.

```text
172.16.0.1 → 192.168.10.50:22 [SYN]
192.168.10.50:22 → 172.16.0.1 [SYN, ACK]
172.16.0.1 → 192.168.10.50:22 [RST]
```

이 패턴은 [E14](evidence/screenshots/14-syn-scan-half-open-pattern.png)에 표시되어 있습니다.

### 판단

정상적인 TCP 3-way handshake의 마지막 ACK를 보내지 않고 RST로 종료하는 반복 패턴이므로, 이번 Case는 **TCP SYN Scan 또는 Half-open Scan 패턴**으로 판단했습니다.

## 16. Evidence Validation and Scope

이번 보고서에서 수행한 검증은 다음과 같습니다.

- 전체 PCAP의 SYN Source 집계
- Source별 Unique Destination Port 비교
- 대상별 포트 다양성 비교
- 분 단위 시간대 변화 확인
- working PCAP에서 SYN, SYN/ACK, RST의 방향과 순서 확인

CIC-IDS2017의 독립 라벨 또는 별도 운영 로그를 이 작업에서 직접 대조했다는 근거는 기록되어 있지 않습니다. 따라서 데이터셋의 라벨을 근거로 실제 외부 주체, 취약점 존재, 후속 침해 여부를 주장하지 않습니다. 최종 판단은 현재 PCAP에서 직접 관찰한 네트워크 행위에 한정합니다.

## 17. MITRE ATT&CK Mapping

| Technique ID | Technique Name | 적용 근거 |
|---|---|---|
| T1046 | Network Service Discovery | 하나의 관찰된 Source가 대상 호스트의 다양한 TCP 목적지 포트로 SYN을 보내 서비스 노출 범위를 탐색한 정황 |

이 매핑은 관찰된 행위의 성격을 설명하기 위한 것이며, 행위 주체의 악성 의도나 후속 침해를 의미하지 않습니다.

## 18. False Positive Analysis

### 왜 확인했는가

다양한 포트로 SYN을 보내는 동작은 악성 정찰뿐 아니라 승인된 보안 점검에서도 발생할 수 있습니다. 따라서 Port Scan 관찰과 악성 사건 확정을 분리해야 합니다.

### 가능한 정상 원인

- 승인된 취약점 스캐너
- Nmap 기반 내부 점검
- Nessus 등 보안 점검 도구
- 정기 네트워크 자산 점검
- 관리자 승인 테스트

### 추가로 확인할 사항

- `172.16.0.1`에 매핑되는 자산과 담당자
- 승인된 스캐너 또는 점검 도구 여부
- 해당 시간대 작업·변경 기록
- 방화벽/NAT 환경에서 Source 주소의 의미
- 동일 Source의 후속 공격 로그와 다른 내부 시스템 대상 스캔

현재 PCAP만으로 위 정상 원인을 배제하지 않았으므로, 최종 분류는 자산·변경·운영 맥락과 함께 판단해야 합니다.

## 19. Detection Engineering

관찰된 패턴을 운영 탐지로 일반화하기 위한 초기 아이디어는 다음과 같습니다.

- 동일 Source IP와 Destination IP 조합
- TCP SYN = 1, ACK = 0
- 60초 이내
- 서로 다른 Destination Port 100개 이상
- 승인된 스캐너는 allowlist로 분리

여기서 100개라는 threshold는 이번 분석에서 사용한 실험 기반 초기값입니다. 운영환경의 정상 트래픽, 스캐너 유형, 서버 역할에 따라 오탐을 측정한 뒤 조정해야 합니다. 상세 규칙은 [detection-rule.md](detection/detection-rule.md)에 정리했습니다.

## 20. Response

이번 문서의 대응 항목은 권고사항이며, 실제 차단이나 격리를 수행했다는 의미가 아닙니다.

1. 관찰된 Source가 어떤 자산인지 식별
2. 승인된 스캐너·내부 점검인지 확인
3. 비인가 Source라면 네트워크 정책상 차단 또는 제한을 검토
4. 대상 서버의 열린 포트 후보와 실제 필요성을 확인
5. 불필요한 서비스 종료 및 SSH/FTP/SMB 접근 제어 점검
6. 동일 Source의 후속 공격 로그와 다른 내부 시스템 대상 스캔 확인

## 21. Lessons Learned

- Endpoint와 Conversation의 패킷 수만으로는 Port Scan을 충분히 판별하기 어려웠습니다.
- SYN과 Unique Destination Port를 결합하자 후보 Source와 대상이 명확해졌습니다.
- 전체 PCAP을 먼저 집계하고 working PCAP으로 축소하면 상세 패킷 검증의 범위를 관리하기 쉽습니다.
- SYN/ACK와 RST/ACK를 구분하면 열린 포트 후보와 닫힌 포트 후보를 별도로 기록할 수 있습니다.
- 관찰된 Source IP를 실제 외부 주체와 동일시하지 않고, 자산·NAT·승인 점검 여부를 후속 확인 항목으로 남겨야 합니다.
