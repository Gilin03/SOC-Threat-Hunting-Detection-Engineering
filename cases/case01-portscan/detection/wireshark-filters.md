# Wireshark Display Filter 기록

이번 분석에서 실제로 사용한 Source/Destination, SYN, SYN/ACK, RST, 22번 포트 추적 필터를 목적과 결과별로 정리했습니다. 필터는 캡처 파일의 패킷을 삭제하지 않고 표시 범위만 좁히는 용도로 사용했습니다.

## Filter 01 — Source / Destination

### Purpose

관찰된 Source와 대상 호스트 사이의 전체 통신을 먼저 확인합니다.

### Filter

```text
ip.src == 172.16.0.1 && ip.dst == 192.168.10.50
```

### Result

두 주소 사이에 ICMP와 일반 TCP/HTTP 통신도 함께 표시되었습니다. 따라서 이 필터의 전체 결과를 Port Scan으로 해석하지 않고, 이후 TCP SYN 조건을 추가했습니다.

### Evidence

[E09 — working PCAP Source/Destination overview](../evidence/screenshots/09-working-window-overview.png)

## Filter 02 — SYN only, 전체 집계 기준

### Purpose

연결을 시작하는 TCP SYN 중 이미 ACK를 포함한 응답은 제외하여 Source별 SYN 발생량과 목적지 포트 다양성을 집계합니다.

### Filter

```text
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

### Result

이 기준으로 `172.16.0.1`의 SYN이 약 256,000건 수준으로 두드러졌고, 해당 Source의 Unique Destination Port가 999개로 확인되었습니다.

### Evidence

- [E04 — SYN Source ranking](../evidence/screenshots/04-syn-source-ranking.png)
- [E05 — Unique Port ranking](../evidence/screenshots/05-unique-port-ranking.png)

## Filter 03 — Source/Destination + SYN only

### Purpose

후보 Source와 대상 호스트 사이에서 목적지 포트가 빠르게 바뀌는 SYN 패킷을 패킷 목록 수준에서 확인합니다.

### Filter

```text
ip.src == 172.16.0.1 &&
ip.dst == 192.168.10.50 &&
tcp.flags.syn == 1 &&
tcp.flags.ack == 0
```

### Result

짧은 시간 동안 80, 256, 139, 1723, 23, 135, 3306, 111, 53, 3389, 21, 443, 445, 22 등 다양한 목적지 포트로 SYN이 연속 전송되었습니다.

### Evidence

[E10 — SYN port scan pattern](../evidence/screenshots/10-syn-port-scan-pattern.png)

## Filter 04 — SYN/ACK response

### Purpose

대상 호스트가 SYN에 SYN/ACK로 응답한 포트를 확인해 열린 TCP 포트 후보를 추출합니다.

### Filter

```text
ip.src == 192.168.10.50 &&
ip.dst == 172.16.0.1 &&
tcp.flags.syn == 1 &&
tcp.flags.ack == 1
```

### Result

중복 제거한 열린 TCP 포트 후보는 21, 22, 80, 139, 445입니다. 포트 번호의 일반적인 서비스 의미는 참고만 하며, 서비스 버전이나 취약점은 확인하지 않았습니다.

### Evidence

- [E11 — SYN/ACK responses](../evidence/screenshots/11-open-port-synack-responses.png)
- [E13 — open port candidates](../evidence/screenshots/13-open-port-list.png)

## Filter 05 — RST response

### Purpose

대상 호스트가 RST/ACK로 응답한 포트를 확인해 닫힌 TCP 포트 후보를 보완합니다.

### Filter

```text
ip.src == 192.168.10.50 &&
ip.dst == 172.16.0.1 &&
tcp.flags.reset == 1
```

### Result

23, 53, 111, 3306, 3389 등을 포함한 다수 포트에서 RST/ACK 응답이 확인되었습니다. 이 문서에서는 이를 닫힌 TCP 포트 후보로 해석했습니다.

### Evidence

[E12 — RST responses](../evidence/screenshots/12-closed-port-rst-responses.png)

## Filter 06 — 22번 포트 추적

### Purpose

특정 포트에서 SYN, SYN/ACK, RST의 순서를 확인해 스캔 방식이 Half-open 형태인지 검증합니다.

### Filter

```text
(ip.addr == 172.16.0.1 && ip.addr == 192.168.10.50) &&
tcp.port == 22
```

### Result

다음 순서가 반복되었습니다.

```text
172.16.0.1 → 192.168.10.50:22 [SYN]
192.168.10.50:22 → 172.16.0.1 [SYN, ACK]
172.16.0.1 → 192.168.10.50:22 [RST]
```

정상적인 TCP 3-way handshake의 마지막 ACK 없이 RST로 종료되는 TCP SYN / Half-open Scan 패턴으로 판단했습니다.

### Evidence

[E14 — SYN scan half-open pattern](../evidence/screenshots/14-syn-scan-half-open-pattern.png)
