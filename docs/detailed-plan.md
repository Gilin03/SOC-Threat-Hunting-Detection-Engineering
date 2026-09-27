# SOC Threat Hunting & Detection Engineering 프로젝트 실행 계획

## 1. 프로젝트 한 줄 정의

공개된 공격 로그와 PCAP 데이터를 활용해 보안관제(SOC) 업무처럼 이벤트를 분석하고, 정탐/오탐 판단, IOC 추출, MITRE ATT&CK 매핑, 탐지 룰 작성 및 튜닝까지 수행하는 개인 프로젝트.

---

# 2. 프로젝트 최종 목표

이 프로젝트는 웹사이트를 만드는 프로젝트가 아니다.

최종적으로 보여주고 싶은 것은 다음 능력이다.

- 네트워크 트래픽 분석
- Windows / Linux 로그 분석
- SIEM 검색 및 이벤트 상관분석
- 정탐 / 오탐 판단
- 공격 성공 여부 판단
- IOC 추출
- MITRE ATT&CK 매핑
- 탐지 Rule 작성
- False Positive 분석
- 탐지 Rule 튜닝
- 침해사고 대응 방안 작성
- 분석 보고서 작성

최종적으로 면접에서 아래 질문에 답할 수 있는 수준을 목표로 한다.

```text
왜 공격이라고 판단했는가?
어떤 로그를 근거로 판단했는가?
정상 행위일 가능성은 없는가?
공격이 실제로 성공했는가?
추가 피해는 없는가?
어떤 IOC를 추출했는가?
어떤 탐지 Rule을 만들었는가?
오탐은 어떻게 줄였는가?
실제 SOC라면 어떻게 대응할 것인가?
```

---

# 3. 전체 프로젝트 진행 흐름

```text
1. 프로젝트 환경 준비
        ↓
2. 공개 공격 데이터 선정
        ↓
3. 데이터 구조 파악
        ↓
4. Wireshark / 로그 분석
        ↓
5. 공격 여부 판단
        ↓
6. 관련 이벤트 추가 조사
        ↓
7. 정탐 / 오탐 판정
        ↓
8. IOC 추출
        ↓
9. MITRE ATT&CK 매핑
        ↓
10. Detection Rule 작성
        ↓
11. False Positive 분석
        ↓
12. Rule 튜닝
        ↓
13. Case별 분석 문서 작성
        ↓
14. GitHub 정리
        ↓
15. 최종 PDF 보고서 작성
        ↓
16. 자소서 / 면접용 요약 작성
```

---

# 4. 프로젝트에서 사용할 데이터

직접 공격을 만들고 직접 분석하는 방식은 기본 방향으로 사용하지 않는다.

가능하면 이미 공개되어 있는 공격 데이터를 사용한다.

## 사용할 데이터 종류

### 네트워크 데이터

- PCAP
- PCAPNG
- Zeek Log
- IDS / IPS Log
- Firewall Log

### Host 데이터

- Windows Event Log
- Sysmon Log
- PowerShell Log
- Linux auth.log
- Linux syslog

### 선택 데이터

- Web Server Log
- WAF Log
- EDR 형태 이벤트
- 공개 DFIR / CTF 데이터

---

# 5. 데이터 선정 원칙

처음부터 복잡한 데이터를 선택하지 않는다.

## 우선순위

### 1순위
정답 또는 분석 가이드가 어느 정도 존재하는 공개 데이터

이유:
- 처음 분석할 때 내가 맞게 보고 있는지 검증 가능
- 학습과 포트폴리오를 동시에 진행하기 좋음

### 2순위
공격 유형이 명확한 데이터

예:

```text
Port Scan
SSH Brute Force
Suspicious PowerShell
Malware C2
```

### 3순위
정상 트래픽과 공격 트래픽이 함께 있는 데이터

이유:
- 정탐 / 오탐 비교
- Detection Rule 테스트
- 튜닝 경험 확보

---

# 6. 최종적으로 분석할 Case

처음 계획은 6개이지만, 실제 완성 목표는 4개를 깊게 분석하는 것이다.

## 필수 Case 4개

### Case 01 — Port Scan

목표:
- PCAP 기반 네트워크 분석
- Source / Destination 분석
- TCP Flag 확인
- 여러 Port 접근 패턴 확인

---

### Case 02 — SSH Brute Force / Password Spraying

목표:
- Linux 인증 로그 분석
- 실패 로그인 패턴 분석
- 로그인 성공 여부 확인
- Credential Attack 차이 이해

---

### Case 03 — Suspicious PowerShell

목표:
- Windows / Sysmon 이벤트 분석
- Process Tree 분석
- Parent / Child Process 확인
- Command Line 분석

---

### Case 04 — Malware C2 / Beaconing

목표:
- 반복 통신 패턴 분석
- DNS / IP / Port 분석
- C2 가능성 판단
- IOC 추출

---

## 추가 Case

시간이 충분한 경우 추가한다.

### Case 05 — SQL Injection

- WAF / Web Log 분석
- 공격 시도와 침해 성공 구분
- HTTP Response 확인

### Case 06 — Credential Attack

- Brute Force
- Password Spraying
- 계정 탈취 가능성 분석

---

# 7. 시작 전에 설치할 프로그램

## 필수

### Wireshark

용도:
- PCAP 분석
- IP / Port 확인
- DNS / HTTP 분석
- TCP Stream 확인
- 통신 패턴 분석

---

### VS Code

용도:
- Markdown 작성
- Python Script 작성
- GitHub 프로젝트 관리

---

### Git

용도:
- 프로젝트 버전 관리
- GitHub 업로드

---

### Python

용도:
- 로그 파싱
- CSV / JSON 분석
- IOC 추출
- 반복 작업 자동화

---

## SIEM

아래 중 하나만 선택한다.

추천 우선순위:

```text
1. Splunk
2. Elastic Stack
3. Wazuh
4. Microsoft Sentinel
```

처음에는 한 제품만 사용한다.

목표는 제품 전문가가 되는 것이 아니라 아래 기능을 경험하는 것이다.

```text
Log Import
Search
Filter
Aggregation
Correlation
Detection Rule
Alert
```

---

# 8. 프로젝트 시작 전 최소 공부 범위

모든 내용을 미리 공부할 필요는 없다.

프로젝트 시작 전에 아래 정도만 알고 시작한다.

## 네트워크

- IP
- Source / Destination
- Port
- TCP / UDP
- TCP 3-Way Handshake
- DNS
- HTTP / HTTPS
- SSH
- ICMP
- NAT 기본 개념

---

## Wireshark

아래 기능만 먼저 익힌다.

```text
ip.addr
ip.src
ip.dst
tcp.port
tcp.flags.syn
dns
http
```

추가 기능:

```text
Follow TCP Stream
Endpoints
Conversations
Statistics
```

---

## 로그 기본

로그에서 아래 내용을 읽을 수 있어야 한다.

```text
Timestamp
Source IP
Destination IP
Username
Success / Failure
Process
Command
Event ID
```

---

## 보안 공격 기본

- Port Scan
- Brute Force
- Password Spraying
- SQL Injection
- PowerShell 악용 개념
- Malware C2
- Beaconing

깊게 외우기보다 각각 아래 4가지만 먼저 이해한다.

```text
무슨 공격인가?
어떤 흔적이 남는가?
어떤 로그에서 확인 가능한가?
어떻게 탐지할 수 있는가?
```

---

# 9. 3주 실행 계획

---

# 1주차 — 환경 구성 + 네트워크 분석

## Day 1 — 프로젝트 세팅

### 해야 할 일

- GitHub Repository 생성
- 프로젝트 폴더 구조 생성
- Wireshark 설치
- Python 설치 확인
- Git 연결
- README 초안 작성

폴더:

```text
soc-threat-hunting-project/

├ README.md
├ datasets/
├ cases/
├ rules/
├ scripts/
├ reports/
└ screenshots/
```

### 완료 기준

- GitHub Repository 생성 완료
- 로컬 프로젝트 폴더 준비 완료
- Wireshark 정상 실행
- README 존재

---

## Day 2 — 네트워크 기본 복습

### 공부

- TCP / UDP
- Port
- DNS
- HTTP
- SSH
- TCP Flags
- 3-Way Handshake

### 실습

Wireshark Sample Traffic을 열어 다음을 직접 찾는다.

- Source IP
- Destination IP
- TCP Port
- DNS Query
- TCP SYN

---

## Day 3 — PCAP 분석 기본

### Wireshark 기능

- Display Filter
- Follow TCP Stream
- Endpoints
- Conversations
- Statistics

### 목표

PCAP을 봤을 때

```text
누가?
어디로?
어떤 프로토콜로?
어떤 포트로?
얼마나 자주?
```

를 확인할 수 있는 수준.

---

## Day 4~5 — Case 01 Port Scan

### 작업 순서

```text
공개 Port Scan PCAP 확보
↓
전체 트래픽 확인
↓
Source IP 확인
↓
Destination IP 확인
↓
Destination Port 수 확인
↓
TCP SYN 패턴 확인
↓
발생 시간대 확인
↓
공격 판단
↓
오탐 가능성 검토
↓
분석 문서 작성
```

### 확인할 질문

- 동일 Source IP인가?
- 동일 Destination인가?
- 몇 개 Port에 접근했는가?
- 시간 간격은 짧은가?
- SYN 패킷이 반복되는가?
- 정상 스캐너일 가능성은 없는가?

### 결과물

```text
cases/case01-portscan/
├ analysis.md
├ screenshots/
├ ioc.csv
└ conclusion.md
```

---

## Day 6~7 — Case 01 정리 + SIEM 준비

### 해야 할 일

- 분석 결과 다시 검토
- Screenshot 정리
- IOC 정리
- MITRE ATT&CK 관련 Technique 조사
- SIEM 하나 설치 또는 사용 환경 준비

---

# 2주차 — 인증 로그 + SIEM + 탐지 Rule

## Day 8 — Linux Log 기본

### 공부

- auth.log
- SSH Login
- Failed password
- Accepted password
- sudo
- Username
- Source IP

---

## Day 9~10 — Case 02 SSH Brute Force

### 분석 흐름

```text
Linux auth.log 확보
↓
Failed Login 검색
↓
Source IP별 횟수 계산
↓
Username별 횟수 계산
↓
시간대 분석
↓
Accepted Login 존재 여부 확인
↓
추가 행동 확인
↓
공격 유형 판단
```

### 확인할 질문

- 하나의 IP에서 반복 실패인가?
- 하나의 계정인가?
- 여러 계정인가?
- 로그인 성공이 발생했는가?
- 성공 이후 sudo 사용이 있는가?

### Brute Force

```text
한 계정
+
많은 비밀번호 시도
```

### Password Spraying

```text
많은 계정
+
소수 비밀번호 반복
```

---

## Day 11 — SIEM에 로그 넣기

목표:

- Linux Log Import
- Source IP 검색
- Username 검색
- Failed Login 필터
- 시간대별 Count 확인

---

## Day 12 — 첫 Detection Rule 작성

초기 Rule 예:

```text
동일 Source IP
AND
10분 이내
AND
Failed Login >= 10
```

### 기록할 내용

- 왜 10회로 설정했는가?
- 어떤 정상 행위가 탐지될 수 있는가?
- Alert 수는 몇 개인가?

---

## Day 13 — False Positive 분석

정상 행위 예:

- 사용자의 비밀번호 반복 오입력
- 관리자 테스트
- 자동화 프로그램 인증 실패
- 사내 보안 스캐너

---

## Day 14 — Rule 튜닝

예:

```text
동일 Source IP
AND
10분 이내
AND
Failed Login >= 15
AND
Distinct Username >= 5
AND
Whitelist IP 제외
```

### 비교

| 항목 | 초기 Rule | 개선 Rule |
|---|---:|---:|
| Alert | 기록 | 기록 |
| True Positive | 기록 | 기록 |
| False Positive | 기록 | 기록 |

이 표는 최종 보고서에 반드시 넣는다.

---

# 3주차 — Endpoint 분석 + C2 + 최종 정리

## Day 15 — Windows / Sysmon 기본

### 공부

- Process
- Parent Process
- Child Process
- Command Line
- User
- File Hash
- Network Connection

### 중요 개념

Process Tree.

예:

```text
WINWORD.EXE
 └ powershell.exe
    └ cmd.exe
```

---

## Day 16~17 — Case 03 Suspicious PowerShell

### 작업 순서

```text
공개 Sysmon / Windows Log 확보
↓
PowerShell 실행 확인
↓
Parent Process 확인
↓
Command Line 확인
↓
Child Process 확인
↓
외부 통신 확인
↓
정상 / 악성 가능성 판단
↓
MITRE ATT&CK 매핑
↓
Detection Rule 작성
```

### 핵심 질문

- PowerShell을 누가 실행했는가?
- Parent Process가 무엇인가?
- Command Line이 정상적인가?
- EncodedCommand가 사용됐는가?
- 외부 통신이 있는가?
- 추가 Process가 생성됐는가?

---

## Day 18~19 — Case 04 Malware C2

### 분석 흐름

```text
공개 Malware PCAP 확보
↓
Endpoints 확인
↓
수상한 외부 IP 확인
↓
Conversations 확인
↓
시간 간격 분석
↓
DNS Query 확인
↓
Port / Protocol 확인
↓
Beaconing 여부 판단
↓
IOC 추출
```

### 확인할 항목

- 같은 IP로 반복 통신?
- 일정한 주기?
- DNS Query?
- 비정상 Domain?
- HTTP/TLS?
- Packet Size가 일정한가?
- Upload / Download 패턴?

---

## Day 20 — IOC / ATT&CK 정리

Case별 IOC 정리.

예:

```text
IP
Domain
URL
File Hash
File Name
User
Command Line
```

ATT&CK은 단순 ID 복사가 아니라 다음까지 작성한다.

```text
Technique:
근거:
관련 Log:
판단 이유:
```

---

## Day 21 — 프로젝트 전체 정리

### GitHub 정리

- README 완성
- Case 01~04 링크
- Screenshot 정리
- Rule 정리
- Python Script 정리
- 데이터 출처 명시

---

# 10. Case별 분석 문서 템플릿

각 Case는 동일한 템플릿을 사용한다.

```markdown
# Case XX - 공격명

## 1. Case 개요

## 2. 데이터 출처

## 3. 최초 관찰

## 4. Raw Log / Packet Evidence

## 5. 분석 과정

## 6. 추가 조사

## 7. 공격 성공 여부

## 8. 최종 판정

## 9. IOC

## 10. MITRE ATT&CK

## 11. Detection Rule

## 12. False Positive

## 13. Rule 개선

## 14. 대응 방안

## 15. 배운 점
```

---

# 11. 프로젝트에서 Python을 사용할 부분

Python은 필수가 아니라 분석 자동화를 위한 보조 도구다.

## Script 01 — Failed Login Counter

기능:

```text
Source IP별 Failed Login 수 계산
```

---

## Script 02 — IOC Extractor

기능:

```text
IP
Domain
URL
Hash
```

추출 및 중복 제거.

---

## Script 03 — Log Parser

기능:

```text
대량 로그
↓
특정 Event 추출
↓
CSV 출력
```

---

# 12. 최종 GitHub 구조

```text
soc-threat-hunting-project/

├ README.md
│
├ datasets/
│   └ README.md
│
├ cases/
│   ├ case01-portscan/
│   │   ├ analysis.md
│   │   ├ ioc.csv
│   │   ├ detection-rule.yml
│   │   └ screenshots/
│   │
│   ├ case02-ssh-bruteforce/
│   ├ case03-powershell/
│   └ case04-c2/
│
├ rules/
│   ├ sigma/
│   └ siem/
│
├ scripts/
│   ├ log_parser.py
│   ├ ioc_extractor.py
│   └ failed_login_counter.py
│
├ reports/
│   └ final-report.pdf
│
└ screenshots/
```

---

# 13. 최종 README에 보여줄 내용

## 프로젝트 설명

```text
공개 보안 로그 및 PCAP 데이터를 활용하여
주요 공격 이벤트를 분석하고,
정탐/오탐 판정, IOC 추출,
MITRE ATT&CK 매핑,
Detection Rule 작성 및 튜닝을 수행한 개인 프로젝트.
```

---

## Case Summary

| Case | 데이터 | 핵심 분석 | 결과물 |
|---|---|---|---|
| Port Scan | PCAP | SYN / Port 패턴 | 분석 보고서 |
| SSH Brute Force | Linux Log | 인증 이벤트 상관분석 | Detection Rule |
| Suspicious PowerShell | Sysmon | Process Tree | Sigma Rule |
| Malware C2 | PCAP | Beaconing | IOC |

---

## 기술 스택

```text
Wireshark
SIEM
Linux Log
Windows Event Log
Sysmon
Sigma
MITRE ATT&CK
Python
Git / GitHub
```

---

# 14. 최종 PDF 보고서 구성

## 1. 프로젝트 개요

- 프로젝트 목적
- 선정 이유
- 수행 범위

## 2. 분석 환경

- OS
- Tool
- SIEM
- 데이터 종류

## 3. 데이터 출처

## 4. Case 01

## 5. Case 02

## 6. Case 03

## 7. Case 04

## 8. IOC Summary

## 9. MITRE ATT&CK Mapping

## 10. Detection Rule Summary

## 11. False Positive / Tuning

## 12. Incident Response 제안

## 13. 프로젝트에서 배운 점

## 14. 한계 및 향후 개선

---

# 15. 프로젝트에서 반드시 남길 증거

각 Case마다 다음을 최소 2~4개 남긴다.

### Network Case

- Wireshark Packet 화면
- Conversations
- Endpoints
- Follow Stream

### Log Case

- Raw Log
- SIEM 검색 결과
- Count / Aggregation 결과
- Detection Alert

### Endpoint Case

- Process Tree
- Command Line
- Network Connection

### Detection

- Rule 원본
- Rule 실행 결과
- False Positive
- 개선 전/후 비교

---

# 16. 프로젝트가 완성됐다고 판단하는 기준

아래가 모두 충족되면 1차 완성으로 본다.

- [ ] 공개 공격 데이터 4개 이상 분석
- [ ] PCAP Case 2개 이상
- [ ] Host Log Case 2개 이상
- [ ] SIEM을 사용한 Case 존재
- [ ] Detection Rule 3개 이상
- [ ] False Positive 분석 존재
- [ ] Rule 튜닝 사례 1개 이상
- [ ] IOC 정리
- [ ] MITRE ATT&CK 매핑
- [ ] Case별 분석 문서
- [ ] Screenshot 증거
- [ ] GitHub README 완성
- [ ] 최종 PDF 보고서 완성
- [ ] 자소서용 요약 준비
- [ ] 면접 예상 질문 답변 준비

---

# 17. 프로젝트에서 하지 않을 것

초기에 범위를 너무 키우지 않는다.

다음은 우선 제외한다.

- React 기반 Dashboard 제작
- 자체 웹서비스 개발
- 복잡한 Backend 개발
- 직접 Malware 제작
- 실제 외부 시스템 공격
- 과도한 자동 대응 기능
- 여러 SIEM 제품 동시 사용
- AD 전체 Lab 구축

필요하면 프로젝트 1차 완성 이후 확장한다.

---

# 18. 프로젝트 완성 후 확장 가능 방향

## 확장 1 — Case 추가

- SQL Injection
- RDP Brute Force
- DNS Tunneling
- Lateral Movement
- Credential Dumping

## 확장 2 — Detection Engineering 강화

- Sigma Rule 추가
- SIEM Query 비교
- Rule 성능 측정

## 확장 3 — Threat Hunting

가설 기반 Hunting Query 작성.

예:

```text
Office 프로그램이 PowerShell을 실행한 흔적이 존재하는가?
```

## 확장 4 — SOAR

탐지 이후

```text
Alert
↓
IOC 조회
↓
Slack / Discord 알림
↓
Ticket 생성
```

자동화.

---

# 19. 최종 자소서 활용 방향

자소서에서는 단순히 도구를 나열하지 않는다.

안 좋은 예:

> Wireshark와 Splunk를 사용했습니다.

좋은 방향:

> 공개된 공격 로그와 PCAP을 기반으로 Port Scan, SSH Brute Force, 비정상 PowerShell 실행, C2 통신 사례를 분석했습니다. 네트워크와 Host 로그를 교차 분석하여 정탐 여부를 판단하고, IOC 및 MITRE ATT&CK 정보를 정리했습니다. 또한 Detection Rule을 작성한 뒤 False Positive 사례를 분석해 조건을 튜닝하며 탐지 정확도를 개선했습니다.

---

# 20. 프로젝트 핵심 원칙

## 원칙 1

많은 도구를 사용하기보다 한 사건을 제대로 분석한다.

## 원칙 2

공격 유형을 맞히는 것에서 끝내지 않는다.

```text
공격 발견
↓
근거 확인
↓
정탐 / 오탐
↓
성공 여부
↓
추가 피해
↓
IOC
↓
Detection
↓
Response
```

까지 진행한다.

## 원칙 3

모든 판단에는 근거를 남긴다.

```text
증거
↓
분석
↓
판단
```

## 원칙 4

결과보다 판단 과정을 보여준다.

## 원칙 5

실제 SOC 업무와 연결되는 결과물로 정리한다.

---

# 21. 가장 먼저 할 일

프로젝트 시작 순서는 아래대로 진행한다.

```text
1. GitHub Repository 생성
2. Wireshark 설치 및 기본 사용 확인
3. 첫 번째 공개 Port Scan PCAP 선정
4. PCAP 다운로드
5. Source / Destination / Port 분석
6. Case 01 분석 문서 작성
7. 결과 검토
8. Case 02로 이동
```

처음부터 SIEM이나 MITRE ATT&CK을 전부 공부하려고 하지 않는다.

첫 Case를 분석하면서 필요한 지식을 하나씩 추가하는 방식으로 진행한다.

---

# 최종 목표

이 프로젝트의 최종 목표는 다음 문장을 실제 경험을 근거로 말할 수 있게 되는 것이다.

> "공개된 공격 데이터를 기반으로 네트워크 및 Endpoint 이벤트를 분석하고, 정탐/오탐 판단과 IOC 추출, MITRE ATT&CK 매핑, 탐지 룰 작성 및 튜닝까지 직접 수행했습니다."

