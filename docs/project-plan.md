# SOC Threat Hunting & Detection Engineering Project

## 1. 프로젝트 개요

공개된 보안 로그와 네트워크 PCAP 데이터를 활용하여 실제 보안관제(SOC) 업무와 유사하게 공격 이벤트를 분석하고, 정탐/오탐 여부를 판단하며, IOC 추출과 탐지 규칙 작성까지 수행하는 개인 프로젝트다.

이 프로젝트의 핵심은 웹사이트를 만드는 것이 아니라 다음 능력을 보여주는 것이다.

- 로그 분석
- 네트워크 트래픽 분석
- SIEM 기반 이벤트 조사
- Windows/Linux 이벤트 분석
- 정탐/오탐 판단
- MITRE ATT&CK 매핑
- IOC 추출
- 탐지 룰 작성
- 탐지 룰 튜닝
- 침해사고 초동 대응 판단
- 분석 보고서 작성

---

## 2. 프로젝트 목표

### 최종 목표

공개 보안 데이터를 대상으로 공격 이벤트를 분석하고 다음 질문에 답할 수 있는 수준까지 프로젝트를 완성한다.

1. 어떤 공격이 발생했는가?
2. 공격자는 어디에서 접근했는가?
3. 공격 대상은 무엇인가?
4. 공격이 단순 시도인지 실제 침해인지?
5. 어떤 로그와 증거를 근거로 판단했는가?
6. 추가 피해는 없는가?
7. IOC는 무엇인가?
8. MITRE ATT&CK 기준으로 어떤 공격 기법인가?
9. 어떻게 탐지할 수 있는가?
10. 오탐 가능성은 무엇인가?
11. 실제 환경에서는 어떻게 대응해야 하는가?

---

## 3. 전체 분석 흐름

```text
공개 데이터 확보
    ↓
Alert 또는 이상행위 발견
    ↓
Raw Log 확인
    ↓
관련 이벤트 추가 검색
    ↓
네트워크 / 호스트 로그 교차 분석
    ↓
정탐 / 오탐 판정
    ↓
공격 성공 여부 판단
    ↓
IOC 추출
    ↓
MITRE ATT&CK 매핑
    ↓
탐지 Rule 작성
    ↓
False Positive 분석
    ↓
탐지 Rule 튜닝
    ↓
대응 방안 작성
    ↓
최종 보고서 작성
```

---

## 4. 사용할 수 있는 데이터

직접 공격 환경을 만들고 스스로 분석하는 방식보다 공개된 보안 데이터셋을 사용한다.

### 데이터 예시

- 공개 PCAP
- Windows Event Log
- Sysmon 로그
- Linux auth.log
- Web Server 로그
- Firewall 로그
- IDS / IPS 로그
- WAF 로그
- 공개 CTF / DFIR 데이터셋
- 공개 Malware Traffic 데이터

원본 데이터는 저작권 및 용량 문제 때문에 GitHub에 직접 포함하지 않고 출처와 다운로드 링크를 README에 정리한다.

---

# 5. 분석할 주요 Case

## Case 01. SSH Brute Force

### 분석 포인트

```text
동일 Source IP
+ 짧은 시간
+ 반복적인 로그인 실패
```

추가로 다음을 확인한다.

- 어떤 계정을 대상으로 시도했는가?
- 로그인 성공 기록이 존재하는가?
- 로그인 성공 이후 sudo 사용이 있었는가?
- 새로운 계정 생성이 있었는가?
- SSH Key가 추가되었는가?
- 외부 연결이 발생했는가?

### 최종 판단 예시

```text
다수 로그인 실패
↓
로그인 성공
↓
계정 탈취 가능성
↓
추가 활동 조사
```

---

## Case 02. Port Scan

### 분석 포인트

```text
한 Source IP
↓
한 Destination IP
↓
짧은 시간에 다수의 Port 접근
```

확인할 항목

- Source IP
- Destination IP
- Destination Port
- TCP Flag
- 패킷 발생 간격
- Scan 이후 추가 공격 발생 여부

### 상관분석 예시

```text
Port Scan
↓
SSH 22번 포트 확인
↓
SSH Brute Force 발생
```

단순 이벤트 하나가 아니라 공격 흐름으로 연결해서 분석한다.

---

## Case 03. SQL Injection

### 분석 포인트

예시 요청

```text
GET /product?id=1' OR '1'='1
```

확인할 항목

- 공격 요청 여부
- WAF 탐지 여부
- WAF Block 여부
- HTTP Response Code
- Backend 서버 도달 여부
- DB Error 여부
- 비정상 데이터 조회 여부

### 중요한 판단

```text
공격 시도 확인 ≠ 침해 성공
```

예를 들어

```text
WAF = BLOCK
HTTP = 403
Backend 접근 없음
```

이라면:

> SQL Injection 공격 시도는 확인됐으나 WAF에서 차단되었으며 실제 침해 흔적은 확인되지 않음.

처럼 작성한다.

---

## Case 04. Suspicious PowerShell

### 분석 포인트

예시 Process Tree

```text
WINWORD.EXE
    ↓
powershell.exe
    ↓
cmd.exe
    ↓
외부 네트워크 연결
```

확인할 항목

- Parent Process
- Child Process
- Command Line
- User
- File Hash
- File Path
- 외부 네트워크 연결
- 추가 생성 프로세스

### 분석 목표

정상 PowerShell 사용인지 악성 행위 가능성이 높은 PowerShell 실행인지 판단한다.

---

## Case 05. Malware C2 Traffic

### 분석 포인트

예시

```text
10:00:00 → External IP
10:00:30 → External IP
10:01:00 → External IP
10:01:30 → External IP
```

일정한 주기로 동일 목적지와 통신한다면 Beaconing 또는 C2 가능성을 조사한다.

확인할 항목

- 통신 주기
- Destination IP
- Domain
- Port
- DNS Query
- HTTP Header
- TLS 여부
- 패킷 크기
- 업로드/다운로드량

### 결과

C2 가능성이 높다고 판단되면 관련 IP, Domain 등을 IOC로 추출한다.

---

## Case 06. Credential Attack

Brute Force와 Password Spraying의 차이를 분석한다.

### Brute Force

```text
하나의 계정
↓
많은 비밀번호 시도
```

### Password Spraying

```text
많은 계정
↓
소수의 비밀번호 반복
```

확인할 항목

- Source IP
- Username 수
- Password Failure 횟수
- 로그인 성공 여부
- 공격 발생 시간
- 이후 행동

---

# 6. 각 Case별 공통 결과물

각 사건은 동일한 형식으로 정리한다.

## 6.1 Incident Summary

```text
공격 유형:
탐지 시간:
Source IP:
Destination IP:
Target:
Severity:
판정:
True Positive / False Positive
```

---

## 6.2 Evidence

사용한 증거

- PCAP
- Firewall Log
- Web Log
- WAF Log
- Windows Event Log
- Sysmon
- Linux auth.log
- EDR 로그

---

## 6.3 Analysis

다음 내용을 작성한다.

- 최초 이상행위
- 추가로 확인한 로그
- 공격 흐름
- 공격 성공 여부
- 최종 판단
- 판단 근거

가능하면 항상 다음 구조로 작성한다.

```text
증거
↓
분석
↓
판단
```

---

## 6.4 IOC

필요한 경우 다음을 추출한다.

```text
IP
Domain
URL
File Name
File Hash
User
Command Line
Registry Key
```

---

## 6.5 MITRE ATT&CK

공격자의 행위를 MITRE ATT&CK Technique과 연결한다.

단순히 Technique ID만 적는 것이 아니라:

- 왜 해당 Technique으로 판단했는가?
- 어떤 로그가 근거인가?

까지 정리한다.

---

## 6.6 Detection Rule

분석한 공격을 탐지할 수 있는 규칙을 작성한다.

사용 가능 형식

- Sigma Rule
- Splunk Query
- Elastic KQL
- 기타 SIEM Query

---

## 6.7 False Positive 분석

탐지 룰에 걸릴 수 있는 정상 행위를 정리한다.

예:

- 정상 사용자의 반복 로그인 실패
- 사내 취약점 스캐너
- 관리자 테스트
- 자동화 시스템
- 정상 PowerShell 스크립트

---

## 6.8 Response

실제 SOC라면 어떤 대응을 해야 하는지 작성한다.

예:

- IP 차단
- 계정 잠금
- 비밀번호 초기화
- Endpoint 격리
- 추가 로그 분석
- IOC 기반 전체 시스템 검색
- WAF / Firewall 정책 수정
- 관련 사용자 확인
- 상위 담당자 Escalation

---

# 7. 탐지 Rule 튜닝

이 프로젝트에서 중요한 부분이다.

단순히 Rule을 만드는 것으로 끝내지 않는다.

예:

## 초기 Rule

```text
로그인 실패 >= 5
```

결과

```text
Alert 200개
True Positive 3개
False Positive 197개
```

문제:

오탐이 너무 많다.

---

## Rule 개선

```text
동일 Source IP
AND
10분 이내
AND
로그인 실패 >= 15
AND
서로 다른 Username >= 5
```

결과

```text
Alert 12개
True Positive 3개
False Positive 9개
```

---

## 추가 튜닝

```text
사내 취약점 스캐너 IP 제외
관리자 테스트 IP 제외
```

결과

```text
Alert 5개
True Positive 3개
False Positive 2개
```

이 과정을 통해 단순 공격 탐지를 넘어 Detection Engineering 경험을 보여준다.

---

# 8. 사용할 수 있는 도구

## 네트워크 분석

- Wireshark
- tshark
- Zeek

## SIEM

초기에는 다음 중 하나를 선택한다.

- Elastic Stack
- Splunk
- Microsoft Sentinel
- Wazuh

중요한 것은 제품 자체보다 다음 기능을 경험하는 것이다.

```text
Search
Filter
Aggregation
Correlation
Detection Rule
Alert
Investigation
```

---

## Endpoint / Host

- Windows Event Viewer
- Sysmon
- Linux Log
- PowerShell Log

---

## 탐지 Rule

- Sigma
- SIEM Query
- YARA (필요한 경우)

---

## 분석 자동화

- Python

Python은 웹서비스 개발 목적이 아니라 반복 작업 자동화에 활용한다.

예:

- 로그 파싱
- JSON 분석
- CSV 분석
- 정규식 검색
- Source IP별 횟수 계산
- Failed Login Count 계산
- IOC 자동 추출
- 중복 제거
- 통계 생성

---

# 9. GitHub 프로젝트 구조

```text
soc-threat-hunting-project/

├ README.md
│
├ datasets/
│   └ README.md
│
├ cases/
│   │
│   ├ case01-ssh-bruteforce/
│   │   ├ analysis.md
│   │   ├ evidence/
│   │   ├ ioc.csv
│   │   └ detection-rule.yml
│   │
│   ├ case02-portscan/
│   │
│   ├ case03-sqli/
│   │
│   ├ case04-powershell/
│   │
│   ├ case05-c2/
│   │
│   └ case06-credential-attack/
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

# 10. README 구성

README 상단에는 프로젝트 목적을 명확하게 작성한다.

예시:

```text
SOC Threat Hunting & Detection Engineering

공개 보안 로그 및 PCAP 데이터를 활용하여
주요 사이버 공격 이벤트를 분석하고,
정탐/오탐 판정, IOC 추출, MITRE ATT&CK 매핑,
탐지 룰 설계 및 튜닝을 수행한 개인 프로젝트입니다.
```

## 분석 대상

```text
01. SSH Brute Force
02. Port Scan
03. SQL Injection
04. Suspicious PowerShell
05. Malware C2 Traffic
06. Credential Attack
```

## 프로젝트 흐름

```text
Raw Log
↓
Investigation
↓
Correlation
↓
Detection
↓
MITRE ATT&CK
↓
IOC
↓
Detection Rule
↓
False Positive Tuning
↓
Response
```

---

# 11. 최종 제출물

최종적으로 다음 자료를 준비한다.

## GitHub Repository

- 분석 기록
- 탐지 Rule
- Python 자동화 Script
- IOC
- Case별 문서
- Screenshot

## 최종 보고서 PDF

포함 내용

1. 프로젝트 개요
2. 분석 환경
3. 사용 데이터
4. Case별 분석
5. 공격 흐름
6. MITRE ATT&CK
7. IOC
8. 탐지 Rule
9. False Positive 분석
10. Rule 튜닝 결과
11. 대응 방안
12. 프로젝트 회고

## 추가 결과물

- IOC CSV
- Sigma Rules
- SIEM Query
- 분석 Screenshot
- PCAP 분석 결과
- 탐지 Rule 튜닝 전/후 비교

---

# 12. 프로젝트 진행 일정

## 1주차

- 프로젝트 환경 구성
- 공개 데이터셋 선정
- SIEM 기본 환경 구축
- Case 01 SSH Brute Force
- Case 02 Port Scan

## 2주차

- Case 03 SQL Injection
- Case 04 Suspicious PowerShell
- MITRE ATT&CK 매핑
- Sigma Rule 작성 시작

## 3주차

- Case 05 Malware C2
- Case 06 Credential Attack
- Detection Rule 작성
- Rule 튜닝
- Python 자동화 Script 작성

## 4주차

- 전체 Case 재검토
- GitHub 구조 정리
- README 작성
- 최종 분석 보고서 작성
- 자소서 문장 작성
- 면접 예상 질문 정리

프로젝트 규모에 따라 2~3주로 축소할 수 있다.

---

# 13. 면접에서 설명할 수 있어야 하는 질문

프로젝트를 완성한 후 다음 질문에 스스로 답할 수 있어야 한다.

1. 왜 해당 이벤트를 공격이라고 판단했는가?
2. 어떤 로그를 가장 먼저 확인했는가?
3. 정탐과 오탐을 어떻게 구분했는가?
4. 공격 시도와 침해 성공을 어떻게 구분했는가?
5. 가장 중요한 증거는 무엇이었는가?
6. 관련 로그를 어떻게 상관분석했는가?
7. 어떤 IOC를 추출했는가?
8. 왜 해당 MITRE ATT&CK Technique으로 분류했는가?
9. Detection Rule의 조건을 왜 그렇게 정했는가?
10. False Positive는 어떤 상황에서 발생했는가?
11. Rule을 어떻게 개선했는가?
12. 같은 공격이 다른 방식으로 들어오면 탐지가 가능한가?
13. 실제 SOC 환경이라면 어떤 순서로 대응할 것인가?
14. 다시 프로젝트를 한다면 무엇을 개선할 것인가?

---

# 14. 자소서 활용 예시

> 공개된 보안 로그와 네트워크 PCAP을 활용하여 SSH Brute Force, Port Scan, SQL Injection, 비정상 PowerShell 실행, C2 통신 등 주요 공격 사례를 분석했습니다. 단순히 공격 유형을 식별하는 데 그치지 않고 Windows/Linux 로그와 네트워크 트래픽을 교차 분석하여 정탐 여부와 침해 성공 여부를 판단했습니다. 이후 IOC와 MITRE ATT&CK 정보를 정리하고 탐지 룰을 직접 작성했으며, False Positive 사례를 분석해 조건을 튜닝하면서 탐지 정확도를 개선했습니다.

---

# 15. 이 프로젝트에서 가장 중요한 것

이 프로젝트의 목적은 많은 도구를 사용해 보는 것이 아니다.

중요한 것은 다음 사고방식을 보여주는 것이다.

```text
Alert 발생
↓
왜 발생했지?
↓
정상일 가능성은?
↓
어떤 로그를 더 봐야 하지?
↓
공격이라면 성공했나?
↓
다른 시스템까지 영향이 있나?
↓
다시 발생하면 어떻게 탐지하지?
↓
오탐은 어떻게 줄이지?
↓
실제 환경이면 어떻게 대응하지?
```

최종적으로 보여주려는 것은

**"도구를 사용할 줄 아는 사람"이 아니라 "보안관제 방식으로 사고하고 분석할 수 있는 사람"이다.**
