# CASE-02 Detection Rule

> 이 문서는 Honeypot에서 확인한 SSH Credential Guessing과 post-login command activity를 운영 탐지 아이디어로 일반화한 초기 설계입니다. 아래 Threshold와 Time Window는 시작값이며, 운영환경의 정상 분포·승인 작업·오탐을 측정한 뒤 조정해야 합니다.

## Detection Objective

- **Rule A:** 반복적인 SSH Credential Guessing 후보 탐지
- **Rule B:** SSH Session에서 외부 연결·다운로드·파일 저장·실행 시도 명령 탐지
- **Rule C:** 동일 Session에서 Credential 입력 이후 수상한 명령이 이어지는 상관분석

탐지 결과는 조사 후보 또는 우선순위이며, 그 자체로 인증 성공·악성코드 실행·침해 성공을 확정하지 않습니다.

## Data Source / Required Fields

- 데이터 출처: SSH Honeypot CSV `raw/ssh_attacks_full.csv`
- 필수 필드: `timestamp`, `session_id`, `ip`, `event_type`, `message`, `command`, `level`
- Credential 추출 필드: `message`의 Username·Password 입력 문자열
- Command 탐지 필드: `command` 및 `message`
- 보조 Context: Source 자산, 계정 소유자, 승인 작업, 변경 티켓, 네트워크 연결 로그
- 필드 한계: `SSH login` 이벤트만으로 인증 성공 여부를 확인할 수 없음

## Detection Logic

### Rule A — SSH Credential Guessing

1. `event_type == "SSH login"`인 이벤트만 선택합니다.
2. 동일 `ip`를 기준으로 시간 창을 묶습니다.
3. 시간 창 안에서 SSH login 횟수와 고유 Username·Credential pair 수를 집계합니다.
4. 반복 횟수와 Credential 다양성이 함께 기준을 넘으면 Credential Guessing 후보를 생성합니다.
5. 승인된 관리·점검 Source는 allowlist와 작업 시간대·변경 티켓을 함께 확인합니다.

초기 의사 조건:

```text
WHEN event_type == "SSH login"
GROUP BY ip
WITHIN 5 minutes
HAVING COUNT(*) >= 10
   AND (COUNT(DISTINCT username) >= 3
        OR COUNT(DISTINCT credential_pair) >= 3)
THEN alert("Possible SSH Credential Guessing")
```

5분, 10회, 고유 3개는 이번 Dataset의 약 20초대 반복 패턴을 빠르게 후보화하기 위한 초기값일 뿐입니다.

### Rule B — Suspicious SSH Command Activity

1. `event_type == "exec_command"`인 이벤트를 선택합니다.
2. `command` 또는 `message`에서 다음 패턴을 정규화해 검색합니다.
   - `/dev/tcp`
   - `wget`
   - `curl`
   - `chmod +x`
   - `/tmp`
   - `nohup bash`
3. 단일 키워드 일치만으로 악성 판정을 하지 않습니다.
4. 외부 연결 + Resource 요청 + 파일 저장 + 권한 변경/실행과 같이 서로 다른 행위 범주가 결합되면 우선순위를 높입니다.

예시 의사 조건:

```text
WHEN event_type == "exec_command"
  AND command/message CONTAINS_ANY
      ("/dev/tcp", "wget", "curl", "chmod +x", "/tmp", "nohup bash")
THEN enrich("Suspicious SSH Command Activity")
```

### Rule C — Credential + Post-login Correlation

1. 동일 `session_id`의 `SSH login`과 `exec_command`를 연결합니다.
2. `SSH login` 이후 초기 5분 안에 `exec_command`가 발생하는지 확인합니다.
3. Rule B 패턴 중 두 개 이상의 행위 범주가 결합되면 높은 조사 우선순위로 분류합니다.
4. 동일 Session의 Source, Credential 입력, 명령, 외부 대상 및 저장 경로를 Alert Context에 포함합니다.

```text
WHEN same session_id has
     SSH login BEFORE exec_command
  AND elapsed_time <= 5 minutes
  AND command/message matches suspicious pattern
THEN alert("SSH Post-login Command Correlation")
```

## Threshold / Time Window

| Rule | 초기값 | 설정 의미 |
|---|---|---|
| Rule A | 5분 내 SSH login 10회 이상 + 고유 Username 또는 pair 3개 이상 | 반복·다양성 조합을 Credential Guessing 후보로 생성 |
| Rule B | `exec_command`에서 단일 키워드 수집; 2개 이상 행위 범주 결합 시 우선순위 상승 | 단일 명령 오탐을 줄이고 복합 행위에 집중 |
| Rule C | 동일 Session, login 이후 5분 이내 command | Credential과 post-login activity 연결 |

초기값은 보편적인 정답이 아닙니다. 운영환경에서는 정상 관리 작업·배포·취약점 스캐너의 이벤트 분포와 비교해 조정합니다.

## Initial Rule

이번 Case에 적용할 초기 우선순위는 다음과 같습니다.

1. Rule A로 반복 Credential Guessing 후보를 생성합니다.
2. Rule B로 `exec_command`의 위험 신호를 수집합니다.
3. Rule C로 동일 Session에서 login과 수상 command가 연결되는지 확인합니다.
4. Source 자산·계정 소유자·승인 작업·변경 티켓을 Enrichment합니다.

Case 기준 참조 결과는 다음과 같습니다.

- Rule A 대표 후보: `170.64.203.74`, SSH login 448건, 약 35 Username, 약 177 Password, 446 pair
- Rule B 대표 후보: `/dev/tcp`, `GET /linux`, `/tmp`, `chmod +x`, `nohup bash`
- Rule C 대표 후보: `47.251.118.172`의 Session `9caa7e8b-7378-41b7-9bdd-4ae800e2466e`

## False Positive

예상 정상 행위:

- 관리자의 비밀번호 반복 오입력
- 잘못된 Credential을 가진 자동화 운영 스크립트
- 승인된 보안 점검 또는 취약점 스캐너
- 배포·원격 관리 작업
- 정상적인 `curl`, `wget`, `chmod`, `/tmp` 사용
- NAT·프록시 뒤 여러 사용자의 공유 Source IP

오탐 확인 시 다음 Context를 함께 확인합니다.

- Source 자산과 네트워크 위치
- 계정 소유자와 작업 담당자
- 승인된 작업 여부와 변경 티켓
- 작업 시간대
- 평소 Source의 Login·Command 행동 패턴
- 동일 Session 이후의 네트워크·Endpoint 로그

## Allowlist / Exception

Allowlist는 Source IP 하나만 고정하지 않고 다음 정보를 함께 관리합니다.

- 승인된 관리·점검 Source IP 또는 자산 ID
- 소유 팀과 담당자
- 허용된 대상과 작업 범위
- 허용된 시간대
- 승인 티켓과 만료일
- 재검토 주기

Allowlist 일치만으로 `exec_command`의 수상한 복합 행위를 완전히 무시하지 않고, 범위·시간대·명령 패턴이 승인 내용과 일치하는지 확인합니다.

## Tuning Strategy

1. 정상 관리·배포·점검 데이터에서 Rule A 발생량을 확인합니다.
2. 동일 Source·계정의 정상 오입력과 자동화 스크립트 재시도를 분리합니다.
3. Rule A의 반복 횟수, Username·pair 다양성, 시간 창을 조정합니다.
4. Rule B는 단일 키워드 Alert를 낮은 우선순위로 두고 복수 행위 범주 결합을 상향합니다.
5. Rule C는 동일 Session의 순서·시간·명령·외부 대상을 Context로 추가합니다.
6. 조정 전후 Alert 수, 승인 작업 적중률, 미승인 행위 탐지 여부를 비교합니다.

## Improved Rule

운영 검증 전의 권고 형태입니다.

- Rule A: 반복 횟수와 Credential 다양성을 함께 사용하고, 승인 Source는 작업 시간대·티켓까지 검증
- Rule B: 단일 키워드보다 네트워크 연결 + 파일 저장 + 권한 변경/실행의 복합 조건 우선
- Rule C: 동일 Session의 login→command 순서와 짧은 시간 창을 유지하고, 외부 대상·파일 경로를 Alert에 포함

운영환경 검증 후 최종 Threshold와 예외 목록을 갱신해야 합니다.

## Operational Considerations

- Alert에는 Source IP, Session ID, Credential 입력, Event Type, Timestamp, Command, 외부 대상 및 저장 경로를 포함합니다.
- `root` 입력은 Honeypot Credential 입력값으로 표현하고 실제 운영 계정 유효성으로 확장하지 않습니다.
- `exec_command`가 없으면 `170.64.203.74`는 Credential Guessing 정황으로만 분류합니다.
- 외부 연결 성공·파일 다운로드·실행 성공은 네트워크·Endpoint 로그로 별도 검증합니다.
- 실제 차단·계정 잠금 등 대응은 자산 소유자와 승인 절차 확인 후 수행합니다.

## Validation Result

- 검증 데이터: `raw/ssh_attacks_full.csv`, 145,425 events
- Rule A 참조 결과: `170.64.203.74`의 448 SSH login과 다수 Credential pair가 초기 조건의 대표 후보
- Rule B 참조 결과: `/dev/tcp`, `/tmp`, `chmod +x`, `nohup bash` 및 `GET /linux`가 관찰됨
- Rule C 참조 결과: `47.251.118.172`의 동일 Session에서 SSH login 이후 exec_command 발생
- 운영 Alert 성능: 미검증
- 최종 False Positive율: 미측정
- 남은 한계: 실제 인증 성공·외부 연결·파일 실행 결과와 정상 운영 데이터 대조 필요
