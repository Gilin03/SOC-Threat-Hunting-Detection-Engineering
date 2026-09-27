# CASE-02 기술 분석 보고서

> 상세 분석에서는 직접 관찰한 사실과 그 사실에 대한 판단을 분리했습니다. Honeypot 로그의 Credential 입력과 명령은 관찰된 행위이며, 실제 운영 계정 유효성·외부 연결 성공·침해 성공을 의미하지 않습니다.

## 1. Case Overview

| 항목 | 내용 |
|---|---|
| Case ID | CASE-02 |
| Case 제목 | SSH Brute Force / Credential Guessing Analysis |
| 데이터 유형 | SSH Honeypot CSV / 인증·Session·명령 로그 |
| 원본 파일 | `raw/ssh_attacks_full.csv` |
| 분석 상태 | 분석 완료 |
| 분석 기간 | 데이터 Timestamp 기준 2025-07-27T07:16:44.579977 ~ 2025-11-14T00:57:51.173075 |
| 핵심 Entity | Source IP, Session ID, Username/Password 입력, Command |

## 2. Objective

### 분석 질문

- SSH login 이벤트에서 자동화된 Credential Guessing 또는 Brute-force-style pattern이 관찰되는가?
- 하나의 Source IP가 여러 Username·Password 조합을 반복하는가?
- 반복 시도는 일정한 시간 간격을 보이는가?
- SSH login 이후 동일 Session에서 명령 실행이 이어지는가?
- 외부 리소스 요청, 파일 저장, 실행 권한 부여와 같은 수상한 명령 입력이 있는가?

### 분석 범위와 제외 범위

이번 분석은 `ssh_attacks_full.csv`의 관찰 이벤트와 저장된 Evidence를 대상으로 합니다. 인증 성공 여부, 실제 운영 계정의 유효성, 외부 연결·다운로드·파일 실행 성공, 실제 악성코드 여부 및 시스템 침해 성공은 직접 확인하지 않았습니다.

## 3. Data Source

- 출처: Interactive SSH Attack & Payload Dataset / Custom SSH Honeypot
- 원본 파일: `raw/ssh_attacks_full.csv`
- 전체 이벤트: `145,425`
- 데이터 Timestamp 범위: `2025-07-27T07:16:44.579977` ~ `2025-11-14T00:57:51.173075`
- 컬럼: `id`, `timestamp`, `session_id`, `ip`, `port`, `event_type`, `message`, `command`, `level`
- 고유 Source IP: `13,897`
- 고유 Session: `137,506`
- 원본 처리: 원본 CSV는 수정하지 않고 분석 대상으로 사용

### Event Type 분포

| event_type | Count | 분석상 의미 |
|---|---:|---|
| SSH connect | 137,506 | SSH 연결 시작 이벤트 |
| SSH login | 4,797 | Username·Password 입력이 기록된 인증 이벤트 |
| SSH disconnect | 3,094 | Session 종료 이벤트 |
| exec_command | 28 | 로그인 이후 입력된 명령 이벤트 |

Dataset 구조와 출처는 [references/dataset-README.md](references/dataset-README.md)에 보존되어 있습니다.

## 4. Analysis Strategy

### 왜 이 순서로 분석했는가

전체 이벤트에서 연결·종료 이벤트와 인증 입력, post-login 명령을 분리해야 단순한 접속량과 Credential Attack 정황을 구분할 수 있습니다. 따라서 `SSH login`을 Credential 분석 대상으로, `exec_command`를 로그인 이후 상호작용 분석 대상으로 사용했습니다.

### 분석 단계

1. CSV 컬럼, Event Type, Source IP, Session ID 구조 확인
2. Event Type별 규모를 집계해 인증·명령 이벤트 범위 확인
3. `SSH login` Source ranking으로 반복 입력 후보 선정
4. 후보 Source의 Username·Password·Credential pair 다양성과 시간 간격 비교
5. `exec_command` Session과 Source를 확인하고 Credential 입력과 연결
6. 일반적인 디렉터리 탐색 Session과 수상한 외부 리소스 요청 Session을 비교
7. 관찰 지표를 IOC 후보와 ATT&CK 행위로 정리
8. Rule A/B/C, False Positive, Tuning 및 Response 기준 작성

## 5. Initial Observation

### 왜 확인했는가

SSH connect 이벤트가 전체의 대부분을 차지하므로, 연결 수만으로 Credential Attack을 판단하면 post-login 행위와 구분되지 않습니다. 인증 입력과 명령 입력이 각각 어떤 Event Type으로 기록되는지 먼저 확인했습니다.

### 확인한 내용

- 전체 이벤트는 `145,425`건입니다.
- `SSH login`은 `4,797`건으로 Username·Password 입력을 포함합니다.
- `exec_command`는 `28`건으로 로그인 이후 명령 입력을 나타냅니다.
- `exec_command`는 `16`개 Session, `7`개 Source IP에서 발생했습니다.
- `exec_command`가 발생한 Session의 Username 입력은 모두 `root`였습니다.

### 초기 가설

`SSH login` Source ranking은 자동화된 반복 Credential 입력 후보를 찾는 데 적합하고, `exec_command`는 로그인 이후 상호작용 또는 추가 행동 정황을 별도로 확인하는 기준으로 사용합니다.

**Evidence:** [E01](evidence/screenshots/01-dataset-overview.png), [E02](evidence/screenshots/02-event-type-summary.png), [E07](evidence/screenshots/07-exec-command-check.png)

## 6. SSH Login 집중 이유

`SSH connect`와 `SSH disconnect`는 Session의 시작과 종료를 보여주지만 Credential 자체를 설명하지 않습니다. 반면 `SSH login`의 `message`에는 `Bot entered username: ..., password: ...` 형태의 입력값이 기록되어 Source·Username·Password·Session을 함께 비교할 수 있습니다.

따라서 `SSH login`을 반복 Credential 입력 분석의 기본 이벤트로 삼았고, 이것이 실제 인증 성공을 의미하는 것으로 해석하지 않았습니다. 성공 여부를 독립적으로 표시하는 필드가 없으므로, 문서에서는 일관되게 “Credential 입력”, “login 이벤트”, “시도”로 표현합니다.

## 7. Candidate Identification — SSH Login Source Ranking

### 왜 확인했는가

반복 Credential 입력이 특정 Source IP에 집중되는지 확인해야 자동화된 공격 후보를 좁힐 수 있습니다.

### 확인한 내용

`SSH login` Source ranking에서 `170.64.203.74`가 `448`건으로 가장 많았습니다. 이 Source의 입력은 단일 Credential을 반복한 형태가 아니라 여러 Username과 Password 조합을 순차적으로 사용했습니다.

| 항목 | 확인 결과 |
|---|---:|
| Source | `170.64.203.74` |
| SSH login 이벤트 | 448 |
| 고유 Username | 약 35 |
| 고유 Password | 약 177 |
| 고유 Credential pair | 446 |
| exec_command | 확인되지 않음 |

### 판단

`170.64.203.74`는 SSH login 입력량과 Credential 다양성이 함께 두드러지는 후보입니다. 이 Source는 login 이벤트 분석만으로 자동화된 Credential Guessing 정황을 판단할 수 있지만, 명령 실행이나 로그인 이후 침해를 연결해 판단할 근거는 확인되지 않았습니다.

**Evidence:** [E03](evidence/screenshots/03-top-login-source-ranking.png), [E04](evidence/screenshots/04-top-source-username-ranking.png), [E05](evidence/screenshots/05-top-source-password-ranking.png)

## 8. Username / Password Pattern Analysis

### 왜 확인했는가

Credential Guessing은 Username 또는 Password 하나를 고정한 반복과 여러 조합을 순차적으로 바꾸는 패턴을 구분할 필요가 있습니다.

### 확인한 내용

- `170.64.203.74`는 약 35개 Username과 약 177개 Password를 사용했습니다.
- `448`개 login 이벤트에서 `446`개의 Credential pair가 관찰되어 거의 매번 다른 조합을 사용한 패턴입니다.
- Source 입력에는 `root`, `ubuntu`, `admin`, `mysql`, `oracle`, `test`, `guest`, `debian` 등 여러 Username이 포함되어 있습니다.
- 상위 Password에는 `123qwe`, `123qwerty`, `wasd`, `54321`, `qwerty`, `4321`, `654321` 등이 관찰됩니다.

### 판단

단일 사용자의 비밀번호 오입력보다 여러 계정명과 비밀번호 조합을 자동으로 순환하는 Credential Guessing / Brute-force-style attack 정황에 가깝습니다. 단, CSV의 `SSH login` 이벤트는 성공 여부를 확정하지 않으므로 Valid Account 사용이나 인증 성공을 주장하지 않습니다.

**Evidence:** [E04](evidence/screenshots/04-top-source-username-ranking.png), [E05](evidence/screenshots/05-top-source-password-ranking.png)

## 9. Login Frequency and Interval Analysis

### 왜 확인했는가

자동화된 도구는 짧고 반복적인 간격으로 요청을 생성하는 경향이 있습니다. 시간 간격을 확인해 수동 입력 가능성과 구분하는 보조 근거로 사용했습니다.

### 확인한 내용

`170.64.203.74`의 연속 SSH login 입력 간격은 평균 약 `19.7초`, 중앙값 약 `19.2초`였습니다. 시각 순으로 Credential pair가 계속 바뀌면서 약 20초대의 반복 간격이 이어졌습니다.

### 판단

여러 Credential pair를 사용하면서 비교적 일정한 20초대 간격을 반복하므로 사람이 수동으로 입력한 것보다 자동화된 Credential Guessing 정황이 강합니다. 이 값은 해당 Dataset에서 관찰된 패턴이며 운영환경의 보편적인 Threshold가 아닙니다.

**Evidence:** [E06](evidence/screenshots/06-login-interval-pattern.png)

## 10. Post-login Interaction Analysis

### 왜 확인했는가

Credential 입력 이후 동일 Session에서 명령이 실행되면 단순한 반복 로그인과 구분되는 추가 조사 지점이 됩니다.

### 확인한 내용

- 전체 `exec_command`: `28`건
- `exec_command` Session: `16`개
- `exec_command` Source IP: `7`개
- `exec_command`가 발생한 Session의 Username: 모두 `root`

### Credential 조합

| Credential 입력 | exec Session 수 | 해석 |
|---|---:|---|
| `root/test` | 11 | Honeypot에서 관찰된 입력값; 실제 운영 Credential 유효성은 미확인 |
| `root/eyble` | 2 | Evidence·분석 요약 표기 기준; 실제 운영 Credential 유효성은 미확인 |
| `root/123456` | 1 | Honeypot에서 관찰된 입력값; 실제 운영 Credential 유효성은 미확인 |
| `root/blabla` | 1 | Honeypot에서 관찰된 입력값; 실제 운영 Credential 유효성은 미확인 |
| `root/00000000` | 1 | Honeypot에서 관찰된 입력값; 실제 운영 Credential 유효성은 미확인 |

Raw CSV의 일부 해당 행은 `root/еуые`로 표시되어 Evidence의 `root/eyble` 표기와 문자 표현이 다릅니다. 이 값은 문서에서 임의로 실제 운영 계정이나 비밀번호로 정규화하지 않고, 표기 차이를 Limitation으로 남깁니다.

**Evidence:** [E07](evidence/screenshots/07-exec-command-check.png), [E08](evidence/screenshots/08-exec-command-source-ranking.png), [E18](evidence/screenshots/18-exec-session-credential-ranking.png)

## 11. 일반적인 Post-login Session

### 확인한 내용

`104.28.252.248`의 한 Session에서 다음 흐름이 관찰되었습니다.

```text
SSH connect
→ SSH login
→ root / test Credential 입력
→ cd /tmp
→ cd ..
→ cd /var
→ ls
→ exit
→ SSH disconnect
```

### 판단

로그인 이후 디렉터리 이동과 목록 확인이 이어진 상호작용 사례입니다. `cd`, `ls`, `exit` 입력만으로 악성 행위, 명령 실행 성공 또는 실제 침해를 단정하지 않습니다. 이 흐름은 Rule C 상관분석에서 “post-login activity가 있었다”는 맥락으로 사용하고, 명령의 성격은 다른 조건과 함께 평가해야 합니다.

**Evidence:** [E10](evidence/screenshots/10-session-timeline.png), [E11](evidence/screenshots/11-exec-command-session-ranking.png)

## 12. Suspicious Session Analysis

### 확인한 내용

다음 Session에서 login 이후 외부 리소스 요청과 파일 처리 명령이 짧은 시간 내 이어졌습니다.

| 항목 | 내용 |
|---|---|
| Source IP | `47.251.118.172` |
| Session ID | `9caa7e8b-7378-41b7-9bdd-4ae800e2466e` |
| Credential 입력 | `root / 123456` |
| 시작 흐름 | SSH connect → SSH login → exec_command |
| 외부 대상 | `8.210.252.89:60147` |
| Resource | `GET /linux` |
| 저장 경로 | `/tmp/6PLL1HZs1W` 등 |
| 후속 명령 | `chmod +x`, 저장 파일 실행 시도, `dd` 기반 파일 생성/조작 |

### 판단

동일 Session에서 Unix shell 명령으로 외부 리소스를 요청하고 `/tmp`에 저장한 뒤 실행 권한을 부여해 실행하려는 명령 입력 정황이 관찰되었습니다. 단일 키워드보다 외부 연결·HTTP 요청·파일 저장·권한 변경·실행 시도가 함께 나타난 점이 높은 조사 우선순위의 근거입니다.

다음 항목은 확인하지 않았습니다.

- 외부 `8.210.252.89:60147` 연결 성공 여부
- `/linux` 리소스 다운로드 성공 여부
- 저장 파일의 실제 내용과 악성코드 여부
- 파일 실행 성공 여부
- 실제 root 계정 탈취 또는 시스템 침해 성공 여부

따라서 최종 표현은 “외부 리소스를 받아 저장하고 실행하려는 명령 입력 정황”으로 제한합니다.

**Evidence:** [E13](evidence/screenshots/13-payload-download-command.png), [E14](evidence/screenshots/14-suspicious-session-timeline.png), [E15](evidence/screenshots/15-suspicious-session-summary.png), [E16](evidence/screenshots/16-suspicious-source-credential.png)

## 13. Validation and Scope

### 직접 확인한 것

- CSV 전체 이벤트 수와 Event Type 분포
- SSH login Source ranking
- `170.64.203.74`의 Username·Password·Credential pair 다양성
- 해당 Source의 약 20초대 반복 Login interval
- `exec_command` 규모, Session 수, Source 수
- exec Session에서 관찰된 `root` Credential 입력 조합
- `104.28.252.248`의 디렉터리 탐색 Session 흐름
- `47.251.118.172`의 외부 리소스 요청·저장·실행 시도 명령
- Evidence screenshot 파일 존재 여부와 문서 링크 대상

### 확인하지 못한 것

- SSH login 이벤트가 실제 인증 성공인지 여부
- `root`가 실제 운영 시스템의 유효 계정인지 여부
- 외부 연결, 다운로드, 파일 실행의 성공 여부
- 저장된 파일의 내용, 해시 및 악성코드 판정
- Honeypot 밖의 시스템에서 동일 Source·Credential이 사용되었는지 여부
- 실제 운영환경의 정상 Login 분포와 Rule 성능

### 추정하지 않은 것

- Source IP를 공격자의 실제 신원 또는 단일 조직으로 단정하지 않음
- Honeypot Credential 입력을 실제 계정 탈취로 표현하지 않음
- ATT&CK 매핑만으로 공격 성공 또는 악성 의도를 확정하지 않음

## 14. MITRE ATT&CK Mapping

| Technique ID | Technique Name | 적용 근거 |
|---|---|---|
| T1110.001 | Password Guessing | `170.64.203.74`가 여러 Username·Password 조합으로 SSH login을 반복한 정황 |
| T1059.004 | Unix Shell | `cd`, `ls`, `exit`, `bash` 등 Unix shell 명령 입력 |
| T1105 | Ingress Tool Transfer | `8.210.252.89:60147` 연결, `GET /linux`, `/tmp` 저장 및 실행 시도 명령 |

실제 유효 계정 사용이 확인되지 않았으므로 Valid Account 계열 매핑은 포함하지 않았습니다. 위 매핑은 관찰된 행위를 분류하기 위한 것이며 성공한 침해를 의미하지 않습니다.

## 15. False Positive Analysis

### 가능한 정상 원인

- 관리자의 비밀번호 반복 오입력
- 잘못된 Credential을 가진 자동화 운영 스크립트
- 승인된 보안 점검 또는 취약점 스캐너
- 배포·원격 관리 작업
- 정상적인 `curl`, `wget`, `chmod`, `/tmp` 사용
- NAT·프록시 뒤 여러 사용자가 공유하는 Source IP

### 구분에 필요한 추가 확인

- Source IP가 승인된 관리·점검 자산인지 여부
- 계정 소유자와 작업 담당자
- 해당 시간대의 승인된 작업 및 변경 티켓
- 평소 Source의 Login·Command 행동 패턴
- 외부 연결 및 후속 행위를 확인할 네트워크·Endpoint 로그

### 현재 판단의 한계

현재 CSV만으로는 `170.64.203.74`의 반복 Credential 입력을 정상 운영 작업으로 배제할 수 없습니다. 다만 여러 조합, 448건, 약 20초대 반복 간격은 자동화 정황을 강하게 지지합니다. `47.251.118.172`의 Session은 복수 명령 패턴이 결합되어 우선순위가 높지만, 실제 성공 결과는 별도 로그 확인이 필요합니다.

## 16. Detection Engineering

- **탐지 목표:** 반복적인 SSH Credential Guessing과 로그인 이후 수상한 명령 실행을 분리·상관분석
- **필요 필드:** `timestamp`, `session_id`, `ip`, `event_type`, `message`, `command`, `level`
- **Rule A:** 동일 Source IP의 `SSH login` 반복, Credential pair·Username 다양성, 시간 창을 조합
- **Rule B:** `exec_command`의 네트워크 연결·다운로드·파일 저장·실행 관련 명령 패턴 탐지
- **Rule C:** 동일 `session_id`에서 SSH login 이후 짧은 시간 내 Rule B 명령이 발생하는지 상관분석
- **Threshold / Time Window:** 초기값만 제안하며 운영 정상 분포 측정 후 조정
- **Allowlist:** 승인된 관리·점검 Source, 작업 시간대, 변경 티켓을 기반으로 제한적으로 적용

상세 조건과 튜닝 계획은 [detection/detection-rule.md](detection/detection-rule.md)에 기록했습니다.

## 17. Response Recommendation

이번 분석에서 실제 차단·격리·계정 변경을 수행한 것은 아닙니다. 다음은 후속 대응 권고입니다.

1. Source IP가 승인된 관리·점검 IP인지 확인합니다.
2. root 원격 로그인 정책, 비밀번호 정책 및 계정 잠금 정책을 점검합니다.
3. `47.251.118.172` Session의 외부 `8.210.252.89:60147` 통신 성공 여부를 다른 네트워크 로그와 대조합니다.
4. 비인가 Source라면 차단 또는 접근 제한을 검토합니다.
5. SSH 접근을 VPN 또는 관리망으로 제한하고 키 기반 인증 사용을 검토합니다.
6. 동일 Source·Credential이 다른 서버에서도 관찰되는지 조사합니다.
7. 동일 `session_id` 이후의 명령·네트워크·파일 이벤트를 추가 확인합니다.

## 18. Lessons Learned

- SSH connect 수보다 `SSH login`의 Credential pair 다양성과 반복 간격이 Credential Guessing 후보 선정에 유용했습니다.
- 반복 Credential 입력과 post-login command activity를 Source·Session 기준으로 분리해야 과도한 판단을 줄일 수 있습니다.
- `exec_command`의 단일 키워드보다 외부 연결, 파일 저장, 권한 변경, 실행 시도 조합이 우선순위 판단에 더 유용합니다.
- Honeypot에 입력된 `root`와 Password를 실제 운영 계정 탈취로 표현하지 않는 범위 통제가 중요합니다.
- 운영 적용 전 정상 관리 작업과 승인된 스캐너의 Source·시간대·변경 티켓을 수집해야 Rule Tuning이 가능합니다.
