# CASE-02 복습 가이드

이 문서는 CASE-02의 분석 흐름과 판단 근거를 빠르게 복습하기 위한 요약 자료입니다.
상세 근거와 전체 Evidence 목록은 `analysis.md`, `conclusion.md`, `notes/investigation-notes.md`를 기준으로 확인합니다.

## 1. 한 문장 요약

SSH Honeypot 이벤트에서 반복 Credential 입력과 로그인 이후 명령 활동을 분리해 분석한 결과, 자동화된 SSH Credential Guessing 정황과 별도 Session의 Suspicious Post-login Command Activity 정황을 확인했습니다.

단, 인증 성공, 실제 운영 계정 유효성, 외부 연결·다운로드·실행 성공 및 시스템 침해 성공은 확인하지 않았습니다.

## 2. 반드시 기억할 핵심 사실

| 구분 | 관찰된 사실 | 판단에서의 의미 |
|---|---|---|
| Dataset | 145,425건의 SSH Honeypot 이벤트 | SSH login과 `exec_command`를 분리해 분석 |
| Credential Guessing 후보 | `170.64.203.74`에서 SSH login 448건 | 반복 입력 Source 후보 선정 |
| Credential 다양성 | 약 35개 Username, 약 177개 Password, 446개 pair | 단일 계정 오입력보다 자동화 정황을 보강 |
| 반복 간격 | 평균 약 19.7초, 중앙값 약 19.2초 | 일정한 반복 패턴 확인 |
| Post-login 규모 | `exec_command` 28건, 16개 Session, 7개 Source IP | 로그인 이후 활동을 별도 축으로 분석 |
| 수상 Session | `47.251.118.172`의 Session `9caa7e8b-7378-41b7-9bdd-4ae800e2466e` | 명령 활동의 우선 조사 대상 |

## 3. 두 가지 분석 축

### A. 자동화된 SSH Credential Guessing

- Source: `170.64.203.74`
- SSH login 448건
- 여러 Username·Password 조합 반복
- 약 20초대의 일정한 Login interval
- 해당 Source에서는 `exec_command`가 확인되지 않음

따라서 이 Source는 **자동화된 Credential Guessing 정황**으로 분류했습니다. SSH login 이벤트만으로 인증 성공을 의미하지는 않습니다.

### B. 로그인 이후 수상한 명령 활동

- Source: `47.251.118.172`
- Session: `9caa7e8b-7378-41b7-9bdd-4ae800e2466e`
- 관찰된 입력: `root / 123456`
- 주요 패턴: `/dev/tcp/8.210.252.89/60147`, `GET /linux`, `/tmp`, `chmod +x`, 실행 시도, `dd`

따라서 이 Session은 **Suspicious Post-login Command Activity 정황**으로 분류했습니다. 외부 연결이나 파일 실행이 실제로 성공했는지는 확인하지 않았습니다.

## 4. 분석 흐름 복습

```text
Dataset 구조 확인
→ Event Type 분리
→ SSH login Source ranking
→ Username·Password·Credential pair 집계
→ Login interval 분석
→ exec_command Source·Session 확인
→ Session timeline 비교
→ IOC·MITRE ATT&CK·Detection Rule 작성
→ False Positive와 한계 정리
```

분석에서 중요한 기준은 다음과 같습니다.

1. `SSH login`과 `exec_command`를 같은 의미로 보지 않습니다.
2. Source IP를 실제 공격자 신원으로 단정하지 않습니다.
3. Honeypot에 입력된 Credential을 실제 운영 Credential로 해석하지 않습니다.
4. 단일 명령 키워드만으로 악성 행위라고 판단하지 않습니다.
5. 관찰 사실, 분석 해석, 최종 판단을 분리합니다.

## 5. Evidence 복습

| Evidence | 복습할 내용 |
|---|---|
| [E03](../evidence/screenshots/03-top-login-source-ranking.png) | 최다 SSH login Source와 448건 집계 |
| [E04](../evidence/screenshots/04-top-source-username-ranking.png) | Source별 Username 다양성 |
| [E05](../evidence/screenshots/05-top-source-password-ranking.png) | Source별 Password 다양성 |
| [E06](../evidence/screenshots/06-login-interval-pattern.png) | 반복 Login interval과 자동화 정황 |
| [E14](../evidence/screenshots/14-suspicious-session-timeline.png) | 수상 Session의 이벤트 순서 |
| [E15](../evidence/screenshots/15-suspicious-session-summary.png) | 외부 요청·저장·권한 변경·실행 시도 요약 |
| [E18](../evidence/screenshots/18-exec-session-credential-ranking.png) | `exec_command` Session의 Credential 분포 |

## 6. MITRE ATT&CK 복습

| Technique | 연결한 근거 | 주의할 점 |
|---|---|---|
| `T1110.001 Password Guessing` | 여러 Username·Password 조합의 반복 SSH login 입력 | 인증 성공을 의미하지 않음 |
| `T1059.004 Unix Shell` | SSH Session에서 관찰된 Unix shell 명령 | 명령 입력만으로 실행 성공을 의미하지 않음 |
| `T1105 Ingress Tool Transfer` | 외부 `/linux` 리소스를 받아 저장·실행하려는 명령 입력 정황 | 다운로드·실행 성공은 별도 검증 필요 |

실제 유효 계정 사용이 확인되지 않아 Valid Account 계열 매핑은 포함하지 않았습니다.

## 7. Detection Rule 복습

### Rule A — SSH Credential Guessing

```text
event_type == "SSH login"
AND 동일 Source
AND 5분 이내
AND SSH login 10회 이상
AND 고유 Username 또는 Credential pair 3개 이상
```

### Rule B — Suspicious SSH Command Activity

`exec_command`의 `command` 또는 `message`에서 다음 패턴을 수집합니다.

- `/dev/tcp`
- `wget`
- `curl`
- `chmod +x`
- `/tmp`
- `nohup bash`

단일 키워드보다 외부 연결, Resource 요청, 파일 저장, 권한 변경·실행이 함께 나타나는 경우 우선순위를 높입니다.

### Rule C — Credential + Post-login Correlation

```text
동일 session_id
AND SSH login 이후
AND 5분 이내 exec_command
AND 수상한 Command pattern 일치
```

현재 Threshold와 Alert 성능은 운영환경의 정상 데이터로 검증하지 않았습니다. 따라서 위 값은 최종 운영 Rule이 아니라 초기 Rule입니다.

## 8. False Positive 복습

다음 정상 행위가 탐지 대상이 될 수 있습니다.

- 관리자의 비밀번호 반복 오입력
- 잘못된 Credential을 사용하는 운영 스크립트
- 승인된 보안 점검 또는 취약점 스캐너
- 배포·원격 관리 작업
- 정상적인 `curl`, `wget`, `chmod`, `/tmp` 사용
- NAT 또는 프록시 뒤의 공유 Source IP

확인해야 할 운영 Context는 Source 자산, 계정 소유자, 승인 작업, 변경 티켓, 작업 시간대, 평소 행동 패턴입니다.

## 9. 자기 점검 질문

1. 왜 `170.64.203.74`를 Credential Guessing 후보로 선정했는가?
2. Login interval은 공격 판단에서 어떤 역할을 했는가?
3. 왜 `170.64.203.74`의 Credential Guessing과 `47.251.118.172`의 명령 활동을 분리했는가?
4. SSH login 이벤트만으로 인증 성공을 판단할 수 없는 이유는 무엇인가?
5. `exec_command`를 Session ID와 연결한 이유는 무엇인가?
6. `/dev/tcp`, `/tmp`, `chmod +x`를 단독으로 악성 판정하지 않는 이유는 무엇인가?
7. Rule A의 5분·10회·3개 조건은 최종값인가, 초기값인가?
8. `T1110.001`, `T1059.004`, `T1105`를 각각 어떤 관찰 근거에 매핑했는가?
9. 실제 침해 성공을 확인하려면 어떤 네트워크·Endpoint 로그가 추가로 필요한가?
10. 운영환경에서 False Positive를 줄이기 위해 어떤 Context를 추가해야 하는가?

## 10. 30초 답변 템플릿

> SSH Honeypot 로그를 Event Type과 Session 기준으로 분리해 분석했습니다. `170.64.203.74`에서는 448건의 SSH login과 다수 Credential pair가 약 20초대 간격으로 반복되어 자동화된 Credential Guessing 정황으로 판단했습니다. 별도로 `47.251.118.172`의 Session에서는 외부 요청, `/tmp` 저장, 권한 변경과 실행 시도 명령이 관찰되어 post-login activity 우선 조사 대상으로 분류했습니다. 다만 인증 성공, 외부 연결·다운로드·실행 성공 및 실제 침해 여부는 확인하지 않았습니다.

## 참고 문서

- [상세 분석](../analysis.md)
- [최종 결론](../conclusion.md)
- [조사 메모](investigation-notes.md)
- [Detection Rule](../detection/detection-rule.md)
- [IOC](../IOC.csv)
