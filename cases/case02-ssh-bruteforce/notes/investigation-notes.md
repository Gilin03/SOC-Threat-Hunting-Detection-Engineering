# CASE-02 Investigation Notes

실제 조사 흐름을 Evidence 순서와 CSV 구조에 맞춰 정리한 메모입니다. Observation과 Assessment를 분리하고, Honeypot에 입력된 Credential과 명령을 실제 운영 계정·침해 성공으로 확장하지 않습니다.

## Investigation Timeline

| Step | 확인한 내용 | 사용 도구/필터 | 결과 | 다음 행동 |
|---|---|---|---|---|
| 01 | Dataset 개요와 원본 구조 확인 | `ssh_attacks_full.csv`, Event Type 집계 | 145,425 events, 9개 컬럼, 13,897 Source IP, 137,506 Session | Event Type별 분석 범위 분리 |
| 02 | Event Type 분포 확인 | `event_type` grouping | SSH login 4,797, exec_command 28 | Credential과 post-login을 별도 분석 |
| 03 | SSH login Source ranking 확인 | `event_type == SSH login`, `ip` grouping | `170.64.203.74`가 448건으로 최다 | 해당 Source Credential 다양성 확인 |
| 04 | Username·Password ranking 확인 | login message의 Credential 추출 | 약 35 Username, 약 177 Password, 446 pair | 반복 간격 확인 |
| 05 | Login interval 확인 | Source별 timestamp 정렬 | 평균 약 19.7초, 중앙값 약 19.2초 | 자동화 정황으로 평가 |
| 06 | 최다 Source의 post-login 여부 확인 | Source + `event_type == exec_command` | `170.64.203.74`의 exec_command 없음 | Credential Guessing과 post-login을 분리 |
| 07 | exec_command 규모 확인 | `event_type == exec_command` grouping | 28 events, 16 Sessions, 7 Source IPs | Session Credential 연결 |
| 08 | exec Session Credential 확인 | 동일 `session_id`의 SSH login 연결 | Username은 모두 root, root/test가 11 Session | 일반 Session과 수상 Session 비교 |
| 09 | 일반 post-login Session 확인 | Source `104.28.252.248`, 동일 Session timeline | cd/ls/exit 중심의 디렉터리 탐색 | 악성 단정 없이 context로 기록 |
| 10 | 수상 Session 확인 | Session `9caa7e8b-7378-41b7-9bdd-4ae800e2466e` | 외부 연결·GET·/tmp 저장·chmod·실행 시도·dd | Rule B/C 및 대응 우선순위 작성 |
| 11 | MITRE 후보 정리 | 관찰된 Credential·Shell·Transfer 행위 | T1110.001, T1059.004, T1105 | 유효 계정 근거가 없어 Valid Account 계열은 제외 |
| 12 | 탐지 Rule 방향 정리 | Source·Session·Command 상관관계 | Rule A/B/C 초기 조건 작성 | 운영 정상 데이터로 Tuning 필요 |

## Observation

- 직접 관찰한 사실: `170.64.203.74`의 SSH login 448건, 다수 Credential pair, 약 20초대 반복 간격
- 직접 관찰한 사실: `exec_command` 28건, 16 Sessions, 7 Source IPs, 모두 root Username 입력
- 직접 관찰한 사실: `47.251.118.172`의 Session에서 외부 `/dev/tcp` 요청과 `/tmp` 저장·실행 시도 명령
- Evidence: [E03](../evidence/screenshots/03-top-login-source-ranking.png), [E06](../evidence/screenshots/06-login-interval-pattern.png), [E15](../evidence/screenshots/15-suspicious-session-summary.png)

## Hypothesis

- 가설 1: `170.64.203.74`는 사람이 수동으로 여러 Credential을 입력한 것이 아니라 자동화된 Credential Guessing을 수행했을 가능성이 높다.
- 가설 1의 근거: 높은 login 반복량, 약 20초대 간격, 다수 Username·Password·pair
- 가설 2: 일부 SSH login은 단순 입력이 아니라 post-login command activity로 이어졌다.
- 가설 2의 근거: 동일 Session의 SSH login 뒤 `exec_command` 발생
- 아직 가설인 부분: 인증 성공 여부, 실제 계정 유효성, 외부 연결·다운로드·실행 성공, 침해 성공

## Verification

- 검증 방법: Event Type·Source·Session grouping, login message Credential 추출, timestamp interval 비교, 동일 Session event order 확인
- 확인한 결과: `170.64.203.74`는 exec_command 없이 Credential 입력 패턴만 확인됨
- 확인한 결과: `47.251.118.172`의 동일 Session에서 login 직후 수상한 명령 패턴 확인
- 가설을 지지한 Evidence: [E04](../evidence/screenshots/04-top-source-username-ranking.png), [E05](../evidence/screenshots/05-top-source-password-ranking.png), [E14](../evidence/screenshots/14-suspicious-session-timeline.png)

## Decision

- 다음 판단 또는 분류: `170.64.203.74`는 Automated SSH Credential Guessing 정황, `47.251.118.172`는 Suspicious Post-login Command Activity 정황
- 판단 근거: 반복 Credential pair·interval, 동일 Session의 login→command 순서, 복수 수상 명령 범주 결합
- 보류한 내용: 성공 인증, 실제 운영 계정, 외부 연결·다운로드·실행 성공, 악성코드 여부, 시스템 침해
- 다음 조사 단계: Source 자산·승인 작업 확인, 네트워크 연결 대조, Endpoint 파일·프로세스 로그 대조

## Evidence Register

| Evidence ID | 경로 또는 식별자 | 확인 내용 | 최종 문서 반영 |
|---|---|---|---|
| E01 | `evidence/screenshots/01-dataset-overview.png` | Dataset 및 CSV 구조 | README / analysis |
| E02 | `evidence/screenshots/02-event-type-summary.png` | Event Type 분포 | analysis |
| E03 | `evidence/screenshots/03-top-login-source-ranking.png` | SSH login Source ranking | README / analysis / conclusion |
| E04 | `evidence/screenshots/04-top-source-username-ranking.png` | Source별 Username 분포 | analysis |
| E05 | `evidence/screenshots/05-top-source-password-ranking.png` | Source별 Password 분포 | analysis |
| E06 | `evidence/screenshots/06-login-interval-pattern.png` | 반복 Login interval | README / analysis / conclusion |
| E07 | `evidence/screenshots/07-exec-command-check.png` | exec_command 존재 여부 | analysis |
| E08 | `evidence/screenshots/08-exec-command-source-ranking.png` | exec Source ranking | analysis |
| E10 | `evidence/screenshots/10-session-timeline.png` | 일반 Session timeline | README / analysis |
| E13 | `evidence/screenshots/13-payload-download-command.png` | 외부 요청·저장·실행 시도 명령 | README / analysis |
| E14 | `evidence/screenshots/14-suspicious-session-timeline.png` | 의심 Session 순서 | analysis |
| E15 | `evidence/screenshots/15-suspicious-session-summary.png` | 의심 Session 요약 | README / conclusion |
| E16 | `evidence/screenshots/16-suspicious-source-credential.png` | 의심 Source Credential | analysis |
| E18 | `evidence/screenshots/18-exec-session-credential-ranking.png` | exec Session Credential ranking | README / analysis |

## 조사 메모 작성 원칙

- Observation과 해석·가설을 한 문장에 섞지 않습니다.
- Source IP를 실제 공격자 신원으로 단정하지 않습니다.
- Honeypot Credential 입력을 실제 운영 Credential 탈취로 표현하지 않습니다.
- 단일 명령 키워드만으로 악성 판정하지 않습니다.
- 운영 검증 전의 Threshold는 초기값으로만 기록합니다.
