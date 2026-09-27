# CASE-02 최종 결론

## Incident Summary

CASE-02는 145,425건의 SSH Honeypot 이벤트를 대상으로 SSH login Credential 입력과 post-login command activity를 분석한 사례입니다. 분석은 두 축으로 구분했습니다.

1. `170.64.203.74`의 반복 Credential Guessing 정황
2. 일부 다른 Source에서 확인된 로그인 이후 명령 실행 정황

## Key Evidence

| Evidence | 관찰된 사실 | 판단에서의 의미 |
|---|---|---|
| [E03](evidence/screenshots/03-top-login-source-ranking.png) | `170.64.203.74`에서 SSH login 448건 | 반복 Credential 입력 후보를 선정하는 직접 근거 |
| [E06](evidence/screenshots/06-login-interval-pattern.png) | 해당 Source의 Login interval이 약 20초대 | 자동화된 반복 시도 정황 보강 |
| [E15](evidence/screenshots/15-suspicious-session-summary.png) | `47.251.118.172` Session에서 login 이후 외부 요청·저장·실행 시도 명령 | Post-login command activity의 높은 우선순위 근거 |
| [E18](evidence/screenshots/18-exec-session-credential-ranking.png) | exec Session Credential 중 `root/test`가 11개 Session | Honeypot post-login 입력값 분포 확인 |

## Final Assessment

- **Observation:** `170.64.203.74`는 448건의 SSH login 입력에서 약 35개 Username, 약 177개 Password, 446개 Credential pair를 사용했습니다.
- **Confirmed Fact:** 해당 Source의 Login interval은 평균 약 19.7초, 중앙값 약 19.2초였고 `exec_command`는 확인되지 않았습니다.
- **Assessment:** 여러 Credential pair를 비교적 일정한 간격으로 반복한 자동화된 SSH Credential Guessing / Brute-force-style attack 정황이 강합니다.
- **Observation:** `47.251.118.172`의 동일 Session에서 `root / 123456` 입력 뒤 `/dev/tcp/8.210.252.89/60147`, `GET /linux`, `/tmp` 저장, `chmod +x`, 파일 실행 시도 및 `dd` 명령이 관찰되었습니다.
- **Assessment:** 외부 리소스를 받아 저장하고 실행하려는 명령 입력 정황으로 분류하며, 단순 반복 로그인보다 높은 조사 우선순위를 부여할 수 있습니다.
- **확인하지 않은 것:** 인증 성공, 실제 운영 계정 유효성, 외부 연결·다운로드·실행 성공, 악성코드 여부, 실제 root 계정 탈취 또는 시스템 침해 성공

## Limitations

- `SSH login` 이벤트만으로 인증 성공 여부를 독립적으로 확인하지 못했습니다.
- Honeypot에 입력된 `root`와 Password를 실제 운영 계정 또는 유효한 Credential로 단정하지 않았습니다.
- 외부 `8.210.252.89:60147` 연결 성공과 `/linux` 다운로드·실행 성공을 확인하지 않았습니다.
- 저장 파일의 내용·해시·악성코드 여부를 확인하지 않았습니다.
- 운영환경의 정상 관리 작업, 취약점 스캐너, 배포 작업과 직접 대조하지 않았습니다.
- Source IP의 실제 소유자·자산·조직을 확인하지 않았습니다.
- `root/eyble` 표기는 Evidence·분석 요약 기준이며, Raw CSV의 일부 행에는 `root/еуые`로 보이는 문자 표현 차이가 있습니다.

## False Positive

- 가능한 정상 원인: 관리자 비밀번호 오입력, 잘못된 Credential을 사용하는 운영 스크립트, 승인된 보안 점검, 취약점 스캐너, 배포·원격 관리 작업
- 명령 관련 정상 원인: 정상적인 `curl`, `wget`, `chmod`, `/tmp` 사용
- 확인해야 할 운영 맥락: Source 자산, 계정 소유자, 승인된 작업 여부, 작업 시간대, 변경 티켓, 평소 행동 패턴
- 현재 단계의 분류: `170.64.203.74`는 자동화 Credential Guessing 정황, `47.251.118.172`는 Suspicious Post-login Command Activity 정황. 운영 맥락과 외부 로그 확인 후 최종 사건 분류가 필요합니다.

## MITRE ATT&CK

- `T1110.001 Password Guessing`: 여러 Username·Password 조합의 반복 SSH login 입력
- `T1059.004 Unix Shell`: `cd`, `ls`, `exit`, `bash` 등 Unix shell 명령 입력
- `T1105 Ingress Tool Transfer`: 외부 `8.210.252.89:60147`의 `/linux` 리소스를 받아 저장·실행하려는 명령 입력 정황
- 실제 유효 계정 사용이 확인되지 않아 Valid Account 계열 매핑은 포함하지 않음

## Response Recommendation

1. Source IP가 승인된 관리·점검 IP인지 확인합니다.
2. root 원격 로그인 정책, 비밀번호 정책 및 계정 잠금 정책을 점검합니다.
3. `47.251.118.172` Session과 외부 `8.210.252.89:60147` 통신 성공 여부를 네트워크 로그와 대조합니다.
4. 비인가 Source라면 차단 또는 접근 제한을 검토합니다.
5. SSH 접근을 VPN 또는 관리망으로 제한하고 키 기반 인증 사용을 검토합니다.
6. 동일 Source와 Credential이 다른 서버에서도 관찰되는지 조사합니다.

위 항목은 대응 권고이며, 이번 Case에서 실제 차단·격리·계정 변경을 수행했다는 의미는 아닙니다.

## Lessons Learned

- Source ranking, Credential 다양성, Login interval을 함께 사용하면 단순 접속량보다 자동화 여부를 설명하기 쉽습니다.
- Login 이벤트와 post-login command를 Session 기준으로 분리하면 Credential Guessing과 후속 상호작용을 구분할 수 있습니다.
- 명령 키워드 하나만으로 악성 판정하지 않고 외부 연결·저장·권한 변경·실행 시도 조합을 확인해야 합니다.
