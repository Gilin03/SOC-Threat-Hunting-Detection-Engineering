# SOC-Portfolio

네트워크 보안 분석 과정을 Case 단위로 기록하기 위한 포트폴리오 저장소입니다.
각 Case는 분석 질문, 원본 데이터, 관찰 근거, 판단 과정, 탐지 아이디어와 대응 권고를 추적 가능하게 정리합니다.

## 프로젝트 목적

- 여러 네트워크 보안 분석 Case를 동일한 형식으로 축적
- Wireshark 분석 과정과 판단 근거를 Evidence 중심으로 기록
- 분석 전 가설과 분석 후 결론을 구분
- 실제 관찰 전에는 공격자 IP, 피해자 IP, 포트, 패킷 수, 최종 판정을 추측하지 않음

## Case 목록

| Case ID | 제목 | 데이터셋 | 상태 | 문서 |
|---|---|---|---|---|
| CASE-01 | Port Scan 네트워크 트래픽 분석 | CIC-IDS2017 / Friday-WorkingHours.pcap | 분석 완료 | [Case 01](cases/case01-portscan/README.md) |

새로운 Case는 docs/case-template.md를 복사하여 cases/ 아래에 추가합니다.

## 분석 방식

1. 데이터셋 출처와 파일 무결성·식별 정보를 기록합니다.
2. 초기 관찰과 분석 질문을 분리하여 작성합니다.
3. Wireshark Display Filter와 관찰 결과를 시간순으로 기록합니다.
4. 각 판단은 Evidence ID와 연결합니다.
5. IOC, MITRE ATT&CK 매핑, 탐지 아이디어, 대응 권고를 분석 결과에 근거하여 작성합니다.
6. 분석을 완료하기 전까지 미확인 값은 미분석, TBD 또는 빈칸으로 둡니다.

## 사용 예정 도구

- Wireshark
- 텍스트 편집기 또는 Markdown 편집기
- 필요 시 스프레드시트 등 분석 기록 보조 도구

도구 버전과 사용 시각은 해당 Case 문서에 기록합니다.

## Evidence 중심 기록 원칙

- 관찰한 사실, 해석, 가설, 최종 판단을 구분합니다.
- 분석 주장을 가능한 한 패킷, 필터 결과, 화면 캡처 또는 원본 데이터의 근거와 연결합니다.
- Screenshot은 cases/<case-id>/evidence/screenshots/에 저장하고 Evidence ID로 연결합니다.
- PCAP 원본은 저장소에 커밋하지 않습니다. CIC-IDS2017 공식 출처에서 직접 다운로드한 뒤 로컬의 Case evidence/pcap/ 폴더에 보관합니다.

## 데이터셋 출처 및 다운로드

- 출처: CIC-IDS2017, Canadian Institute for Cybersecurity
- 대상 파일: Friday-WorkingHours.pcap
- 다운로드 방법: 공식 데이터셋 배포 페이지에서 파일을 다운로드하여 cases/case01-portscan/evidence/pcap/에 직접 저장합니다.
- 저장소 정책: 대용량 PCAP 파일은 GitHub에 업로드하지 않습니다. 관련 확장자는 .gitignore에서 제외합니다.
