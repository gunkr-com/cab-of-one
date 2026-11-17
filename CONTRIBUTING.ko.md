# 기여 안내 (Contributing)

[English](CONTRIBUTING.md) | 한국어

관심을 가져 주셔서 감사합니다. 이 프로젝트는 Claude Code 시뮬레이터 프리뷰입니다. 기여 작업을 시작하기 전에, 먼저 이슈를 열어 제안하려는 내용을 논의해 주세요.

## 커밋에 서명하기 (DCO)

모든 커밋에는 [Developer Certificate of Origin](https://developercertificate.org/)에 따른 `Signed-off-by` 줄이 있어야 합니다. 다음을 사용하세요.

```sh
git commit -s
```

기여자 라이선스 동의서(CLA)는 없습니다.

## 시작하기 전에

- 새 어댑터, 새 쓰기 표면(write surface) 또는 큰 변경은 먼저 이슈를 여세요.
- guard, 등급 하한(tier floor), 정책 스키마, 훅, 승인, 검증 또는 생성기의 병합 규칙을 바꾸는 경우, 같은 풀 리퀘스트에 새 단위 테스트나 수정된 단위 테스트가 있어야 합니다.
- 게이트(guard, 승인, intake, Stop 훅 또는 검증)를 바꾸는 경우, `evals/` 아래 러너로 얻은 관련 에이전트 수준 결과도 필요합니다([evals/results/latest.md](evals/results/latest.md) 참고, 원자료는 영문).
  - FAIL, INCONCLUSIVE, ERROR를 포함해 모든 시도를 보고하세요. 재시도하거나 시도를 빼지 마세요.
  - 사용한 Claude Code 버전과 모델을 밝히세요.
  - 에이전트 수준 실행은 본인의 Claude Code 로그인과 모델 사용량을 씁니다. 로컬에서 실행하며 CI에 포함되지 않습니다.

## 실제 데이터를 절대 넣지 마세요

이슈, 풀 리퀘스트, 테스트, 픽스처에 실제 테넌트 ID, 도메인, 사용자 이름, 이메일 주소, 호스트 이름, IP 주소, 토큰, 대화 기록(transcript), 원장(ledger) 줄을 넣지 마세요. `simtenant/`의 가상 Contoso 데이터를 쓰거나, 같은 방식으로 새 가상 데이터를 만드세요.

## 범위 밖

다음은 받아들이지 않습니다.

- 자동 승인, 또는 승인, 검토, 스냅샷, 검증을 건너뛰는 모든 스위치
- 생성되는 통제 하한(floor)을 낮추거나 끄는 프로필 필드나 옵션
- UNMEASURED를 PASS로 취급하는 것
- 생성기나 테스트에서 실제 테넌트에 연결하는 어댑터나 예시

## 코드와 테스트

- 런타임과 생성기는 Python 3.11+ 표준 라이브러리만 사용합니다. `pytest`와 `ruff`는 개발 도구입니다.
- 테스트는 체크아웃 안의 픽스처와 임시 폴더를 사용해야 합니다. 네트워크, 실제 테넌트, 실제 Claude Code 설정, 실제 대화 기록에 닿으면 안 됩니다.
- 풀 리퀘스트를 열기 전에 다음을 실행하세요.

  ```sh
  python3 -m pytest -q
  ruff check .
  ruff format --check .
  ```

- 단위 테스트를 엔드투엔드(end-to-end) 증거나 에이전트 수준 증거라고 설명하지 마세요. 실제로 무엇을 실행했는지 쓰세요.

## AI 지원 기여

환영합니다. 제출하는 모든 줄은 본인이 책임지므로, 직접 쓴 것처럼 읽고 테스트하세요.

## 보안 문제

취약점은 공개 이슈로 올리지 마세요. [SECURITY.ko.md](SECURITY.ko.md)(영문 원본: [SECURITY.md](SECURITY.md))를 따르세요.

## 행동 강령

[행동 강령](CODE_OF_CONDUCT.ko.md)을 따라 주세요. 행동 문제에 대한 비공개 신고 연락처는 영문 원본 [CODE_OF_CONDUCT.md의 Enforcement 절](CODE_OF_CONDUCT.md#enforcement)에 있으며, 그곳에 적힌 주소가 신고 연락처입니다. 한국어 문서에는 그 주소를 다시 적지 않습니다.

## 상표

Claude와 Claude Code는 Anthropic의 상표입니다. Microsoft 365, Entra ID, Exchange Online, Intune, Azure는 Microsoft의 상표입니다. 이 프로젝트는 Anthropic, Microsoft 또는 Harness Inc.와 제휴 관계가 없으며, 이들의 보증을 받지 않았습니다.
