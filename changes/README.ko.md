# changes/

[English](README.md) | 한국어

변경마다 이곳에 폴더가 하나씩 생기며, 폴더 이름은 ID와 짧은 slug로 정합니다. 예: `CHG-0001-block-sign-in/`. 한 번에 하나의 변경만 열 수 있습니다.

이 폴더는 증거입니다. 생성기는 이 안에 아무것도 만들거나 지우지 않으며, `cab setup uninstall`은 이 폴더를 그대로 둡니다. 이 저장소의 이 폴더에는 실제 변경이 없습니다. 모든 예시는 가상의 Contoso 데이터입니다.

이 한국어판은 이 저장소에서 읽기 위한 것입니다. 생성된 프로젝트에는 영문 `changes/README.md`만 처음 적용할 때 한 번 만들어지며, 이 한국어판은 복사되지 않습니다.

## 변경 폴더의 파일

| 파일 | 작성 주체 | 내용 |
|---|---|---|
| `intake.md` | 사람이 자기 터미널에서 실행하는 `cab intake CHG-NNNN`. 또는 `cab intake CHG-NNNN --from-file PATH`로, 이 경우 픽스처로 기록되며 헤드리스 테스트 전용입니다. 메인 세션은 이 파일을 절대 쓰지 않습니다. | 목적, 범위, 범위 밖 항목, 시점, 알려진 의존 대상, 성공 기준 |
| `change.toml` | `runbook-author` 서브에이전트 | 기계용 계획: 등급(tier) 답변, 테넌트 상태 범위, 정확한 대상이 정해진 단계, 대상마다 하나의 검증 프로브, 롤백 명령 |
| `plan.md` | `runbook-author` 서브에이전트 | 사람을 위한 계획과 그 이유 |
| `targets.csv` | 메인 세션, 읽기 전용 조회 결과로 작성 | 정확하고 변하지 않는 대상 ID. 필터가 아니라 목록 |
| `impact.md` | 메인 세션, `impact-analyst` 보고서로 작성 | 읽기 전용 프로브로 찾은 의존 대상과 위험 |
| `snapshot.json` | `cab snapshot` | 쓰기 전 모든 대상의 현재 값 |
| `review.json` | SubagentStop 훅 | 계획 해시에 묶인 `safety-reviewer` 판정과 발견 사항 |
| `approval.json` | 사람이 터미널에서 실행하는 `cab approve` | 계획과 검토에 묶인 승인. 만료 시각 포함 |
| `verify.json` | `cab verify` | 대상별 관찰 값, 시도 횟수, 결과(PASS, FAIL 또는 UNMEASURED) |
| `record.md` | `recorder` 서브에이전트 | 무엇을 왜 바꿨는지, 검증 표, 되돌리는 방법, 교훈 하나 |

거부 규칙(deny rules)과 guard는 에이전트가 `snapshot.json`, `review.json`, `approval.json`, `verify.json`을 쓰지 못하게 막습니다.

## 파일에서 따라 나오는 규칙

- **계획 해시는 `change.toml`, `plan.md`, `targets.csv`를 포함합니다.** 이 중 하나라도 수정하면 검토, 승인, 스냅샷이 지워집니다.
- **대상은 `targets.csv`에서만 옵니다.** `targets.csv`에 없는 ID에 대한 쓰기는 거부됩니다.
- **쓰기가 이루어진 모든 대상이 PASS일 때만 변경이 성공으로 닫힙니다.** FAIL이면 실패로 닫힙니다. UNMEASURED가 하나라도 있으면 검증되지 않은 상태로 열려 있으며, 사람이 실행해야 할 명령이 함께 표시됩니다.

상태 머신 자체는 `.cab/state/`에 있습니다. 보호되어 있으며, 손으로 편집하도록 만든 것이 아닙니다.
