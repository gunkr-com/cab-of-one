# 프로필 스키마 (`profile.toml`, schema 1)

[English](schema.md) | **한국어**

> 이 문서는 [schema.md](schema.md)의 한국어판입니다. 필드 이름, 값, 오류 코드는 영어 그대로입니다.

프로필은 설정 인터뷰의 답을 기록합니다. 생성기는 이를 프로젝트 파일로 바꿉니다. 프로필은
통제를 더 엄격하게 하거나 여러분이 쓰는 시스템에 맞출 수 있습니다. 통제를 끌 수는 없습니다.
핵심 하한을 끄는 필드는 없으며, 로더는 알 수 없는 키를 거부합니다.

로더: `cab_of_one.setup.profile.load_profile(path_or_bytes)`.

## 일반 규칙

- `schema = 1`과 아래의 모든 테이블과 키가 필수입니다. 알 수 없는 키, 빠진 키, 중복된
  키나 테이블은 거부됩니다.
- 불리언은 `true`/`false`여야 하고 정수는 맨 정수여야 합니다. `1`은 `true`가 아니며,
  `true`는 `1`이 아닙니다.
- 목록에 같은 항목이 반복되면 안 됩니다. 순서는 상관없습니다. 목록은 정렬되어 저장됩니다.
- 파일은 바이트 순서 표시(BOM) 없는 UTF-8이며 최대 64 KiB입니다.
- 오류는 값이 아니라 필드를 지목합니다(예: `bad_choice: session.permission_mode`).

## 필드

| 필드 | 유형 | 허용 값 | 효과 |
|---|---|---|---|
| `org.name` | string | 1–64자: 문자, 숫자, 공백, `. & , ' -`; 문자나 숫자로 시작하고, 문자, 숫자 또는 `.`로 끝남 | 생성되는 설명문에만 사용(`$org_name`) |
| `org.it_team` | enum | `solo`, `small` | 설명문에만 사용 |
| `systems.entra` | bool | | M365 PowerShell 및 Graph 어댑터 |
| `systems.exchange_online` | bool | | M365 PowerShell 및 Graph 어댑터 |
| `systems.intune` | bool | | M365 PowerShell 및 Graph 어댑터 |
| `systems.sharepoint_teams` | bool | | M365 PowerShell 및 Graph 어댑터 |
| `systems.azure` | bool | | Azure CLI 어댑터 |
| `systems.demo_simtenant` | bool | 참조 프로필에서만 `true` | simtenant 어댑터, 데모 파일, 신뢰된 데모 스크립트 |
| `surfaces.powershell_modules` | 문자열 목록, ≤ 16 | `Microsoft.Graph` 같은 점으로 구분된 모듈 이름 | M365 PowerShell 어댑터 |
| `surfaces.azure_cli` | bool | | Azure CLI 어댑터 |
| `surfaces.graph_http` | bool | | Graph HTTP 어댑터 |
| `surfaces.mcp_write_servers` | 문자열 목록, ≤ 64 | `[A-Za-z0-9_-]{1,64}` | 이 MCP 서버들의 모든 도구가 관리 쓰기로 분류됨 |
| `identity.agent_identity` | enum | `read-only`, `admin` | `admin`은 설정 알림을 추가 |
| `identity.deny_read_paths` | 문자열 목록, ≤ 32 | `./` 뒤에 `A–Z a–z 0–9 . _ * -`로 된 구성 요소; `.`나 `..` 구성 요소, 절대 경로나 `~` 경로, 공백 불가, ≤ 200자 | `Read(<path>)` 거부 규칙 |
| `approval.approvers` | enum | `self`, `named` | `named`는 렌더링 시 거부됨(아직 지원하지 않음) |
| `approval.approval_ttl_hours` | int | 1–24 | `policy.toml`의 승인 유효 기간 |
| `session.permission_mode` | enum | `manual`, `bypass-guarded`, `auto` | `manual`은 프로젝트에서 bypass 권한 모드를 끔. 나머지는 설정 알림을 추가 |
| `session.git` | bool | | `false`면 `git init`을 직접 실행하라는 알림을 추가 |
| `session.multi_machine` | bool | | 인계(handoff) 알림 |
| `session.sync_folder` | bool | | 동기화 폴더는 원장을 고정할 수 없다는 알림 |
| `session.ticketing` | enum | `none`, `planner`, `jira`, `servicenow`, `other` | `none` 외의 값은 렌더링 시 거부됨(아직 지원하지 않음) |
| `changes.routine` | enum 목록 | `forwarding-removal`, `group-add-allowlisted`, `joiner-license-group`, `leaver-block-signin` | `policy/standard-changes.toml`의 주석 처리된 제안. 결코 활성 항목이 아님 |
| `changes.extra_critical` | enum 목록 | `admin-units`, `break-glass`, `executive-mailboxes`, `finance-groups` | `policy/policy.toml`의 주석 처리된 자리표시자. `break-glass`는 항상 나열됨 |

시스템이나 쓰기 표면(surface)이 최소 하나는 설정되어야 합니다. 그렇지 않으면 프로필이
거부됩니다(`no_write_surface`).

## 데모

`systems.demo_simtenant = true`는 알려진 참조 프로필을
`load_reference_profile(name, source_root)`로 로드할 때만 허용됩니다. 현재 참조 프로필은
`contoso-solo` 하나뿐입니다. `load_profile`은 다른 모든 프로필에서 이 필드를 거부합니다
(`demo_requires_reference`). 렌더러도 같은 규칙을 확인하며, 데모를 요청하지 않은 프로필에
데모를 추가하려는 규칙도 거부합니다.

## 모든 프로필이 받는 것(하한)

하한은 답과 상관없이 생성됩니다.

- 보호 경로와 사람 전용 `cab` 명령에 대한 거부 규칙;
- `onFailure: "block"`이 설정된 PreToolUse 및 ConfigChange 훅, 그리고 Stop 훅.
  `onFailure`는 Stop에 효과가 없으므로, Stop 훅이 충돌하거나 시간 초과되면 턴이 끝납니다.
  [위협 모델](../docs/threat-model.ko.md)을 참조하십시오;
- 감사 훅과 SessionStart 자체 테스트;
- 고정된 훅 항목과 런타임;
- 도구가 명시된 에이전트 5개(`safety-reviewer`: Read, Grep, Glob만);
- 핵심 스킬 5개;
- `CLAUDE.md` 블록;
- 활성 변경 하나, critical 카나리(canary), 실패 시 중단을 유지하는 정책.

## 참조 프로필

- `contoso-solo.toml`: 1인 IT 팀, Microsoft 365, Intune, Azure, 여러 대의 컴퓨터,
  가드레일 안에서의 bypass 모드. 가상입니다.
- `contoso-team.toml`: 보류. 지정 승인자와 티켓 연동이 필요한데, 둘 다 아직 렌더링할 수
  없습니다.
