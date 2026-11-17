# 릴리스와 공개 전 검사 (Releasing and publication checks)

[English](releasing.md) | 한국어

이 검사들은 비밀 정보, 식별자, 비공개 이름이 공개 저장소에 들어가지 않게 합니다. CI는 모든
push와 pull request에서 공개 검사를 실행합니다. 관리자는 매번 push하기 전에 로컬에서 비공개
검사를 실행합니다. 게이트 로직, 병합 규칙, 공개 문서, 첫 push는 여전히 사람이 검토합니다. 여기의
어떤 검사도 그 검토를 대신하지 않습니다.

## 어디서 무엇이 실행되는가

| 검사 | CI(공개) | 로컬 pre-push(선택 사항) |
|---|---|---|
| Linux와 macOS, Python 3.11과 3.14에서 `pytest`, `ruff check`, `ruff format --check` | 예 | 직접 실행 |
| 식별자 스캔, 일반 규칙(`scripts/check_identifiers.py`) | 작업 트리 후보 | 작업 트리, push되는 모든 커밋, push되는 모든 원격 ref 이름 |
| 식별자 스캔, 비공개 거부 목록(denylist) | 실행하지 않음 | 예, 필수(같은 범위) |
| 커밋 메시지와 author/committer 신원(GitHub noreply) | 아니요 | push되는 모든 커밋 |
| gitleaks 이력(`gitleaks git --redact --log-opts="--all -m"`) | 예 | 예 |
| 내보낸 후보에 대한 gitleaks(`gitleaks dir --redact`) | 예 | 예(HEAD 트리) |
| DCO 서명(`scripts/check_dco.py`) | 모든 새 커밋, 병합 커밋 포함 | 직접 실행 |

CI와 훅의 모든 gitleaks 호출은 `--ignore-gitleaks-allow`도 함께 넘기므로, 인라인
`gitleaks:allow` 주석은 아무것도 억제하지 않습니다. 이력 스캔의 `-m`은 gitleaks가 병합 커밋의
diff도 읽게 합니다.

`.gitleaksignore` 파일을 통한 fingerprint 억제는 플래그가 아니라 그런 파일을 거부하는 방식으로
막습니다. gitleaks 8.30.1은 `--gitleaks-ignore-path /dev/null`을 넘겨도 스캔 대상의 루트에 있는
`.gitleaksignore`를 항상 읽습니다. 그래서 훅과 CI는 다음 위치에 `.gitleaksignore`가 하나라도
있으면 막는 사전 검사(preflight)를 실행합니다.

- 공개 후보 또는 그 내보낸 사본 안
- push되거나 스캔되는 모든 커밋 안
- 물리적 저장소 루트. Git이 무시하는 파일이거나 심볼릭 링크여도 해당

예외는 `.gitleaks.toml`에 있는, 검토를 거친 규칙(아래)뿐입니다.

### 일반 식별자 규칙

GUID, IPv4 주소(RFC 1918 사설, CGNAT, 공인 및 그 밖의 예약 범위), 이메일 주소, 절대 홈 경로
(macOS, Linux, Windows 형식), 긴 Discord 형식 숫자 ID, 그리고 `contoso`가 아닌
`*.onmicrosoft.com` 테넌트입니다. 규칙 자체가 가상으로 취급하는 형식은 두 가지입니다. 처음
20개의 16진수 숫자가 0인 GUID(문서용 자리표시자)와, 예약된 이름(`.example`, `.test`, `.invalid`,
`.localhost`, `example.com`/`.net`/`.org`) 또는 Contoso onmicrosoft 도메인 아래의 이메일
주소입니다. 그 밖에 의도적으로 만든 가상 픽스처는 스캐너의 `EXCEPTIONS`에 항목이 있어야 합니다.
규칙 하나, 정확한 경로 하나, 정확한 값 하나에, 왜 가상인지 설명하는 메모를 붙입니다. 의도적으로
공개하는, 검토를 거친 연락처는 픽스처가 아니며 그렇게 표시합니다. 그런 연락처는 `CODE_OF_CONDUCT.md`의
신고 주소 하나뿐이며 그 파일에서만 허용됩니다. 따라서 같은 주소가 다른 곳에 있거나, 그 파일에
다른 주소가 있으면 여전히 발견 사항(finding)입니다. 기준선(baseline) 파일, 도메인 전체 허용,
경로 전체 억제, 인라인 또는 fingerprint 억제는 없습니다.

스캐너는 Git이 공개할 파일만 읽습니다. 즉 추적 중인 파일과 추적되지 않은 파일에서 무시되는
파일을 뺀 것입니다. 심볼릭 링크, 바이너리 또는 UTF-8이 아닌 파일, ignore 규칙에 맞는 추적 파일,
비공개 경로(`.local/`, `.build-inputs/`, `CLAUDE.md`, `AGENTS.md`, `.claude/settings.local.json`)는
거부하며, 어느 것도 읽지 않습니다. 첫 커밋 전에도 동작합니다. 출력은 규칙, 경로, 줄 번호뿐입니다.
경로 자체가 규칙에 맞으면 `[redacted path #N]`으로 출력하며, 여기서 N은 `git ls-files` 순서에서의
위치입니다.

```sh
python3 -I scripts/check_identifiers.py            # working-tree candidate
python3 -I scripts/check_identifiers.py --json     # machine-readable
python3 -I scripts/check_identifiers.py --rev HEAD --check-commit-metadata
```

### gitleaks 설정

`.gitleaks.toml`은 gitleaks 기본 규칙을 확장합니다. 전역 허용 목록(allowlist)은 없습니다. 인라인
`gitleaks:allow` 주석은 모든 실행에서 무시되고, `.gitleaksignore` 파일은 모두 거부되므로(위 참조),
예외가 있을 수 있는 곳은 이 파일뿐입니다. 각 예외는 기본 규칙 하나에 속하고, 고정된(anchored)
테스트 경로를 지정하며, redaction 테스트가 의도적으로 쓰는 정확한 가상 값을 나열합니다
(`condition = "AND"`). 이 파일의 변경은 게이트 로직처럼 검토하세요.

## 비공개 거부 목록 (로컬 전용)

저장소 밖에, 본인만 읽을 수 있게 한 번 만듭니다.

```sh
mkdir -p "$HOME/.config/cab-of-one"
chmod 700 "$HOME/.config/cab-of-one"
$EDITOR "$HOME/.config/cab-of-one/denylist.txt"
chmod 600 "$HOME/.config/cab-of-one/denylist.txt"
```

비어 있지 않은 각 줄은 대소문자를 구분하지 않고 비교하는 문자 그대로의 용어입니다(주석이나
패턴 없음). 고용주와 고객 이름, 브랜드와 도메인, 사람 이름, 호스트와 tailnet 이름, 개인 시스템
이름을 넣습니다. 절대 커밋하지 마세요. 스캐너는 목록 전체를 읽으며, 읽을 수 없으면 실패하는
쪽으로 닫힙니다(fail closed). 목록이 없거나, 비어 있거나, 심볼릭 링크이거나, UTF-8이 아니거나,
저장소 안에 있을 때도 실패하는 쪽으로 닫힙니다. GitHub Actions에서 실행될 때는 목록 읽기 자체를
거부합니다. 용어, 용어의 해시, 목록의 파일 이름은 절대 출력하지 않습니다.

```sh
python3 -I scripts/check_identifiers.py --denylist "$HOME/.config/cab-of-one/denylist.txt"
```

## pre-push 훅 (선택 사항)

훅을 대신 설치하거나 Git 설정을 바꾸는 것은 없습니다. 이 클론에서 사용하려면 다음을 실행하세요.

```sh
git config --local core.hooksPath .githooks
test -x .githooks/pre-push && echo "hook is executable"
```

Git은 실행 권한이 없는 훅을 아무 말 없이 건너뛰므로, 두 번째 줄이 출력되는지 확인하세요. 이
파일은 mode 100755로 커밋되어야 합니다.

훅에는 Python 3.11+, `PATH`에 있는 `gitleaks`, 그리고 위의 거부 목록이 필요합니다. 훅은 다음
조건을 모두 만족하지 않으면 push를 막습니다.

1. push되는 모든 ref가 체크아웃된 `HEAD` 커밋을 가리키고, 삭제되는 것이 없으며, 작업 트리가
   깨끗해야 합니다(`git push <remote> HEAD:<branch>`로 push하고, 다른 ref는 먼저 체크아웃한 뒤
   push하세요).
2. 작업 트리 스캔이 일반 규칙과 거부 목록을 통과해야 합니다.
3. push되는 모든 원격 ref 이름(예: `refs/heads/<branch>` 또는 `refs/tags/<tag>`)이 스캐너의
   반복 가능한 `--ref` 옵션을 통해 일반 규칙과 거부 목록을 통과해야 합니다(각각 정확한 전체 ref
   이름 하나, 예: `--ref=refs/heads/main`). 브랜치나 태그 이름도 공개되기 때문입니다.
4. push되는 모든 커밋이 트리 스캔, 메시지 스캔, noreply 신원 검사를 통과해야 합니다. "push되는"
   커밋이란 push되는 커밋에서 도달할 수 있지만, 이번 push에서 Git이 원격 ref에 대해 보고하는 이전
   객체 ID에서는 도달할 수 없는 커밋을 뜻합니다. 로컬 원격 추적 ref(`refs/remotes/...`)는 오래된
   값일 수 있으므로 원격에 이미 무엇이 있는지 판단하는 데 신뢰하지 않습니다. 이 ref는 스캔할
   커밋 집합을 절대 줄이지 않습니다.
5. `gitleaks git --redact --log-opts="--all -m"`이 병합 diff를 포함한 로컬 이력 전체에서 통과하고,
   `gitleaks dir --redact`가 임시 디렉터리에 새로 내보낸 `HEAD` 트리에서 통과해야 합니다. 둘 다
   `.gitleaks.toml`과 `--ignore-gitleaks-allow`를 사용하며, 그 전에 `.gitleaksignore`를 모두
   거부하는 사전 검사를 실행합니다(후보, 그 내보낸 사본, push되는 커밋, 또는 물리적 저장소 루트.
   무시되는 파일이거나 심볼릭 링크여도 해당).

이 훅에는 우회 스위치가 없습니다. Git 자체의 `--no-verify`는 모든 훅을 건너뜁니다. 이 저장소에서는
사용하지 마세요.

gitleaks는 공식 릴리스 페이지에서 직접 설치하고, 압축을 풀기 전에 공개된 SHA-256을 확인하세요. CI는
gitleaks 8.30.1을 고정해 쓰며, 같은 방식으로 아카이브 해시를 검증합니다.

## DCO

모든 커밋에는 author 이메일과 일치하는 `Signed-off-by: Name <email>`이 있어야 합니다
(`git commit -s`). 예외는 없으며, 병합도 마찬가지입니다.

- 로컬 병합: `git merge --signoff`
- squash 병합: squash 커밋 author의 `Signed-off-by:` 줄을 메시지에 명시적으로 넣습니다.
- 호스팅 서비스 화면에서 만든 병합: 결과 커밋에 일치하는 서명이 있는 경우에만 허용합니다. 그렇지
  않으면 로컬에서 병합하세요.

CI는 push나 pull request가 추가하는 커밋을 검사합니다.

- pull request: base에는 없고 head에 있는 커밋(`head --not base`)
- push: 이전 끝(tip) 이후의 커밋(`after --not before`)
- 첫 push 또는 새 브랜치(`before`가 모두 0), 또는 force push 뒤 이력에 base가 없는 경우: head에서
  도달할 수 있는 모든 커밋, 최대 500개. 그보다 많으면 검사가 실패합니다.

이벤트 데이터는 환경 변수를 통해 스크립트에 전달되며, 전체 커밋 ID여야 합니다. 로컬에서는 다음과
같습니다.

```sh
python3 -I scripts/check_dco.py --base origin/main --head HEAD
```

## 첫 공개

1. 깨끗한 작업 트리에서 시작해 새 커밋 하나를 만듭니다(비공개 이력 없음). 서명(sign-off)을 하고,
   GitHub noreply author 주소를 사용합니다.
2. 테스트, `ruff check .`, `ruff format --check .`, 거부 목록을 포함한 식별자 스캔, 두 가지
   gitleaks 스캔, DCO 검사를 실행합니다. 모두 발견 사항 0건으로 통과해야 합니다.
3. 사람 검토자에게 첫 push 승인을 받은 뒤, 훅을 켠 상태에서 `HEAD`를 push합니다.
4. GitHub에서 비공개 취약점 신고(private vulnerability reporting), secret scanning, push protection을
   켭니다. `main`을 보호하고, 기본 Actions 토큰을 읽기 전용으로 유지하며, Actions secret은 추가하지
   않습니다.
