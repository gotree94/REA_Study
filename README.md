# REA (Reverse Engineer Anything) 사용법 & 환경 설정 가이드

https://youtu.be/tByhXkxDKDo

> 참고 저장소: <https://github.com/morluto/rea>
> 공식 사이트: <https://rea.tools/> · 가이드: <https://rea.tools/guides/> · 쇼케이스: <https://rea.tools/showcase/>
> npm 패키지: `rea-agents`

---

## 1. REA란?

**REA**는 에이전트(AI 코딩 도구)를 리버스 엔지니어링 도구에 연결해 주는 **MCP(Model Context Protocol) 서버 + CLI**입니다.
앱의 특정 기능이 어떻게 동작하는지 소스 코드 없이 조사하고, 증거(Evidence)와 함께 설명한 뒤, 사용자의 프로젝트에 유사 기능을 구현할 수 있도록 돕습니다.

한 문장 요약:

> **"네이티브 바이너리부터 애플리케이션, 런타임 동작까지 아우르는 리버스 엔지니어링용 단일 MCP."**

- 모든 분석은 **로컬에서 실행**됩니다. (앱을 업로드하지 않음)
- 결과에는 각 결론의 **증거와 한계**가 함께 포함됩니다.
- 에이전트를 통해서도, **터미널 CLI로 직접**도 사용할 수 있습니다.
- 정적 JavaScript 분석은 네이티브 분석 엔진 없이도 동작합니다.

---

## 2. 무엇을 분석할 수 있나 (분석 대상)

| 대상 (Target) | REA가 반환하는 것 | 요구 사항 / 가이드 |
| --- | --- | --- |
| **네이티브 바이너리** | 의사코드(pseudocode), 어셈블리, 문자열, 심볼, 호출/참조 | Hopper, Ghidra 또는 IDA 필요 |
| **오프라인 ELF 레이아웃** | 섹션, 세그먼트, 원본 심볼/재배치, 정적 완화 후보 | Linux x64 + pwntools |
| **Go 바이너리** | 내장 컴파일러 버전, 모듈, 교체, 빌드 설정 | 내장 정적 검사 (Go 설치 불필요) |
| **Rust 바이너리** | cargo-auditable 크레이트 이름/버전/소스/의존성 엣지 | 내장 정적 검사 |
| **WASM 산출물** | 검증, 섹션, import/export WAT, 디코드된 WAT | WABT 1.0.42 |
| **EVM 바이트코드** | 디스패치 셀렉터, 바이트 오프셋, 추론된 인자/가변성 | Linux x64 로컬 캐리어 |
| **SQLite 데이터베이스** | 테이블, 컬럼, 인덱스, 뷰, 트리거, 일부 행 | Node.js 24.x ≥24.15 또는 26+ |
| **기록된 Linux 크래시** | raw 노트, 스레드 레지스터/시그널, 매핑 후보 | pwntools (Linux x64), 선택적 GDB/pwndbg |
| **JavaScript / Electron** | 모듈, import, 소스맵, 라우트, IPC, 네이티브 애드온 관계 | Node.js + npm (Linux: procps `ps`) |
| **웹사이트** | 페이지 구조, 스크립트, 네트워크 관찰, 요청 스크린샷 | Chrome 계열 브라우저 |
| **저장된 네트워크 캡처** | 요청/응답, 노출된 페이로드, 소스 위치 | HAR / Fiddler SAZ / (Linux) mitmdump |
| **.NET 어셈블리** | 메타데이터, CIL 명령어, 네이티브 의존성, 빌드 비교 | 없음 (정적 전용) |
| **Android APK** | 매니페스트, 클래스, 디컴파일 메서드, 참조 | Headless JADX + 풀 JDK (Linux/macOS/Windows x64) |
| **Android 기기** | 기기/패키지/프로세스/로그/덤프/스크린샷/파일 전송 | adb |
| **JEB 프로젝트** | 엔진 기반 프로젝트 유닛, 산출물 다이제스트, 의사코드 | JEB 클라이언트 + `REA_JEB_MCP_URL` |
| **Android 리소스** | 디코드된 매니페스트, 문자열 테이블, 로케일 | Apktool 런처 |
| **Flutter 앱** | Dart 스냅샷 해시, ABI별 라이브러리 다이제스트 | 없음 (정적 APK 파싱) |
| **펌웨어** | 리전, 추출 결과, 네이티브 분석 핸드오프 | Binwalk / Unblob (Linux) |
| **기록된 패킷 / PCAP** | 필드, 반복 값, 필터, 엔드포인트/DNS/TLS SNI/HTTP | TShark 4.x + prlimit (Linux) |
| **기록된 로직 신호** | 디코더 주석, 샘플 범위, 진단 | sigrok-cli 0.7.2 + prlimit (Linux) |
| **패키지 & 리소스** | 파일 인벤토리, 다이제스트, plist, Apple 번들 구조 | 산출물/JavaScript 가이드 |
| **프로세스 동작** | 터미널 출력, 상호작용, 종료/파일시스템 관찰, 실행 비교 | 네이티브 PTY (Linux/macOS) |

> **정적** JavaScript/.NET 검사는 파일을 실행하지 않고 읽습니다.
> **런타임** 캡처는 사용자 권한으로 대상을 실행/조작합니다.

---

## 3. 사전 요구사항 (환경)

### 3.1 필수

- **Node.js**: `22.x` (>=22.19), `24.x` (>=24.11), 또는 `26+`
- **npm** (Node.js 설치 시 함께 설치됨)

설치 여부 확인:

```powershell
node --version
npm --version
```

> Node.js가 없다면 <https://nodejs.org/> 에서 LTS 이상을 설치하세요. (v22.19+/v24.11+ 권장)

### 3.2 선택적 (분석 대상에 따라)

- **네이티브 분석 엔진**: Hopper, Ghidra, IDA 중 하나 (정적 JS/.NET 분석엔 불필요)
- **브라우저**: 웹사이트 분석 시 Chrome 계열
- **JDK + JADX**: Android APK 분석
- **adb**: Android 기기 분석
- **Linux 한정**: procps 호환 `ps`, pwntools, tshark, sigrok-cli, binwalk/unblob 등

### 3.3 Linux 전용 주의사항

Linux에서는 Ghidra, JADX, 펌웨어 도구, 정적 JS/Electron 분석 시 **procps 호환 `ps`** 가 REA의 `PATH`에 있어야 합니다(프로세스 소유권 검사). 없으면 자식 프로세스 시작 전에 거부됩니다.

```bash
# Debian/Ubuntu
sudo apt install procps
# RHEL/Fedora
sudo dnf install procps-ng
```

---

## 4. 설치 방법

### 4.1 가장 빠른 시작: 에이전트 자동 설정 (권장)

Node.js/npm이 설치된 상태에서:

```bash
npx rea-agents setup
```

동작 순서:

1. 설정할 에이전트들을 **멀티셀렉트**로 선택
2. REA가 제안하는 **경로/변경 사항을 미리보기(preview)**
3. **승인(Approve)** 하면 설정 적용 (기존 설정은 백업됨)
4. 안내 메시지에 나온 **에이전트 재시작**

최신 릴리스를 쓰려면:

```bash
npx rea-agents@latest setup
```

> ⚠️ **Claude Desktop** 사용자는 승인 전에 앱을 **완전히 종료**하세요. 실행 중이면 등록 정보를 덮어쓸 수 있습니다.

### 4.2 전역 설치 (CLI 상시 사용)

```bash
npm install --global rea-agents
rea --help
```

Bun 사용자:

```bash
bun add --global rea-agents
```

### 4.3 스킬만 설치 (MCP 등록 없이)

에이전트 지침(스킬)만 설치하고 MCP 서버/분석 엔진은 설치하지 않는 방식:

```bash
npx skills add morluto/rea --skill reverse-engineer-anything
```

### 4.4 curl 인스톨러

저장소 루트의 `install.sh`를 사용할 수도 있습니다. (`--no-setup` 옵션으로 Claude Code 자동 설정을 건너뛸 수 있음)

---

## 5. 에이전트 연동 (지원 클라이언트)

`setup`은 로컬 MCP 서버를 지원하는 에이전트에 REA를 등록합니다.

| 클라이언트 | `--client` 값 |
| --- | --- |
| Claude Code | `claude_code` |
| Claude Desktop | `claude_desktop` |
| Codex | `codex` |
| Cursor | `cursor` |
| Gemini CLI | `gemini_cli` |
| Windsurf | `windsurf` |
| Devin | `devin` |
| OpenCode | `opencode` |
| Antigravity | `antigravity` |
| GitHub Copilot CLI | `copilot_cli` |
| Command Code | `commandcode` |
| Qwen Code | `qwen_code` |
| Kimi Code | `kimi` |
| VS Code | `vscode` |
| Grok Build | `grok_build` |
| OMP | `omp` |
| Pi | `pi` |
| Hermes | `hermes` |
| Qoder | `qoder` |
| Factory Droid | `droid` |
| Trae | `trae` |
| WorkBuddy | `workbuddy` |
| ZCode | `zcode` |
| DeepSeek Harness | `dsh` |

> `droid`, `dsh`, `kimi`, `qoder`, `trae`, `workbuddy`, `zcode` 는 `rea-agents@6.5.0` 이상이 필요합니다.

### 5.1 비대화형 / 자동화 옵션

```bash
# 특정 클라이언트들만, 스킬 제외, 드라이런(읽기 전용 계획)
rea setup --client codex --client cursor --skill=false --dry-run

# 계획만 JSON으로 출력 (적용 안 함)
rea setup --json

# 명시적 범위 + 자동 승인 (예: 감지된 모든 클라이언트 + Hopper 설치)
rea setup --yes --all-detected --install-hopper --json
```

- `--client <값>`: 반복 지정 가능, 대화형 선택 생략
- `--all-detected`: 감지된 모든 지원 클라이언트 설정
- `--skill=false`: 번들 스킬 설치 생략
- `--dry-run`: 변경 없이 계획만 반환 (exit 0)
- `--yes`: 명시적 범위와 함께 사용. 승인 안 된 적용은 `needs_confirmation` (exit 1)
- `--accessible`: 순차적 yes/no 프롬프트
- `NO_COLOR=1`: 색상 비활성화

### 5.2 수동 MCP 등록 (CLI, 프로젝트 국소 범위)

특정 프로젝트에서만 REA를 쓰고 싶을 때 (Claude Code 예):

```bash
# POSIX
claude mcp add --scope local rea -- npx -y rea-agents@6.5.0 mcp
```

```powershell
# Windows PowerShell (npx shim 래핑 필요)
claude mcp add --scope local rea -- cmd.exe /d /c npx -y rea-agents@6.5.0 mcp
```

> `--scope project`(저장소에 `.mcp.json` 생성)는 커밋될 수 있으므로 피하세요.
> `--scope local` 등록은 `rea doctor`/`rea uninstall`이 인식하지 못하므로 직접 `claude mcp remove --scope local rea`로 제거해야 합니다.

### 5.3 특정 프로필로 격리 (Claude Code 예)

```powershell
$previousClaudeConfigDir = $env:CLAUDE_CONFIG_DIR
try {
  $env:CLAUDE_CONFIG_DIR = Join-Path $HOME ".claude-rea"
  npx rea-agents setup --client claude_code
  claude mcp list
  npx rea-agents doctor --client claude_code --skill --json
} finally {
  if ($null -eq $previousClaudeConfigDir) {
    Remove-Item Env:CLAUDE_CONFIG_DIR -ErrorAction SilentlyContinue
  } else {
    $env:CLAUDE_CONFIG_DIR = $previousClaudeConfigDir
  }
}
```

---

## 6. 사용 방법

### 6.1 에이전트에게 질문하기 (MCP)

설정 후 에이전트를 재시작하고 자연어로 요청:

```
Notes 앱에서 검색이 어떻게 동작하는지 이해하고, 증거를 보여준 다음,
내 프로젝트에 비슷한 기능을 구현해줘.
```

`Notes` 자리에 대상 앱을, 그리고 원하는 기능을 넣으면 됩니다. REA는 MCP를 통해 대상을 검사하고 증거와 함께 결과를 반환합니다.

### 6.2 터미널 CLI

전역 설치했다면 `rea`, 아니면 `npx -y rea-agents@latest` 뒤에 명령을 붙입니다.

```bash
# JavaScript/Electron 앱 디렉터리 또는 ASAR 검사
npx -y rea-agents@latest analyze-javascript-application /absolute/path/to/app --json
```

Windows 경로 예:

```bash
npx -y rea-agents@latest analyze-javascript-application "D:/apps/example" --json
```

**대규모 결과 처리 팁** (앱 증거가 수백 MB일 수 있음):

```bash
rea analyze-javascript-application /path/to/app --json > app-evidence.json
jq -c '{source: {kind: "inline", evidence: .}, view: {kind: "summary"}}' app-evidence.json > app-view.json
rea inspect-analysis-view app-view.json
```

### 6.3 네이티브 바이너리 분석 (provider 필요)

먼저 Hopper/Ghidra/IDA 중 하나를 설정한 뒤:

```bash
rea analyze  /absolute/path/to/program --provider ghidra --json   # 개요
rea search   /absolute/path/to/program "search" --provider ghidra --json
rea function /absolute/path/to/program main --provider ghidra --json   # 함수 도시에
rea decompile /absolute/path/to/program 0x1000 --provider ghidra --json  # 의사코드
rea xrefs    /absolute/path/to/program 0x1000 --provider ghidra --json   # 교차 참조
rea trace    /absolute/path/to/program "search" --provider ghidra --json  # 추적
rea instructions /absolute/path/to/program ...   # 어셈블리만
```

- `analyze`와 `inspect`는 네이티브 개요 워크플로우를 공유합니다.
- macOS `.app` 번들을 직접 지정 가능합니다.
- `rea --help` 또는 각 명령의 `--help`로 인자/출력 옵션 확인.

**Go / Rust 바이너리** (디스어셈블러 불필요):

```bash
rea inspect-go-binary   /absolute/path/to/program --json
rea inspect-rust-binary /absolute/path/to/program --json
```

**.NET 어셈블리** (엔진 불필요, 실행 없이 메타데이터/CIL만):

```bash
rea inspect-managed-artifact /path/Assembly.dll --json
rea inspect-managed-members  /path/Assembly.dll --json
rea inspect-managed-members  /path/Assembly.dll --type Example.Parser --json
```

**SQLite 스냅샷**:

```bash
rea inspect-sqlite-database PATH --json
rea inspect-sqlite-database PATH --table NAME --row-limit 20 --json
```

### 6.4 Provider 선택

```bash
rea providers --json      # 사용 가능한 provider와 지원 작업
rea capabilities --json   # 보조 기능
```

- 단일 provider만 지원하면 자동 선택됩니다.
- 여러 provider가 지원하면 `--provider`로 명시 지정:

```bash
rea analyze /path/to/program --provider hopper
```

- 상시 선호는 환경변수 `REA_ANALYSIS_PROVIDER`로 설정 (명시적 `--provider`가 우선).
- MCP에서는 `open_binary`에 `provider_id` 전달:

```json
{ "path": "/absolute/path/to/program", "provider_id": "hopper" }
```

### 6.5 스냅샷 저장/재사용

동일한 대상 바이트/작업/파라미터/provider/설정이 일치하면 저장된 결과를 재사용합니다.

```bash
rea analyze /path/to/program --provider ghidra --snapshot /path/to/analysis/program.json
# 동일 쿼리를 반복하면 저장된 결과 재사용
rea analyze /path/to/program --provider ghidra --snapshot /path/to/analysis/program.json
```

> 스냅샷 파일은 로컬이며 소유자 전용 권한을 사용합니다. 메타데이터 쓰기를 디스패치하면 활성 세션의 스냅샷 캐시가 무효화됩니다.

### 6.6 Evidence 가져오기/내보내기/비교

```bash
rea evidence-import /path/to/evidence/bundle.json
rea evidence-export /path/to/evidence/bundle.json /path/to/evidence/canonical.json
rea compare        /path/to/evidence/left.json   /path/to/evidence/right.json
```

`--overwrite`를 명시하지 않으면 기존 목적지는 보존됩니다.

### 6.7 과거 소스 가져오기 (버전 비교)

```bash
rea import-reference-source /path/to/source
rea import-reference-source /path/to/source --detail summary --outline-depth 2 --json
```

> ⚠️ Historical-source import는 **Linux/macOS에서만** 지원됩니다. **네이티브 Windows는 `unsupported_host` 반환** → WSL 등에서 Linux REA를 사용하세요.

### 6.8 출력 형식 & 종료 상태

- 기본 터미널 출력: **TOON**. JSON 소비자용으로 저장할 때는 `--json`.
- `--json`은 터미널에서는 들여쓰기, 파이프/리다이렉트 시 컴팩트 → 에이전트/스크립트에 유리.
- 값이 있는 출력 플래그: `--format`, `--filter-output`, `--token-limit`, `--token-offset` (`--flag value` 또는 `--flag=value`).

| 상태 | 의미 |
| --- | --- |
| `0` | 작업 완료 (부분 증거/경고/미해결 질문 포함 가능) |
| `1` | 작업 미완료 (입력 오류, 권한, 취소, 타임아웃 등) |
| `128 + N` | 시그널 기반 상태 (SIGINT=130, SIGTERM=143). `| head` 등으로 파이프 닫히면 141 |

```bash
set -o pipefail
rea inspect-artifact ./app.asar --json | jq . > inspection.json
```

---

## 7. 네이티브 분석 엔진 설정

깊은 네이티브 분석에는 **Hopper / Ghidra / IDA** 중 하나가 필요합니다. (정적 JS/.NET은 불필요)

### 7.1 Hopper

- 별도 상용 소프트웨어. 무료 데모는 벤더 정의 제한, 유료 라이선스는 선택.
- REA는 감지된 기존 설치를 재사용하며, uninstall 시 Hopper를 보존합니다.
- 자동 설치 지원 OS: macOS 12+, Ubuntu 24.04+, Fedora 41+, Nobara 44+, 64-bit Arch Linux, CachyOS, Omarchy.
- macOS: 공식 DMG를 다운로드→크기/다이제스트 검증→`~/Applications/Hopper Disassembler.app`에 설치.
- Linux: 공식 `.deb`/`.rpm`/Arch 패키지를 PGP 검증 후 설치.
- REA가 필요할 때 Hopper를 시작합니다. macOS 첫 실행 시 데모/라이선스 대화상자를 **같은 사용자 세션에서** 완료해야 합니다.

**런처 경로 수동 지정**:

```bash
export HOPPER_LAUNCHER_PATH=/absolute/path/to/Hopper
rea doctor --provider hopper --json
```

**큰 바이너리용 시작 타임아웃** (기본 120,000ms):

```bash
# 환경변수: 1 ~ 2,147,483,647 사이 정수 (ms)
REA_HOPPER_STARTUP_TIMEOUT_MS=300000
```

> Hopper 의사코드 대신 브릿지가 Python 스크립트를 실행하는 동안 `Executing Python Script...` 오버레이가 보일 수 있으며, 그 자체로는 지연이 아닙니다.

### 7.2 Ghidra

- 기존 Ghidra 설치를 사용 (설치 시 검증된 경로 저장 가능).
- 16비트 DOS 분석 지원.
- **Windows Ghidra 지원은 실험적(P0)** — `docs/windows-ghidra-p0.md` 참조.

```bash
rea doctor --provider ghidra --json
```

### 7.3 IDA

- IDA 가이드(`docs/ida-provider.md`) 참조. 선택적 네이티브 MCP 브릿지 지원.

### 7.4 Kuna / 기타

- Kuna 디컴파일러 가이드(`docs/kuna-provider.md`) 참조.
- 오프라인 네이티브 검사 시 사용자 제공 GNU objdump, Rizin도 지원 (REA가 설치/업데이트하지 않음).

**대상이 여러 provider를 지원할 때** `doctor`가 `capability_unavailable`을 반환할 수 있습니다. 이때 `details.selection_reason`을 확인하세요:

- `ambiguous` → `details.candidate_ids`에서 선택
- `provider_unavailable` → 선택된 엔진 복구

---

## 8. 상태 진단 (doctor)

`rea doctor`는 호스트 사전요구사항과 에이전트 설정을 **읽기만** 하고 변경하지 않습니다.

```bash
rea doctor --json                         # 전체 감사
rea doctor --provider ghidra --json       # 특정 엔진
rea doctor --provider hopper --json
rea doctor --provider ida --json
rea doctor --client codex --json          # 특정 에이전트 등록
rea doctor --skill --json                 # 설치된 워크플로우 지침 검증
rea doctor --target /path/to/app --json   # 대상 검사 추가
```

- 범위 지정 보고서는 `scope.mode: "explicit"`, `scope_checks`가 `healthy`와 종료 상태를 결정.
- `--json`은 엄격히 읽기 전용.
- 작업 전에 `binary_session`을 `{}`로 호출하면 세션 상태별 도구 가용성을 확인할 수 있습니다.

---

## 9. 업데이트 & 삭제

### 9.1 업데이트

```bash
rea update
```

- `npm install --global` 또는 `bun add --global`로 설치한 전역 설치만 업데이트합니다.
- 소스 체크아웃/패키지 러너 복사본은 소유 메커니즘으로 갱신해야 합니다.
- Bun 전역 업데이트는 **Bun 1.2.17+** 필요.
- 업데이트 후 안내되는 스코프 setup 명령을 실행해 에이전트 등록/스킬을 새로 고칩니다.
- npx 사용자:

```bash
npx rea-agents@latest setup
```

### 9.2 삭제

```bash
rea uninstall              # REA 소유 등록/스킬만 제거
rea uninstall --purge-data # 추가로 REA 캐시/상태(~/.rea) 제거
```

- **보존됨**: Hopper, Node.js, Evidence 파일, 캡처, 무관한 스킬, 다른 MCP 서버.
- `--purge-data`는 REA의 `~/.rea` 하위 캐시/상태만 제거.

---

## 10. 문제 해결

### 10.1 일반 절차

1. **먼저 업데이트** (최근 릴리스에서 이미 수정됐을 수 있음):

   ```bash
   rea update
   # npx 사용 시
   npx rea-agents@latest setup
   ```

2. 에이전트를 사용 중이라면 setup 새로고침 후 **재시작**.
3. 같은 작업 재시도.
4. 지속되면 이슈 등록 시 다음을 포함: REA 버전, 대상 타입, 재현 단계, 오류 출력.

### 10.2 작업별 준비 상태 확인

| 작업 | 확인 방법 |
| --- | --- |
| 정적 JS/Electron 분석 | `rea analyze-javascript-application PATH --json` 직접 실행 |
| 특정 분석 엔진 | `rea doctor --provider ghidra --json` (또는 hopper, ida) |
| 특정 에이전트 등록 | `rea doctor --client codex --json` |
| 설치된 워크플로우 지침 | `rea doctor --skill --json` |

### 10.3 자주 겪는 문제

- **Hopper가 시작 안 됨**: `Cannot launch Hopper! Connection is invalid.` → Hopper의 데모/라이선스/로더 대화상자를 완료 후 재시도.
- **macOS Apple Events 거부**: `시스템 설정 → 개인정보 보호 및 보안 → 자동화`에서 REA를 시작하는 앱 허용 후 재시도.
- **Linux 런처 공유 라이브러리 누락**:

  ```bash
  ldd /absolute/path/to/Hopper | grep 'not found'
  ```

- **Linux 데모 의존성**: Xvfb, Python 3, X11, XTEST 필요 (지원 배포판에서 setup이 설치).
- **PATH 확인**: curl 인스톨러가 안내하는 실행 디렉터리(보통 `~/.local/bin`)를 셸 `PATH`에 추가.
- **에이전트가 도구를 못 보는 경우**: 등록은 되어 있으나 활성 세션에 도구가 없으면 **재시작/재연결** 필요 (`doctor`는 파일/사전요구사항만 검사, 라이브 연결은 검사하지 않음).

---

## 11. Hooks / 환경변수 요약

| 변수 | 용도 |
| --- | --- |
| `REA_ANALYSIS_PROVIDER` | 기본 분석 provider 상시 지정 |
| `HOPPER_LAUNCHER_PATH` | Hopper 런처 경로 수동 지정 |
| `REA_HOPPER_STARTUP_TIMEOUT_MS` | Hopper 시작 타임아웃 (ms) |
| `REA_GHIDRA_STARTUP_TIMEOUT_MS` | Ghidra 시작 타임아웃 (ms) |
| `REA_JEB_MCP_URL` | JEB 클라이언트 MCP URL |
| `REA_MCP_INPUT_SCHEMA_PROFILE` / `REA_MCP_OUTPUT_SCHEMA_PROFILE` | MCP 스키마 프로필 |
| `REA_MCP_MAX_RESPONSE_BYTES` | MCP 응답 크기 제한 |
| `REA_REFERENCE_SECRET_PATTERNS_JSON` | 민감 경로 지정용 ignore 패턴 JSON 배열 |
| `CLAUDE_CONFIG_DIR` | Claude Code 프로필 위치 |
| `NO_COLOR=1` | 색상 비활성화 |

> Setup은 기존 서버 엔트리의 유효한 환경 오버라이드(예: `REA_MCP_INPUT_SCHEMA_PROFILE`, `REA_MCP_MAX_RESPONSE_BYTES`)를 보존합니다.

---

## 12. Windows 사용자 특이사항 요약

- 경로는 `"D:/apps/example"` 처럼 슬래시 사용 가능.
- Claude Code 로컬 MCP 등록 시 `cmd.exe /d /c npx ...` 로 shim 래핑 필요.
- 프로필 선택은 POSIX `VAR=value cmd` 대신 PowerShell `$env:VAR` 패턴 사용.
- **Historical-source import는 네이티브 Windows 미지원** → WSL/Linux REA 사용.
- **Windows Ghidra는 실험적(P0)** 단계.
- Android APK 분석은 Windows x64에서 JADX + 풀 JDK로 지원.

---

## 13. 보안 · 면책

- 분석은 **로컬 수행**되며 대상 앱을 업로드하지 않습니다. 다만 에이전트의 모델 provider는 자체 데이터 정책을 가집니다.
- **합법적 연구·교육·상호운용성·소프트웨어 보존, 소유하거나 분석 권한이 있는 소프트웨어 분석**에만 사용하세요. (자세한 내용은 `DISCLAIMER.md`)
- 공식 배포처는 [morluto/rea](https://github.com/morluto/rea), [rea.tools](https://rea.tools/), npm `rea-agents` 뿐입니다. 유사 저장소명/복사된 README는 공식이 아닙니다.
- 취약점 신고는 `SECURITY.md` 절차를 따르세요.
- 라이선스: **MIT** (REA-authored 코드). 서드파티는 각자의 라이선스를 유지합니다.

---

## 14. 한눈에 보는 요약 (Quick Reference)

```text
# 1) 설치 & 설정
npx rea-agents setup                     # 에이전트 연동 (권장)

# 2) 전역 CLI 설치
npm install --global rea-agents

# 3) 정적 JS/Electron 분석 (엔진 불필요)
rea analyze-javascript-application <path> --json

# 4) 네이티브 분석 (provider 필요)
rea analyze <path> --provider ghidra --json
rea decompile <path> 0x1000 --provider ghidra --json

# 5) 상태 진단
rea doctor --json

# 6) 업데이트 / 삭제
rea update
rea uninstall            # 또는 --purge-data
```

**공식 문서 바로가기**

- 설치/설정: `docs/installation.md` → <https://github.com/morluto/rea/blob/main/docs/installation.md>
- CLI & Evidence: `docs/cli.md` → <https://github.com/morluto/rea/blob/main/docs/cli.md>
- MCP 계약/프롬프트: `docs/mcp-contracts.md`, `docs/mcp-prompts.md`
- 가이드(워크스루): <https://rea.tools/guides/>
- 쇼케이스: <https://rea.tools/showcase/>

---

*문서 생성일: 2026-10-17 · 소스: morluto/rea 저장소 README 및 docs (installation.md, cli.md) 기준*
