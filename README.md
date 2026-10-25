# Mac 프로세스 모니터 (mac-process-monitor)

팬이 갑자기 "웅" 하고 돌 때 **무엇이 CPU·메모리·디스크를 쓰는지 한눈에 보고, 바로 종료하거나 정리**할 수 있는 macOS용 로컬 GUI 도구입니다.
Python(tkinter)과 [psutil](https://github.com/giampaolo/psutil) 하나로 동작하고, 데이터는 밖으로 보내지 않습니다.

> **English summary** — A lightweight macOS activity monitor written in Python/tkinter + psutil (Korean UI).
> Shows CPU/memory/thermal/disk at a glance, explains common macOS background processes, kills processes safely,
> sums memory per app, and finds large folders with a safe move-to-Trash. Run `./run.command`.

스크린샷: _(추가 예정)_

## 주요 기능

| 화면 | 내용 |
|---|---|
| 대시보드 | CPU(코어별 막대), 메모리 구성(앱·와이어드·압축·캐시·여유), **발열로 인한 CPU 감속 여부**, 디스크 여유·읽기/쓰기, 네트워크, 배터리, 최근 2분 그래프, 지금 CPU를 많이 쓰는 프로세스 5개 |
| 프로세스 탭 | 전체 프로세스 목록(정렬·검색·"내 프로세스만"), Spotlight·사진 분석·Time Machine 처럼 소음의 흔한 원인은 한국어 설명, 그 외에는 소속 앱 표시. 종료/강제 종료/상세 정보 |
| 앱별 메모리 탭 | 같은 앱(.app)의 프로세스를 묶은 메모리·CPU 합계. 더블클릭하면 그 앱의 프로세스만 보기 |
| 저장 공간 탭 | 디스크 구성(사용자 데이터·시스템·스왑), 용량을 많이 차지하기 쉬운 위치(다운로드, 캐시, Xcode, Android SDK, npm, Docker 등)의 크기와 정리 방법, 폴더 탐색, **휴지통으로 이동**(되돌려 놓기 가능) |

## 요구 사항

- macOS. **Intel Mac + macOS 15 에서만 테스트했습니다.** Apple Silicon 에서도 동작할 것으로 보지만 확인하지 않았고, 발열 감속 정보는 "정보 없음"으로 나옵니다.
- **Python 3.10 이상 + tkinter(Tk 8.6)**
  - 권장: [python.org 설치본](https://www.python.org/downloads/macos/)
  - Homebrew: `brew install python python-tk`
  - macOS 기본 `/usr/bin/python3`(3.9)는 쓸 수 없습니다. `run.command` 가 알려줍니다.

## 설치와 실행

```bash
git clone https://github.com/lsy3709/mac-process-monitor.git
cd mac-process-monitor
./run.command
```

처음 실행하면 `.venv` 가상환경을 만들고 psutil 을 설치한 뒤 창을 띄웁니다. Finder 에서 `run.command` 를 더블클릭해도 됩니다.

### Dock 에 앱으로 고정하기 (선택)

```bash
.venv/bin/python make_app.py --dock
```

`~/Applications/ProcessMonitor.app` 이 만들어지고 Dock 에 고정됩니다(Dock 이 한 번 다시 시작됩니다).
앱은 이 폴더의 코드를 실행하므로, **폴더를 옮기면 위 명령을 다시 실행**하세요. 오류 기록: `~/Library/Logs/ProcessMonitor.log`

## 간단 사용법

1. **소음 원인 찾기**: 상단 "지금 CPU를 많이 쓰는 프로세스"를 클릭하면 목록에서 선택됩니다. "설명" 열을 확인한 뒤 **종료**(정상 종료 요청)를 누르고, 반응이 없으면 **강제 종료**를 누릅니다.
   시스템 카드에 "발열로 CPU 감속 중"이 보이면 Mac 이 뜨거워서 성능을 낮추고 있다는 뜻입니다.
2. **메모리**: 메모리 카드에서 구성을 보고, "앱별 메모리" 탭에서 어떤 앱이 많이 쓰는지 확인합니다. 앱을 더블클릭하면 그 앱의 프로세스만 보입니다.
3. **저장 공간**: "저장 공간" 탭 → **크기 계산** → 큰 항목을 더블클릭해 들어가며 원인을 찾고, 선택 후 **휴지통으로 이동**합니다.
   지운 것은 Finder 휴지통에서 '되돌려 놓기'로 복구할 수 있고, 휴지통 비우기는 Finder 에서 직접 합니다.

단축키: `⌘F` 검색 · 더블클릭/`Enter` 상세 정보 · `Delete` 종료 · 저장 공간 탭에서 `⌫` 상위 폴더 · 우클릭 메뉴

## 안전장치와 권한

- **프로세스 종료**: PID 0·1 과 이 프로그램 자신은 거부합니다. WindowServer 같은 핵심 프로세스는 강하게 경고합니다. 확인 창이 떠 있는 사이 PID 가 다른 프로세스에 재사용됐으면 건너뜁니다.
  다른 사용자·root 프로세스를 종료하려면 `sudo .venv/bin/python procmon.py` 로 실행해야 합니다.
- **휴지통으로 이동**: 홈 폴더와 `/Applications` 안의 항목만 옮길 수 있습니다. 문서·다운로드·Library 같은 기본 폴더 자체, 링크, 이 프로그램 폴더는 거부합니다. 항상 확인 창을 띄웁니다. 영구 삭제 기능은 없습니다.
- **macOS 가 묻는 권한**
  - 저장 공간 계산: 데스크탑·문서·다운로드 접근. Docker 폴더는 '다른 앱의 데이터' 접근
  - 휴지통으로 이동: 'Finder 제어'(처음 한 번)
  - 시스템 설정 > 개인정보 보호 및 보안 > **전체 디스크 접근 권한**을 주면 폴더 크기가 정확해집니다. 주지 않으면 일부 폴더는 "권한 없음" 또는 "(일부)"로 표시됩니다.
  - `make_app.py` 로 앱을 다시 만들면 서명이 바뀌어 위 권한을 다시 묻습니다.

## 측정 방식과 한계

- CPU % 는 활동 모니터처럼 코어 1개 = 100% 라서 100% 를 넘을 수 있습니다.
- 메모리 % 는 활동 모니터의 "사용된 메모리"(앱 + 와이어드 + 압축) 비율입니다. 프로세스 메모리는 활동 모니터의 "메모리"와 같은 기준(물리 footprint)입니다.
- 일반 권한으로는 root 프로세스의 값을 직접 못 읽습니다. CPU 는 `ps` 값으로 보완하고, 메모리는 "앱별 메모리" 탭을 보는 동안만 2분마다 `top` 으로 채웁니다(그 전에는 `*` 추정치). `kernel_task` 의 CPU 는 표시하지 않습니다.
- 메모리는 1024 단위(활동 모니터와 같음), 디스크는 1000 단위(Finder 와 같음)입니다.
- 모니터 자체 부하(코어 1개 기준, `ps`·`vm_stat`·`top` 포함, 기본 3초 갱신): 프로세스·저장 공간 탭 약 12%, 앱별 메모리 탭 약 15%.
  창을 최소화하면 화면 갱신을 멈춥니다.
- 개발 메모: macOS 의 `ttk.Progressbar` 는 쉬지 않고 애니메이션하며 창 전체를 다시 그려 CPU 를 60% 이상 씁니다. 그래서 막대는 Canvas 로 직접 그립니다.

## 자동 점검

```bash
.venv/bin/python procmon.py --selftest
```

창을 띄워 갱신·정렬·필터·상세 창·종료·앱별 탭·저장 공간 크기 계산·휴지통 보호 규칙을 실제로 실행해 보고 결과를 출력합니다.
실제 Finder 휴지통 이동은 점검에서 실행하지 않습니다.

## 파일 구성

| 파일 | 역할 |
|---|---|
| `procmon.py` | 프로그램 본체 (수집·GUI·자동 점검) |
| `run.command` | 가상환경 준비 후 실행 |
| `make_app.py` | `~/Applications/ProcessMonitor.app` 생성, `--dock` 으로 Dock 고정 |
| `requirements.txt` | 의존성 (psutil) |

## 라이선스

[MIT](LICENSE)
