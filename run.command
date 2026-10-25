#!/bin/bash
# 터미널에서 실행하거나 Finder 에서 더블클릭: 최초 1회 .venv 를 만들고 모니터를 띄운다.
set -e
cd "$(dirname "$0")"
if ! .venv/bin/python -c "import psutil" 2>/dev/null; then
  # macOS 기본 python3(3.9, Tk 8.5)로는 동작하지 않으므로 3.10 이상 + Tk 8.6 을 찾는다.
  PY=""
  for cand in python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v "$cand" >/dev/null 2>&1 && "$cand" -c \
        'import sys, tkinter; sys.exit(sys.version_info < (3, 10) or tkinter.TkVersion < 8.6)' 2>/dev/null; then
      PY="$cand"
      break
    fi
  done
  if [ -z "$PY" ]; then
    echo "Python 3.10 이상(tkinter 포함)이 필요합니다." >&2
    echo "  python.org: https://www.python.org/downloads/macos/" >&2
    echo "  Homebrew:   brew install python python-tk" >&2
    exit 1
  fi
  rm -rf .venv
  "$PY" -m venv .venv
  .venv/bin/pip install -q -r requirements.txt
fi
exec .venv/bin/python procmon.py "$@"
