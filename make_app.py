#!/usr/bin/env python3
"""~/Applications/ProcessMonitor.app 을 만들고, --dock 을 주면 Dock 에 고정한다.

앱 번들 안에 파이썬 실행 파일을 복사해 두면 Dock 에 'Python' 아이콘이 따로 뜨지 않고
이 앱의 이름·아이콘으로 실행된다. 프로젝트 폴더를 옮겼다면 이 스크립트를 다시 실행할 것.
"""

from __future__ import annotations

import argparse
import math
import plistlib
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

PROJECT = Path(__file__).resolve().parent
APP = Path.home() / "Applications" / "ProcessMonitor.app"
VENV_PY = PROJECT / ".venv" / "bin" / "python"
BUNDLE_ID = "local.procmon.ProcessMonitor"
LSREGISTER = Path("/System/Library/Frameworks/CoreServices.framework/Frameworks/"
                  "LaunchServices.framework/Support/lsregister")

LAUNCHER = """#!/bin/bash
# ProcessMonitor.app 실행기 (make_app.py 가 생성)
DIR="$(cd "$(dirname "$0")" && pwd)"
LOG="$HOME/Library/Logs/ProcessMonitor.log"
export PYTHONPATH={site}
if [ -x "$DIR/python" ]; then
  exec "$DIR/python" {script} "$@" >>"$LOG" 2>&1
fi
exec {venv_py} {script} "$@" >>"$LOG" 2>&1
"""


# ── 아이콘 (외부 라이브러리 없이 PNG 를 직접 그린다) ─────────────────────────

def _disc(px: bytearray, size: int, cx: float, cy: float, r: int, color: tuple) -> None:
    fill = bytes(color) + b"\xff"
    for dy in range(-r, r + 1):
        y = round(cy) + dy
        if not 0 <= y < size:
            continue
        half = int(math.sqrt(r * r - dy * dy))
        x0, x1 = max(round(cx) - half, 0), min(round(cx) + half + 1, size)
        px[(y * size + x0) * 4:(y * size + x1) * 4] = fill * (x1 - x0)


def render_icon(size: int = 1024) -> bytearray:
    s = size / 1024
    px = bytearray(size * size * 4)
    margin, radius = round(100 * s), round(185 * s)
    top, bottom = (40, 48, 66), (14, 17, 26)
    for y in range(margin, size - margin):  # 그라데이션 둥근 사각형
        t = (y - margin) / (size - 2 * margin)
        fill = bytes(round(a + (b - a) * t) for a, b in zip(top, bottom)) + b"\xff"
        dy = max(margin + radius - y, y - (size - margin - radius - 1), 0)
        inset = radius - math.sqrt(max(radius * radius - dy * dy, 0)) if dy else 0
        x0, x1 = round(margin + inset), round(size - margin - inset)
        px[(y * size + x0) * 4:(y * size + x1) * 4] = fill * (x1 - x0)
    for gy in (330, 480, 630, 780):  # 눈금선
        for y in range(round(gy * s), round((gy + 4) * s)):
            x0, x1 = round(180 * s), round(844 * s)
            px[(y * size + x0) * 4:(y * size + x1) * 4] = bytes((62, 70, 92, 255)) * (x1 - x0)
    points = [(190, 700), (300, 610), (400, 660), (500, 470), (600, 540), (700, 330), (830, 400)]
    r = round(24 * s)
    for (x0, y0), (x1, y1) in zip(points, points[1:]):  # CPU 그래프 선
        steps = max(1, int(math.hypot(x1 - x0, y1 - y0) / 6))
        for i in range(steps + 1):
            _disc(px, size, (x0 + (x1 - x0) * i / steps) * s, (y0 + (y1 - y0) * i / steps) * s,
                  r, (63, 185, 80))
    _disc(px, size, 700 * s, 330 * s, round(54 * s), (229, 72, 77))  # 최고점
    _disc(px, size, 700 * s, 330 * s, round(20 * s), (255, 236, 236))
    return px


def png_bytes(px: bytearray, size: int) -> bytes:
    raw = b"".join(b"\x00" + bytes(px[y * size * 4:(y + 1) * size * 4]) for y in range(size))

    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data))

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def build_icns(dest: Path) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / "icon_1024.png"
        base.write_bytes(png_bytes(render_icon(1024), 1024))
        iconset = Path(tmp) / "AppIcon.iconset"
        iconset.mkdir()
        for pt in (16, 32, 128, 256, 512):
            for scale in (1, 2):
                n = pt * scale
                name = f"icon_{pt}x{pt}{'@2x' if scale == 2 else ''}.png"
                subprocess.run(["/usr/bin/sips", "-z", str(n), str(n), str(base),
                                "--out", str(iconset / name)], check=True, capture_output=True)
        subprocess.run(["/usr/bin/iconutil", "-c", "icns", str(iconset), "-o", str(dest)], check=True)


# ── 앱 번들 ─────────────────────────────────────────────────────────────────

def ensure_venv() -> None:
    if not VENV_PY.exists():
        subprocess.run([sys.executable, "-m", "venv", str(PROJECT / ".venv")], check=True)
    subprocess.run([str(VENV_PY), "-m", "pip", "install", "-q", "-r",
                    str(PROJECT / "requirements.txt")], check=True)


def venv_paths() -> tuple[Path, str]:
    out = subprocess.run([str(VENV_PY), "-c", "import sys, sysconfig; print(sys.base_prefix); "
                          "print(sysconfig.get_paths()['platlib'])"],
                         capture_output=True, text=True, check=True).stdout.splitlines()
    return Path(out[0]), out[1]


def remove_old_bundle() -> None:
    if not APP.exists():
        return
    try:
        with open(APP / "Contents" / "Info.plist", "rb") as f:
            ours = plistlib.load(f).get("CFBundleIdentifier") == BUNDLE_ID
    except (OSError, plistlib.InvalidFileException):
        ours = False
    if not ours:
        sys.exit(f"{APP} 가 이미 있고 이 스크립트가 만든 앱이 아닙니다. 직접 확인 후 지워 주세요.")
    shutil.rmtree(APP)


def build_app() -> None:
    ensure_venv()
    base_prefix, site = venv_paths()
    remove_old_bundle()
    macos = APP / "Contents" / "MacOS"
    resources = APP / "Contents" / "Resources"
    macos.mkdir(parents=True)
    resources.mkdir()

    python_app = base_prefix / "Resources" / "Python.app" / "Contents" / "MacOS" / "Python"
    if python_app.exists():
        shutil.copy2(python_app, macos / "python")
        # 원래 서명(하드닝 런타임)은 다른 번들 안에서 무효가 되어 실행 즉시 종료되므로 로컬 서명으로 바꾼다.
        subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", "--identifier",
                        f"{BUNDLE_ID}.python", str(macos / "python")], check=True, capture_output=True)
    else:
        print("※ 프레임워크 파이썬이 아니라 Dock 에 Python 아이콘이 따로 보일 수 있습니다.")
    launcher = macos / "ProcessMonitor"
    launcher.write_text(LAUNCHER.format(site=shlex.quote(site),
                                        script=shlex.quote(str(PROJECT / "procmon.py")),
                                        venv_py=shlex.quote(str(VENV_PY))))
    launcher.chmod(0o755)
    build_icns(resources / "AppIcon.icns")
    with open(APP / "Contents" / "Info.plist", "wb") as f:
        plistlib.dump({
            "CFBundleName": "ProcessMonitor",
            "CFBundleDisplayName": "프로세스 모니터",
            "CFBundleIdentifier": BUNDLE_ID,
            "CFBundleExecutable": "ProcessMonitor",
            "CFBundleIconFile": "AppIcon",
            "CFBundlePackageType": "APPL",
            "CFBundleShortVersionString": "1.0",
            "CFBundleVersion": "1",
            "LSApplicationCategoryType": "public.app-category.utilities",
            "LSMinimumSystemVersion": "11.0",
            "NSHighResolutionCapable": True,
            "NSRequiresAquaSystemAppearance": False,      # 다크 모드 허용
            "NSSupportsAutomaticGraphicsSwitching": True,  # 외장 GPU 를 깨우지 않음 (발열 방지)
        }, f)
    if LSREGISTER.exists():
        subprocess.run([str(LSREGISTER), "-f", str(APP)], check=False)
    print(f"앱 생성: {APP}")


def add_to_dock() -> None:
    current = subprocess.run(["/usr/bin/defaults", "read", "com.apple.dock", "persistent-apps"],
                             capture_output=True, text=True).stdout
    url = APP.as_uri() + "/"
    if APP.as_uri() in current:
        print("이미 Dock 에 있습니다.")
        return
    tile = ("<dict><key>tile-data</key><dict><key>file-data</key><dict>"
            f"<key>_CFURLString</key><string>{url}</string>"
            "<key>_CFURLStringType</key><integer>15</integer></dict></dict></dict>")
    subprocess.run(["/usr/bin/defaults", "write", "com.apple.dock", "persistent-apps",
                    "-array-add", tile], check=True)
    subprocess.run(["/usr/bin/killall", "Dock"], check=False)
    print("Dock 에 고정했습니다.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dock", action="store_true", help="만든 앱을 Dock 에 고정")
    args = parser.parse_args()
    build_app()
    if args.dock:
        add_to_dock()


if __name__ == "__main__":
    main()
