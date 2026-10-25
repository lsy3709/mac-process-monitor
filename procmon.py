#!/usr/bin/env python3
"""Mac 프로세스 모니터: CPU·메모리 대시보드와 프로세스 종료 GUI (tkinter + psutil).

실행:  ./run.command                (최초 실행 시 .venv 생성 후 psutil 설치)
점검:  .venv/bin/python procmon.py --selftest
"""

from __future__ import annotations

import argparse
import collections
import ctypes
import functools
import os
import pwd
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
import traceback
from dataclasses import dataclass, field
from tkinter import filedialog, messagebox, ttk
from typing import Any

if sys.version_info < (3, 10):
    sys.exit("Python 3.10 이상이 필요합니다. https://www.python.org/downloads/macos/ 에서 설치하세요.")

import psutil

# ── 데이터 수집 ─────────────────────────────────────────────────────────────

# 이름·경로·사용자·시작 시각은 처음 한 번만 읽고 캐시한다. exec(이름 변경)나 PID 재사용은
# 매 주기 읽는 ps 의 실행 경로가 달라진 것으로 알아채고 다시 읽는다.
STATIC_ATTRS = ["ppid", "name", "uids", "exe", "create_time"]
DYNAMIC_ATTRS = ["cpu_percent", "num_threads", "status"]

NEVER_KILL = {0, 1}
CRITICAL_NAMES = {"kernel_task", "launchd", "WindowServer", "loginwindow"}

# 팬 소음·발열의 흔한 원인이 되는 macOS 프로세스 (이름 앞부분으로 매칭)
KNOWN_PROCESSES = {
    "kernel_task": "커널. 과열 시 CPU를 점유해 온도를 낮춤 (종료 불가)",
    "launchd": "모든 프로세스의 부모 (종료 불가)",
    "WindowServer": "화면 그리기. 창·외장 모니터가 많으면 증가 (종료 시 로그아웃)",
    "loginwindow": "로그인 세션 관리 (종료 시 로그아웃)",
    "mds_stores": "Spotlight 색인 저장. 색인이 끝나면 진정됨",
    "mds": "Spotlight 색인 관리",
    "mdworker": "Spotlight 파일 색인 작업자",
    "corespotlightd": "Spotlight 앱 데이터 색인",
    "photoanalysisd": "사진 앱 얼굴·장면 분석 (전원 연결·유휴 시 실행)",
    "mediaanalysisd": "사진·영상 분석 (시각 검색 등)",
    "photolibraryd": "사진 보관함 관리",
    "backupd": "Time Machine 백업",
    "softwareupdated": "macOS 업데이트 확인·다운로드",
    "cloudd": "iCloud 동기화",
    "bird": "iCloud Drive 동기화",
    "fileproviderd": "iCloud·클라우드 파일 동기화",
    "nsurlsessiond": "백그라운드 다운로드 (업데이트, iCloud 등)",
    "syspolicyd": "Gatekeeper: 새로 받은 앱 검사",
    "XprotectService": "XProtect 악성코드 검사",
    "XProtect": "XProtect 악성코드 검사",
    "trustd": "인증서 검증",
    "spindump": "멈춘 앱 진단 보고서 생성",
    "ReportCrash": "충돌 보고서 생성",
    "coreaudiod": "오디오 (종료 시 소리가 잠시 끊긴 뒤 재시작)",
    "fseventsd": "파일 변경 감지",
    "logd": "시스템 로그 기록",
    "distnoted": "알림 전달. 계속 높으면 재로그인 권장",
    "sysmond": "활동 모니터용 통계 수집",
    "Google Chrome Helper": "크롬 탭·확장 프로그램 (크롬에서 Shift+Esc로 확인)",
    "com.apple.WebKit": "Safari 또는 앱 안의 웹 페이지",
    "remoting_me2me_host": "크롬 원격 데스크톱 호스트. 원격 접속 중이면 높음 (안 쓴다면 확인 필요)",
    "com.docker": "Docker Desktop 가상 머신",
    "qemu": "가상 머신 (Docker·에뮬레이터)",
    "node": "Node.js 프로세스 (개발 서버·빌드 등)",
    "java": "Java 프로세스 (IDE·Gradle 등)",
    "Finder": "Finder (종료해도 자동 재시작)",
    "Dock": "Dock (종료해도 자동 재시작)",
}
_KNOWN_BY_LENGTH = sorted(((k.lower(), v) for k, v in KNOWN_PROCESSES.items()),
                          key=lambda kv: -len(kv[0]))


def owning_app(exe: str | None) -> str | None:
    """실행 파일 경로에서 가장 바깥쪽 .app 번들 경로를 돌려준다."""
    if not exe:
        return None
    idx = exe.find(".app/")
    return exe[: idx + 4] if idx != -1 else None


@functools.lru_cache(maxsize=4096)
def describe(name: str, exe: str | None = None) -> str:
    low = name.lower()
    for key, desc in _KNOWN_BY_LENGTH:
        if low.startswith(key):
            return desc
    app = owning_app(exe)
    return f"{os.path.basename(app)[:-4]} 앱" if app else ""


def is_system_user(user: str) -> bool:
    return user in ("", "root") or user.startswith("_")


@functools.lru_cache(maxsize=256)
def user_name(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


@dataclass(slots=True)
class ProcInfo:
    pid: int
    ppid: int | None
    name: str
    user: str
    exe: str | None
    cpu: float | None
    mem: float | None
    memory: int | None          # 활동 모니터의 '메모리'(물리 footprint). 못 읽으면 RSS
    mem_rss: bool               # memory 가 RSS 추정치인지 (권한 제한)
    threads: int | None
    status: str
    create_time: float | None
    desc: str
    app: str                    # 앱별 합계용 묶음 이름 (.app 번들 이름, 없으면 프로세스 이름)


@dataclass
class MemoryBreakdown:
    """vm_stat 기준 메모리 구성(바이트). 활동 모니터의 '사용된 메모리' = 앱 + 와이어드 + 압축."""
    total: int
    app: int          # 앱 메모리: 익명 페이지 − purgeable
    wired: int        # 커널·드라이버·GPU 가 고정한 메모리 (압축·스왑 불가)
    compressed: int   # 압축된 데이터가 실제로 차지한 RAM
    cached: int       # 파일 캐시: 필요하면 바로 비워진다
    free: int

    @property
    def used(self) -> int:
        return self.app + self.wired + self.compressed


@dataclass
class Snapshot:
    wall_time: float
    mono_time: float
    elapsed: float              # 수집에 걸린 시간(초)
    cpu: float
    cpu_user: float
    cpu_system: float
    per_core: list[float]
    vm: Any
    swap: Any
    load: tuple[float, float, float]
    disk_read: float            # B/s
    disk_write: float
    disk_free: int | None       # 내장 디스크(/) 여유 공간
    net_recv: float
    net_sent: float
    memory: MemoryBreakdown | None
    mem_pct: float              # 사용된 메모리 비율 (vm_stat 이 없으면 psutil 값)
    procs: list[ProcInfo]
    estimated: int              # psutil 권한 부족으로 CPU 를 ps 값으로 보완한 프로세스 수
    speed_limit: int | None     # pmset CPU_Speed_Limit, 100 미만이면 발열로 감속 중
    memory_level: int | None    # kern.memorystatus_level, 메모리 여유 비율(%)
    battery: Any


def _safe_call(fn):
    try:
        return fn()
    except (OSError, RuntimeError, psutil.Error):
        return None


def _run(cmd: list[str], timeout: float = 5) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def parse_cputime(text: str) -> float:
    """ps 의 TIME 값([dd-][hh:]mm:ss.ss)을 초로 바꾼다."""
    days = 0
    if "-" in text:
        day_part, text = text.split("-", 1)
        days = int(day_part)
    seconds = 0.0
    for part in text.split(":"):
        seconds = seconds * 60 + float(part)
    return days * 86400 + seconds


def read_ps_table() -> dict[int, tuple[float, int, str]]:
    """setuid 인 /bin/ps 로 모든 프로세스의 누적 CPU 시간(초), RSS(바이트), 실행 경로를 읽는다."""
    table = {}
    for line in _run(["/bin/ps", "-axo", "pid=,time=,rss=,comm="]).splitlines():
        parts = line.split(None, 3)
        if len(parts) < 3:
            continue
        try:
            table[int(parts[0])] = (parse_cputime(parts[1]), int(parts[2]) * 1024,
                                    parts[3] if len(parts) == 4 else "")
        except ValueError:
            continue
    return table


_SIZE_UNITS = {"B": 1, "K": 2**10, "M": 2**20, "G": 2**30, "T": 2**40}


def read_top_footprints() -> dict[int, int]:
    """setuid 인 top 으로 모든 프로세스의 메모리(footprint)를 읽는다.
    root 프로세스까지 정확하지만 CPU 를 약 2초 쓰므로 드물게만 호출한다."""
    table, started = {}, False
    for line in _run(["/usr/bin/top", "-l", "1", "-stats", "pid,mem"], timeout=20).splitlines():
        if not started:
            started = line.split()[:2] == ["PID", "MEM"]
            continue
        m = re.match(r"\s*(\d+)\s+([\d.]+)([BKMGT])", line)
        if m:
            table[int(m[1])] = int(float(m[2]) * _SIZE_UNITS[m[3]])
    return table


class _RusageInfoV0(ctypes.Structure):
    _fields_ = [("uuid", ctypes.c_uint8 * 16)] + [(name, ctypes.c_uint64) for name in (
        "user_time", "system_time", "pkg_idle_wkups", "interrupt_wkups", "pageins",
        "wired_size", "resident_size", "phys_footprint", "proc_start_abstime", "proc_exit_abstime")]


try:
    _libproc = ctypes.CDLL("/usr/lib/libproc.dylib")
    _libproc.proc_pid_rusage.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.POINTER(_RusageInfoV0)]
except (OSError, AttributeError):
    _libproc = None


def phys_footprint(pid: int) -> int | None:
    """활동 모니터의 '메모리' 값. 다른 사용자(root 등)의 프로세스는 권한이 없어 None."""
    if _libproc is None:
        return None
    info = _RusageInfoV0()
    if _libproc.proc_pid_rusage(pid, 0, ctypes.byref(info)) != 0:
        return None
    return info.phys_footprint


def read_memory_breakdown(total: int) -> MemoryBreakdown | None:
    out = _run(["/usr/bin/vm_stat"], timeout=3)
    m = re.search(r"page size of (\d+) bytes", out)
    if not m:
        return None
    page = int(m[1])
    pages = {}
    for line in out.splitlines()[1:]:
        key, _, value = line.partition(":")
        value = value.strip().rstrip(".")
        if value.isdigit():
            pages[key.strip().strip('"')] = int(value) * page
    try:
        purgeable = pages["Pages purgeable"]
        app = max(pages["Anonymous pages"] - purgeable, 0)
        cached = pages["File-backed pages"] + purgeable
        wired = pages["Pages wired down"]
        compressed = pages["Pages occupied by compressor"]
    except KeyError:
        return None
    return MemoryBreakdown(total=total, app=app, wired=wired, compressed=compressed, cached=cached,
                           free=max(total - app - wired - compressed - cached, 0))


def read_cpu_speed_limit() -> int | None:
    for line in _run(["/usr/bin/pmset", "-g", "therm"], timeout=3).splitlines():
        if "CPU_Speed_Limit" in line:
            try:
                return int(line.split("=")[1])
            except (IndexError, ValueError):
                return None
    return None


def read_memory_level() -> int | None:
    out = _run(["/usr/sbin/sysctl", "-n", "kern.memorystatus_level"], timeout=3).strip()
    return int(out) if out.isdigit() else None


class Sampler:
    """시스템·프로세스 상태를 수집한다. 한 스레드에서만 호출할 것."""

    EXTRAS_EVERY = 5.0  # pmset·sysctl·배터리는 몇 초에 한 번만 읽는다
    TOP_EVERY = 120.0   # root 프로세스 메모리용 top(1회 CPU 약 2초)은 앱별 화면을 볼 때만, 2분에 한 번
    TOP_MAX_AGE = 300.0

    def __init__(self, wake: threading.Event | None = None) -> None:
        # psutil 의 CPU 사용률은 직전 호출과의 차이로 계산되므로 한 번씩 미리 호출해 둔다.
        psutil.cpu_percent(percpu=True)
        psutil.cpu_times_percent()
        for _ in psutil.process_iter(["cpu_percent"], ad_value=None):
            pass
        self._last_mono = time.monotonic()
        self._last_disk = _safe_call(psutil.disk_io_counters)
        self._last_net = _safe_call(psutil.net_io_counters)
        self._ps_prev = {pid: row[0] for pid, row in read_ps_table().items()}
        self._ps_mono = time.monotonic()
        self._static: dict[int, tuple[str | None, dict]] = {}  # pid -> (ps 실행 경로, 정적 정보)
        self._extras_mono = float("-inf")
        self._speed_limit: int | None = None
        self._memory_level: int | None = None
        self._battery = None
        self._disk_free: int | None = None
        self._wake = wake
        self._top: tuple[float, dict[int, int]] = (float("-inf"), {})  # (읽은 시각, pid -> 바이트)
        self._top_started = float("-inf")

    def _refresh_top(self) -> None:
        table = read_top_footprints()
        if table:
            self._top = (time.monotonic(), table)  # 튜플 통째로 바꾸므로 잠금 없이 안전
            if self._wake:
                self._wake.set()

    def sample(self, top_wanted: bool = False) -> Snapshot:
        started = time.monotonic()
        times = psutil.cpu_times_percent()
        per_core = psutil.cpu_percent(percpu=True)
        vm = psutil.virtual_memory()
        swap = psutil.swap_memory()
        disk = _safe_call(psutil.disk_io_counters)
        net = _safe_call(psutil.net_io_counters)
        now = time.monotonic()
        dt = max(now - self._last_mono, 1e-6)
        disk_read = disk_write = net_recv = net_sent = 0.0
        if disk and self._last_disk:
            disk_read = max(0, disk.read_bytes - self._last_disk.read_bytes) / dt
            disk_write = max(0, disk.write_bytes - self._last_disk.write_bytes) / dt
        if net and self._last_net:
            net_recv = max(0, net.bytes_recv - self._last_net.bytes_recv) / dt
            net_sent = max(0, net.bytes_sent - self._last_net.bytes_sent) / dt
        self._last_mono, self._last_disk, self._last_net = now, disk, net

        if top_wanted and now - self._top_started >= self.TOP_EVERY:
            self._top_started = now
            threading.Thread(target=self._refresh_top, daemon=True, name="top").start()
        memory = read_memory_breakdown(vm.total)
        procs, estimated = self._processes(vm.total)

        if now - self._extras_mono >= self.EXTRAS_EVERY:
            self._extras_mono = now
            self._speed_limit = read_cpu_speed_limit()
            self._memory_level = read_memory_level()
            self._battery = _safe_call(psutil.sensors_battery)
            usage = _safe_call(lambda: psutil.disk_usage("/"))
            self._disk_free = usage.free if usage else None

        return Snapshot(
            wall_time=time.time(), mono_time=now, elapsed=time.monotonic() - started,
            cpu=max(0.0, 100.0 - times.idle), cpu_user=times.user + times.nice,
            cpu_system=times.system, per_core=per_core, vm=vm, swap=swap, load=os.getloadavg(),
            disk_read=disk_read, disk_write=disk_write, disk_free=self._disk_free,
            net_recv=net_recv, net_sent=net_sent, memory=memory, mem_pct=memory.used / memory.total * 100 if memory else vm.percent,
            procs=procs, estimated=estimated, speed_limit=self._speed_limit,
            memory_level=self._memory_level, battery=self._battery,
        )

    def _processes(self, mem_total: int) -> tuple[list[ProcInfo], int]:
        # psutil 은 root·다른 사용자 프로세스의 CPU·메모리를 읽지 못하므로 ps 값으로 보완한다.
        ps_table = read_ps_table()
        ps_mono = time.monotonic()
        ps_dt = ps_mono - self._ps_mono
        prev = self._ps_prev
        self._ps_prev = {pid: row[0] for pid, row in ps_table.items()}
        self._ps_mono = ps_mono
        top_time, top_table = self._top
        if time.monotonic() - top_time > self.TOP_MAX_AGE:
            top_table = {}

        procs, estimated = [], 0
        static_cache: dict[int, tuple[str | None, dict]] = {}
        for proc in psutil.process_iter(DYNAMIC_ATTRS, ad_value=None):
            pid, info = proc.pid, proc.info
            row = ps_table.get(pid)
            comm = row[2] if row else None
            cached = self._static.get(pid)
            if cached is None or (comm is not None and cached[0] != comm):
                # psutil 은 Process 객체에 exe·create_time 을 캐시하므로 새 객체로 읽어야 최신 값이다.
                try:
                    static = psutil.Process(pid).as_dict(STATIC_ATTRS, ad_value=None)
                except psutil.NoSuchProcess:
                    continue
                static["user"] = user_name(static["uids"].real) if static["uids"] else ""
                static["name"] = static["name"] or "?"
                static["desc"] = describe(static["name"], static["exe"])
                app = owning_app(static["exe"])
                static["app"] = os.path.basename(app)[:-4] if app else static["name"]
                cached = (comm, static)
            static_cache[pid] = cached
            static = cached[1]
            cpu = info["cpu_percent"]
            if cpu is None and row:
                estimated += 1
                if pid in prev and ps_dt > 0:
                    cpu = max(0.0, (row[0] - prev[pid]) / ps_dt * 100)
            # 메모리: 직접 읽은 footprint → (root 프로세스는) top 의 footprint → 그래도 없으면 ps 의 RSS
            memory, mem_rss = phys_footprint(pid), False
            if memory is None:
                memory = top_table.get(pid)
                if memory is None and row:
                    memory, mem_rss = row[1], True
            procs.append(ProcInfo(
                pid=pid, ppid=static["ppid"], name=static["name"], user=static["user"],
                exe=static["exe"], cpu=cpu, mem=None if memory is None else memory / mem_total * 100,
                memory=memory, mem_rss=mem_rss, threads=info["num_threads"],
                status=info["status"] or "", create_time=static["create_time"],
                desc=static["desc"], app=static["app"],
            ))
        self._static = static_cache
        return procs, estimated


class Collector(threading.Thread):
    """백그라운드에서 주기적으로 Sampler 를 돌려 결과를 큐에 넣는다."""

    def __init__(self, out: queue.Queue, interval: float) -> None:
        super().__init__(daemon=True, name="collector")
        self.out = out
        self.interval = interval
        self.paused = False
        self.top_wanted = False  # 앱별 메모리 화면을 보는 중이면 root 프로세스 메모리도 top 으로 채운다
        self.wake = threading.Event()
        self.stopping = threading.Event()

    def run(self) -> None:
        try:
            sampler = Sampler(wake=self.wake)
        except Exception as exc:  # noqa: BLE001 — GUI 에 알리고 종료
            self.out.put(("error", exc))
            return
        self.wake.wait(1.0)  # 첫 CPU 측정 구간
        while not self.stopping.is_set():
            self.wake.clear()
            if not self.paused:
                try:
                    self.out.put(("snapshot", sampler.sample(top_wanted=self.top_wanted)))
                except Exception as exc:  # noqa: BLE001
                    self.out.put(("error", exc))
            self.wake.wait(self.interval)


# ── 프로세스 종료·상세 ──────────────────────────────────────────────────────

@dataclass
class KillResult:
    gone: list[str] = field(default_factory=list)
    alive: list[str] = field(default_factory=list)
    denied: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def kill_processes(targets: list[tuple[int, float | None]], force: bool = False,
                   include_children: bool = False, wait: float = 3.0) -> KillResult:
    """targets 는 (pid, create_time) 목록. create_time 이 다르면 PID 가 재사용된 것이라 건너뛴다."""
    result = KillResult()
    me = os.getpid()
    labels: dict[int, str] = {}
    procs: list[psutil.Process] = []
    for pid, ctime in targets:
        if pid in NEVER_KILL or pid == me:
            result.errors.append(f"PID {pid}: 보호된 프로세스라 종료하지 않음")
            continue
        try:
            proc = psutil.Process(pid)
            label = f"{proc.name()} ({pid})"
            if ctime is not None and abs(proc.create_time() - ctime) > 0.01:
                result.errors.append(f"{label}: PID 가 다른 프로세스에 재사용되어 건너뜀")
                continue
            group = proc.children(recursive=True) if include_children else []
        except psutil.NoSuchProcess:
            result.gone.append(f"PID {pid}")
            continue
        except psutil.AccessDenied:
            result.denied.append(f"PID {pid}")
            continue
        for member in [*group, proc]:  # 자식부터 종료
            if member.pid in labels or member.pid == me or member.pid in NEVER_KILL:
                continue
            labels[member.pid] = label if member is proc else _label(member)
            procs.append(member)

    sent = []
    for proc in procs:
        try:
            proc.kill() if force else proc.terminate()
            sent.append(proc)
        except psutil.NoSuchProcess:
            result.gone.append(labels[proc.pid])
        except psutil.AccessDenied:
            result.denied.append(labels[proc.pid])
    gone, alive = psutil.wait_procs(sent, timeout=wait)
    result.gone += [labels[p.pid] for p in gone]
    result.alive += [labels[p.pid] for p in alive]
    return result


def _label(proc: psutil.Process) -> str:
    try:
        return f"{proc.name()} ({proc.pid})"
    except psutil.Error:
        return f"PID {proc.pid}"


def process_details(pid: int) -> dict[str, str]:
    """상세 창에 보여줄 항목. 프로세스가 사라졌으면 psutil.NoSuchProcess 를 낸다."""
    proc = psutil.Process(pid)
    rows: dict[str, str] = {}

    def add(label, fn):
        try:
            value = fn()
        except psutil.NoSuchProcess:
            raise
        except psutil.AccessDenied:
            value = "(권한 없음)"
        except (OSError, psutil.Error) as exc:
            value = f"({exc})"
        rows[label] = "" if value is None else str(value)

    with proc.oneshot():
        add("이름", proc.name)
        add("PID", lambda: proc.pid)
        add("부모", lambda: _label(proc.parent()) if proc.parent() else "-")
        add("사용자", proc.username)
        add("상태", proc.status)
        add("시작 시각", lambda: time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(proc.create_time())))
        add("실행 파일", proc.exe)
        add("소속 앱", lambda: owning_app(proc.exe()) or "-")
        add("명령줄", lambda: " ".join(proc.cmdline()))
        add("작업 폴더", proc.cwd)
        add("스레드 수", proc.num_threads)
        add("열린 파일 수", proc.num_fds)
        add("자식 프로세스", lambda: len(proc.children(recursive=True)))
    rows["설명"] = describe(rows["이름"], rows["실행 파일"] or None) or "-"
    return rows


# ── 저장 공간 ───────────────────────────────────────────────────────────────

# 용량을 많이 차지하기 쉬운 위치 (경로, 이름, 정리 방법). 있는 것만 보여준다.
STORAGE_LOCATIONS = (
    ("~/Downloads", "다운로드", "오래된 설치 파일(.dmg·.pkg·.zip)은 지워도 됨"),
    ("~/Desktop", "데스크탑", ""),
    ("~/Documents", "문서", ""),
    ("~/Movies", "동영상", ""),
    ("~/Pictures", "사진", "사진 보관함은 사진 앱 안에서 정리"),
    ("~/Music", "음악", ""),
    ("~/.Trash", "휴지통", "Finder 에서 '휴지통 비우기'로 비움 (크기는 전체 디스크 접근 권한이 있어야 보임)"),
    ("/Applications", "응용 프로그램", "안 쓰는 앱은 휴지통으로"),
    ("~/Library/Caches", "앱 캐시", "앱을 끈 뒤 하위 폴더를 지우면 필요할 때 다시 생성됨"),
    ("~/Library/Application Support", "앱 데이터", "브라우저 프로필 등. 각 앱 안에서 정리 권장"),
    ("~/Library/Developer/Xcode/DerivedData", "Xcode 빌드 캐시", "지워도 다음 빌드 때 다시 생성됨"),
    ("~/Library/Developer/Xcode/iOS DeviceSupport", "Xcode 기기 지원 파일", "오래된 iOS 버전 폴더는 지워도 됨"),
    ("~/Library/Developer/CoreSimulator", "iOS 시뮬레이터", "터미널: xcrun simctl delete unavailable"),
    ("~/Library/Android/sdk", "Android SDK", "안 쓰는 시스템 이미지는 SDK Manager 에서 삭제"),
    ("~/.gradle", "Gradle 캐시", "caches 폴더는 지워도 다시 내려받음"),
    ("~/.npm", "npm 캐시", "터미널: npm cache clean --force"),
    ("~/.cache", "개발 도구 캐시", "pip·huggingface 등. 하위 폴더별로 확인"),
    ("~/Library/Containers/com.docker.docker", "Docker 디스크 이미지",
     "Docker Desktop 설정 > Resources 또는 docker system prune (처음 계산 시 '다른 앱의 데이터' 접근을 물음)"),
)
DU_DENIED = ("Permission denied", "Operation not permitted")


def storage_locations() -> list[tuple[str, str, str]]:
    """존재하는 주요 위치 (절대 경로, 이름, 정리 방법)."""
    found = []
    for path, name, hint in STORAGE_LOCATIONS:
        full = os.path.expanduser(path)
        if os.path.isdir(full):
            found.append((full, name, hint))
    return found


def storage_hint(path: str) -> str:
    for full, name, hint in storage_locations():
        if path == full:
            return f"{name}. {hint}" if hint else name
    lower = path.lower()
    if lower.endswith((".dmg", ".pkg", ".iso")):
        return "설치 이미지. 설치를 마쳤다면 지워도 됨"
    if lower.endswith(".app"):
        return "앱"
    if os.path.basename(path) == "node_modules":
        return "npm 의존성. 프로젝트에서 npm install 로 다시 받을 수 있음"
    return ""


@dataclass
class VolumeUsage:
    name: str
    mount: str
    total: int
    free: int
    parts: list[tuple[str, int]]   # 사용 중인 공간의 구성 (이름, 바이트)

    @property
    def used(self) -> int:
        return max(self.total - self.free, 0)


def _boot_volume_name() -> str:
    try:
        for entry in os.scandir("/Volumes"):
            if entry.is_symlink() and os.path.realpath(entry.path) == "/":
                return entry.name
    except OSError:
        pass
    return "내장 디스크"


def read_volumes() -> list[VolumeUsage]:
    """내장 디스크(APFS 컨테이너 기준)와 /Volumes 아래 외장 볼륨의 사용량.
    APFS 에서 psutil 의 used 는 볼륨 하나의 사용량이라, 디스크 전체 사용량은 total − free 로 계산한다."""
    internal: dict[str, int] = {}
    root = None
    volumes = []
    for part in psutil.disk_partitions(all=False):
        mount = part.mountpoint
        usage = _safe_call(lambda: psutil.disk_usage(mount))  # noqa: B023 — 바로 호출
        if usage is None or usage.total == 0:
            continue
        if mount == "/":
            root = usage
            internal["시스템"] = internal.get("시스템", 0) + usage.used
        elif mount.startswith("/System/Volumes/"):
            role = mount.rsplit("/", 1)[-1]
            key = {"Data": "사용자 데이터·앱", "VM": "가상 메모리(스왑)"}.get(role, "기타")
            internal[key] = internal.get(key, 0) + usage.used
        elif mount.startswith("/Volumes/"):
            volumes.append(VolumeUsage(os.path.basename(mount), mount, usage.total, usage.free,
                                       [("사용", usage.total - usage.free)]))
    if root:
        used = root.total - root.free
        named = sum(v for k, v in internal.items() if k != "기타")
        internal["기타"] = max(used - named, 0)  # Preboot·스냅샷 등
        parts = [(k, internal[k]) for k in ("사용자 데이터·앱", "시스템", "가상 메모리(스왑)", "기타")
                 if internal.get(k)]
        volumes.insert(0, VolumeUsage(_boot_volume_name(), "/", root.total, root.free, parts))
    return volumes


@dataclass
class SizeEntry:
    path: str
    size: int | None        # 바이트. None 이면 읽을 권한이 없음
    partial: bool = False   # 일부 하위 항목을 읽지 못해 실제보다 작을 수 있음


def _du_denied_path(line: str) -> str | None:
    """'du: <경로>: Operation not permitted' 같은 오류 줄에서 경로를 뽑는다."""
    if not line.startswith("du: "):
        return None
    path, _, message = line[4:].rstrip("\n").rpartition(": ")
    return path if path and any(d in message for d in DU_DENIED) else None


class DiskScanner:
    """du 로 폴더 크기를 잰다. 한 번에 한 작업만 실행하고(새 작업이나 cancel 이 이전 du 를 끝낸다)
    결과는 ("disk", (작업 번호, 종류, 값)) 로 큐에 넣는다. 종류: entry · partial · done · error."""

    def __init__(self, out: queue.Queue) -> None:
        self.out = out
        self.job = 0
        self._proc: subprocess.Popen | None = None
        self._lock = threading.Lock()

    def cancel(self) -> None:
        with self._lock:
            self.job += 1
            proc, self._proc = self._proc, None
        if proc and proc.poll() is None:
            proc.kill()

    def scan(self, paths: list[str], children: bool) -> int:
        """children=False 면 paths 각각의 전체 크기, True 면 paths[0] 바로 아래 폴더별 크기와 전체 합계."""
        self.cancel()
        with self._lock:
            job = self.job
        threading.Thread(target=self._run, args=(job, paths, children), daemon=True, name="du").start()
        return job

    def _put(self, job: int, kind: str, value) -> None:
        self.out.put(("disk", (job, kind, value)))

    def _run(self, job: int, paths: list[str], children: bool) -> None:
        total = None
        try:
            if children:
                total = self._du(job, ["-k", "-d", "1", "-x"], paths[0], children=True)
            else:
                for path in paths:
                    self._du(job, ["-s", "-k", "-x"], path, children=False)
        except Exception as exc:  # noqa: BLE001 — 화면에 그대로 보여준다
            self._put(job, "error", repr(exc))
            return
        if job == self.job:
            self._put(job, "done", total)

    def _du(self, job: int, args: list[str], path: str, children: bool) -> int | None:
        with self._lock:
            if job != self.job:
                return None
            proc = self._proc = subprocess.Popen(["/usr/bin/du", *args, path], stdout=subprocess.PIPE,
                                                 stderr=subprocess.PIPE, text=True, errors="replace")
        denied: list[str] = []
        reader = threading.Thread(target=lambda: denied.extend(
            d for d in map(_du_denied_path, proc.stderr) if d), daemon=True)
        reader.start()
        total = None
        for line in proc.stdout:
            size_text, sep, entry_path = line.rstrip("\n").partition("\t")  # 경로에 공백이 있을 수 있다
            if not sep or not size_text.isdigit():
                continue
            size = int(size_text) * 1024
            if entry_path == path:
                total = size
                if children:
                    continue
            self._put(job, "entry", SizeEntry(entry_path, size))
        proc.wait()
        reader.join(timeout=2)
        for bad in denied:
            if bad == path and not children:
                self._put(job, "entry", SizeEntry(path, None))
            elif bad == path:
                self._put(job, "partial", path)
            else:
                first = os.path.relpath(bad, path).split(os.sep)[0]
                self._put(job, "partial", path if first in (".", "..") or not children
                          else os.path.join(path, first))
        return total


# POSIX file 변환은 Finder 블록 밖에서 해야 한다(안에서 하면 Finder 가 -1728 오류를 낸다).
# alias 는 링크를 따라가지만 trash_refusal 이 링크를 미리 거부한다.
TRASH_SCRIPT = """on run argv
    set targets to {}
    repeat with p in argv
        set end of targets to (POSIX file (p as text)) as alias
    end repeat
    tell application "Finder" to delete targets
end run"""


def trash_refusal(path: str) -> str | None:
    """휴지통으로 옮기면 안 되는 경로면 이유를, 괜찮으면 None 을 돌려준다."""
    if os.path.islink(path):
        return "링크(바로가기)는 Finder 에서 직접 지워 주세요"
    home = os.path.realpath(os.path.expanduser("~"))
    real = os.path.realpath(path)
    project = os.path.dirname(os.path.realpath(__file__))
    if real == project or project.startswith(real + os.sep) or real.startswith(project + os.sep):
        return "이 프로그램이 들어 있는 폴더입니다"
    if not (real.startswith(home + os.sep) or real.startswith("/Applications" + os.sep)):
        return "홈 폴더와 /Applications 안의 항목만 옮길 수 있습니다"
    protected = {os.path.join(home, name) for name in (
        "Desktop", "Documents", "Downloads", "Movies", "Music", "Pictures", "Public",
        "Library", "Applications", ".Trash")}
    protected |= {os.path.realpath(full) for full, *_ in storage_locations()}
    if real in protected:
        return "기본 폴더 자체는 옮길 수 없습니다 (안의 항목을 골라 주세요)"
    return None


def move_to_trash(paths: list[str]) -> str | None:
    """Finder 로 휴지통에 넣는다('되돌려 놓기' 가능). 처음에는 macOS 가 Finder 제어 권한을 묻는다.
    경로는 스크립트 문자열이 아니라 인자로 넘긴다. 실패하면 오류 메시지를 돌려준다."""
    result = subprocess.run(["/usr/bin/osascript", "-e", TRASH_SCRIPT, *paths],
                            capture_output=True, text=True, timeout=300, check=False)
    return None if result.returncode == 0 else (result.stderr.strip() or "알 수 없는 오류")


# ── GUI ──────────────────────────────────────────────────────────────────────

CHART_BG = "#1e1f22"
CHART_GRID = "#3a3c42"
CHART_TEXT = "#9aa0a6"
CPU_COLOR = "#3fb950"
MEM_COLOR = "#58a6ff"
HOT = "#e5484d"
WARM = "#d9822b"
FREE_COLOR = "#4a4d55"
MEM_PARTS = (  # 메모리 구성 막대의 순서·이름·색 (MemoryBreakdown 속성)
    ("app", "앱", MEM_COLOR),
    ("wired", "와이어드", "#e3b341"),
    ("compressed", "압축", "#bc8cff"),
    ("cached", "캐시", "#8b949e"),
    ("free", "여유", FREE_COLOR),
)
DIM = "#8b949e"
VOLUME_COLORS = (MEM_COLOR, "#e3b341", "#bc8cff", DIM)
STORAGE_COLUMNS = (
    ("name", "이름", 300, "w"),
    ("size", "크기", 110, "e"),
    ("share", "비율", 170, "w"),
    ("note", "설명 / 정리 방법", 440, "w"),
)
LOCATIONS_KEY = "<주요 위치>"
HISTORY_SECONDS = 120
INTERVALS = ("1", "2", "3", "5", "10")
STATUS_KO = {"running": "실행", "sleeping": "대기", "idle": "유휴", "stopped": "정지", "zombie": "좀비"}

COLUMNS = (  # 키(ProcInfo 속성), 제목, 폭, 정렬
    ("pid", "PID", 70, "e"),
    ("name", "이름", 240, "w"),
    ("user", "사용자", 110, "w"),
    ("cpu", "CPU %", 70, "e"),
    ("mem", "메모리 %", 75, "e"),
    ("memory", "메모리", 90, "e"),
    ("threads", "스레드", 60, "e"),
    ("status", "상태", 55, "center"),
    ("desc", "설명 / 소속 앱", 380, "w"),
)
NUMERIC_KEYS = {"pid", "cpu", "mem", "memory", "threads"}
APP_COLUMNS = (  # 앱별 메모리 탭
    ("app", "앱 / 프로세스", 240, "w"),
    ("count", "프로세스 수", 90, "e"),
    ("memory", "메모리", 100, "e"),
    ("share", "메모리 비율", 90, "e"),
    ("cpu", "CPU %", 80, "e"),
    ("desc", "설명", 420, "w"),
)


def fmt_bytes(n: float | None) -> str:
    """메모리 크기 (1024 단위, 활동 모니터와 같음)."""
    if n is None:
        return "–"
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024:
            return f"{n:.0f} {unit}" if unit in ("B", "KB") else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def fmt_disk(n: float | None) -> str:
    """디스크 크기 (1000 단위, Finder 와 같음: 500 GB 디스크가 500 GB 로 보이게)."""
    if n is None:
        return "–"
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1000:
            return f"{n:.0f} {unit}" if unit in ("B", "KB") else f"{n:.1f} {unit}"
        n /= 1000
    return f"{n:.2f} TB"


def fmt_rate(n: float) -> str:
    return fmt_bytes(n) + "/s"


def fmt_pct(v: float | None) -> str:
    return "–" if v is None else f"{v:.1f}"


def fmt_duration(seconds: float) -> str:
    days, rem = divmod(int(seconds), 86400)
    hours, rem = divmod(rem, 3600)
    if days:
        return f"{days}일 {hours}시간"
    if hours:
        return f"{hours}시간 {rem // 60}분"
    return f"{rem // 60}분"


def load_color(pct: float) -> str:
    return CPU_COLOR if pct < 50 else WARM if pct < 80 else HOT


def _set_text(label: ttk.Label, text: str, **options) -> None:
    """내용이 같으면 건드리지 않는다. 같은 값이라도 configure 하면 macOS Tk 는 창 전체를 다시 그린다."""
    if label.cget("text") != text or any(str(label.cget(k)) != str(v) for k, v in options.items()):
        label.configure(text=text, **options)


class Meter(tk.Canvas):
    """막대 게이지. macOS 의 ttk.Progressbar 는 쉬지 않고 애니메이션하며 창 전체를 다시 그려
    CPU 를 크게 쓰므로(표가 있는 창에서 60% 이상) 캔버스로 직접 그린다."""

    def __init__(self, parent: tk.Misc, color=load_color, width: int = 230, height: int = 8) -> None:
        super().__init__(parent, width=width, height=height, bg=CHART_GRID, highlightthickness=0, bd=0)
        self._color = color
        self._value = 0.0
        self.bind("<Configure>", lambda _e: self._draw())

    def set(self, value: float) -> None:
        if round(value) != round(self._value):
            self._value = value
            self._draw()

    def _draw(self) -> None:
        self.delete("all")
        width = self.winfo_width() * min(max(self._value, 0), 100) / 100
        self.create_rectangle(0, 0, width, self.winfo_height(), fill=self._color(self._value), outline="")


class StackBar(tk.Canvas):
    """메모리 구성 누적 막대. 어느 구간이든 0.1 GB 이상 바뀔 때만 다시 그린다."""

    STEP = 0.1 * 2**30

    def __init__(self, parent: tk.Misc, width: int = 230, height: int = 10) -> None:
        super().__init__(parent, width=width, height=height, bg=FREE_COLOR, highlightthickness=0, bd=0)
        self._parts: list[tuple[float, str]] = []
        self._total = 1.0
        self.bind("<Configure>", lambda _e: self._draw())

    def set(self, parts: list[tuple[float, str]], total: float) -> None:
        if (total == self._total and len(parts) == len(self._parts)
                and all(abs(a[0] - b[0]) < self.STEP for a, b in zip(parts, self._parts))):
            return
        self._parts, self._total = parts, total
        self._draw()

    def _draw(self) -> None:
        self.delete("all")
        width, height, x = self.winfo_width(), self.winfo_height(), 0.0
        for value, color in self._parts:
            dx = width * value / self._total
            self.create_rectangle(x, 0, x + dx, height, fill=color, outline="")
            x += dx


class App:
    def __init__(self, root: tk.Tk, interval: float = 3.0, interactive: bool = True) -> None:
        self.root = root
        self.interactive = interactive
        self.events: queue.Queue = queue.Queue()
        self.snapshot: Snapshot | None = None
        self.procs: dict[int, ProcInfo] = {}
        self.history: collections.deque = collections.deque(maxlen=3000)  # (mono, cpu, mem)
        self.sort_key, self.sort_desc = "cpu", True
        self.app_sort_key, self.app_sort_desc = "memory", True
        self._app_cache: dict[str, tuple] = {}
        self.scanner = DiskScanner(self.events)
        self.storage_mode = "locations"          # locations | folder
        self.storage_path: str | None = None
        self.storage_rows: dict[str, dict] = {}  # 경로 -> 표시 정보
        self.storage_total: int | None = None
        self.storage_partial = False
        self.storage_job: int | None = None      # 진행 중인 du 작업 번호
        self.storage_note = ""
        self.storage_cache: dict[str, tuple] = {}  # 다 잰 폴더 -> (rows, total, partial)
        self.last_trash: tuple | None = None
        self._storage_row_cache: dict[str, tuple] = {}
        self._volume_widgets: dict[str, dict] = {}
        self._storage_autoscanned = False
        self.errors: list[str] = []
        self.render_count = 0
        self.last_kill: KillResult | None = None
        self._row_cache: dict[str, tuple] = {}
        self._message_token: object | None = None
        self._closed = False
        self.me = _safe_call(lambda: psutil.Process().username()) or ""
        self.boot_time = psutil.boot_time()

        root.title("Mac 프로세스 모니터")
        root.geometry("1280x860")
        root.minsize(1120, 680)
        root.report_callback_exception = self._on_tk_error
        self._init_fonts()
        self._build_dashboard()
        self._build_toolbar(interval)
        self._build_statusbar()
        self._build_table()
        self._bind_keys()

        self.collector = Collector(self.events, interval)
        self.collector.start()
        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.after(150, self._poll_events)

    # ── 화면 구성 ──

    def _init_fonts(self) -> None:
        base = tkfont.nametofont("TkDefaultFont")
        size = abs(int(base.cget("size"))) or 13
        self.font_big = base.copy()
        self.font_big.configure(size=size + 12, weight="bold")
        self.font_bold = base.copy()
        self.font_bold.configure(weight="bold")
        self.font_small = base.copy()
        self.font_small.configure(size=max(size - 2, 9))

    def _card(self, parent: ttk.Frame, title: str, column: int, lines: int, meter_color=None) -> dict:
        frame = ttk.LabelFrame(parent, text=title, padding=8)
        frame.grid(row=0, column=column, sticky="nsew", padx=(0, 8))
        widgets: dict[str, Any] = {"frame": frame, "lines": []}
        if meter_color:
            widgets["value"] = ttk.Label(frame, text="–", font=self.font_big)
            widgets["value"].pack(anchor="w")
            widgets["bar"] = Meter(frame, color=meter_color)
            widgets["bar"].pack(fill="x", pady=(2, 6))
        for _ in range(lines):
            label = ttk.Label(frame, text="")
            label.pack(anchor="w")
            widgets["lines"].append(label)
        return widgets

    def _build_memory_card(self, parent: ttk.Frame, column: int) -> dict:
        widgets = self._card(parent, "메모리", column, lines=0)
        frame = widgets["frame"]
        widgets["value"] = ttk.Label(frame, text="–", font=self.font_big)
        widgets["value"].pack(anchor="w")
        widgets["bar"] = StackBar(frame)
        widgets["bar"].pack(fill="x", pady=(2, 4))
        legend = ttk.Frame(frame)
        legend.pack(anchor="w", pady=(0, 2))
        self.mem_legend: dict[str, ttk.Label] = {}
        for i, (key, title, color) in enumerate(MEM_PARTS):
            cell = ttk.Frame(legend)
            cell.grid(row=i // 3, column=i % 3, sticky="w", padx=(0, 8))
            ttk.Label(cell, text="■", foreground=color, font=self.font_small).pack(side="left")
            self.mem_legend[key] = ttk.Label(cell, text=title, font=self.font_small)
            self.mem_legend[key].pack(side="left")
        for _ in range(2):
            label = ttk.Label(frame, text="")
            label.pack(anchor="w")
            widgets["lines"].append(label)
        return widgets

    def _build_dashboard(self) -> None:
        dash = ttk.Frame(self.root, padding=(10, 10, 10, 0))
        dash.pack(side="top", fill="x")
        cards = ttk.Frame(dash)
        cards.pack(fill="x")
        cards.columnconfigure(3, weight=1)
        self.cpu_w = self._card(cards, "CPU", 0, lines=2, meter_color=load_color)
        self.mem_w = self._build_memory_card(cards, 1)
        self.sys_w = self._card(cards, "시스템", 2, lines=5)
        self.core_canvas = tk.Canvas(cards, width=200, height=150, bg=CHART_BG, highlightthickness=0)
        self.core_canvas.grid(row=0, column=3, sticky="nsew")

        lower = ttk.Frame(dash)
        lower.pack(fill="x", pady=(8, 0))
        self.history_canvas = tk.Canvas(lower, width=300, height=150, bg=CHART_BG, highlightthickness=0)
        self.history_canvas.pack(side="left", fill="both", expand=True)
        top = ttk.LabelFrame(lower, text="지금 CPU를 많이 쓰는 프로세스 (클릭하면 목록에서 선택)", padding=6)
        top.pack(side="left", fill="y", padx=(8, 0))
        self.top_tree = ttk.Treeview(top, columns=("cpu", "name", "desc"), show="headings",
                                     height=5, selectmode="none")
        for key, title, width, anchor in (("cpu", "CPU %", 60, "e"), ("name", "이름", 170, "w"),
                                          ("desc", "설명 / 소속 앱", 290, "w")):
            self.top_tree.heading(key, text=title)
            self.top_tree.column(key, width=width, anchor=anchor, stretch=False)
        self.top_tree.tag_configure("hot", foreground=HOT)
        self.top_tree.tag_configure("warm", foreground=WARM)
        self.top_tree.pack(fill="both", expand=True)
        self.history_canvas.bind("<Configure>", lambda _e: self._draw_history())
        self.core_canvas.bind("<Configure>", lambda _e: self._draw_cores())

    def _build_toolbar(self, interval: float) -> None:
        bar = ttk.Frame(self.root, padding=(10, 8, 10, 4))
        bar.pack(side="top", fill="x")
        # 창이 좁아져도 종료 버튼이 잘리지 않도록 오른쪽 묶음을 먼저 배치한다.
        ttk.Button(bar, text="강제 종료", command=lambda: self.kill_selected(force=True)).pack(side="right")
        ttk.Button(bar, text="종료", command=lambda: self.kill_selected(force=False)).pack(side="right", padx=(0, 4))
        ttk.Button(bar, text="상세 정보", command=self.show_details).pack(side="right", padx=(0, 4))
        self.children_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="자식 프로세스 포함", variable=self.children_var).pack(side="right", padx=(0, 10))

        ttk.Label(bar, text="검색").pack(side="left")
        self.filter_var = tk.StringVar()
        self.filter_entry = ttk.Entry(bar, textvariable=self.filter_var, width=20)
        self.filter_entry.pack(side="left", padx=(4, 10))
        self.filter_var.trace_add("write", lambda *_: self._render_visible())
        self.mine_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="내 프로세스만", variable=self.mine_var,
                        command=self._render_visible).pack(side="left")
        ttk.Label(bar, text="갱신").pack(side="left", padx=(14, 4))
        self.interval_var = tk.StringVar(value=f"{interval:g}")
        combo = ttk.Combobox(bar, textvariable=self.interval_var, values=INTERVALS,
                             width=4, state="readonly")
        combo.pack(side="left")
        combo.bind("<<ComboboxSelected>>", self._on_interval)
        ttk.Label(bar, text="초").pack(side="left", padx=(2, 8))
        self.pause_button = ttk.Button(bar, text="일시정지", command=self.toggle_pause)
        self.pause_button.pack(side="left")
        ttk.Button(bar, text="새로고침", command=self.refresh_now).pack(side="left", padx=(4, 0))

    def _build_statusbar(self) -> None:
        bar = ttk.Frame(self.root, padding=(10, 4, 10, 8))
        bar.pack(side="bottom", fill="x")
        self.status_var = tk.StringVar(value="데이터 수집 중…")
        ttk.Label(bar, textvariable=self.status_var).pack(side="left")
        self.message_var = tk.StringVar()
        ttk.Label(bar, textvariable=self.message_var, font=self.font_bold).pack(side="right")

    def _build_table(self) -> None:
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(side="top", fill="both", expand=True, padx=10)
        frame = self.proc_tab = ttk.Frame(self.notebook)
        self.apps_tab = ttk.Frame(self.notebook, padding=(0, 4, 0, 0))
        self.storage_tab = ttk.Frame(self.notebook, padding=(0, 4, 0, 0))
        self.notebook.add(self.proc_tab, text="프로세스")
        self.notebook.add(self.apps_tab, text="앱별 메모리")
        self.notebook.add(self.storage_tab, text="저장 공간")
        self._build_apps_tab()
        self._build_storage_tab()
        self.tree = ttk.Treeview(frame, columns=[c[0] for c in COLUMNS], show="headings",
                                 selectmode="extended")
        for key, title, width, anchor in COLUMNS:
            self.tree.heading(key, text=title, command=lambda k=key: self.sort_by(k))
            self.tree.column(key, width=width, minwidth=40, anchor=anchor,
                             stretch=key in ("name", "desc"))
        scroll = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="left", fill="y")
        self.tree.tag_configure("hot", foreground=HOT)
        self.tree.tag_configure("warm", foreground=WARM)
        self._update_headings()

        self.menu = tk.Menu(self.root, tearoff=0)
        self.menu.add_command(label="상세 정보", command=self.show_details)
        self.menu.add_command(label="Finder에서 보기", command=self.reveal_selected)
        self.menu.add_separator()
        self.menu.add_command(label="종료 (SIGTERM)", command=lambda: self.kill_selected(force=False))
        self.menu.add_command(label="강제 종료 (SIGKILL)", command=lambda: self.kill_selected(force=True))

    def _build_apps_tab(self) -> None:
        self.apps_info = ttk.Label(self.apps_tab, text="", font=self.font_small)
        self.apps_info.pack(anchor="w", pady=(0, 4))
        body = ttk.Frame(self.apps_tab)
        body.pack(fill="both", expand=True)
        self.app_tree = ttk.Treeview(body, columns=[c[0] for c in APP_COLUMNS], show="headings",
                                     selectmode="browse")
        for key, title, width, anchor in APP_COLUMNS:
            self.app_tree.heading(key, text=title, command=lambda k=key: self.sort_apps_by(k))
            self.app_tree.column(key, width=width, minwidth=40, anchor=anchor, stretch=key in ("app", "desc"))
        scroll = ttk.Scrollbar(body, orient="vertical", command=self.app_tree.yview)
        self.app_tree.configure(yscrollcommand=scroll.set)
        self.app_tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="left", fill="y")
        self.app_tree.tag_configure("warm", foreground=WARM)
        self.app_tree.bind("<Double-1>", self._on_app_double_click)
        self.app_tree.bind("<Return>", lambda _e: self._open_selected_app())
        self._update_app_headings()

    def _build_storage_tab(self) -> None:
        tab = self.storage_tab
        self.volume_frame = ttk.Frame(tab)
        self.volume_frame.pack(fill="x", pady=(0, 6))
        self.volume_frame.columnconfigure(1, weight=1)

        bar = ttk.Frame(tab)
        bar.pack(fill="x", pady=(0, 4))
        ttk.Button(bar, text="휴지통으로 이동", command=self.storage_trash).pack(side="right")
        ttk.Button(bar, text="Finder에서 보기", command=self.storage_reveal).pack(side="right", padx=(0, 4))
        ttk.Button(bar, text="주요 위치", command=self.storage_show_locations).pack(side="left")
        ttk.Button(bar, text="◀ 상위 폴더", command=self.storage_up).pack(side="left", padx=(4, 0))
        ttk.Button(bar, text="폴더 선택…", command=self.storage_choose_folder).pack(side="left", padx=(4, 0))
        ttk.Button(bar, text="크기 계산", command=self.storage_scan).pack(side="left", padx=(12, 0))
        ttk.Button(bar, text="중지", command=self.storage_stop).pack(side="left", padx=(4, 0))
        self.storage_path_label = ttk.Label(bar, text="", font=self.font_bold)
        self.storage_path_label.pack(side="left", padx=(12, 0))
        self.storage_info = ttk.Label(tab, text="", font=self.font_small)
        self.storage_info.pack(anchor="w", pady=(0, 4))

        body = ttk.Frame(tab)
        body.pack(fill="both", expand=True)
        self.storage_tree = ttk.Treeview(body, columns=[c[0] for c in STORAGE_COLUMNS], show="headings",
                                         selectmode="extended")
        for key, title, width, anchor in STORAGE_COLUMNS:
            self.storage_tree.heading(key, text=title)
            self.storage_tree.column(key, width=width, minwidth=40, anchor=anchor,
                                     stretch=key in ("name", "note"))
        scroll = ttk.Scrollbar(body, orient="vertical", command=self.storage_tree.yview)
        self.storage_tree.configure(yscrollcommand=scroll.set)
        self.storage_tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="left", fill="y")
        self.storage_tree.tag_configure("dim", foreground=DIM)
        self.storage_tree.tag_configure("warm", foreground=WARM)
        self.storage_tree.bind("<Double-1>", self._on_storage_double_click)
        self.storage_tree.bind("<Return>", lambda _e: self._open_selected_folder())
        self.storage_tree.bind("<BackSpace>", lambda _e: self.storage_up())
        self.storage_show_locations()

    def _bind_keys(self) -> None:
        self.tree.bind("<Double-1>", self._on_double_click)
        self.tree.bind("<Return>", lambda _e: self.show_details())
        self.tree.bind("<BackSpace>", lambda _e: self.kill_selected(force=False))
        self.tree.bind("<Delete>", lambda _e: self.kill_selected(force=False))
        for seq in ("<Button-2>", "<Button-3>", "<Control-Button-1>"):
            self.tree.bind(seq, self._on_right_click)
        self.top_tree.bind("<ButtonRelease-1>", self._on_top_click)
        self.root.bind("<Command-f>", lambda _e: self.filter_entry.focus_set())
        self.filter_entry.bind("<Escape>", lambda _e: self.filter_var.set(""))

    # ── 갱신 ──

    def _poll_events(self) -> None:
        latest, kills, disk_events, trashes = None, [], [], []
        try:
            while True:
                try:
                    kind, payload = self.events.get_nowait()
                except queue.Empty:
                    break
                if kind == "snapshot":
                    latest = payload
                elif kind == "kill":
                    kills.append(payload)
                elif kind == "disk":
                    disk_events.append(payload)
                elif kind == "trash":
                    trashes.append(payload)
                elif kind == "error":
                    self._record_error(f"수집 오류: {payload!r}")
            if latest is not None:
                self._apply_snapshot(latest)
            if disk_events:
                for event in disk_events:
                    self._on_disk_event(*event)
                self._render_storage()
            for result, force in kills:
                self._on_kill_result(result, force)
            for paths, error in trashes:
                self._on_trash_result(paths, error)
        finally:
            if not self._closed:
                self.root.after(150, self._poll_events)

    def _apply_snapshot(self, snap: Snapshot) -> None:
        self.snapshot = snap
        self.procs = {p.pid: p for p in snap.procs}
        self.history.append((snap.mono_time, snap.cpu, snap.mem_pct))
        # macOS 의 Tk 는 위젯 하나만 바뀌어도 창 전체를 다시 그리므로, 최소화 중에는 화면을 건드리지 않는다.
        if self.root.state() == "iconic":
            return
        self._update_cards(snap)
        self._draw_history()
        self._draw_cores()
        self._render_visible()
        self._render_top(snap)
        self.render_count += 1

    def _update_cards(self, s: Snapshot) -> None:
        _set_text(self.cpu_w["value"], f"{s.cpu:.0f}%")
        self.cpu_w["bar"].set(s.cpu)
        usage, load = self.cpu_w["lines"]
        _set_text(usage, f"사용자 {s.cpu_user:.0f}% · 시스템 {s.cpu_system:.0f}% · 코어 {len(s.per_core)}개")
        _set_text(load, "부하 평균 " + " / ".join(f"{x:.2f}" for x in s.load))

        vm, mem = s.vm, s.memory
        _set_text(self.mem_w["value"], f"{s.mem_pct:.0f}%")
        used, swap = self.mem_w["lines"]
        if mem:
            self.mem_w["bar"].set([(getattr(mem, key), color) for key, _, color in MEM_PARTS[:4]], mem.total)
            for key, title, _ in MEM_PARTS:
                _set_text(self.mem_legend[key], f"{title} {fmt_bytes(getattr(mem, key))}")
            _set_text(used, f"사용 {fmt_bytes(mem.used)} / {fmt_bytes(mem.total)} (앱+와이어드+압축)")
        else:
            self.mem_w["bar"].set([(vm.total - vm.available, MEM_COLOR)], vm.total)
            _set_text(used, f"사용 {fmt_bytes(vm.total - vm.available)} / {fmt_bytes(vm.total)}")
        swap_text = f"스왑 {fmt_bytes(s.swap.used)} / {fmt_bytes(s.swap.total)}"
        if s.memory_level is not None:
            swap_text += f" · 여유 수준 {s.memory_level}%"
        _set_text(swap, swap_text)

        thermal, disk, net, procs, power = self.sys_w["lines"]
        if s.speed_limit is None:
            _set_text(thermal, "열 상태: 정보 없음", foreground="")
        elif s.speed_limit < 100:
            _set_text(thermal, f"⚠ 발열로 CPU 감속 중 (최대 속도 {s.speed_limit}%)", foreground=HOT)
        else:
            _set_text(thermal, "열 상태: 정상 (CPU 속도 제한 없음)", foreground="")
        free = f"여유 {fmt_disk(s.disk_free)} · " if s.disk_free is not None else ""
        _set_text(disk, f"디스크 {free}읽기 {fmt_rate(s.disk_read)} · 쓰기 {fmt_rate(s.disk_write)}")
        _set_text(net, f"네트워크 ↓ {fmt_rate(s.net_recv)} · ↑ {fmt_rate(s.net_sent)}")
        _set_text(procs, f"프로세스 {len(s.procs)}개 · 가동 {fmt_duration(time.time() - self.boot_time)}")
        if s.battery is None:
            _set_text(power, "전원: 정보 없음")
        else:
            source = "전원 연결" if s.battery.power_plugged else "배터리 사용 중"
            _set_text(power, f"배터리 {s.battery.percent:.0f}% · {source}")

    def _draw_history(self) -> None:
        c = self.history_canvas
        c.delete("all")
        w, h = c.winfo_width(), c.winfo_height()
        if w < 60 or h < 40:
            return
        left, right, top, bottom = 34, 10, 22, 10
        pw, ph = w - left - right, h - top - bottom
        for pct in (0, 25, 50, 75, 100):
            y = top + ph * (1 - pct / 100)
            c.create_line(left, y, w - right, y, fill=CHART_GRID, dash=() if pct in (0, 100) else (2, 3))
            c.create_text(left - 6, y, text=str(pct), fill=CHART_TEXT, anchor="e", font=self.font_small)
        c.create_text(left, 4, anchor="nw", text="● CPU", fill=CPU_COLOR, font=self.font_small)
        c.create_text(left + 64, 4, anchor="nw", text="● 메모리", fill=MEM_COLOR, font=self.font_small)
        c.create_text(w - right, 4, anchor="ne", text=f"최근 {HISTORY_SECONDS}초 (%)",
                      fill=CHART_TEXT, font=self.font_small)
        if not self.history:
            return
        now = self.history[-1][0]
        for idx, color in ((2, MEM_COLOR), (1, CPU_COLOR)):
            points = []
            for sample in self.history:
                age = now - sample[0]
                if age <= HISTORY_SECONDS:
                    points += (left + pw * (1 - age / HISTORY_SECONDS),
                               top + ph * (1 - min(sample[idx], 100) / 100))
            if len(points) >= 4:
                c.create_line(*points, fill=color, width=2)

    def _draw_cores(self) -> None:
        c = self.core_canvas
        c.delete("all")
        w, h = c.winfo_width(), c.winfo_height()
        cores = self.snapshot.per_core if self.snapshot else []
        c.create_text(10, 4, anchor="nw", fill=CHART_TEXT, font=self.font_small,
                      text=f"코어별 사용률 ({len(cores)}개)" if cores else "코어별 사용률")
        if not cores or w < 60:
            return
        pad, top, bottom, gap = 10, 24, h - 10, 3
        bar_w = (w - 2 * pad - gap * (len(cores) - 1)) / len(cores)
        for i, value in enumerate(cores):
            x0 = pad + i * (bar_w + gap)
            c.create_rectangle(x0, top, x0 + bar_w, bottom, fill="#2b2d31", outline="")
            y = bottom - (bottom - top) * min(value, 100) / 100
            c.create_rectangle(x0, y, x0 + bar_w, bottom, fill=load_color(value), outline="")

    def _row_tags(self, p: ProcInfo) -> tuple[str, ...]:
        if p.cpu is None:
            return ()
        return ("hot",) if p.cpu >= 50 else ("warm",) if p.cpu >= 15 else ()

    def _row_values(self, p: ProcInfo) -> tuple:
        memory = fmt_bytes(p.memory) + ("*" if p.mem_rss else "")
        return (p.pid, p.name, p.user, fmt_pct(p.cpu), fmt_pct(p.mem), memory,
                "" if p.threads is None else p.threads, STATUS_KO.get(p.status, p.status), p.desc)

    def _sort_value(self, p: ProcInfo):
        value = getattr(p, self.sort_key)
        if isinstance(value, str):
            return value.lower()
        return -1 if value is None else value

    def _filtered_procs(self) -> list[ProcInfo]:
        text = self.filter_var.get().strip().lower()
        mine = self.mine_var.get()
        rows = []
        for p in self.procs.values():
            if mine and p.user != self.me:
                continue
            if text and not (text in p.name.lower() or text in p.user.lower() or text in str(p.pid)
                             or text in p.desc.lower() or text in p.app.lower()):
                continue
            rows.append(p)
        return rows

    def _visible_procs(self) -> list[ProcInfo]:
        rows = self._filtered_procs()
        rows.sort(key=self._sort_value, reverse=self.sort_desc)
        return rows

    def _apps_tab_active(self) -> bool:
        return self.notebook.select() == str(self.apps_tab)

    def _storage_tab_active(self) -> bool:
        return self.notebook.select() == str(self.storage_tab)

    def _render_visible(self) -> None:
        # 보이지 않는 탭까지 갱신하면 그만큼 다시 그리는 비용이 들므로 보이는 탭만 그린다.
        if self._apps_tab_active():
            self._render_apps()
        elif self._storage_tab_active():
            self._render_volumes()
            self._update_status()
        else:
            self._render_table()

    def _app_groups(self) -> list[dict]:
        groups: dict[str, dict] = {}
        for p in self._filtered_procs():
            g = groups.get(p.app)
            if g is None:
                g = groups[p.app] = {"app": p.app, "count": 0, "memory": 0, "estimated": False,
                                     "cpu": 0.0, "top": p}
            g["count"] += 1
            g["memory"] += p.memory or 0
            g["estimated"] |= p.mem_rss
            g["cpu"] += p.cpu or 0.0
            if (p.memory or 0) > (g["top"].memory or 0):
                g["top"] = p
        total = self.snapshot.vm.total
        rows = list(groups.values())
        for g in rows:
            top = g["top"]
            g["share"] = g["memory"] / total * 100
            if g["count"] > 1:
                g["desc"] = f"가장 큰 프로세스: {top.name} ({fmt_bytes(top.memory)})"
            else:
                g["desc"] = "" if top.desc.endswith(" 앱") else top.desc
        key = self.app_sort_key
        rows.sort(key=lambda g: g[key].lower() if isinstance(g[key], str) else g[key],
                  reverse=self.app_sort_desc)
        return rows

    def _render_apps(self) -> None:
        if self.snapshot is None:
            return
        tree = self.app_tree
        selected = tree.selection()
        groups = self._app_groups()
        wanted = ["a:" + g["app"] for g in groups]
        existing = set(tree.get_children(""))
        stale = existing - set(wanted)
        if stale:
            tree.delete(*stale)
            for iid in stale:
                self._app_cache.pop(iid, None)
        for g, iid in zip(groups, wanted):
            row = ((g["app"], g["count"], fmt_bytes(g["memory"]) + ("*" if g["estimated"] else ""),
                    f"{g['share']:.1f}%", fmt_pct(g["cpu"]), g["desc"]),
                   ("warm",) if g["memory"] >= 2**30 else ())
            if iid not in existing:
                tree.insert("", "end", iid=iid, values=row[0], tags=row[1])
            elif self._app_cache.get(iid) != row:
                tree.item(iid, values=row[0], tags=row[1])
            self._app_cache[iid] = row
        if tuple(wanted) != tree.get_children(""):
            tree.set_children("", *wanted)
        keep = [iid for iid in selected if tree.exists(iid)]
        if keep and tuple(keep) != tree.selection():
            tree.selection_set(keep)
        info = (f"앱·프로세스 묶음 {len(groups)}개 · 합계 {fmt_bytes(sum(g['memory'] for g in groups))}"
                " · 메모리는 활동 모니터와 같은 기준(압축분 포함) · 더블클릭하면 해당 프로세스 목록으로 이동")
        if any(g["estimated"] for g in groups):
            info += " · * 는 root 프로세스를 아직 RSS 로 추정 중 (top 으로 곧 갱신)"
        _set_text(self.apps_info, info)
        self._update_status()

    def _update_app_headings(self) -> None:
        for key, title, *_ in APP_COLUMNS:
            arrow = (" ▼" if self.app_sort_desc else " ▲") if key == self.app_sort_key else ""
            self.app_tree.heading(key, text=title + arrow)

    def _render_table(self) -> None:
        # 행 iid 를 PID 로 고정해 갱신 중에도 선택·스크롤 위치가 유지되게 한다.
        tree = self.tree
        selected = tree.selection()
        yview = tree.yview()[0]
        rows = self._visible_procs()
        wanted = [str(p.pid) for p in rows]
        wanted_set = set(wanted)
        existing = set(tree.get_children(""))
        stale = [iid for iid in existing if iid not in wanted_set]
        if stale:
            tree.delete(*stale)
            for iid in stale:
                self._row_cache.pop(iid, None)
        for p, iid in zip(rows, wanted):
            row = (self._row_values(p), self._row_tags(p))
            if iid not in existing:
                tree.insert("", "end", iid=iid, values=row[0], tags=row[1])
            elif self._row_cache.get(iid) != row:
                tree.item(iid, values=row[0], tags=row[1])
            self._row_cache[iid] = row
        if tuple(wanted) != tree.get_children(""):
            tree.set_children("", *wanted)
        keep = [iid for iid in selected if iid in wanted_set]
        if keep and tuple(keep) != tree.selection():
            tree.selection_set(keep)
        tree.yview_moveto(yview)
        self._update_status()

    def _render_top(self, s: Snapshot) -> None:
        top = sorted(s.procs, key=lambda p: -1 if p.cpu is None else p.cpu, reverse=True)[:5]
        self.top_tree.delete(*self.top_tree.get_children(""))
        for p in top:
            self.top_tree.insert("", "end", iid=str(p.pid), tags=self._row_tags(p),
                                 values=(fmt_pct(p.cpu), p.name, p.desc or p.user))

    def _update_status(self) -> None:
        s = self.snapshot
        if s is None:
            return
        if self._apps_tab_active():
            shown = f"앱 {len(self.app_tree.get_children(''))}개"
        elif self._storage_tab_active():
            shown = "저장 공간"
        else:
            shown = f"표시 {len(self.tree.get_children(''))}개"
        parts = [f"프로세스 {len(s.procs)}개 ({shown})",
                 f"갱신 {time.strftime('%H:%M:%S', time.localtime(s.wall_time))}",
                 f"수집 {s.elapsed * 1000:.0f}ms"]
        if s.estimated:
            parts.append(f"권한 제한 {s.estimated}개는 ps 값으로 보완 (스레드 수 미표시)")
        rss_only = sum(1 for p in s.procs if p.mem_rss)
        if rss_only:
            parts.append(f"메모리* {rss_only}개는 RSS 추정")
        if self.collector.paused:
            parts.insert(0, "⏸ 일시정지됨")
        self.status_var.set("   ·   ".join(parts))

    def _update_headings(self) -> None:
        for key, title, *_ in COLUMNS:
            arrow = (" ▼" if self.sort_desc else " ▲") if key == self.sort_key else ""
            self.tree.heading(key, text=title + arrow)

    # ── 사용자 동작 ──

    def sort_by(self, key: str) -> None:
        if self.sort_key == key:
            self.sort_desc = not self.sort_desc
        else:
            self.sort_key, self.sort_desc = key, key in NUMERIC_KEYS
        self._update_headings()
        self._render_table()

    def sort_apps_by(self, key: str) -> None:
        if self.app_sort_key == key:
            self.app_sort_desc = not self.app_sort_desc
        else:
            self.app_sort_key, self.app_sort_desc = key, key not in ("app", "desc")
        self._update_app_headings()
        self._render_apps()

    def _on_tab_changed(self, _event=None) -> None:
        if self._storage_tab_active():
            self._render_volumes()
            # 처음 열면 주요 위치 크기를 바로 잰다 (버튼을 누르기 전엔 비어 보여 고장으로 오해하기 쉽다).
            if (self.interactive and not self._storage_autoscanned and self.storage_mode == "locations"
                    and LOCATIONS_KEY not in self.storage_cache and self.storage_job is None):
                self._storage_autoscanned = True
                self.storage_scan()
        apps = self._apps_tab_active()
        self.collector.top_wanted = apps
        if apps:
            self.collector.wake.set()
        self._render_visible()

    def _on_app_double_click(self, event) -> None:
        if self.app_tree.identify_region(event.x, event.y) == "cell":
            self._open_selected_app()

    def _open_selected_app(self) -> None:
        selection = self.app_tree.selection()
        if selection:
            self.open_app_group(selection[0][2:])

    def open_app_group(self, app: str) -> None:
        """앱 묶음의 프로세스만 보이도록 검색어를 넣고 프로세스 탭으로 이동한다."""
        self.mine_var.set(False)
        self.filter_var.set(app)
        self.notebook.select(self.proc_tab)

    # ── 저장 공간 ──

    def _render_volumes(self) -> None:
        volumes = read_volumes()
        frame = self.volume_frame
        if set(self._volume_widgets) != {v.mount for v in volumes}:
            for child in frame.winfo_children():
                child.destroy()
            self._volume_widgets = {}
            for row, vol in enumerate(volumes):
                widgets = {
                    "name": ttk.Label(frame, text=vol.name, font=self.font_bold),
                    "bar": StackBar(frame, width=360, height=12),
                    "summary": ttk.Label(frame, text=""),
                    "legend": ttk.Frame(frame),
                    "parts": None,
                    "labels": [],
                }
                widgets["name"].grid(row=row * 2, column=0, sticky="w", padx=(0, 10))
                widgets["bar"].grid(row=row * 2, column=1, sticky="ew")
                widgets["summary"].grid(row=row * 2, column=2, sticky="w", padx=(10, 0))
                widgets["legend"].grid(row=row * 2 + 1, column=1, columnspan=2, sticky="w", pady=(0, 4))
                self._volume_widgets[vol.mount] = widgets
        for vol in volumes:
            widgets = self._volume_widgets[vol.mount]
            colors = VOLUME_COLORS * 2
            widgets["bar"].set([(size, colors[i]) for i, (_, size) in enumerate(vol.parts)], vol.total)
            _set_text(widgets["summary"], f"{fmt_disk(vol.used)} / {fmt_disk(vol.total)} 사용 · "
                                          f"여유 {fmt_disk(vol.free)}")
            names = [name for name, _ in vol.parts]
            if widgets["parts"] != names:  # 범례 칸은 구성이 바뀔 때만 다시 만든다
                for child in widgets["legend"].winfo_children():
                    child.destroy()
                widgets["labels"] = []
                for i, name in enumerate(names):
                    ttk.Label(widgets["legend"], text="■", foreground=colors[i],
                              font=self.font_small).pack(side="left")
                    label = ttk.Label(widgets["legend"], text=name, font=self.font_small)
                    label.pack(side="left", padx=(0, 10))
                    widgets["labels"].append(label)
                widgets["parts"] = names
            for label, (name, size) in zip(widgets["labels"], vol.parts):
                _set_text(label, f"{name} {fmt_disk(size)}")

    def _location_rows(self) -> dict[str, dict]:
        return {path: {"label": f"{name}  ({path.replace(os.path.expanduser('~'), '~', 1)})",
                       "note": hint, "size": None, "state": "idle", "partial": False, "is_dir": True}
                for path, name, hint in storage_locations()}

    def _set_storage_view(self, mode: str, path: str | None, rows: dict, total: int | None,
                          partial: bool, note: str = "") -> None:
        self.storage_mode, self.storage_path = mode, path
        self.storage_rows, self.storage_total, self.storage_partial = rows, total, partial
        self.storage_note = note
        self._storage_row_cache.clear()
        self.storage_tree.delete(*self.storage_tree.get_children(""))
        self._render_storage()

    def storage_show_locations(self) -> None:
        self.storage_stop(quiet=True)
        cached = self.storage_cache.get(LOCATIONS_KEY)
        if cached:
            rows, total, partial = cached
            self._set_storage_view("locations", None, {k: dict(v) for k, v in rows.items()}, total, partial)
        else:
            self._set_storage_view("locations", None, self._location_rows(), None, False,
                                   "'크기 계산'을 누르면 주요 위치의 크기를 잽니다 (1~2분). "
                                   "처음에는 macOS 가 폴더 접근 허용을 물을 수 있습니다.")

    def storage_open(self, path: str, rescan: bool = False) -> None:
        """폴더 바로 아래 항목의 크기를 보여준다. 이미 잰 폴더는 다시 재지 않는다."""
        path = os.path.normpath(os.path.abspath(path))
        self.storage_stop(quiet=True)
        cached = None if rescan else self.storage_cache.get(path)
        if cached:
            rows, total, partial = cached
            self._set_storage_view("folder", path, {k: dict(v) for k, v in rows.items()}, total, partial)
            return
        try:
            entries = list(os.scandir(path))
        except OSError as exc:
            self._set_storage_view("folder", path, {}, None, False,
                                   f"열 수 없습니다: {exc.strerror}. 시스템 설정 > 개인정보 보호 및 보안 > "
                                   "파일 및 폴더(또는 전체 디스크 접근 권한)에서 허용하세요.")
            return
        rows = {}
        for entry in entries:
            is_dir = entry.is_dir(follow_symlinks=False)
            size, state = None, "pending"
            if not is_dir:  # 파일은 du -d 1 에 나오지 않으므로 직접 잰다
                try:
                    size, state = entry.stat(follow_symlinks=False).st_blocks * 512, "done"
                except OSError:
                    state = "denied"
            rows[entry.path] = {"label": entry.name + ("/" if is_dir else ""), "note": storage_hint(entry.path),
                                "size": size, "state": state, "partial": False, "is_dir": is_dir}
        self._set_storage_view("folder", path, rows, None, False)
        if any(r["state"] == "pending" for r in rows.values()) or not rows:
            self.storage_job = self.scanner.scan([path], children=True)
            self._render_storage()
        else:
            self._finish_storage_scan(sum(r["size"] or 0 for r in rows.values()))

    def storage_scan(self) -> None:
        if self.storage_mode == "folder" and self.storage_path:
            self.storage_open(self.storage_path, rescan=True)
            return
        rows = self._location_rows()
        for row in rows.values():
            row["state"] = "pending"
        self._set_storage_view("locations", None, rows, None, False)
        self.storage_job = self.scanner.scan(list(rows), children=False)
        self._render_storage()

    def storage_stop(self, quiet: bool = False) -> None:
        self.scanner.cancel()
        if self.storage_job is not None:
            self.storage_job = None
            for row in self.storage_rows.values():
                if row["state"] == "pending":
                    row["state"] = "idle"
            if not quiet:
                self.storage_note = "중지했습니다. '크기 계산'으로 다시 잴 수 있습니다."
                self._render_storage()

    def storage_up(self) -> None:
        if self.storage_mode != "folder" or not self.storage_path:
            return
        parent = os.path.dirname(self.storage_path)
        if parent != self.storage_path:
            self.storage_open(parent)

    def storage_choose_folder(self) -> None:
        path = filedialog.askdirectory(parent=self.root, mustexist=True,
                                       initialdir=self.storage_path or os.path.expanduser("~"))
        if path:
            self.storage_open(path)

    def _on_storage_double_click(self, event) -> None:
        if self.storage_tree.identify_region(event.x, event.y) == "cell":
            self._open_selected_folder()

    def _open_selected_folder(self) -> None:
        selection = self.storage_tree.selection()
        if selection and self.storage_rows.get(selection[0], {}).get("is_dir"):
            self.storage_open(selection[0])

    def _on_disk_event(self, job: int, kind: str, value) -> None:
        if job != self.storage_job:
            return  # 중지했거나 다른 폴더로 옮긴 뒤 도착한 결과
        if kind == "entry":
            row = self.storage_rows.get(value.path)
            if row is None:
                if self.storage_mode != "folder" or os.path.dirname(value.path) != self.storage_path:
                    return
                row = self.storage_rows[value.path] = {
                    "label": os.path.basename(value.path) + "/", "note": storage_hint(value.path),
                    "size": None, "state": "pending", "partial": False, "is_dir": True}
            row["size"] = value.size
            row["state"] = "done" if value.size is not None else "denied"
        elif kind == "partial":
            if value == self.storage_path:
                self.storage_partial = True
            elif value in self.storage_rows:
                self.storage_rows[value]["partial"] = True
        elif kind == "done":
            self._finish_storage_scan(value)
        elif kind == "error":
            self.storage_job = None
            self.storage_note = f"크기를 재지 못했습니다: {value}"

    def _finish_storage_scan(self, total: int | None) -> None:
        self.storage_job = None
        for row in self.storage_rows.values():
            if row["state"] == "pending":  # du 가 건너뛴 항목 (다른 디스크·권한 없음)
                row["state"] = "denied"
        if self.storage_mode == "locations":
            self.storage_partial = any(r["partial"] or r["state"] == "denied" for r in self.storage_rows.values())
            total = sum(r["size"] or 0 for r in self.storage_rows.values())
        self.storage_total = total
        key = LOCATIONS_KEY if self.storage_mode == "locations" else self.storage_path
        self.storage_cache[key] = ({k: dict(v) for k, v in self.storage_rows.items()}, total,
                                   self.storage_partial)
        self.storage_note = ""
        self._render_storage()

    def _storage_values(self, row: dict, denom: int) -> tuple:
        state, size = row["state"], row["size"]
        if state == "idle":
            size_text = "계산 전"
        elif state == "pending":
            size_text = "계산 중…"
        elif state == "denied":
            size_text = "권한 없음"
        else:
            size_text = fmt_disk(size) + (" (일부)" if row["partial"] else "")
        share = ""
        if state == "done" and denom:
            frac = min((size or 0) / denom, 1.0)
            filled = round(frac * 12)
            share = "█" * filled + "·" * (12 - filled) + f" {frac * 100:4.1f}%"
        return row["label"], size_text, share, row["note"]

    def _render_storage(self) -> None:
        tree = self.storage_tree
        rows = self.storage_rows
        ordered = sorted(rows, key=lambda p: (rows[p]["state"] != "done", -(rows[p]["size"] or 0),
                                              rows[p]["label"].lower()))
        if self.storage_mode == "folder":
            denom = self.storage_total or sum(r["size"] or 0 for r in rows.values())
        else:
            denom = sum(r["size"] or 0 for r in rows.values())
        existing = set(tree.get_children(""))
        for path in ordered:
            row = rows[path]
            item = (self._storage_values(row, denom),
                    ("dim",) if row["state"] in ("idle", "denied") else ("warm",) if row["partial"] else ())
            if path not in existing:
                tree.insert("", "end", iid=path, values=item[0], tags=item[1])
            elif self._storage_row_cache.get(path) != item:
                tree.item(path, values=item[0], tags=item[1])
            self._storage_row_cache[path] = item
        stale = existing - set(rows)
        if stale:
            tree.delete(*stale)
        if tuple(ordered) != tree.get_children(""):
            tree.set_children("", *ordered)

        home = os.path.expanduser("~")
        where = "주요 위치" if self.storage_mode == "locations" else (self.storage_path or "").replace(home, "~", 1)
        _set_text(self.storage_path_label, where)
        done = sum(1 for r in rows.values() if r["state"] in ("done", "denied"))
        if self.storage_note:
            info = self.storage_note
        elif self.storage_job is not None:
            info = f"계산 중… {done}/{len(rows)}개 완료. 다른 폴더로 가거나 '중지'를 누르면 멈춥니다."
        else:
            label = "주요 위치 합계" if self.storage_mode == "locations" else "합계"
            info = f"{label} {fmt_disk(self.storage_total)} · 항목 {len(rows)}개 · 더블클릭: 폴더 열기 · ⌫: 상위 폴더"
            if self.storage_partial:
                info += " · 주황/회색은 권한이 없어 일부만 잰 항목 (전체 디스크 접근 권한을 주면 정확)"
        _set_text(self.storage_info, info)

    def _selected_storage_paths(self) -> list[str]:
        return [path for path in self.storage_tree.selection() if path in self.storage_rows]

    def storage_reveal(self) -> None:
        paths = self._selected_storage_paths() or ([self.storage_path] if self.storage_path else [])
        if paths:
            self._reveal(paths[0])
        else:
            self._notify("목록에서 항목을 선택하세요.")

    def storage_trash(self, paths: list[str] | None = None) -> None:
        paths = self._selected_storage_paths() if paths is None else paths
        if not paths:
            self._notify("목록에서 휴지통으로 옮길 항목을 선택하세요.")
            return
        refused = [(path, trash_refusal(path)) for path in paths]
        blocked = [(path, why) for path, why in refused if why]
        if blocked:
            messagebox.showerror("옮길 수 없음", "다음 항목은 보호되어 있어 옮기지 않습니다.", parent=self.root,
                                 detail="\n".join(f"• {path}\n   {why}" for path, why in blocked[:10]))
            paths = [path for path, why in refused if not why]
            if not paths:
                return
        lines = []
        for path in paths[:10]:
            row = self.storage_rows.get(path, {})
            size = fmt_disk(row["size"]) if row.get("state") == "done" else "크기 모름"
            lines.append(f"• {os.path.basename(path)}  ({size})\n   {path}")
        if len(paths) > 10:
            lines.append(f"… 외 {len(paths) - 10}개")
        detail = ("\n".join(lines) + "\n\nFinder 휴지통으로 옮깁니다. 휴지통에서 '되돌려 놓기'로 복구할 수 있습니다."
                  "\n처음 사용할 때 macOS 가 'Finder 제어' 허용 여부를 묻습니다.")
        if not messagebox.askyesno("휴지통으로 이동", f"{len(paths)}개 항목을 휴지통으로 옮길까요?",
                                   detail=detail, icon="warning", default="no", parent=self.root):
            return
        self._notify("휴지통으로 옮기는 중…")

        def work():
            try:
                error = move_to_trash(paths)
            except Exception as exc:  # noqa: BLE001 — 결과 창에 그대로 보여준다
                error = repr(exc)
            self.events.put(("trash", (paths, error)))

        threading.Thread(target=work, daemon=True, name="trash").start()

    def _on_trash_result(self, paths: list[str], error: str | None) -> None:
        self.last_trash = (paths, error)
        if error:
            self._notify("휴지통으로 옮기지 못했습니다.")
            if self.interactive:
                messagebox.showerror("휴지통으로 이동 실패", "옮기지 못했습니다.", detail=error, parent=self.root)
            return
        for path in paths:
            row = self.storage_rows.pop(path, None)
            if row and row["state"] == "done" and self.storage_total:
                self.storage_total = max(self.storage_total - (row["size"] or 0), 0)
            # 옮긴 항목을 포함하던 폴더들의 저장된 결과는 이제 틀리므로 버린다.
            for key in list(self.storage_cache):
                if key == LOCATIONS_KEY or path == key or path.startswith(key.rstrip(os.sep) + os.sep):
                    self.storage_cache.pop(key, None)
        self._notify(f"{len(paths)}개 항목을 휴지통으로 옮겼습니다.")
        self._render_storage()
        self._render_volumes()

    def _on_interval(self, _event=None) -> None:
        self.collector.interval = float(self.interval_var.get())
        self.collector.wake.set()

    def toggle_pause(self) -> None:
        self.collector.paused = not self.collector.paused
        self.pause_button.configure(text="재개" if self.collector.paused else "일시정지")
        if not self.collector.paused:
            self.collector.wake.set()
        self._update_status()

    def refresh_now(self) -> None:
        self.collector.wake.set()

    def _selected_procs(self, purpose: str = "") -> list[ProcInfo]:
        """프로세스 탭에서 선택한 항목. 다른 탭이 보이는 동안에는 숨은 선택을 쓰지 않는다."""
        if self.notebook.select() != str(self.proc_tab):
            self._notify("'프로세스' 탭에서 선택하세요. 앱을 더블클릭하면 그 앱의 프로세스만 보여줍니다.")
            return []
        procs = [self.procs[int(iid)] for iid in self.tree.selection() if int(iid) in self.procs]
        if not procs and purpose:
            self._notify(f"목록에서 {purpose} 프로세스를 먼저 선택하세요.")
        return procs

    def _on_double_click(self, event) -> None:
        if self.tree.identify_region(event.x, event.y) == "cell":
            self.show_details()

    def _on_right_click(self, event) -> str:
        iid = self.tree.identify_row(event.y)
        if iid:
            if iid not in self.tree.selection():
                self.tree.selection_set(iid)
            self.menu.tk_popup(event.x_root, event.y_root)
        return "break"

    def _on_top_click(self, event) -> None:
        iid = self.top_tree.identify_row(event.y)
        if not iid:
            return
        if not self.tree.exists(iid):
            self.filter_var.set("")
            self.mine_var.set(False)
            self._render_table()
        if self.tree.exists(iid):
            self.tree.selection_set(iid)
            self.tree.focus(iid)
            self.tree.see(iid)
            self.tree.focus_set()

    def show_details(self) -> None:
        procs = self._selected_procs("상세 정보를 볼")
        if procs:
            self.open_details(procs[0].pid)

    def open_details(self, pid: int) -> tk.Toplevel | None:
        try:
            rows = process_details(pid)
        except psutil.NoSuchProcess:
            self._notify(f"PID {pid} 는 이미 종료되었습니다.")
            return None
        win = tk.Toplevel(self.root)
        win.title(f"{rows['이름']} (PID {pid})")
        text = tk.Text(win, width=100, height=20, wrap="word", padx=12, pady=12,
                       borderwidth=0, tabs=("120p",))
        text.tag_configure("label", font=self.font_bold)
        text.tag_configure("value", lmargin2=120)
        for label, value in rows.items():
            text.insert("end", f"{label}\t", "label")
            text.insert("end", f"{value}\n", "value")
        text.configure(state="disabled")
        text.pack(fill="both", expand=True)

        buttons = ttk.Frame(win, padding=8)
        buttons.pack(fill="x")
        ttk.Button(buttons, text="닫기", command=win.destroy).pack(side="right")
        ttk.Button(buttons, text="명령줄 복사",
                   command=lambda: self._copy(rows["명령줄"])).pack(side="right", padx=(0, 4))
        target = owning_app(rows["실행 파일"]) or rows["실행 파일"]
        if target.startswith("/"):
            ttk.Button(buttons, text="Finder에서 보기",
                       command=lambda: self._reveal(target)).pack(side="right", padx=(0, 4))
        win.bind("<Escape>", lambda _e: win.destroy())
        return win

    def reveal_selected(self) -> None:
        procs = self._selected_procs("Finder에서 볼")
        if not procs:
            return
        target = owning_app(procs[0].exe) or procs[0].exe
        if target:
            self._reveal(target)
        else:
            self._notify("실행 파일 경로를 알 수 없습니다.")

    def _reveal(self, path: str) -> None:
        subprocess.Popen(["/usr/bin/open", "-R", path])

    def _copy(self, text: str) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self._notify("클립보드에 복사했습니다.")

    def kill_selected(self, force: bool) -> None:
        procs = self._selected_procs("종료할")
        if not procs:
            return
        blocked = [p for p in procs if p.pid in NEVER_KILL or p.pid == os.getpid()]
        if blocked:
            messagebox.showerror("종료할 수 없음", "보호된 프로세스는 종료하지 않습니다.", detail="\n".join(
                f"{p.name} (PID {p.pid})" for p in blocked), parent=self.root)
            procs = [p for p in procs if p not in blocked]
            if not procs:
                return

        action = "강제 종료(SIGKILL)" if force else "종료(SIGTERM)"
        lines = [f"• {p.name}  (PID {p.pid}, {p.user or '?'}, CPU {fmt_pct(p.cpu)}%)" for p in procs[:10]]
        if len(procs) > 10:
            lines.append(f"… 외 {len(procs) - 10}개")
        # macOS 에서는 message 가 굵은 제목으로 표시되므로 목록과 경고는 detail 에 넣는다.
        message = f"다음 프로세스를 {action}할까요?"
        detail = "\n".join(lines)
        if self.children_var.get():
            detail += "\n\n자식 프로세스도 함께 종료합니다."
        critical = [p.name for p in procs if p.name in CRITICAL_NAMES]
        if critical:
            detail += (f"\n\n⚠ {', '.join(critical)} 은(는) 핵심 시스템 프로세스입니다. "
                       "종료하면 로그아웃되거나 시스템이 멈출 수 있습니다.")
        elif any(is_system_user(p.user) for p in procs):
            detail += ("\n\n⚠ 시스템 계정 프로세스가 포함되어 있습니다. 대부분 자동으로 다시 시작되지만 "
                       "잠시 기능이 멈출 수 있고, 권한이 없으면 실패합니다.")
        if not force:
            detail += "\n\n(정상 종료를 요청합니다. 응답이 없으면 '강제 종료'를 사용하세요.)"
        if not messagebox.askyesno("프로세스 종료 확인", message, detail=detail, icon="warning",
                                   default="no", parent=self.root):
            return
        self.start_kill([(p.pid, p.create_time) for p in procs], force, self.children_var.get())

    def start_kill(self, targets: list[tuple[int, float | None]], force: bool,
                   include_children: bool) -> None:
        self._notify("종료 요청 중…")

        def work():
            try:
                result = kill_processes(targets, force=force, include_children=include_children)
            except Exception as exc:  # noqa: BLE001 — 결과 창에 그대로 보여준다
                result = KillResult(errors=[repr(exc)])
            self.events.put(("kill", (result, force)))

        threading.Thread(target=work, daemon=True, name="killer").start()

    def _on_kill_result(self, result: KillResult, force: bool) -> None:
        self.last_kill = result
        summary = []
        if result.gone:
            summary.append(f"종료됨 {len(result.gone)}개")
        if result.alive:
            summary.append(f"아직 실행 중 {len(result.alive)}개")
        if result.denied:
            summary.append(f"권한 없음 {len(result.denied)}개")
        if result.errors:
            summary.append(f"건너뜀 {len(result.errors)}개")
        self._notify(" · ".join(summary) or "변경 없음")
        self.collector.wake.set()
        if not self.interactive or not (result.alive or result.denied or result.errors):
            return
        lines = []
        if result.gone:
            lines.append("종료됨: " + ", ".join(result.gone))
        if result.alive:
            lines.append("아직 실행 중: " + ", ".join(result.alive))
            if not force:
                lines.append("→ 정상 종료 요청에 응답하지 않습니다. '강제 종료'를 시도해 보세요.")
        if result.denied:
            lines.append("권한 없음: " + ", ".join(result.denied))
            lines.append("→ 다른 사용자·시스템 프로세스는 sudo 로 이 앱을 실행해야 종료할 수 있습니다.")
        lines.extend(result.errors)
        messagebox.showwarning("종료 결과", " · ".join(summary), detail="\n".join(lines), parent=self.root)

    def _notify(self, message: str) -> None:
        self.message_var.set(message)
        token = self._message_token = object()

        def clear():
            if self._message_token is token:
                self.message_var.set("")

        self.root.after(8000, clear)

    def _on_tk_error(self, exc_type, exc, tb) -> None:
        self._record_error("".join(traceback.format_exception(exc_type, exc, tb)))

    def _record_error(self, text: str) -> None:
        self.errors.append(text)
        print(text, file=sys.stderr)
        self.message_var.set("오류: " + text.strip().splitlines()[-1][:120])

    def close(self) -> None:
        self._closed = True
        self.scanner.cancel()
        self.collector.stopping.set()
        self.collector.wake.set()
        self.root.destroy()


# ── 자동 점검 ───────────────────────────────────────────────────────────────

def _selftest_script(app: App, sleeper: subprocess.Popen, failures: list[str]):
    """각 yield 는 다음 단계로 넘어가기 전에 참이 되어야 하는 조건."""
    yield lambda: app.render_count >= 2
    for key, *_ in COLUMNS:
        app.sort_by(key)
        app.sort_by(key)
    app.sort_by("cpu")
    app.toggle_pause()
    app.toggle_pause()

    iid = str(sleeper.pid)
    app.filter_var.set("sleep")
    yield lambda: app.tree.exists(iid)
    app.tree.selection_set(iid)
    win = app.open_details(sleeper.pid)
    if win is None:
        failures.append("상세 창이 열리지 않음")
    else:
        win.update_idletasks()
        win.destroy()

    if not kill_processes([(1, None)]).errors:
        failures.append("PID 1 보호 실패")
    proc = app.procs[sleeper.pid]
    if not kill_processes([(proc.pid, proc.create_time + 5)], wait=0.1).errors:
        failures.append("PID 재사용 검사 실패")
    app.start_kill([(proc.pid, proc.create_time)], force=False, include_children=False)
    yield lambda: app.last_kill is not None
    if sleeper.poll() is None:
        failures.append("sleep 프로세스가 종료되지 않음")

    rendered = app.render_count
    app.filter_var.set("")
    yield lambda: app.render_count >= rendered + 1
    if app.tree.exists(iid):
        failures.append("종료된 프로세스가 목록에 남아 있음")
    shown = len(app.tree.get_children(""))
    if shown < 50:
        failures.append(f"표시된 프로세스가 너무 적음: {shown}")

    # 앱별 메모리 탭
    first_row = app.tree.get_children("")[0]
    app.tree.selection_set(first_row)
    rendered = app.render_count
    app.notebook.select(app.apps_tab)
    yield lambda: app.render_count >= rendered + 1
    groups = app.app_tree.get_children("")
    if len(groups) < 10:
        failures.append(f"앱 묶음이 너무 적음: {len(groups)}")
    for key, *_ in APP_COLUMNS:
        app.sort_apps_by(key)
        app.sort_apps_by(key)
    app.sort_apps_by("memory")
    # 앱 탭이 보이는 동안에는 프로세스 탭의 숨은 선택으로 종료하면 안 된다
    attempts = []
    real_askyesno, real_start_kill = messagebox.askyesno, app.start_kill
    messagebox.askyesno = lambda *a, **k: attempts.append("confirm") or True
    app.start_kill = lambda *a, **k: attempts.append("kill")
    try:
        app.kill_selected(force=False)
        app.show_details()
    finally:
        messagebox.askyesno, app.start_kill = real_askyesno, real_start_kill
    if attempts:
        failures.append(f"앱 탭에서 숨은 선택으로 종료 시도: {attempts}")
    target = app.app_tree.get_children("")[0][2:]
    app.open_app_group(target)
    if app._apps_tab_active() or app.filter_var.get() != target or not app.tree.get_children(""):
        failures.append(f"앱 묶음 '{target}' 으로 이동 실패")
    app.filter_var.set("")

    # 저장 공간 탭: 크기를 아는 임시 폴더로 du 결과·이동·캐시·중지를 확인한다
    tmp = tempfile.mkdtemp(prefix="procmon-selftest-")
    try:
        for rel, size in (("a/f1", 400), ("b c/f2", 800), ("c.bin", 200)):
            full = os.path.join(tmp, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as f:
                f.write(os.urandom(size * 1024))
        app.notebook.select(app.storage_tab)
        shown_at = time.monotonic()
        yield lambda: app._volume_widgets or time.monotonic() - shown_at > 5  # 탭 전환 이벤트는 비동기
        if not app._volume_widgets:
            failures.append("볼륨 사용량이 표시되지 않음")
        app.storage_open(tmp)
        yield lambda: app.storage_job is None
        expect = {"a": 400, "b c": 800, "c.bin": 200}
        got = {os.path.basename(p): (r["size"] or 0) // 1024 for p, r in app.storage_rows.items()}
        if any(abs(got.get(k, -999) - v) > 16 for k, v in expect.items()):
            failures.append(f"폴더 크기가 다름: {got}")
        if app.storage_tree.get_children("")[0] != os.path.join(tmp, "b c"):
            failures.append("저장 공간 목록이 크기순이 아님")
        app.storage_open(os.path.join(tmp, "a"))
        yield lambda: app.storage_job is None
        if list(app.storage_rows) != [os.path.join(tmp, "a", "f1")]:
            failures.append(f"하위 폴더 이동 실패: {list(app.storage_rows)}")
        app.storage_up()
        if app.storage_job is not None or len(app.storage_rows) != 3:
            failures.append("상위 폴더로 돌아올 때 저장된 결과를 쓰지 않음")
        app.storage_open("/usr", rescan=True)
        running = app.scanner._proc
        app.storage_stop()
        yield lambda: running is None or running.poll() is not None
        # 휴지통: 실제 Finder 는 부르지 않고 확인 창·보호 규칙·결과 처리만 확인한다
        moved, errors = [], []
        real_move, real_ask, real_err = globals()["move_to_trash"], messagebox.askyesno, messagebox.showerror
        globals()["move_to_trash"] = lambda ps: moved.append(list(ps))
        messagebox.askyesno = lambda *a, **k: True
        messagebox.showerror = lambda *a, **k: errors.append(a)
        try:
            app.storage_trash(["/", os.path.expanduser("~"), os.path.dirname(os.path.realpath(__file__))])
            fake = os.path.expanduser("~/procmon-selftest-fake/old.dmg")
            app.storage_trash([fake])
            yield lambda: app.last_trash is not None
        finally:
            globals()["move_to_trash"], messagebox.askyesno, messagebox.showerror = real_move, real_ask, real_err
        if moved != [[fake]] or len(errors) != 1:
            failures.append(f"휴지통 보호 규칙 확인 실패: moved={moved} errors={len(errors)}")
        # 저장 공간 탭에서도 숨은 프로세스 선택으로 종료하면 안 된다
        attempts = []
        real_ask, real_start = messagebox.askyesno, app.start_kill
        messagebox.askyesno = lambda *a, **k: attempts.append("confirm") or True
        app.start_kill = lambda *a, **k: attempts.append("kill")
        try:
            app.kill_selected(force=True)
        finally:
            messagebox.askyesno, app.start_kill = real_ask, real_start
        if attempts:
            failures.append(f"저장 공간 탭에서 숨은 선택으로 종료 시도: {attempts}")
        app.notebook.select(app.proc_tab)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    s = app.snapshot
    print(f"렌더 {app.render_count}회 · 프로세스 {len(s.procs)}개 · 표시 {shown}개 · 앱 묶음 {len(groups)}개 "
          f"(최대 '{target}') · ps 보완 {s.estimated}개 · CPU {s.cpu:.0f}% · 메모리 {s.mem_pct:.0f}% · "
          f"수집 {s.elapsed * 1000:.0f}ms · 종료 결과 {app.last_kill}")


def run_selftest(root: tk.Tk, app: App) -> int:
    sleeper = subprocess.Popen(["/bin/sleep", "300"])
    failures: list[str] = []
    script = _selftest_script(app, sleeper, failures)
    deadline = time.monotonic() + 40
    state = {"waiting": None, "done": False}

    def finish():
        state["done"] = True
        if sleeper.poll() is None:
            sleeper.kill()
        failures.extend(app.errors)
        print("SELFTEST " + ("FAILED\n- " + "\n- ".join(failures) if failures else "OK"))
        app.close()

    def tick():
        try:
            if time.monotonic() > deadline:
                failures.append("시간 초과")
                return finish()
            if state["waiting"] is None or state["waiting"]():
                state["waiting"] = next(script)
            root.after(100, tick)
        except StopIteration:
            finish()
        except Exception:  # noqa: BLE001
            failures.append(traceback.format_exc())
            finish()

    root.after(100, tick)
    root.mainloop()
    return 0 if state["done"] and not failures else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Mac 프로세스 모니터")
    parser.add_argument("--interval", type=float, default=3.0, help="갱신 주기(초)")
    parser.add_argument("--selftest", action="store_true", help="창을 띄워 자동 점검 후 종료")
    args, _ = parser.parse_known_args()  # Finder 가 붙이는 -psn_ 인자 무시
    root = tk.Tk()
    app = App(root, interval=0.5 if args.selftest else args.interval, interactive=not args.selftest)
    if args.selftest:
        return run_selftest(root, app)
    root.lift()
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
