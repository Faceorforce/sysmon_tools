"""系统监视浮窗：看谁在吃 CPU / 内存 / GPU，哪些定时任务、队列、批处理在跑。

约束（用户 2026-10-06）：功能简单、要可靠、别把系统搞崩。
- 只读：没有结束进程按钮；不连任何数据库；Redis 只发 SCAN / GET / MGET / HLEN / ZCARD / SCARD。
- 读别人的文件一律带 FILE_SHARE_DELETE 打开（不挡对方改名、删除、原子替换）；锁文件只看目录项、不打开。
- 采样在后台低优先级线程；每个采集项各自 try，失败只在界面上标出来；线程死了界面会重启它。
- 只写本目录下的 logs/ 和 settings.json；日志按天、限大小、过期自动删。
- 代码里不写任何本机信息：端口、服务、路径、归属规则、Redis 键名都放在本地 settings.json（不进仓库，
  格式见 settings.example.json）；不配置的面板就不显示。

用法：pythonw sysmon.py          打开浮窗
      python  sysmon.py --selftest  不开窗口，各采集项跑一轮打印结果
"""

from __future__ import annotations

import ctypes
import json
import os
import re
import subprocess
import sys
import threading
import time
import traceback
import urllib.request
from collections import Counter, deque
from ctypes import wintypes
from datetime import datetime
from pathlib import Path

import psutil

APP_DIR = Path(__file__).resolve().parent
LOG_DIR = APP_DIR / "logs"
SETTINGS_PATH = APP_DIR / "settings.json"

# 只有通用默认值；本机相关的一律在 settings.json 里配置。
DEFAULTS = {
    "fast_interval_s": 3,
    "slow_interval_s": 10,
    "task_interval_s": 30,
    "thresholds": {"cpu": 90, "ram": 85, "gpu": 90, "vram": 85},
    "spike_sustain_samples": 2,
    "spike_cooldown_s": 60,
    "history_every_s": 60,
    "keep_log_days": 14,
    "max_log_mb_per_day": 20,
    "max_process_rows": 80,
    "ports": [],             # [["名称", 端口], ...]：看有没有进程在监听，不连过去
    "windows_services": [],  # Windows 服务名
    "http_checks": [],       # [{"group", "name", "url", "kind": "status" | "models", "down_level"}]
    "redis": None,           # 见 settings.example.json；不配就不读 Redis
    "owner_rules": [],       # [{"match": "子串", "label": "归属名"}]，匹配进程名 + 命令行（不分大小写）
    "dir_pattern": "",       # 正则：从命令行 / 工作目录认出属于哪个目录，group(1) 作标签
    "dir_root_tag": "main",  # 正则匹配但 group(1) 为空时的标签
    "lock_dirs": [],
    "lock_notes": {},        # {"文件名": "说明"}：这些锁 / 标记文件出现就标黄并显示说明
    "activity_dirs": [],
    "activity_window_min": 20,
    "state_files": [],       # 见 settings.example.json
    "window": {"geometry": "1010x660+1530+60", "topmost": True, "alpha": 1.0, "tab": 0},
}


def load_settings() -> dict:
    cfg = json.loads(json.dumps(DEFAULTS))
    try:
        user = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
        for k, v in user.items():
            if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                cfg[k].update(v)
            else:
                cfg[k] = v
    except FileNotFoundError:
        pass
    except Exception:
        log_error("settings.json 读取失败，用默认值")
    return cfg


def save_settings(cfg: dict) -> None:
    """只回写窗口状态；手工写进 settings.json 的其他覆盖项原样保留，没写的继续跟默认值走。"""
    try:
        try:
            user = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
        except FileNotFoundError:
            user = {}
        user["window"] = {k: cfg["window"][k] for k in ("geometry", "topmost", "tab") if k in cfg["window"]}
        tmp = SETTINGS_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(user, ensure_ascii=False, indent=1), encoding="utf-8")
        os.replace(tmp, SETTINGS_PATH)
    except Exception:
        log_error("settings.json 保存失败")


def log_error(msg: str) -> None:
    try:
        LOG_DIR.mkdir(exist_ok=True)
        path = LOG_DIR / "sysmon-error.log"
        if path.exists() and path.stat().st_size > 2_000_000:
            os.replace(path, LOG_DIR / "sysmon-error.old.log")
        with path.open("a", encoding="utf-8") as fh:
            fh.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} {msg}\n{traceback.format_exc()}\n")
    except Exception:
        pass


# ---------------------------------------------------------------- 安全读文件

def safe_read(path: str | Path, max_bytes: int, tail: bool = True) -> bytes | None:
    """带 FILE_SHARE_READ|WRITE|DELETE 打开：对方此时改名、删除、替换都不受影响。"""
    import win32con
    import win32file

    try:
        h = win32file.CreateFile(
            str(path), win32con.GENERIC_READ,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
            None, win32con.OPEN_EXISTING, win32con.FILE_ATTRIBUTE_NORMAL, None)
    except Exception:
        return None
    try:
        size = win32file.GetFileSize(h)
        if size > max_bytes:
            if not tail:
                return None
            win32file.SetFilePointer(h, size - max_bytes, win32con.FILE_BEGIN)
        remaining, chunks = min(size, max_bytes), []
        while remaining > 0:
            _, data = win32file.ReadFile(h, min(remaining, 1 << 20))
            if not data:
                break
            chunks.append(bytes(data))
            remaining -= len(data)
        return b"".join(chunks)
    except Exception:
        return None
    finally:
        h.Close()


def last_line(path: str) -> str:
    data = safe_read(path, 4096, tail=True)
    if not data:
        return ""
    lines = [x for x in data.decode("utf-8", "replace").splitlines() if x.strip()]
    return lines[-1].strip() if lines else ""


# ---------------------------------------------------------------- 时间格式

def parse_iso(s) -> float | None:
    if not s:
        return None
    try:
        d = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        if d.tzinfo is None:
            d = d.astimezone()
        return d.timestamp()
    except Exception:
        return None


def ago(ts: float | None) -> str:
    if ts is None:
        return "—"
    d = time.time() - ts
    if d < 0:
        return "之后 " + dur(-d)
    return dur(d) + "前"


def dur(sec: float | None) -> str:
    if sec is None:
        return "—"
    sec = int(sec)
    if sec < 60:
        return f"{sec}秒"
    if sec < 3600:
        return f"{sec // 60}分"
    if sec < 86400:
        return f"{sec // 3600}时{sec % 3600 // 60:02d}分"
    return f"{sec // 86400}天{sec % 86400 // 3600}时"


def hm(ts: float | None) -> str:
    if ts is None:
        return "—"
    d = datetime.fromtimestamp(ts)
    return d.strftime("%H:%M:%S") if d.date() == datetime.now().date() else d.strftime("%m-%d %H:%M")


# ---------------------------------------------------------------- 进程描述 / 归属

_PATH_SPLIT = re.compile(r"[\\/]")
_SITE: dict = {"owner_rules": [], "dir_re": None, "dir_root": "main"}
_SCRIPT = re.compile(r"([\w\-.]+\.(?:py|ps1|bat|cmd|mjs|js))\b", re.I)


def _base(p: str) -> str:
    return _PATH_SPLIT.split(p.strip('"'))[-1]


def _opt(args: list[str], flag: str) -> str:
    low = [a.lower() for a in args]
    if flag.lower() in low:
        i = low.index(flag.lower())
        if i + 1 < len(args):
            return args[i + 1]
    return ""


def _brief(args: list[str], limit: int = 60) -> str:
    out = " ".join(_base(a) if ("\\" in a or "/" in a) else a for a in args[:6])
    return out if len(out) <= limit else out[: limit - 1] + "…"


def describe(name: str, cmd: list[str]) -> str:
    n = (name or "").lower()
    if not cmd:
        return name or "?"
    joined = " ".join(cmd)
    if n.startswith("python"):
        args, i = cmd[1:], 0
        while i < len(args) and args[i].startswith("-") and args[i] not in ("-m", "-c"):
            i += 2 if args[i] in ("-X", "-W") else 1
        if i >= len(args):
            return name
        if args[i] == "-m" and i + 1 < len(args):
            return f"-m {args[i + 1]} {_brief(args[i + 2:])}".strip()
        if args[i] == "-c":
            return "多进程子进程" if "multiprocessing" in joined else "python -c"
        return f"{_base(args[i])} {_brief(args[i + 1:])}".strip()
    if n == "node.exe":
        script = next((x for x in cmd[1:] if not x.startswith("-")), "")
        b = _base(script)
        if b == "npm-cli.js":
            return "npm " + " ".join(cmd[cmd.index(script) + 1:][:2])
        return f"node {b}" if b else "node"
    if n in ("pwsh.exe", "powershell.exe"):
        f = _opt(cmd[1:], "-File")
        if f:
            return f"pwsh {_base(f)}"
        c = _opt(cmd[1:], "-Command")
        if c:
            m = _SCRIPT.search(c)
            return f"pwsh → {m.group(1)}" if m else "pwsh -Command"
        return name
    if n == "cmd.exe":
        m = _SCRIPT.search(joined)
        return f"cmd → {m.group(1)}" if m else name
    return name


def apply_site(cfg: dict) -> None:
    """把 settings.json 里的本机规则装进来（代码里不写死任何本机信息）。"""
    rules = []
    for r in cfg.get("owner_rules") or []:
        if isinstance(r, dict) and r.get("match") and r.get("label"):
            rules.append((str(r["match"]).lower(), str(r["label"])))
    _SITE["owner_rules"] = rules
    try:
        _SITE["dir_re"] = re.compile(cfg["dir_pattern"], re.I) if cfg.get("dir_pattern") else None
    except re.error:
        _SITE["dir_re"] = None
        log_error("dir_pattern 不是合法正则")
    _SITE["dir_root"] = str(cfg.get("dir_root_tag") or "main")


def checkout_of(text: str) -> str:
    rx = _SITE["dir_re"]
    m = rx.search(text or "") if rx else None
    if not m:
        return ""
    tag = (m.group(1) or "") if m.groups() else ""
    return tag.lstrip("_-") or _SITE["dir_root"]


def owner_rule(info: dict) -> str | None:
    """这个进程是不是一个「源头」：是就返回归属名。先看本机规则，再看通用的 Windows 规则。"""
    n = (info["name"] or "").lower()
    cmd = info["cmdstr"]
    hay = n + " " + cmd.lower()
    for match, label in _SITE["owner_rules"]:
        if match in hay:
            return label
    if n == "taskhostw.exe" or (n == "svchost.exe" and "schedule" in cmd.lower()):
        return "计划任务"
    if n == "code.exe":
        return "VS Code"
    if n == "windowsterminal.exe":
        return "终端"
    if n == "services.exe":
        return "系统服务"
    if n == "explorer.exe":
        return "桌面/手动"
    if n in ("wininit.exe", "winlogon.exe", "smss.exe", "csrss.exe", "system"):
        return "系统"
    return None


_SCRIPTY = ("python.exe", "pythonw.exe", "pwsh.exe", "powershell.exe", "cmd.exe", "node.exe")


# ---------------------------------------------------------------- GPU：NVML / PDH

class _NvUtil(ctypes.Structure):
    _fields_ = [("gpu", ctypes.c_uint), ("memory", ctypes.c_uint)]


class _NvMem(ctypes.Structure):
    _fields_ = [("total", ctypes.c_ulonglong), ("free", ctypes.c_ulonglong), ("used", ctypes.c_ulonglong)]


class Nvml:
    def __init__(self):
        lib = None
        for p in (r"C:\Windows\System32\nvml.dll", r"C:\Program Files\NVIDIA Corporation\NVSMI\nvml.dll"):
            if os.path.exists(p):
                lib = ctypes.WinDLL(p)
                break
        if lib is None:
            raise RuntimeError("找不到 nvml.dll")
        if lib.nvmlInit_v2() != 0:
            raise RuntimeError("nvmlInit 失败")
        self.lib, self.h = lib, ctypes.c_void_p()
        if lib.nvmlDeviceGetHandleByIndex_v2(0, ctypes.byref(self.h)) != 0:
            raise RuntimeError("取 GPU 0 失败")
        buf = ctypes.create_string_buffer(96)
        lib.nvmlDeviceGetName(self.h, buf, 96)
        self.name = buf.value.decode(errors="replace").replace("NVIDIA GeForce ", "")

    def read(self) -> dict:
        u, m, t, p = _NvUtil(), _NvMem(), ctypes.c_uint(), ctypes.c_uint()
        if self.lib.nvmlDeviceGetUtilizationRates(self.h, ctypes.byref(u)) != 0:
            raise RuntimeError("NVML 读利用率失败")
        if self.lib.nvmlDeviceGetMemoryInfo(self.h, ctypes.byref(m)) != 0:
            raise RuntimeError("NVML 读显存失败")
        temp = t.value if self.lib.nvmlDeviceGetTemperature(self.h, 0, ctypes.byref(t)) == 0 else None
        power = p.value / 1000 if self.lib.nvmlDeviceGetPowerUsage(self.h, ctypes.byref(p)) == 0 else None
        return {"name": self.name, "util": float(u.gpu), "used": m.used, "total": m.total, "temp": temp, "power": power}


def nvidia_smi() -> dict:
    out = subprocess.run(
        ["nvidia-smi", "--query-gpu=utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw,name",
         "--format=csv,noheader,nounits"],
        capture_output=True, text=True, timeout=4, creationflags=subprocess.CREATE_NO_WINDOW).stdout
    u, used, total, temp, power, name = [x.strip() for x in out.splitlines()[0].split(",", 5)]
    f = lambda x: float(x) if x not in ("", "[N/A]") else None  # noqa: E731
    return {"name": name.replace("NVIDIA GeForce ", ""), "util": f(u), "used": f(used) * 2**20,
            "total": f(total) * 2**20, "temp": f(temp), "power": f(power)}


class GpuPerProcess:
    """任务管理器同款：Windows 性能计数器 GPU Engine / GPU Process Memory。"""

    _PID = re.compile(r"pid_(\d+)_")
    _ENG = re.compile(r"engtype_(\w+)$")

    def __init__(self):
        import win32pdh
        self.pdh = win32pdh
        self.q = win32pdh.OpenQuery()
        self.c_util = win32pdh.AddEnglishCounter(self.q, r"\GPU Engine(*)\Utilization Percentage")
        self.c_mem = win32pdh.AddEnglishCounter(self.q, r"\GPU Process Memory(*)\Dedicated Usage")
        win32pdh.CollectQueryData(self.q)

    def read(self, vram_total: float | None) -> dict[int, list[float]]:
        pdh = self.pdh
        pdh.CollectQueryData(self.q)
        out: dict[int, list[float]] = {}
        try:
            mem = pdh.GetFormattedCounterArray(self.c_mem, pdh.PDH_FMT_LARGE)
        except Exception:
            mem = {}
        cap = (vram_total or 64 * 2**30) * 1.05
        for inst, v in mem.items():
            m = self._PID.search(inst)
            if m and 0 <= v <= cap:
                out.setdefault(int(m.group(1)), [0.0, 0.0])[0] += v
        try:
            util = pdh.GetFormattedCounterArray(self.c_util, pdh.PDH_FMT_DOUBLE)
        except Exception:
            util = {}
        per: dict[int, Counter] = {}
        for inst, v in util.items():
            m, e = self._PID.search(inst), self._ENG.search(inst)
            if m and e and v > 0:
                per.setdefault(int(m.group(1)), Counter())[e.group(1)] += v
        for pid, c in per.items():
            out.setdefault(pid, [0.0, 0.0])[1] = min(100.0, max(c.values()))
        return out


class _SysProcInfo(ctypes.Structure):
    """SYSTEM_PROCESS_INFORMATION（x64）里用得到的前半段。"""

    _fields_ = [("NextEntryOffset", wintypes.ULONG), ("NumberOfThreads", wintypes.ULONG),
                ("WorkingSetPrivateSize", ctypes.c_longlong), ("HardFaultCount", wintypes.ULONG),
                ("NumberOfThreadsHighWatermark", wintypes.ULONG), ("CycleTime", ctypes.c_ulonglong),
                ("CreateTime", ctypes.c_longlong), ("UserTime", ctypes.c_longlong), ("KernelTime", ctypes.c_longlong),
                ("NameLength", ctypes.c_ushort), ("NameMax", ctypes.c_ushort), ("NameBuffer", ctypes.c_void_p),
                ("BasePriority", ctypes.c_long), ("UniqueProcessId", ctypes.c_void_p),
                ("InheritedFromUniqueProcessId", ctypes.c_void_p), ("HandleCount", wintypes.ULONG),
                ("SessionId", wintypes.ULONG), ("UniqueProcessKey", ctypes.c_size_t),
                ("PeakVirtualSize", ctypes.c_size_t), ("VirtualSize", ctypes.c_size_t),
                ("PageFaultCount", wintypes.ULONG), ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t), ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t), ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t), ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t), ("PrivatePageCount", ctypes.c_size_t)]


class NtProcesses:
    """一次系统调用取全部进程（任务管理器同款），不用对每个进程开句柄。"""

    def __init__(self):
        self.fn = ctypes.windll.ntdll.NtQuerySystemInformation
        self.size = 2 * 2**20
        self.buf = ctypes.create_string_buffer(self.size)

    def read(self) -> dict[int, dict]:
        need = wintypes.ULONG()
        for _ in range(6):
            st = self.fn(5, self.buf, self.size, ctypes.byref(need)) & 0xFFFFFFFF
            if st == 0xC0000004:  # STATUS_INFO_LENGTH_MISMATCH
                self.size = max(need.value + 256 * 1024, self.size * 2)
                self.buf = ctypes.create_string_buffer(self.size)
                continue
            if st != 0:
                raise OSError(f"NtQuerySystemInformation 0x{st:08x}")
            break
        else:
            raise OSError("NtQuerySystemInformation 缓冲区反复不够")
        out, off, base = {}, 0, ctypes.addressof(self.buf)
        while True:
            e = _SysProcInfo.from_buffer(self.buf, off)
            pid = e.UniqueProcessId or 0
            if pid:
                name = ctypes.wstring_at(e.NameBuffer, e.NameLength // 2) if e.NameBuffer and e.NameLength else "?"
                out[pid] = {"name": name, "ppid": e.InheritedFromUniqueProcessId or 0,
                            "ctime": e.CreateTime / 1e7 - 11644473600 if e.CreateTime else 0.0,
                            "cpu_100ns": e.UserTime + e.KernelTime, "rss": e.WorkingSetSize,
                            "priv": e.PrivatePageCount}
            if not e.NextEntryOffset:
                break
            off += e.NextEntryOffset
            if off >= self.size or base + off < base:
                break
        return out


class _PerfInfo(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("CommitTotal", ctypes.c_size_t), ("CommitLimit", ctypes.c_size_t),
                ("CommitPeak", ctypes.c_size_t), ("PhysicalTotal", ctypes.c_size_t),
                ("PhysicalAvailable", ctypes.c_size_t), ("SystemCache", ctypes.c_size_t),
                ("KernelTotal", ctypes.c_size_t), ("KernelPaged", ctypes.c_size_t),
                ("KernelNonpaged", ctypes.c_size_t), ("PageSize", ctypes.c_size_t),
                ("HandleCount", wintypes.DWORD), ("ProcessCount", wintypes.DWORD), ("ThreadCount", wintypes.DWORD)]


def commit_charge() -> tuple[float, float] | None:
    pi = _PerfInfo()
    pi.cb = ctypes.sizeof(pi)
    if not ctypes.windll.psapi.GetPerformanceInfo(ctypes.byref(pi), pi.cb):
        return None
    return pi.CommitTotal * pi.PageSize, pi.CommitLimit * pi.PageSize


# ---------------------------------------------------------------- 共享存储与日志

class Store:
    def __init__(self):
        self.lock = threading.Lock()
        self.fast: dict = {}
        self.slow: dict = {}
        self.tasks: dict = {}
        self.spikes: deque = deque(maxlen=300)
        self.ver = Counter()

    def put(self, field: str, value) -> None:
        with self.lock:
            setattr(self, field, value)
            self.ver[field] += 1

    def add_spike(self, ev: dict) -> None:
        with self.lock:
            self.spikes.appendleft(ev)
            self.ver["spikes"] += 1

    def get(self, field: str):
        with self.lock:
            return getattr(self, field), self.ver[field]


class DayLog:
    def __init__(self, prefix: str, cfg: dict):
        self.prefix, self.cfg = prefix, cfg

    def write(self, row: dict) -> None:
        try:
            LOG_DIR.mkdir(exist_ok=True)
            path = LOG_DIR / f"{self.prefix}-{datetime.now():%Y%m%d}.jsonl"
            if path.exists() and path.stat().st_size > self.cfg["max_log_mb_per_day"] * 2**20:
                return
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        except Exception:
            log_error(f"写 {self.prefix} 日志失败")


def prune_logs(days: int) -> None:
    cutoff = time.time() - days * 86400
    for p in LOG_DIR.glob("*.jsonl"):
        try:
            if p.stat().st_mtime < cutoff and re.match(r"^(history|spikes)-\d{8}\.jsonl$", p.name):
                p.unlink()
        except Exception:
            pass


def load_recent_spikes(limit: int = 200) -> list[dict]:
    rows: list[dict] = []
    for p in sorted(LOG_DIR.glob("spikes-*.jsonl"))[-2:]:
        data = safe_read(p, 2_000_000, tail=True) or b""
        for line in data.decode("utf-8", "replace").splitlines():
            try:
                rows.append(json.loads(line))
            except Exception:
                pass
    return list(reversed(rows[-limit:]))


# ---------------------------------------------------------------- 快采样：系统总量 + 进程 + GPU

def _proc_entry(r: dict) -> dict:
    return {"pid": r["pid"], "label": r["label"], "owner": r["owner_full"], "dir": r["checkout"],
            "mem_mb": r["mem_mb"], "vram_mb": r["vram_mb"], "cpu": round(r["cpu"], 1), "gpu": round(r["gpu"], 1)}


class FastSampler:
    name = "fast"

    def __init__(self, cfg: dict, store: Store):
        self.cfg, self.store = cfg, store
        self.nvml = None
        self.pergpu = None
        self.cache: dict[tuple, dict] = {}
        self.over = Counter()
        self.last_spike: dict[str, float] = {}
        self.last_history = 0.0
        self.spike_log = DayLog("spikes", cfg)
        self.history_log = DayLog("history", cfg)
        self.errors: dict[str, str] = {}
        self.nt = NtProcesses()
        self.prev_cpu: dict[tuple, int] = {}
        self.prev_mono = 0.0
        try:
            self.nvml = Nvml()
        except Exception as e:
            self.errors["nvml"] = str(e)
        try:
            self.pergpu = GpuPerProcess()
        except Exception as e:
            self.errors["pdh"] = str(e)
        psutil.cpu_percent(None)

    def gpu_totals(self) -> dict | None:
        try:
            if self.nvml:
                return self.nvml.read()
        except Exception as e:
            self.errors["nvml"] = str(e)
        try:
            return nvidia_smi()
        except Exception as e:
            self.errors["gpu"] = f"nvidia-smi: {e}"
            return None

    def _meta(self, pid: int, name: str) -> dict:
        try:
            p = psutil.Process(pid)
            cmd = p.cmdline()
        except Exception:
            p, cmd = None, []
        cmdstr = " ".join(cmd)
        co = checkout_of(cmdstr)
        if not co and p is not None and name.lower() in _SCRIPTY:
            try:
                co = checkout_of(p.cwd())
            except Exception:
                pass
        return {"cmdstr": cmdstr, "label": describe(name, cmd), "checkout": co}

    def procs(self, gpu_map: dict) -> list[dict]:
        ncpu = psutil.cpu_count() or 1
        now, mono = time.time(), time.monotonic()
        raw = self.nt.read()
        wall = mono - self.prev_mono if self.prev_mono else None
        infos: dict[int, dict] = {}
        live, cpu_now = set(), {}
        for pid, i in raw.items():
            key = (pid, round(i["ctime"], 3))
            live.add(key)
            meta = self.cache.get(key)
            if meta is None:
                meta = self.cache[key] = self._meta(pid, i["name"])
            prev = self.prev_cpu.get(key)
            cpu_now[key] = i["cpu_100ns"]
            cpu = (i["cpu_100ns"] - prev) / 1e7 / wall / ncpu * 100 if prev is not None and wall else 0.0
            g = gpu_map.get(pid, (0.0, 0.0))
            infos[pid] = {
                "pid": pid, "name": i["name"], "ppid": i["ppid"], "ctime": i["ctime"],
                "cmdstr": meta["cmdstr"], "label": meta["label"], "checkout": meta["checkout"],
                "mem_mb": round(i["rss"] / 2**20), "priv_mb": round(i["priv"] / 2**20),
                "cpu": max(0.0, min(100.0, cpu)),
                "vram_mb": round(g[0] / 2**20), "gpu": g[1],
                "age_s": now - i["ctime"] if i["ctime"] else None,
            }
        self.prev_cpu, self.prev_mono = cpu_now, mono
        for k in [k for k in self.cache if k not in live]:
            del self.cache[k]

        for info in infos.values():
            chain, cur, seen = [], info, set()
            while cur and cur["pid"] not in seen and len(chain) < 14:
                seen.add(cur["pid"])
                chain.append(cur)
                par = infos.get(cur["ppid"])
                if par is None or par["ctime"] > cur["ctime"] + 1:
                    break
                cur = par
            owner = next((o for o in (owner_rule(c) for c in chain) if o), None)
            if owner is None:
                owner = "父进程已退出" if chain[-1]["ppid"] and chain[-1]["ppid"] not in infos else "—"
            # 最外层的脚本最能说明「是谁发起的」（如批处理驱动脚本 → 它拉起的子进程）
            parent_script = next((c["label"] for c in reversed(chain[1:])
                                  if c["name"].lower() in _SCRIPTY and owner_rule(c) is None
                                  and c["label"] not in ("多进程子进程",)), "")
            if info["label"] == "多进程子进程" and len(chain) > 1:
                info["label"] = chain[1]["label"] + " · 子进程"
            info["owner"] = owner
            info["owner_full"] = owner + (f" › {parent_script}" if parent_script else "")
            info["chain"] = [f"{c['pid']} {c['label']}" for c in chain]
            if not info["checkout"]:
                info["checkout"] = next((c["checkout"] for c in chain[1:] if c["checkout"]), "")
        return list(infos.values())

    def tick(self) -> None:
        t0 = time.perf_counter()
        self.errors = {k: v for k, v in self.errors.items() if k in ("nvml", "pdh")}
        cpu = psutil.cpu_percent(None)
        vm = psutil.virtual_memory()
        commit = None
        try:
            commit = commit_charge()
        except Exception:
            pass
        gpu = self.gpu_totals()
        gpu_map = {}
        if self.pergpu:
            try:
                gpu_map = self.pergpu.read(gpu["total"] if gpu else None)
            except Exception as e:
                self.errors["pdh"] = str(e)
        rows = self.procs(gpu_map)
        vram_pct = gpu["used"] / gpu["total"] * 100 if gpu and gpu.get("total") else None
        totals = {"cpu": cpu, "ram": vm.percent, "ram_used": vm.used, "ram_total": vm.total,
                  "gpu": gpu["util"] if gpu else None, "vram": vram_pct, "gpu_info": gpu,
                  "commit": commit, "nproc": len(rows)}
        cost = (time.perf_counter() - t0) * 1000
        self.store.put("fast", {"t": time.time(), "totals": totals, "procs": rows,
                                "errors": dict(self.errors), "cost_ms": cost})
        self.spikes(totals, rows)

    def spikes(self, totals: dict, rows: list[dict]) -> None:
        cfg, now = self.cfg, time.time()
        names = {"cpu": "CPU", "ram": "内存", "gpu": "GPU 利用率", "vram": "显存"}
        sort_keys = {"cpu": "cpu", "ram": "mem_mb", "gpu": "gpu", "vram": "vram_mb"}
        for m, th in cfg["thresholds"].items():
            v = totals.get(m)
            if v is None:
                continue
            self.over[m] = self.over[m] + 1 if v >= th else 0
            if self.over[m] >= cfg["spike_sustain_samples"] and now - self.last_spike.get(m, 0) >= cfg["spike_cooldown_s"]:
                self.last_spike[m] = now
                top = sorted(rows, key=lambda r: r[sort_keys[m]], reverse=True)[:6]
                ev = {"t": now, "at": datetime.now().isoformat(timespec="seconds"), "metric": m,
                      "metric_name": names[m], "value": round(v, 1), "threshold": th,
                      "top": [_proc_entry(r) for r in top]}
                self.store.add_spike(ev)
                self.spike_log.write(ev)
        if now - self.last_history >= cfg["history_every_s"]:
            self.last_history = now
            top = lambda k: [_proc_entry(r) for r in sorted(rows, key=lambda r: r[k], reverse=True)[:3]]  # noqa: E731
            self.history_log.write({
                "at": datetime.now().isoformat(timespec="seconds"),
                **{k: (round(totals[k], 1) if totals.get(k) is not None else None) for k in ("cpu", "ram", "gpu", "vram")},
                "top_mem": top("mem_mb"), "top_vram": top("vram_mb"), "top_cpu": top("cpu")})

    def interval(self) -> float:
        return float(self.cfg["fast_interval_s"])


# ---------------------------------------------------------------- 慢采样：服务、队列、调度器、锁、日志

def row(group, name, status="", when="", detail="", level="", key=None) -> dict:
    return {"key": key or f"{group}|{name}", "group": group, "name": name, "status": status,
            "when": when, "detail": detail, "level": level}


def dig(d, path: str):
    """按 a.b.c 取嵌套字段，取不到返回 None。"""
    cur = d
    for part in str(path).split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


class SlowSampler:
    name = "slow"

    def __init__(self, cfg: dict, store: Store):
        self.cfg, self.store = cfg, store
        self.redis = None
        self.state_cache: dict[str, tuple] = {}

    def interval(self) -> float:
        return float(self.cfg["slow_interval_s"])

    def _r(self):
        if self.redis is None:
            import redis
            from redis.backoff import NoBackoff
            from redis.retry import Retry
            c = self.cfg["redis"]
            self.redis = redis.Redis(host=c.get("host", "127.0.0.1"), port=int(c["port"]), db=int(c.get("db", 0)),
                                     socket_timeout=1.5, socket_connect_timeout=1, decode_responses=True,
                                     retry=Retry(NoBackoff(), 0))
        return self.redis

    def tick(self) -> None:
        services: list[dict] = []
        sched: list[dict] = []
        errors: dict[str, str] = {}
        for name, fn, target in (("端口", self.ports, services), ("Windows 服务", self.win_services, services),
                                 ("Redis", self.redis_state, None), ("HTTP 检查", self.http_checks, services),
                                 ("状态文件", self.state_files, sched), ("锁文件", self.locks, sched),
                                 ("活跃日志", self.activity, sched)):
            try:
                if target is None:
                    s_rows, d_rows = fn()
                    services.extend(s_rows)
                    sched[:0] = d_rows
                else:
                    target.extend(fn())
            except Exception as e:
                errors[name] = f"{type(e).__name__}: {e}"
                if name == "Redis":
                    self.redis = None
        self.store.put("slow", {"t": time.time(), "services": services, "sched": sched, "errors": errors})

    def ports(self) -> list[dict]:
        if not self.cfg["ports"]:
            return []
        listen: dict[int, int] = {}
        for c in psutil.net_connections("tcp"):
            if c.status == psutil.CONN_LISTEN and c.laddr:
                listen.setdefault(c.laddr.port, c.pid or 0)
        out = []
        for name, port in self.cfg["ports"]:
            pid = listen.get(int(port))
            if pid is None:
                out.append(row("端口", f"{name} :{port}", "未监听", level="warn"))
            else:
                try:
                    pname = psutil.Process(pid).name() if pid else "?"
                except Exception:
                    pname = "?"
                out.append(row("端口", f"{name} :{port}", "监听中", detail=f"pid {pid} {pname}", level="ok"))
        return out

    def win_services(self) -> list[dict]:
        out = []
        for n in self.cfg["windows_services"]:
            try:
                st = psutil.win_service_get(n).status()
                out.append(row("Windows 服务", n, st, level="ok" if st == "running" else "bad"))
            except Exception:
                out.append(row("Windows 服务", n, "找不到", level="warn"))
        return out

    def redis_state(self) -> tuple[list[dict], list[dict]]:
        c = self.cfg.get("redis")
        if not c or not c.get("port"):
            return [], []
        r = self._r()
        svc: list[dict] = []
        sch: list[dict] = []
        keys = list(r.scan_iter(count=1000))

        # 调度器：一个状态键（含 tasks[].next_run_time）+ 每个任务一个状态键
        sc = c.get("scheduler") or {}
        if sc.get("status_key"):
            raw = r.get(sc["status_key"])
            st = json.loads(raw) if raw else {"status": "offline"}
            ts = parse_iso(st.get("updated_at"))
            stale = ts is None or time.time() - ts > 180
            svc.append(row("调度器", sc.get("name", "调度器"), st.get("status", "?"), ago(ts),
                           f"pid {st.get('pid', '?')} · {st.get('task_count', '?')} 个任务",
                           "bad" if stale or st.get("status") != "running" else "ok"))
            upcoming = sorted(st.get("tasks") or [], key=lambda x: str(x.get("next_run_time")))
            for t in upcoming[:10]:
                sch.append(row("调度器·下次", t.get("task", "?"), "待运行", hm(parse_iso(t.get("next_run_time")))))
        if sc.get("task_prefix"):
            task_keys = sorted(k for k in keys if k.startswith(sc["task_prefix"]))
            for k, v in zip(task_keys, r.mget(task_keys) if task_keys else []):
                try:
                    d = json.loads(v)
                except Exception:
                    continue
                s = str(d.get("status", "?"))
                lvl = "bad" if s in ("failed", "error", "timeout") else ("warn" if s == "running" else "")
                extra = d.get("reason") or d.get("error") or ""
                sch.append(row("调度器·最近", d.get("task", k.rsplit(":", 1)[-1]), s,
                               ago(parse_iso(d.get("updated_at"))), str(extra)[:160], lvl))

        # worker 心跳
        if c.get("workers_prefix"):
            wk = sorted(k for k in keys if k.startswith(c["workers_prefix"]))
            for k, v in zip(wk, r.mget(wk) if wk else []):
                try:
                    d = json.loads(v)
                except Exception:
                    continue
                t = parse_iso(d.get("updated_at"))
                alive = t is not None and time.time() - t < 120
                svc.append(row("Worker", f"{d.get('role')} pid {d.get('pid')}", "心跳" if alive else "心跳过期",
                               ago(t), "队列 " + ",".join(d.get("queues") or []), "ok" if alive else "bad"))

        # 队列：{ns}:{q}.msgs 消息、{ns}:__acks__.*.{q} 处理中、{ns}:{q}.DQ.msgs 延迟、{ns}:{q}.XQ 死信
        qc = c.get("queues") or {}
        ns = qc.get("namespace")
        if ns:
            pre = ns + ":"
            queues = sorted({k[len(pre):-len(".msgs")] for k in keys
                             if k.startswith(pre) and k.endswith(".msgs") and ".DQ." not in k and ".XQ." not in k
                             and not k.startswith(pre + "__")})
            for q in qc.get("names") or []:
                if q not in queues:
                    queues.append(q)
            for q in queues:
                total = r.hlen(f"{pre}{q}.msgs")
                inflight = sum(r.scard(k) for k in keys if k.startswith(pre + "__acks__.") and k.endswith("." + q))
                delayed = r.hlen(f"{pre}{q}.DQ.msgs")
                dead = r.zcard(f"{pre}{q}.XQ")
                waiting = max(0, total - inflight)
                svc.append(row("队列", q, f"处理中 {inflight} · 排队 {waiting}", "",
                               f"延迟 {delayed} · 死信 {dead}", "warn" if waiting > 20 else ("ok" if inflight else "")))

        # 任务记录：每条一个 JSON 键（job_id / job_type / status / queue / attempt / started_at）
        jc = c.get("jobs") or {}
        if jc.get("prefix"):
            label = jc.get("label", "任务记录")
            jk = [k for k in keys if k.startswith(jc["prefix"])]
            jobs = []
            for i in range(0, len(jk), 200):
                for v in r.mget(jk[i:i + 200]):
                    try:
                        jobs.append(json.loads(v))
                    except Exception:
                        pass
            done = set(jc.get("done_status") or ["completed", "failed", "dead_letter", "cancelled", "canceled",
                                                   "succeeded", "success", "skipped"])
            counts = Counter(str(j.get("status")) for j in jobs)
            active = [j for j in jobs if str(j.get("status")) not in done]
            svc.append(row(label, f"共 {len(jobs)} 条", f"进行中 {len(active)}", "",
                           " · ".join(f"{k} {v}" for k, v in counts.most_common())))
            active.sort(key=lambda j: str(j.get("started_at") or j.get("created_at")), reverse=True)
            for j in active[:12]:
                t = parse_iso(j.get("started_at") or j.get("created_at"))
                svc.append(row(label, f"{j.get('job_type')} {j.get('job_id')}", str(j.get("status")), ago(t),
                               f"队列 {j.get('queue')} · 第 {j.get('attempt')} 次", "warn", key=f"job|{j.get('job_id')}"))
        return svc, sch

    def http_checks(self) -> list[dict]:
        out = []
        for chk in self.cfg["http_checks"]:
            group, name, url = chk.get("group", "HTTP"), chk.get("name", "?"), chk.get("url", "")
            down = chk.get("down_level", "bad")
            try:
                with urllib.request.urlopen(url, timeout=1.5) as resp:
                    body = resp.read(200_000)
                    code = resp.status
            except urllib.error.HTTPError as e:
                out.append(row(group, name, f"HTTP {e.code}", detail=chk.get("down_note", ""), level=down))
                continue
            except Exception:
                out.append(row(group, name, "无法连接", detail=chk.get("down_note", ""), level=down))
                continue
            if chk.get("kind") == "models":
                # 模型服务的 {"models": [{name, size, size_vram, expires_at}]} 格式：显示谁占了显存
                try:
                    models = json.loads(body).get("models") or []
                except Exception:
                    models = []
                if not models:
                    out.append(row(group, name, "无已加载模型", level=""))
                for m in models:
                    vram = (m.get("size_vram") or 0) / 2**30
                    out.append(row(group, m.get("name", "?"), f"显存 {vram:.1f} GB",
                                   "到期 " + hm(parse_iso(m.get("expires_at"))),
                                   f"总大小 {(m.get('size') or 0) / 2**30:.1f} GB", "warn" if vram > 4 else "ok"))
            else:
                out.append(row(group, name, f"HTTP {code}", detail=body[:120].decode("utf-8", "replace"), level="ok"))
        return out

    def state_files(self) -> list[dict]:
        """dict-of-dicts 的 JSON 状态文件：按时间字段倒序列出最近几条及其状态。"""
        out = []
        for sf in self.cfg["state_files"]:
            path = sf.get("path")
            if not path:
                continue
            try:
                st = os.stat(path)
            except FileNotFoundError:
                continue
            sig = (st.st_mtime, st.st_size)
            cached = self.state_cache.get(path)
            if cached and cached[0] == sig:
                out.extend(cached[1])
                continue
            data = safe_read(path, 32 * 2**20, tail=False)
            if data is None:
                out.extend(cached[1] if cached else [])
                continue
            state = json.loads(data.decode("utf-8"))
            label = sf.get("label", "状态文件")
            bad, warn = set(sf.get("bad") or []), set(sf.get("warn") or [])
            items = []
            for k, v in (state.items() if isinstance(state, dict) else []):
                if isinstance(v, dict):
                    items.append((str(dig(v, sf.get("time_field", "")) or ""), k, v))
            items.sort(reverse=True)
            rows = []
            for when, k, v in items[: int(sf.get("limit", 14))]:
                s = str(dig(v, sf.get("status_field", "status")))
                names = [str(dig(v, f)) for f in sf.get("name_fields") or [] if dig(v, f) is not None]
                detail = " · ".join(f"{f.rsplit('.', 1)[-1]} {dig(v, f)}" for f in sf.get("detail_fields") or [])
                rows.append(row(label, " · ".join(names) or k, s, hm(parse_iso(when)), detail,
                                "bad" if s in bad else ("warn" if s in warn else ""), key=f"sf|{path}|{k}"))
            self.state_cache[path] = (sig, rows)
            out.extend(rows)
        return out

    def locks(self) -> list[dict]:
        out = []
        now = time.time()
        notes = self.cfg.get("lock_notes") or {}

        def scan(d: str, depth: int):
            try:
                with os.scandir(d) as it:
                    for e in it:
                        if e.is_dir(follow_symlinks=False):
                            if depth > 0 and not e.name.startswith("."):
                                scan(e.path, depth - 1)
                        elif e.name.endswith((".lock", ".flag")):
                            age = now - e.stat().st_mtime
                            note = notes.get(e.name) or ("超过 2 小时，可能是残留" if age > 7200 else "")
                            lvl = "warn" if age > 7200 or e.name in notes else ""
                            out.append(row("锁文件", os.path.relpath(e.path, os.path.dirname(d.rstrip("\\"))),
                                           "持有", ago(now - age), note, lvl, key=f"lock|{e.path}"))
            except (FileNotFoundError, PermissionError, NotADirectoryError):
                pass

        for d in self.cfg["lock_dirs"]:
            scan(d, 2)
        return out

    def activity(self) -> list[dict]:
        cutoff = time.time() - self.cfg["activity_window_min"] * 60
        files = []
        for d in self.cfg["activity_dirs"]:
            try:
                with os.scandir(d) as it:
                    for e in it:
                        if e.is_file() and e.name.endswith((".log", ".jsonl")):
                            m = e.stat().st_mtime
                            if m >= cutoff:
                                files.append((m, e.path, e.name))
            except Exception:
                pass
        files.sort(reverse=True)
        out = []
        for m, path, name in files[:12]:
            line = last_line(path)
            out.append(row("活跃日志", name, "写入中" if time.time() - m < 120 else "", ago(m),
                           line[:220], key=f"log|{path}"))
        return out


class TaskSampler:
    """Windows 任务计划程序（COM，只读）。"""

    name = "tasks"
    STATE = {0: "未知", 1: "已禁用", 2: "排队", 3: "就绪", 4: "运行中"}

    def __init__(self, cfg: dict, store: Store):
        self.cfg, self.store = cfg, store
        self.svc = None

    def interval(self) -> float:
        return float(self.cfg["task_interval_s"])

    def tick(self) -> None:
        import pythoncom
        import win32com.client
        if self.svc is None:
            pythoncom.CoInitialize()
            self.svc = win32com.client.Dispatch("Schedule.Service")
            self.svc.Connect()
        rows = []
        try:
            for t in self.svc.GetRunningTasks(1):
                rows.append(row("计划任务·运行中", t.Path, "运行中", "", f"pid {t.EnginePID} · {t.CurrentAction or ''}",
                                "warn", key=f"run|{t.Path}"))

            def ts(v):
                try:
                    return None if v.year < 2000 else datetime(v.year, v.month, v.day, v.hour, v.minute, v.second).timestamp()
                except Exception:
                    return None

            def walk(folder):
                if folder.Path.lower().startswith("\\microsoft"):
                    return
                for t in folder.GetTasks(1):
                    res = t.LastTaskResult
                    res_s = {0: "成功", 0x41303: "从未运行", 0x41301: "运行中", 0x41306: "被终止"}.get(res, hex(res & 0xFFFFFFFF))
                    lvl = "" if res in (0, 0x41303, 0x41301) else "warn"
                    if t.State == 4:
                        lvl = "warn"
                    rows.append(row("计划任务", t.Path, self.STATE.get(t.State, str(t.State)),
                                    "上次 " + hm(ts(t.LastRunTime)), f"结果 {res_s} · 下次 {hm(ts(t.NextRunTime))}",
                                    lvl, key=f"task|{t.Path}"))
                for sub in folder.GetFolders(0):
                    walk(sub)

            walk(self.svc.GetFolder("\\"))
            self.store.put("tasks", {"t": time.time(), "rows": rows, "errors": {}})
        except Exception as e:
            self.svc = None
            self.store.put("tasks", {"t": time.time(), "rows": rows, "errors": {"计划任务": f"{type(e).__name__}: {e}"}})


# ---------------------------------------------------------------- 线程

class Worker(threading.Thread):
    def __init__(self, sampler, stop: threading.Event):
        super().__init__(name=f"sysmon-{sampler.name}", daemon=True)
        self.sampler, self.stop = sampler, stop

    def run(self) -> None:
        while not self.stop.is_set():
            t0 = time.monotonic()
            try:
                self.sampler.tick()
            except Exception:
                log_error(f"{self.sampler.name} 采样异常")
            self.stop.wait(max(0.5, self.sampler.interval() - (time.monotonic() - t0)))


def lower_priority() -> None:
    try:
        psutil.Process().nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
    except Exception:
        pass


# ---------------------------------------------------------------- 界面

BG, BG2, BG3 = "#1b1d21", "#23262b", "#2d3137"
FG, FG_DIM = "#e4e6ea", "#8b929c"
C_OK, C_WARN, C_BAD, C_SEL = "#4cc38a", "#e3b341", "#ff7b72", "#2f4f8f"
F_UI = ("Microsoft YaHei UI", 9)
F_SMALL = ("Microsoft YaHei UI", 8)
F_BOLD = ("Microsoft YaHei UI", 11, "bold")
F_MONO = ("Consolas", 9)


def level_of(v, th) -> str:
    if v is None:
        return "dim"
    return "bad" if v >= th else ("warn" if v >= th - 15 else "ok")


LEVEL_COLOR = {"ok": C_OK, "warn": C_WARN, "bad": C_BAD, "dim": FG_DIM, "": FG}


def _on_screen(geom: str) -> str:
    """保存的位置超出（或整个跑出）虚拟屏幕时拉回来，免得换了显示器后窗口找不到。"""
    m = re.match(r"^(\d+)x(\d+)([+-]-?\d+)([+-]-?\d+)$", geom or "")
    if not m:
        return geom
    w, h, x, y = int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4))
    try:
        gsm = ctypes.windll.user32.GetSystemMetrics
        vx, vy, vw, vh = gsm(76), gsm(77), gsm(78), gsm(79)
    except Exception:
        return geom
    if vw <= 0 or vh <= 0:
        return geom
    w, h = min(w, vw), min(h, vh)
    x = max(vx, min(x, vx + vw - w))
    y = max(vy, min(y, vy + vh - h))
    return f"{w}x{h}+{x}+{y}"


def run_gui(cfg: dict) -> None:
    import tkinter as tk
    from tkinter import ttk

    store = Store()
    for ev in load_recent_spikes():
        store.spikes.append(ev)
    stop = threading.Event()
    samplers = [FastSampler(cfg, store), SlowSampler(cfg, store), TaskSampler(cfg, store)]
    workers = {s.name: Worker(s, stop) for s in samplers}
    for w in workers.values():
        w.start()

    root = tk.Tk()
    root.title("系统监视")
    root.configure(bg=BG)
    root.report_callback_exception = lambda *a: log_error("界面回调异常")
    wcfg = cfg["window"]
    root.geometry(_on_screen(wcfg.get("geometry") or DEFAULTS["window"]["geometry"]))
    root.attributes("-topmost", bool(wcfg.get("topmost", True)))
    try:
        root.attributes("-alpha", float(wcfg.get("alpha", 1.0)))
    except Exception:
        pass

    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure(".", background=BG, foreground=FG, font=F_UI, fieldbackground=BG2)
    style.configure("Treeview", background=BG2, fieldbackground=BG2, foreground=FG, rowheight=20, borderwidth=0)
    style.map("Treeview", background=[("selected", C_SEL)], foreground=[("selected", "#ffffff")])
    style.configure("Treeview.Heading", background=BG3, foreground=FG, relief="flat", font=F_SMALL)
    style.map("Treeview.Heading", background=[("active", "#3a3f47")])
    style.configure("TNotebook", background=BG, borderwidth=0)
    style.configure("TNotebook.Tab", background=BG3, foreground=FG_DIM, padding=(10, 3))
    style.map("TNotebook.Tab", background=[("selected", BG2)], foreground=[("selected", FG)])
    style.configure("TButton", background=BG3, foreground=FG, padding=(8, 1), borderwidth=0)
    style.map("TButton", background=[("active", "#3a3f47")])
    style.configure("TCheckbutton", background=BG, foreground=FG)
    style.map("TCheckbutton", background=[("active", BG)])
    style.configure("TEntry", fieldbackground=BG2, foreground=FG, insertcolor=FG)
    style.configure("Vertical.TScrollbar", background=BG3, troughcolor=BG, borderwidth=0, arrowcolor=FG_DIM)

    # ---- 顶部指标
    head = tk.Frame(root, bg=BG)
    head.pack(fill="x", padx=6, pady=(6, 2))

    class Meter:
        W, H = 205, 52

        def __init__(self, title):
            self.c = tk.Canvas(head, width=self.W, height=self.H, bg=BG2, highlightthickness=0)
            self.c.pack(side="left", padx=(0, 6))
            self.title, self.hist = title, deque(maxlen=120)

        def draw(self, pct, text, level, push):
            c = self.c
            c.delete("all")
            col = LEVEL_COLOR[level]
            if push:
                self.hist.append(None if pct is None else max(0.0, min(100.0, pct)))
            top, bot = 22, self.H - 4
            pts = [(i, v) for i, v in enumerate(self.hist) if v is not None]
            if len(pts) >= 2:
                step = (self.W - 8) / (self.hist.maxlen - 1)
                x0 = self.W - 4 - step * (len(self.hist) - 1)
                xy = []
                for i, v in pts:
                    xy += [x0 + i * step, bot - (bot - top) * v / 100]
                c.create_line(*xy, fill=col, width=1.4)
            c.create_text(7, 4, anchor="nw", text=self.title, fill=FG_DIM, font=F_SMALL)
            c.create_text(self.W - 6, 2, anchor="ne", text=text, fill=col, font=F_BOLD)

    meters = {k: Meter(t) for k, t in (("cpu", "CPU"), ("ram", "内存"), ("gpu", "GPU"), ("vram", "显存"))}

    # 状态行：右侧固定一个「迷你 / 展开」按钮，迷你模式下也一直看得见
    status_row = tk.Frame(root, bg=BG)
    status_row.pack(fill="x", padx=(8, 6))
    v_mini_text = tk.StringVar(value="迷你")
    ttk.Button(status_row, textvariable=v_mini_text, width=6, command=lambda: toggle_mini()).pack(side="right")
    status = tk.Label(status_row, text="启动中…", bg=BG, fg=FG_DIM, font=F_SMALL, anchor="w")
    status.pack(side="left", fill="x", expand=True)

    # ---- 工具条
    bar = tk.Frame(root, bg=BG)
    bar.pack(fill="x", padx=6, pady=2)
    v_top = tk.BooleanVar(value=bool(wcfg.get("topmost", True)))
    v_pause = tk.BooleanVar(value=False)
    ttk.Checkbutton(bar, text="置顶", variable=v_top,
                    command=lambda: root.attributes("-topmost", v_top.get())).pack(side="left")
    ttk.Checkbutton(bar, text="暂停刷新", variable=v_pause).pack(side="left", padx=6)

    ttk.Button(bar, text="日志目录", command=lambda: os.startfile(LOG_DIR) if LOG_DIR.exists() else None).pack(side="left", padx=4)
    tk.Label(bar, text="过滤", bg=BG, fg=FG_DIM, font=F_SMALL).pack(side="left", padx=(16, 2))
    v_filter = tk.StringVar()
    ttk.Entry(bar, textvariable=v_filter, width=24).pack(side="left")
    count_lbl = tk.Label(bar, text="", bg=BG, fg=FG_DIM, font=F_SMALL)
    count_lbl.pack(side="left", padx=6)

    body = tk.Frame(root, bg=BG)
    body.pack(fill="both", expand=True, padx=6, pady=(2, 6))
    nb = ttk.Notebook(body)
    nb.pack(fill="both", expand=True)

    class Table:
        def __init__(self, master, cols, key="key", sort=None, height=12):
            self.cols, self.key = cols, key
            self.sort_key, self.sort_desc = sort or (None, True)
            frame = tk.Frame(master, bg=BG)
            frame.pack(fill="both", expand=True)
            self.tree = ttk.Treeview(frame, columns=[c[0] for c in cols], show="headings", height=height)
            sb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
            self.tree.configure(yscrollcommand=sb.set)
            self.tree.pack(side="left", fill="both", expand=True)
            sb.pack(side="right", fill="y")
            for cid, title, width, anchor, *_ in cols:
                self.tree.heading(cid, text=title, command=lambda c=cid: self.resort(c))
                self.tree.column(cid, width=width, anchor=anchor, stretch=anchor == "w")
            for lv, col in LEVEL_COLOR.items():
                if lv:
                    self.tree.tag_configure(lv, foreground=col)
            self.tree.tag_configure("ok", foreground=FG)
            self.rows: list[dict] = []
            self.on_resort = None

        def resort(self, c):
            self.sort_desc = not self.sort_desc if self.sort_key == c else True
            self.sort_key = c
            if self.on_resort:
                self.on_resort()

        def fmt(self, r):
            out = []
            for cid, _t, _w, _a, *f in self.cols:
                v = r.get(cid)
                out.append(f[0](v) if f else ("" if v is None else v))
            return out

        def set(self, rows, level_fn=lambda r: r.get("level", "")):
            if self.sort_key:
                k = self.sort_key
                rows = sorted(rows, key=lambda r: (r.get(k) is None, r.get(k) if not isinstance(r.get(k), str) else r.get(k).lower()),
                              reverse=False)
                if self.sort_desc:
                    nones = [r for r in rows if r.get(k) is None]
                    rows = [r for r in rows if r.get(k) is not None][::-1] + nones
            self.rows = rows
            t = self.tree
            existing = set(t.get_children())
            want = []
            for i, r in enumerate(rows):
                iid = str(r[self.key])
                want.append(iid)
                vals, tags = self.fmt(r), (level_fn(r) or "",)
                if iid in existing:
                    t.item(iid, values=vals, tags=tags)
                    if t.index(iid) != i:
                        t.move(iid, "", i)
                else:
                    t.insert("", i, iid=iid, values=vals, tags=tags)
            for iid in existing - set(want):
                t.delete(iid)
            return rows

    num = lambda d: (lambda v: "" if v is None else (f"{v:.{d}f}" if d else f"{v:,.0f}"))  # noqa: E731
    blank0 = lambda d: (lambda v: "" if not v else (f"{v:.{d}f}" if d else f"{v:,.0f}"))  # noqa: E731

    # 进程页
    tab_p = tk.Frame(nb, bg=BG)
    nb.add(tab_p, text="进程")
    t_proc = Table(tab_p, [
        ("pid", "PID", 58, "e"), ("label", "进程 / 在做什么", 290, "w"), ("owner_full", "归属 › 上级脚本", 230, "w"),
        ("checkout", "目录", 64, "w"), ("cpu", "CPU%", 52, "e", num(1)), ("mem_mb", "内存MB", 70, "e", num(0)),
        ("vram_mb", "显存MB", 66, "e", blank0(0)), ("gpu", "GPU%", 50, "e", blank0(0)), ("age_s", "已运行", 70, "e", dur),
    ], key="pid", sort=("mem_mb", True), height=14)
    detail = tk.Text(tab_p, height=6, bg=BG2, fg=FG, font=F_MONO, relief="flat", wrap="word", insertbackground=FG)
    detail.pack(fill="x", pady=(4, 0))
    detail.insert("1.0", "点选一行看完整命令行、父进程链。按表头排序（点「显存MB」看谁占 GPU）。")
    detail.configure(state="disabled")
    copy_bar = tk.Frame(tab_p, bg=BG)
    copy_bar.pack(fill="x")
    sel = {"pid": None}

    def show_detail(*_):
        s = t_proc.tree.selection()
        if s:
            sel["pid"] = int(s[0])
        r = next((x for x in t_proc.rows if x["pid"] == sel["pid"]), None)
        if r is None:
            return
        txt = (f"PID {r['pid']}  {r['name']}  ·  {r['label']}\n"
               f"归属 {r['owner_full']}    目录 {r['checkout'] or '—'}    已运行 {dur(r['age_s'])}"
               f"（启动 {datetime.fromtimestamp(r['ctime']):%m-%d %H:%M:%S}）\n"
               f"CPU {r['cpu']:.1f}%  工作集 {r['mem_mb']:,} MB  提交 {r['priv_mb']:,} MB  "
               f"显存 {r['vram_mb']:,} MB  GPU {r['gpu']:.0f}%\n"
               f"父进程链 {'  ←  '.join(r['chain'])}\n"
               f"命令行 {r['cmdstr'] or '（无权限读取）'}")
        detail.configure(state="normal")
        detail.delete("1.0", "end")
        detail.insert("1.0", txt)
        detail.configure(state="disabled")

    def copy_cmd():
        r = next((x for x in t_proc.rows if x["pid"] == sel["pid"]), None)
        if r:
            root.clipboard_clear()
            root.clipboard_append(r["cmdstr"] or "")

    t_proc.tree.bind("<<TreeviewSelect>>", show_detail)
    ttk.Button(copy_bar, text="复制命令行", command=copy_cmd).pack(side="left", pady=2)
    tk.Label(copy_bar, text="只读工具：不提供结束进程。要停某个任务，请回到发起它的地方（看「归属」列）处理。",
             bg=BG, fg=FG_DIM, font=F_SMALL).pack(side="left", padx=8)

    gcols = [("group", "类别", 110, "w"), ("name", "名称", 280, "w"), ("status", "状态", 150, "w"),
             ("when", "时间", 110, "w"), ("detail", "说明", 360, "w")]
    tab_s = tk.Frame(nb, bg=BG)
    nb.add(tab_s, text="服务与队列")
    t_svc = Table(tab_s, gcols, height=18)
    tab_t = tk.Frame(nb, bg=BG)
    nb.add(tab_t, text="定时与批处理")
    t_sched = Table(tab_t, gcols, height=18)
    tab_k = tk.Frame(nb, bg=BG)
    nb.add(tab_k, text="峰值记录")
    tk.Label(tab_k, text=(f"超过阈值连续 {cfg['spike_sustain_samples']} 次采样就记一条（同一指标 {cfg['spike_cooldown_s']} 秒内只记一次），"
                          f"阈值 CPU {cfg['thresholds']['cpu']}% · 内存 {cfg['thresholds']['ram']}% · "
                          f"GPU {cfg['thresholds']['gpu']}% · 显存 {cfg['thresholds']['vram']}%；另每分钟记一行前三名到 history 日志。"),
             bg=BG, fg=FG_DIM, font=F_SMALL, anchor="w", justify="left", wraplength=860).pack(fill="x")
    t_spk = Table(tab_k, [("at", "时间", 140, "w"), ("metric_name", "指标", 80, "w"), ("value", "数值", 60, "e"),
                          ("culprits", "当时占用最多的进程", 700, "w")], key="key", height=18)

    # ---- 刷新
    seen = Counter()
    mini = {"on": False, "geom": None}
    body_widgets = [bar, body]

    def toggle_mini(*_):
        if not mini["on"]:
            mini["geom"] = root.geometry()
            for w in body_widgets:
                w.pack_forget()
            m = re.search(r"([+-]-?\d+)([+-]-?\d+)$", mini["geom"])
            root.geometry(f"{4 * (Meter.W + 6) + 8}x{Meter.H + 46}" + (m.group(1) + m.group(2) if m else ""))
            v_mini_text.set("展开")
        else:
            bar.pack(fill="x", padx=6, pady=2)
            body.pack(fill="both", expand=True, padx=6, pady=(2, 6))
            if mini["geom"]:
                root.geometry(mini["geom"])
            v_mini_text.set("迷你")
        mini["on"] = not mini["on"]

    head.bind("<Double-Button-1>", toggle_mini)
    for m in meters.values():
        m.c.bind("<Double-Button-1>", toggle_mini)

    def render_procs(force=False):
        fast, ver = store.get("fast")
        if not fast:
            return
        f = v_filter.get().strip().lower()
        rows = fast["procs"]
        if f:
            rows = [r for r in rows if f in (r["label"] + " " + r["owner_full"] + " " + r["cmdstr"] + " " + r["name"] + " " + str(r["pid"])).lower()]
        k = t_proc.sort_key or "mem_mb"
        rows = sorted(rows, key=lambda r: (r.get(k) is not None, r.get(k) or 0) if k not in ("label", "owner_full", "checkout") else (True, 0),
                      reverse=True)[: cfg["max_process_rows"]] if k not in ("label", "owner_full", "checkout") else rows[: cfg["max_process_rows"]]
        heavy = lambda r: "warn" if r["vram_mb"] >= 1000 or r["mem_mb"] >= 3000 or r["cpu"] >= 50 else (  # noqa: E731
            "dim" if r["owner"] in ("系统", "系统服务") else "")
        t_proc.set(rows, heavy)
        count_lbl.configure(text=f"显示 {len(rows)} / {len(fast['procs'])}")
        if sel["pid"]:
            show_detail()

    t_proc.on_resort = lambda: render_procs(True)
    v_filter.trace_add("write", lambda *_: render_procs(True))

    def tick():
        try:
            now = time.time()
            fast, fv = store.get("fast")
            if fast and fv != seen["fast"]:
                seen["fast"] = fv
                tt, th = fast["totals"], cfg["thresholds"]
                g = tt.get("gpu_info") or {}
                meters["cpu"].draw(tt["cpu"], f"{tt['cpu']:.0f}%", level_of(tt["cpu"], th["cpu"]), True)
                meters["ram"].draw(tt["ram"], f"{tt['ram_used'] / 2**30:.1f}/{tt['ram_total'] / 2**30:.0f}G",
                                   level_of(tt["ram"], th["ram"]), True)
                meters["gpu"].draw(tt["gpu"], "—" if tt["gpu"] is None else f"{tt['gpu']:.0f}%",
                                   level_of(tt["gpu"], th["gpu"]), True)
                meters["vram"].draw(tt["vram"], "—" if tt["vram"] is None else
                                    f"{g['used'] / 2**30:.1f}/{g['total'] / 2**30:.0f}G", level_of(tt["vram"], th["vram"]), True)
                if not v_pause.get():
                    render_procs()
            age = now - fast["t"] if fast else None
            if fast:
                tt = fast["totals"]
                g = tt.get("gpu_info") or {}
                parts = []
                if g:
                    parts.append(f"{g.get('name', 'GPU')} {g.get('temp') or '?'}°C {g.get('power') or 0:.0f}W")
                if tt.get("commit"):
                    parts.append(f"提交 {tt['commit'][0] / 2**30:.0f}/{tt['commit'][1] / 2**30:.0f}G")
                parts.append(f"进程 {tt['nproc']}")
                parts.append(f"采样 {fast['cost_ms']:.0f}ms")
                errs = {**fast.get("errors", {})}
                slow, _ = store.get("slow")
                tasks, _ = store.get("tasks")
                errs.update((slow or {}).get("errors", {}))
                errs.update((tasks or {}).get("errors", {}))
                errs.pop("nvml", None) if g else None
                if errs:
                    parts.append("采集失败：" + "；".join(f"{k} {v[:60]}" for k, v in errs.items()))
                stale = age is not None and age > 3 * cfg["fast_interval_s"] + 5
                parts.append(("数据停了 " + dur(age)) if stale else f"更新 {datetime.now():%H:%M:%S}")
                status.configure(text="  ·  ".join(parts), fg=C_BAD if stale or errs else FG_DIM)
            if not v_pause.get():
                slow, sv = store.get("slow")
                tasks, tv = store.get("tasks")
                if slow and (sv, tv) != (seen["slow"], seen["tasks"]):
                    seen["slow"], seen["tasks"] = sv, tv
                    t_svc.set(slow["services"])
                    sched = list(slow["sched"])
                    trows = (tasks or {}).get("rows", [])
                    sched = [r for r in trows if r["group"] == "计划任务·运行中"] + sched + [r for r in trows if r["group"] != "计划任务·运行中"]
                    t_sched.set(sched)
                spk, kv = store.get("spikes")
                if kv != seen["spikes"]:
                    seen["spikes"] = kv
                    rows = []
                    for i, ev in enumerate(list(spk)):
                        cul = "  |  ".join(
                            f"{p['label'][:40]}（{p['owner'][:24]}）内存{p['mem_mb']:,}M 显存{p['vram_mb']:,}M CPU{p['cpu']:.0f}% GPU{p['gpu']:.0f}%"
                            for p in ev.get("top", [])[:3])
                        rows.append({"key": f"{ev.get('at')}|{ev.get('metric')}|{i}", "at": ev.get("at", "").replace("T", " "),
                                     "metric_name": ev.get("metric_name"), "value": f"{ev.get('value')}%",
                                     "culprits": cul, "level": "bad"})
                    t_spk.set(rows)
                    nb.tab(tab_k, text=f"峰值记录 ({len(rows)})" if rows else "峰值记录")
        except Exception:
            log_error("界面刷新异常")
        root.after(1000, tick)

    def watchdog():
        for name, w in list(workers.items()):
            if not w.is_alive() and not stop.is_set():
                log_error(f"采样线程 {name} 退出，重启")
                nw = Worker(w.sampler, stop)
                nw.start()
                workers[name] = nw
        root.after(10_000, watchdog)

    def daily_prune():
        prune_logs(cfg["keep_log_days"])
        root.after(6 * 3600 * 1000, daily_prune)

    def on_close():
        stop.set()
        wc = cfg["window"]
        wc["geometry"] = mini["geom"] if mini["on"] and mini["geom"] else root.geometry()
        wc["topmost"] = bool(v_top.get())

        try:
            wc["tab"] = nb.index(nb.select())
        except Exception:
            pass
        save_settings(cfg)
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    try:  # 深色标题栏（Win11）
        root.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
        ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(ctypes.c_int(1)), 4)
    except Exception:
        pass
    try:
        start_tab = int(sys.argv[sys.argv.index("--tab") + 1]) if "--tab" in sys.argv else int(wcfg.get("tab", 0))
        nb.select(max(0, min(3, start_tab)))
    except Exception:
        pass

    root.after(500, tick)
    root.after(10_000, watchdog)
    root.after(60_000, daily_prune)
    root.mainloop()


# ---------------------------------------------------------------- 入口

def selftest(cfg: dict) -> int:
    store = Store()
    t0 = time.perf_counter()
    fs = FastSampler(cfg, store)
    fs.tick()
    time.sleep(1.5)
    fs.tick()
    print(f"fast x2: {(time.perf_counter() - t0) * 1000:.0f} ms")
    fast, _ = store.get("fast")
    tt = fast["totals"]
    print("totals:", {k: tt[k] for k in ("cpu", "ram", "gpu", "vram", "nproc")}, "errors:", fast["errors"],
          f"tick {fast['cost_ms']:.0f} ms")
    for k in ("mem_mb", "vram_mb", "cpu"):
        print(f"-- top by {k}")
        for r in sorted(fast["procs"], key=lambda r: r[k], reverse=True)[:6]:
            print(f"  {r['pid']:>6} {r[k]:>8} | {r['label'][:55]:<55} | {r['owner_full'][:50]} | {r['checkout']}")
    t0 = time.perf_counter()
    SlowSampler(cfg, store).tick()
    slow, _ = store.get("slow")
    print(f"slow: {(time.perf_counter() - t0) * 1000:.0f} ms errors: {slow['errors']}")
    for r in slow["services"] + slow["sched"]:
        print(f"  [{r['group']}] {r['name'][:50]} | {r['status']} | {r['when']} | {r['detail'][:90]}")
    t0 = time.perf_counter()
    TaskSampler(cfg, store).tick()
    tasks, _ = store.get("tasks")
    print(f"tasks: {(time.perf_counter() - t0) * 1000:.0f} ms errors: {tasks['errors']}")
    for r in tasks["rows"]:
        print(f"  [{r['group']}] {r['name'][:60]} | {r['status']} | {r['when']} | {r['detail'][:80]}")
    return 0


def main() -> int:
    cfg = load_settings()
    apply_site(cfg)
    lower_priority()
    if "--selftest" in sys.argv:
        return selftest(cfg)
    import win32api
    import win32event
    import winerror
    mutex = win32event.CreateMutex(None, False, "Local\\SysmonFloatWindow_v1")  # noqa: F841 — 持有到进程结束
    if win32api.GetLastError() == winerror.ERROR_ALREADY_EXISTS:
        import ctypes as _c
        _c.windll.user32.MessageBoxW(0, "系统监视已经在运行了（看看屏幕边上或任务栏）。", "系统监视", 0x40)
        return 0
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    LOG_DIR.mkdir(exist_ok=True)
    prune_logs(cfg["keep_log_days"])
    try:
        run_gui(cfg)
    except Exception:
        log_error("界面崩溃")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
