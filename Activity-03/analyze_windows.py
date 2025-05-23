"""Windows Admin Toolkit – reference solution (extended)
-------------------------------------------------------
Requires **pywin32** (pip install pywin32) and works on Win10/11.

Implemented tasks (select with --task):

* win-events       – failed & successful logons from the Security log
* win-pkgs         – list installed software (DisplayName + Version)
* win-services     – check service states; auto-start if --fix flag supplied
* win-startup      – list startup programs
* win-disk         – show disk space usage
* win-users        – list local user accounts (enabled/disabled)
* win-uptime       – show system uptime

Example runs
------------
python analyze_windows.py --task win-events --hours 12 --min-count 3
python analyze_windows.py --task win-pkgs --csv pkgs.csv
python analyze_windows.py --task win-services --watch Spooler wuauserv --fix
python analyze_windows.py --task win-startup
python analyze_windows.py --task win-disk
python analyze_windows.py --task win-users
python analyze_windows.py --task win-uptime
"""

from __future__ import annotations
import argparse
import collections
import csv
import datetime as _dt
import io
import re
import subprocess
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

try:
    import win32evtlog  # type: ignore
    import winreg  # std-lib but Windows-only
except ImportError:
    sys.stderr.write("pywin32 required → pip install pywin32\n")
    sys.exit(1)

# ── Constants / regex ──────────────────────────────────────────────────────
SECURITY_CHANNEL = "Security"
EVENT_FAILED = "4625"   # failed logon
EVENT_SUCCESS = "4624"  # successful logon
IP_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")

# ── Utility: pretty Counter table ──────────────────────────────────────────

def _print_counter(counter: dict, h1: str, h2: str):
    if not counter:
        print("(no data)\n")
        return
    width = max(len(str(k)) for k in counter)
    print(f"{h1:<{width}} {h2:>8}")
    print("-" * (width + 9))
    for k, v in sorted(counter.items(), key=lambda item: item[1], reverse=True):
        print(f"{k:<{width}} {v:>8}")
    print()

# ══════════════════════════════════════════════════════════════════════════
# Task 1: Event‑Log triage (win-events)
# ══════════════════════════════════════════════════════════════════════════

def _query_security_xml(hours_back: int):
    delta_sec = hours_back * 3600
    q = (
        f"*[(System/TimeCreated[timediff(@SystemTime) <= {delta_sec}] "
        f"and (System/EventID={EVENT_FAILED} or System/EventID={EVENT_SUCCESS}))]"
    )
    try:
        h = win32evtlog.EvtQuery(SECURITY_CHANNEL, win32evtlog.EvtQueryReverseDirection, q)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "winerror", None) == 5:
            sys.exit("❌ Access denied – run as Administrator or add your account to *Event Log Readers* group.")
        raise
    while True:
        try:
            ev = win32evtlog.EvtNext(h, 1)[0]
        except IndexError:
            break
        yield win32evtlog.EvtRender(ev, win32evtlog.EvtRenderEventXml)

def _parse_event(xml_str: str):
    root = ET.fromstring(xml_str)
    eid = root.findtext("./System/EventID")
    data = {n.attrib.get("Name"): n.text for n in root.findall("./EventData/Data")}
    user = data.get("TargetUserName") or data.get("SubjectUserName") or "?"
    ip = data.get("IpAddress") or "?"
    if ip == "?":
        m = IP_RE.search(xml_str)
        if m:
            ip = m.group()
    return eid, user, ip

def win_events(hours_back: int, min_count: int):
    failed = collections.Counter()
    success = collections.defaultdict(set)  # user → {ip,…}
    for xml_str in _query_security_xml(hours_back):
        eid, user, ip = _parse_event(xml_str)
        if eid == EVENT_FAILED and ip != "?":
            failed[ip] += 1
        elif eid == EVENT_SUCCESS and user not in ("-", "?"):
            success[user].add(ip)

    print(f"\n❌ Failed logons ≥{min_count} (last {hours_back}h)")
    _print_counter({ip: c for ip, c in failed.items() if c >= min_count}, "Source IP", "Count")

    print(f"✅ Successful logons ≥{min_count} IPs (last {hours_back}h)")
    succ = {u: ips for u, ips in success.items() if len(ips) >= min_count}
    width = max((len(u) for u in succ), default=8)
    print(f"{'Username':<{width}} {'IPs':>8}")
    print("-" * (width + 9))
    for user, ips in sorted(succ.items(), key=lambda item: len(item[1]), reverse=True):
        print(f"{user:<{width}} {len(ips):>8}")
    print()

# ══════════════════════════════════════════════════════════════════════════
# Task 2: Installed software audit (win-pkgs)
# ══════════════════════════════════════════════════════════════════════════

UNINSTALL_PATHS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
]

def win_pkgs(csv_path: str | None):
    rows: list[tuple[str, str]] = []
    for root, path in UNINSTALL_PATHS:
        try:
            hive = winreg.OpenKey(root, path)
        except FileNotFoundError:
            continue
        for i in range(winreg.QueryInfoKey(hive)[0]):
            try:
                sub = winreg.OpenKey(hive, winreg.EnumKey(hive, i))
                name, _ = winreg.QueryValueEx(sub, "DisplayName")
                ver, _ = winreg.QueryValueEx(sub, "DisplayVersion")
                rows.append((name, ver))
            except FileNotFoundError:
                continue
            except OSError:
                continue
    print(f"\n🗃 Installed software ({len(rows)} entries)")
    if rows:
        width = max(len(n) for n, _ in rows)
    else:
        width = 10
    print(f"{'DisplayName':<{width}} Version")
    print("-" * (width + 8))
    for name, ver in sorted(rows):
        print(f"{name:<{width}} {ver}")
    print()
    if csv_path:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerows(rows)
        print(f"📑 CSV exported → {csv_path}\n")

# ══════════════════════════════════════════════════════════════════════════
# Task 3: Service status checker (win-services)
# ══════════════════════════════════════════════════════════════════════════

COLOR_OK = "\033[92m"  # green
COLOR_BAD = "\033[91m"  # red
COLOR_RESET = "\033[0m"

def _service_state(name: str) -> str:
    out = subprocess.check_output(["sc", "query", name], text=True, stderr=subprocess.STDOUT)
    return "RUNNING" if "RUNNING" in out else "STOPPED"

def win_services(watch: list[str], auto_fix: bool):
    if not watch:
        watch = ["Spooler", "wuauserv"]
    print("\n🩺 Service status")
    for svc in watch:
        state = _service_state(svc)
        ok = state == "RUNNING"
        colour = COLOR_OK if ok else COLOR_BAD
        print(f"{svc:<20} {colour}{state}{COLOR_RESET}")
        if not ok and auto_fix:
            print(f"  ↳ attempting to start {svc} …", end="")
            subprocess.call(["sc", "start", svc], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            state = _service_state(svc)
            print("done" if state == "RUNNING" else "failed")
    print()

# ══════════════════════════════════════════════════════════════════════════
# Task 4: Startup programs (win-startup)
# ══════════════════════════════════════════════════════════════════════════

def win_startup():
    print("\n🚀 Startup Programs")
    print("{:<40} {}".format("Program Name", "Path"))
    print("-" * 80)

    keys = [
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run")
    ]

    for hive, path in keys:
        try:
            with winreg.OpenKey(hive, path) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        print(f"{name:<40} {value}")
                        i += 1
                    except OSError:
                        break
        except FileNotFoundError:
            pass
    print()

# ══════════════════════════════════════════════════════════════════════════
# Task 5: Disk usage (win-disk)
# ══════════════════════════════════════════════════════════════════════════

def win_disk():
    import shutil
    import string

    print("\n💾 Disk Space Usage")
    print("{:<8} {:>10} {:>10} {:>10}".format("Drive", "Total", "Used", "Free"))
    print("-" * 50)

    for drive in string.ascii_uppercase:
        drive_path = f"{drive}:/"
        try:
            usage = shutil.disk_usage(drive_path)
            print("{:<8} {:>10} {:>10} {:>10}".format(
                drive_path,
                f"{usage.total // (1024**3)}G",
                f"{usage.used // (1024**3)}G",
                f"{usage.free // (1024**3)}G"
            ))
        except:
            continue
    print()

# ══════════════════════════════════════════════════════════════════════════
# Task 6: Local users list (win-users)
# ══════════════════════════════════════════════════════════════════════════

def win_users():
    # Use 'net user' command to get local user list and their status
    print("\n👥 Local User Accounts")
    print(f"{'Username':<20} Status")
    print("-" * 30)

    try:
        output = subprocess.check_output(["net", "user"], text=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        print("Error: Unable to retrieve user accounts.")
        return

    users = []
    in_list = False
    for line in output.splitlines():
        if "-----" in line:
            in_list = not in_list
            continue
        if in_list:
            # usernames can be space-separated in one line
            users.extend(line.split())

    for user in users:
        try:
            detail = subprocess.check_output(["net", "user", user], text=True, stderr=subprocess.DEVNULL)
            # Check if account is active or disabled
            # Look for line: "Account active               Yes" or "No"
            status = "Unknown"
            for l in detail.splitlines():
                if "Account active" in l:
                    status = l.split()[-1]
                    break
            print(f"{user:<20} {status}")
        except subprocess.CalledProcessError:
            print(f"{user:<20} Error retrieving details")
    print()

# ══════════════════════════════════════════════════════════════════════════
# Task 7: System uptime (win-uptime)
# ══════════════════════════════════════════════════════════════════════════

def win_uptime():
    import ctypes
    import time

    class SYSTEM_TIME:
        _fields_ = [
            ("wYear", ctypes.c_ushort),
            ("wMonth", ctypes.c_ushort),
            ("wDayOfWeek", ctypes.c_ushort),
            ("wDay", ctypes.c_ushort),
            ("wHour", ctypes.c_ushort),
            ("wMinute", ctypes.c_ushort),
            ("wSecond", ctypes.c_ushort),
            ("wMilliseconds", ctypes.c_ushort),
        ]

    # Alternatively, use GetTickCount64 from kernel32
    GetTickCount64 = ctypes.windll.kernel32.GetTickCount64
    GetTickCount64.restype = ctypes.c_ulonglong
    ms = GetTickCount64()

    seconds = ms / 1000
    uptime_str = str(_dt.timedelta(seconds=int(seconds)))

    print(f"\n⏱ System uptime: {uptime_str}\n")

# ══════════════════════════════════════════════════════════════════════════
# Main CLI parsing and dispatch
# ══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Windows Admin Toolkit")
    parser.add_argument(
        "--task",
        choices=["win-events", "win-pkgs", "win-services", "win-startup", "win-disk", "win-users", "win-uptime"],
        required=True,
        help="Select task to run",
    )
    parser.add_argument("--hours", type=int, default=12, help="Hours to look back (for win-events)")
    parser.add_argument("--min-count", type=int, default=3, help="Minimum count to show (for win-events)")
    parser.add_argument("--csv", type=str, help="Export output as CSV (for win-pkgs)")
    parser.add_argument("--watch", nargs="*", default=[], help="Service names to watch (for win-services)")
    parser.add_argument("--fix", action="store_true", help="Attempt to restart stopped services (for win-services)")

    args = parser.parse_args()

    if args.task == "win-events":
        win_events(args.hours, args.min_count)
    elif args.task == "win-pkgs":
        win_pkgs(args.csv)
    elif args.task == "win-services":
        win_services(args.watch, args.fix)
    elif args.task == "win-startup":
        win_startup()
    elif args.task == "win-disk":
        win_disk()
    elif args.task == "win-users":
        win_users()
    elif args.task == "win-uptime":
        win_uptime()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()