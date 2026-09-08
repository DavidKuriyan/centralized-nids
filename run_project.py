from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEFAULT_DB = Path.home() / ".local" / "share" / "delta-nids" / "nids.sqlite"


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="Run the Delta-NIDS capture, API, and dashboard together")
    value.add_argument("--pcap", help="replay a PCAP instead of live capture")
    value.add_argument("--interface", help="live capture interface; omitted means automatic selection")
    value.add_argument("--db", type=Path, default=DEFAULT_DB, help="shared SQLite database path")
    value.add_argument("--filter", default="", help="live capture BPF filter (default: empty = capture all protocols)")
    value.add_argument("--count", type=int, default=0, help="stop live capture after N packets; 0 means unlimited")
    value.add_argument("--capture-mode", choices=["normal", "span"], default="normal",
                       help="capture mode: 'normal' (standard interface) or 'span' (switch mirror/SPAN port)")
    value.add_argument("--no-capture", action="store_true", help="start only the API and dashboard")
    value.add_argument("--api-port", type=int, default=8080, help="API port")
    value.add_argument("--dashboard-port", type=int, default=8081, help="dashboard port")
    return value


def wait_for(url: str, process: subprocess.Popen) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"process exited unexpectedly with code {process.returncode}")
        try:
            urllib.request.urlopen(url, timeout=0.25).close()
            return
        except (urllib.error.URLError, TimeoutError, OSError):
            time.sleep(0.05)
    raise RuntimeError(f"service did not become ready: {url}")


def command(args: argparse.Namespace) -> int:
    if args.api_port < 1 or args.api_port > 65535 or args.dashboard_port < 1 or args.dashboard_port > 65535:
        print("error: ports must be between 1 and 65535", file=sys.stderr)
        return 2
    db = args.db.expanduser().resolve()
    db.parent.mkdir(parents=True, exist_ok=True)
    if db.exists() and not os.access(db, os.W_OK):
        print(f"error: database is not writable: {db}", file=sys.stderr)
        print("hint: choose a user-owned path with --db or repair its ownership", file=sys.stderr)
        return 2
    if not os.access(db.parent, os.W_OK):
        print(f"error: database directory is not writable: {db.parent}", file=sys.stderr)
        return 2

    base_name = "delta-nids.exe" if os.name == "nt" else "delta-nids"
    candidates = [
        ROOT / "build" / base_name,
        ROOT / "build" / "Release" / base_name,
        ROOT / "build" / "Debug" / base_name,
    ]
    executable = next((path for path in candidates if path.exists()), candidates[0])
    if not executable.exists():
        print("error: C++ executable not found; build the project first", file=sys.stderr)
        print("run: cmake -S . -B build -DDELTA_NIDS_BUILD_TESTS=ON && cmake --build build", file=sys.stderr)
        return 2

    python_bin = sys.executable
    venv_python = ROOT / ".venv" / ("Scripts" if os.name == "nt" else "bin") / ("python.exe" if os.name == "nt" else "python")
    if venv_python.exists():
        try:
            res = subprocess.run([str(venv_python), "-c", "import flask"], capture_output=True)
            if res.returncode == 0:
                python_bin = str(venv_python)
        except Exception:
            pass

    processes: list[subprocess.Popen] = []
    try:
        api = subprocess.Popen([str(executable), "--api", str(db), str(args.api_port)], cwd=ROOT)
        processes.append(api)

        env = os.environ.copy()
        env["DELTA_NIDS_API_URL"] = f"http://127.0.0.1:{args.api_port}"
        env["DELTA_NIDS_DASHBOARD_PORT"] = str(args.dashboard_port)
        env["DELTA_NIDS_DB_PATH"] = str(db)
        # dashboard/app.py imports `core.*` from the project root. Python only
        # puts the script's own directory (dashboard/) on sys.path, so without
        # PYTHONPATH the import fails with ModuleNotFoundError.
        env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        dashboard = subprocess.Popen([python_bin, str(ROOT / "dashboard" / "app.py")], cwd=ROOT, env=env)
        processes.append(dashboard)
        wait_for(f"http://127.0.0.1:{args.api_port}/api/status", api)
        wait_for(f"http://127.0.0.1:{args.dashboard_port}/", dashboard)

        if not args.no_capture:
            capture = [python_bin, str(ROOT / "main.py"), "--persist", "--db", str(db), "--filter", args.filter, "--count", str(args.count), "--capture-mode", args.capture_mode]
            if args.pcap:
                capture += ["--pcap", args.pcap]
            elif args.interface:
                capture += ["--interface", args.interface]
            processes.insert(0, subprocess.Popen(capture, cwd=ROOT, env=env))

        print(f"Dashboard: http://127.0.0.1:{args.dashboard_port}")
        print(f"API:       http://127.0.0.1:{args.api_port}")
        print(f"Database:  {db}")
        print("Press Ctrl+C to stop all processes.")
        while True:
            for process in list(processes):
                if process.poll() is not None:
                    if args.pcap and process is processes[0] and process.returncode == 0:
                        processes.remove(process)
                        continue
                    return_code = process.returncode or 1
                    raise RuntimeError(f"process exited unexpectedly with code {return_code}")
            time.sleep(0.5)
    except KeyboardInterrupt:
        return 0
    except (OSError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
        for process in reversed(processes):
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()


def main() -> int:
    return command(parser().parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
