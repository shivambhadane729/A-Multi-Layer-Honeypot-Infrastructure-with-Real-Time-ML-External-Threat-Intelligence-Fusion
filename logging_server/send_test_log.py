#!/usr/bin/env python3
"""
Advanced Test Client for Honeypot Logging Server
 - multi-scenario attack simulation
 - concurrency, retries, CSV export
 - endpoint checks and simple verification
 Usage:
  python advanced_test_client.py --url http://localhost:5000 --concurrency 8 --iterations 100 --mode mixed --out sent_logs.csv
"""

import argparse
import requests
import json
import datetime
import uuid
import time
import random
import sys
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, Optional

# ------------------------------
# Configuration / Defaults
# ------------------------------
DEFAULT_URL = "http://localhost:5000"
DEFAULT_TIMEOUT = 8
DEFAULT_RETRIES = 2
DEFAULT_BACKOFF = 1.0
DEFAULT_CONCURRENCY = 4
DEFAULT_ITERATIONS = 50
USER_AGENT_POOL = [
    "git/2.34.1", "curl/7.68.0", "python-requests/2.28.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "git/2.32.0", "git/2.40.0"
]

# ------------------------------
# Safety note
# ------------------------------
SAFETY_MSG = """
SAFETY: Only run this tool against systems you own (your honeypot lab).
Do NOT use to target third-party hosts or networks. Use demo 'burst' mode only in isolated lab.
"""

# ------------------------------
# Utility helpers
# ------------------------------
def random_public_ip() -> str:
    # generate a random public-ish IPv4 (avoid RFC1918)
    while True:
        a = random.randint(1, 223)
        b = random.randint(0, 255)
        c = random.randint(0, 255)
        d = random.randint(1, 254)
        ip = f"{a}.{b}.{c}.{d}"
        # skip private/reserved ranges
        if not (a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or a >= 224):
            return ip

def random_private_ip() -> str:
    return f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"

def now_iso() -> str:
    return datetime.datetime.utcnow().isoformat() + "Z"

# ------------------------------
# Attack / event generators
# ------------------------------
def gen_git_push(source_ip: str) -> Dict[str, Any]:
    return {
        "timestamp": now_iso(),
        "source_ip": source_ip,
        "protocol": "HTTP",
        "target_service": "Fake Git Repository",
        "action": "git_push",
        "target_file": None,
        "payload": {
            "commit_message": random.choice([
                "Update README", "Fix bug", "Add feature", "Add malicious backdoor"]),
            "branch": random.choice(["main", "dev", "staging"]),
            "files_changed": ["src/backdoor.py", "config/secrets.yml"] if random.random() < 0.2 else ["src/app.py"],
            "author": f"attacker{random.randint(1,100)}@evil.com"
        },
        "headers": {
            "User-Agent": random.choice(USER_AGENT_POOL),
            "Content-Type": "application/json",
            "Authorization": "Bearer fake_token_" + str(random.randint(100,999))
        },
        "session_id": str(uuid.uuid4()),
        "user_agent": random.choice(USER_AGENT_POOL)
    }

def gen_cicd_run(source_ip: str) -> Dict[str, Any]:
    return {
        "timestamp": now_iso(),
        "source_ip": source_ip,
        "protocol": "HTTP",
        "target_service": "Fake CI/CD Runner",
        "action": "ci_job_run",
        "payload": {
            "job_id": f"job_{random.randint(1000,9999)}",
            "job_name": random.choice(["deploy", "malicious-deploy", "build"]),
            "environment": random.choice(["production","staging"]),
            "branch": random.choice(["main","dev"]),
            "triggered_by": random.choice(["webhook","user","attacker"])
        },
        "headers": {
            "User-Agent": random.choice(USER_AGENT_POOL),
            "Content-Type": "application/json",
            "X-API-Key": "fake_api_" + str(random.randint(1000,9999))
        },
        "session_id": str(uuid.uuid4()),
        "user_agent": random.choice(USER_AGENT_POOL)
    }

def gen_file_access(source_ip: str) -> Dict[str, Any]:
    fname = random.choice(["secrets.yml","config.json",".env","credentials.txt"])
    return {
        "timestamp": now_iso(),
        "source_ip": source_ip,
        "protocol": "HTTP",
        "target_service": "Fake Git Repository",
        "action": "file_access",
        "target_file": fname,
        "payload": {
            "file_type": "secrets" if "secret" in fname or "env" in fname else "config",
            "file_size": random.randint(100, 5000),
            "access_method": random.choice(["direct_request","raw_url","api_endpoint"])
        },
        "headers": {
            "User-Agent": random.choice(USER_AGENT_POOL),
            "Accept": "text/yaml,application/yaml,*/*",
            "Referer": "https://github.com/company/repo"
        },
        "session_id": str(uuid.uuid4()),
        "user_agent": random.choice(USER_AGENT_POOL)
    }

def gen_credentials_access(source_ip: str) -> Dict[str, Any]:
    return {
        "timestamp": now_iso(),
        "source_ip": source_ip,
        "protocol": "HTTP",
        "target_service": "Fake CI/CD Runner",
        "action": "file_access",
        "target_file": "ci_credentials",
        "payload": {
            "file_type": "ci_credentials",
            "credentials_accessed": random.sample(["docker_registry","kubernetes","aws","gcr","ecr"], k=2),
            "access_method": random.choice(["api_endpoint","direct_download"])
        },
        "headers": {
            "User-Agent": random.choice(USER_AGENT_POOL),
            "Authorization": "Bearer fake_ci_token_" + str(random.randint(1000,9999))
        },
        "session_id": str(uuid.uuid4()),
        "user_agent": random.choice(USER_AGENT_POOL)
    }

def gen_bruteforce_attempt(source_ip: str) -> Dict[str, Any]:
    return {
        "timestamp": now_iso(),
        "source_ip": source_ip,
        "protocol": "SSH",
        "target_service": "Fake SSH",
        "action": "login_attempt",
        "payload": {
            "username": random.choice(["root","admin","user","git"]),
            "success": False,
            "attempts": random.randint(1, 30)
        },
        "headers": {
            "User-Agent": "ssh_client"
        },
        "session_id": str(uuid.uuid4()),
        "user_agent": "ssh_client"
    }

def gen_malformed_payload(source_ip: str) -> Dict[str, Any]:
    # intentionally invalid JSON or unusually large payload fields
    return {
        "timestamp": now_iso(),
        "source_ip": source_ip,
        "protocol": "HTTP",
        "target_service": "Fake Git Repository",
        "action": "malformed_upload",
        "payload": "<<<INVALID>>> " + "A" * random.randint(1000, 10000),
        "headers": {
            "User-Agent": random.choice(USER_AGENT_POOL),
            "Content-Type": "application/octet-stream"
        },
        "session_id": str(uuid.uuid4()),
        "user_agent": random.choice(USER_AGENT_POOL)
    }

# ------------------------------
# Sender + validation
# ------------------------------
def post_with_retries(url: str, json_payload: dict, timeout: int, retries: int, backoff: float, verbose: bool=False) -> Dict[str, Any]:
    attempt = 0
    while attempt <= retries:
        try:
            resp = requests.post(url, json=json_payload, timeout=timeout, headers={'Content-Type': 'application/json'})
            if verbose:
                print(f"[POST] {url} → {resp.status_code}")
            # Accept 200-201 as success
            if resp.status_code in (200, 201):
                try:
                    return {"ok": True, "status": resp.status_code, "json": resp.json()}
                except ValueError:
                    return {"ok": True, "status": resp.status_code, "json": None}
            else:
                # allow backend to return structured error
                try:
                    err = resp.json()
                except ValueError:
                    err = resp.text
                return {"ok": False, "status": resp.status_code, "error": err}
        except requests.exceptions.RequestException as e:
            if verbose:
                print(f"[ERROR] attempt {attempt+1}/{retries+1}: {e}")
            attempt += 1
            if attempt <= retries:
                time.sleep(backoff * (2 ** (attempt-1)))
    return {"ok": False, "status": None, "error": "max_retries_exceeded"}

# ------------------------------
# High-level test scenarios
# ------------------------------
SCENARIO_GENERATORS = {
    "git_push": gen_git_push,
    "ci_run": gen_cicd_run,
    "file_access": gen_file_access,
    "cred_access": gen_credentials_access,
    "bruteforce": gen_bruteforce_attempt,
    "malformed": gen_malformed_payload
}

def run_scenario(session_id: int, server_url: str, scenario: str, timeout: int, retries: int, backoff: float, verbose: bool):
    src_ip = random_public_ip() if random.random() > 0.2 else random_private_ip()
    payload = SCENARIO_GENERATORS[scenario](src_ip)
    url = server_url.rstrip("/") + "/log"
    result = post_with_retries(url, payload, timeout, retries, backoff, verbose)
    out = {
        "time": now_iso(),
        "scenario": scenario,
        "source_ip": src_ip,
        "status": result.get("status"),
        "ok": result.get("ok"),
        "error": result.get("error"),
        "response_json": result.get("json")
    }
    return out

# ------------------------------
# Higher-level orchestrator
# ------------------------------
def orchestrate(args):
    print(SAFETY_MSG)
    if not args.force:
        confirm = input("Proceed? (y/N): ").strip().lower()
        if confirm != "y":
            print("Aborted by user.")
            sys.exit(0)

    server_url = args.url
    # health check
    try:
        h = requests.get(f"{server_url.rstrip('/')}/health", timeout=DEFAULT_TIMEOUT)
        if h.status_code == 200:
            print("✅ Logging server health OK")
            try:
                print("   ", h.json())
            except Exception:
                pass
        else:
            print(f"⚠️ Health endpoint returned {h.status_code} - continuing anyway")
    except Exception as e:
        print(f"❌ Health check failed: {e}")
        if not args.force:
            print("Use --force to continue despite failed health check.")
            sys.exit(1)

    scenarios = []
    if args.mode == "mixed":
        # mix scenarios roughly
        scenarios = ["git_push"] * 3 + ["ci_run"] * 2 + ["file_access"] * 3 + ["cred_access"]*1 + ["bruteforce"]*2 + ["malformed"]*1
    else:
        # single scenario repeated
        if args.mode not in SCENARIO_GENERATORS:
            print(f"Unknown mode {args.mode}. Valid: mixed or {list(SCENARIO_GENERATORS.keys())}")
            sys.exit(1)
        scenarios = [args.mode]

    # prepare outputs
    results = []
    csv_file = None
    csv_writer = None
    if args.out:
        csv_file = open(args.out, "w", newline="", encoding="utf-8")
        csv_writer = csv.DictWriter(csv_file, fieldnames=["time","scenario","source_ip","status","ok","error"])
        csv_writer.writeheader()

    total = args.iterations
    concurrency = args.concurrency

    print(f"Starting test: {total} events, concurrency={concurrency}, mode={args.mode}")
    start_ts = time.time()

    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = []
        for i in range(total):
            # pick a scenario
            sc = random.choice(scenarios)
            futures.append(ex.submit(run_scenario, i, server_url, sc, args.timeout, args.retries, args.backoff, args.verbose))
            # optionally throttle
            if args.delay and args.delay > 0:
                time.sleep(args.delay)

        # progress loop
        succeeded = 0
        failed = 0
        for fut in as_completed(futures):
            res = fut.result()
            results.append(res)
            ok = res.get("ok", False)
            if ok:
                succeeded += 1
            else:
                failed += 1
            if csv_writer:
                csv_writer.writerow({k: res.get(k) for k in ["time","scenario","source_ip","status","ok","error"]})
            if args.verbose:
                print(f"[{res['time']}] {res['scenario']} from {res['source_ip']} -> ok={res['ok']} status={res['status']}")

    duration = time.time() - start_ts
    print("\n=== Test Summary ===")
    print(f"Total events: {total}")
    print(f"Succeeded: {succeeded}")
    print(f"Failed: {failed}")
    print(f"Duration: {duration:.1f}s")
    print(f"Rate: {total/duration:.2f} events/sec")

    # try to validate stats endpoint if available
    try:
        stats = requests.get(f"{server_url.rstrip('/')}/stats", timeout=5).json()
        print("\nStats endpoint sample:")
        print(json.dumps(stats, indent=2))
    except Exception:
        pass

    if csv_file:
        csv_file.close()
        print(f"Saved events to {args.out}")

    return results

# ------------------------------
# CLI
# ------------------------------
def main():
    parser = argparse.ArgumentParser(description="Advanced test client for honeypot logging server")
    parser.add_argument("--url", default=DEFAULT_URL, help="Logging server base URL (default http://localhost:5000)")
    parser.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS, help="Total events to send")
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY, help="Concurrent worker threads")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay (s) between scheduling new events (throttle)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Request timeout (s)")
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES, help="Retries per request")
    parser.add_argument("--backoff", type=float, default=DEFAULT_BACKOFF, help="Base backoff (s) for retries")
    parser.add_argument("--mode", default="mixed", help="Mode: mixed or one of scenarios: " + ", ".join(SCENARIO_GENERATORS.keys()))
    parser.add_argument("--out", default=None, help="CSV file to save sent events")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--force", action="store_true", help="Skip interactive confirmation")
    args = parser.parse_args()

    orchestrate(args)

if __name__ == "__main__":
    main()
