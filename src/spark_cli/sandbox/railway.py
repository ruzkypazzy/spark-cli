from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from .audit import sandbox_audit_ref, write_audit_event
from .capabilities import CapabilityManifest


RAILWAY_CONFIG_CANDIDATES = [".railway/config.json"]
RAILWAY_LOGIN_TIMEOUT_SECONDS = 120


RAILWAY_SUBPROCESS_ENV_ALLOWLIST = {
    "APPDATA",
    "HOME",
    "LANG",
    "LC_ALL",
    "LOCALAPPDATA",
    "PATH",
    "PATHEXT",
    "RAILWAY_TOKEN",
    "SYSTEMROOT",
    "TEMP",
    "TERM",
    "TMP",
    "USERPROFILE",
    "WINDIR",
}


def railway_doctor_capabilities() -> CapabilityManifest:
    return CapabilityManifest(
        backend="railway",
        filesystem="none",
        network="off",
        secrets="none",
        persistence="named-target",
        privilege="non-root",
        inbound="none",
        cost="free-local",
    )


def _check(name: str, ok: bool, detail: str, *, repair: str = "", level: str | None = None) -> dict[str, object]:
    return {
        "name": name,
        "ok": ok,
        "detail": detail,
        "repair": repair,
        "level": level or ("info" if ok else "error"),
    }


def railway_cli_path() -> str:
    return shutil.which("railway") or ""


def railway_auth_markers(*, home: Path | None = None) -> dict[str, object]:
    root = home or Path.home()
    config_paths = [root / c for c in RAILWAY_CONFIG_CANDIDATES if (root / c).exists()]
    env_token = bool(os.environ.get("RAILWAY_TOKEN"))
    return {
        "env_token": env_token,
        "config_present": bool(config_paths),
        "config_count": len(config_paths),
    }


def railway_subprocess_env(env: dict[str, str] | None = None) -> dict[str, str]:
    source = os.environ if env is None else env
    return {key: value for key, value in source.items() if key.upper() in RAILWAY_SUBPROCESS_ENV_ALLOWLIST}


def collect_railway_doctor_payload(*, home: Path | None = None) -> dict[str, object]:
    capabilities = railway_doctor_capabilities()
    cli = railway_cli_path()
    auth = railway_auth_markers(home=home)
    auth_ok = bool(auth["env_token"] or auth["config_present"])
    checks = [
        _check(
            "railway_cli",
            bool(cli),
            f"Railway CLI found at {cli}." if cli else "Railway CLI not found on PATH.",
            repair="Install the Railway CLI: `npm install -g @railway/cli` or `brew install railway`, then rerun doctor.",
        ),
        _check(
            "railway_auth_marker",
            auth_ok,
            "Railway auth marker found." if auth_ok else "No Railway auth marker found.",
            repair="Run `spark sandbox railway login` to authenticate, or set RAILWAY_TOKEN.",
        ),
    ]
    ok = all(bool(check["ok"]) for check in checks if check["level"] != "warning")
    return {
        "ok": ok,
        "backend": "railway",
        "command": "doctor",
        "mode": "read_only",
        "capabilities": capabilities.to_dict(),
        "checks": checks,
        "auth": {
            "env_token": auth["env_token"],
            "config_present": auth["config_present"],
        },
        "next": "Run `spark sandbox railway login` to authenticate." if not auth_ok else "Railway is ready. Run `spark sandbox railway doctor` to recheck.",
    }


def _run_railway_login_subprocess(*, timeout: int) -> dict[str, object]:
    cli = railway_cli_path()
    if not cli:
        return {
            "ok": False,
            "returncode": 127,
            "detail": "Railway CLI not found. Install it with `npm install -g @railway/cli` or `brew install railway`.",
        }
    try:
        result = subprocess.run(
            [cli, "login"],
            env=railway_subprocess_env(),
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "returncode": 124,
            "detail": f"Railway login timed out after {timeout}s.",
        }
    except OSError as error:
        return {
            "ok": False,
            "returncode": 127,
            "detail": f"Could not start Railway login: {error.__class__.__name__}.",
        }
    ok = result.returncode == 0
    return {
        "ok": ok,
        "returncode": result.returncode,
        "detail": "Railway login completed successfully." if ok else f"Railway login exited with code {result.returncode}.",
    }


def collect_railway_login_payload(*, home: Path | None = None, timeout: int = RAILWAY_LOGIN_TIMEOUT_SECONDS) -> dict[str, object]:
    capabilities = railway_doctor_capabilities()
    auth_before = railway_auth_markers(home=home)

    if auth_before["env_token"]:
        write_audit_event(
            "railway",
            "login",
            {"action_id": "railway_login_skip", "ok": True, "reason": "env_token_present"},
            home=home,
        )
        return {
            "ok": True,
            "backend": "railway",
            "command": "login",
            "mode": "read_only",
            "capabilities": capabilities.to_dict(),
            "skipped": True,
            "detail": "RAILWAY_TOKEN is already set; no interactive login needed.",
            "audit": sandbox_audit_ref("railway", "login"),
            "next": "Run `spark sandbox railway doctor` to verify Railway readiness.",
        }

    login = _run_railway_login_subprocess(timeout=timeout)
    auth_after = railway_auth_markers(home=home)
    ok = bool(login.get("ok")) or bool(auth_after["env_token"] or auth_after["config_present"])

    write_audit_event(
        "railway",
        "login",
        {
            "action_id": "railway_login",
            "ok": ok,
            "returncode": login.get("returncode"),
            "auth_present_after": bool(auth_after["env_token"] or auth_after["config_present"]),
        },
        home=home,
    )
    return {
        "ok": ok,
        "backend": "railway",
        "command": "login",
        "mode": "mutating",
        "capabilities": capabilities.to_dict(),
        "auth": {
            "env_token": auth_after["env_token"],
            "config_present": auth_after["config_present"],
        },
        "probe": login,
        "audit": sandbox_audit_ref("railway", "login"),
        "next": "Run `spark sandbox railway doctor` to verify Railway readiness." if ok else "Railway login failed. Set RAILWAY_TOKEN or retry `spark sandbox railway login`.",
    }
