"""Flask backend for the local SecureChain GUI.

Every endpoint here calls the exact same functions the CLI uses
(run_scan, evaluate_gate, accept_risk) so a scan run from this GUI produces
the same result a CI run would produce given the same manifest and network
conditions. Nothing here is a second implementation of the scan logic.

No GitHub login is required anywhere in this file. Pushing a commit reuses
whatever git credentials are already configured on this machine (the same
ones a normal git push already uses). Checking the resulting CI status calls
GitHub's public REST API without a token, which works for public
repositories at a lower, unauthenticated rate limit.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Optional

import requests
from flask import Flask, jsonify, request, send_from_directory

from securechain.gate import evaluate_gate
from securechain.pipeline import run_scan
from securechain.riskignore import accept_risk, load_riskignore

STATIC_DIR = Path(__file__).resolve().parent / "static"
REQUEST_TIMEOUT_SECONDS = 10

app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="")


_SKIP_DIR_NAMES = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".pytest_cache", "result", ".idea", ".vscode",
}
_MAX_MANIFESTS = 200


def _ignore_file(folder: str) -> Path:
    return Path(folder) / ".riskignore.json"


def _find_manifests(folder: str) -> list[str]:
    """Searches the selected folder and every subfolder for files named
    package.json, so pointing the GUI at a whole project root finds a
    manifest that sits a few levels down (for example demo/package.json in
    this repository), not only one at the very top. Common heavy or
    irrelevant directories are skipped so this stays fast even on a large
    project.
    """
    root = Path(folder)
    if not root.is_dir():
        return []

    found: list[str] = []
    stack = [root]
    while stack and len(found) < _MAX_MANIFESTS:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_dir():
                if entry.name not in _SKIP_DIR_NAMES:
                    stack.append(entry)
            elif entry.name == "package.json":
                found.append(str(entry.relative_to(root)))

    found.sort(key=lambda p: (p.count("/"), p.count("\\"), p))
    return found[:_MAX_MANIFESTS]


def _find_demo_cache(manifest_dir: Path) -> Optional[Path]:
    """A fixtures folder can sit right next to a manifest (as it does in
    demo/fixtures next to demo/package.json in this repository) or one level
    further down (a fixtures folder nested under demo inside a project
    root). Both are checked, since a user may point the GUI at either
    level.
    """
    for candidate in (manifest_dir / "fixtures", manifest_dir / "demo" / "fixtures"):
        if candidate.is_dir():
            return candidate
    return None


def _run_git(folder: str, args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=folder,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _parse_github_remote(url: str) -> Optional[tuple[str, str]]:
    """Extracts (owner, repo) from an https or ssh GitHub remote URL."""
    patterns = [
        r"github\.com[:/]([^/]+)/([^/.]+?)(?:\.git)?/?$",
    ]
    for pattern in patterns:
        match = re.search(pattern, url.strip())
        if match:
            return match.group(1), match.group(2)
    return None


@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/api/browse", methods=["GET"])
def browse():
    """Opens a native folder picker on this machine. Falls back to a plain
    error if no display is available, so the frontend can ask for a typed
    path instead.
    """
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        chosen = filedialog.askdirectory()
        root.destroy()
        if not chosen:
            return jsonify({"path": None})
        return jsonify({"path": chosen})
    except Exception as exc:
        return jsonify({"path": None, "error": f"Folder dialog unavailable, type the path instead. {exc}"})


@app.route("/api/check-manifest", methods=["GET"])
def check_manifest():
    folder = request.args.get("folder", "")
    if not Path(folder).is_dir():
        return jsonify({"folder_exists": False, "manifests": []})

    manifests = _find_manifests(folder)
    manifest_info = []
    for relpath in manifests:
        manifest_dir = (Path(folder) / relpath).parent
        manifest_info.append({
            "path": relpath,
            "demo_cache_available": _find_demo_cache(manifest_dir) is not None,
        })

    return jsonify({
        "folder_exists": True,
        "manifests": manifest_info,
    })


@app.route("/api/scan", methods=["POST"])
def scan():
    body = request.get_json(force=True) or {}
    folder = body.get("folder", "")
    manifest_relpath = body.get("manifest", "package.json")
    use_demo_cache = bool(body.get("use_demo_cache", False))

    manifest = Path(folder) / manifest_relpath
    if not manifest.is_file():
        return jsonify({"error": f"No package.json found at {manifest}"}), 400

    cache_dir = None
    offline = False
    if use_demo_cache:
        candidate = _find_demo_cache(manifest.parent)
        if candidate is not None:
            cache_dir = str(candidate)
            offline = True

    try:
        report = run_scan(manifest, cache_dir=cache_dir, offline=offline)
    except Exception as exc:
        return jsonify({"error": f"Scan failed. {exc}"}), 500

    ignore_file = _ignore_file(folder)
    gate_result = evaluate_gate(report, max_severity="safe", ignore_file=str(ignore_file))

    ignore_store = load_riskignore(ignore_file)
    accepted_keys = {
        f"{e['package']}@{e['version']}" for e in ignore_store.get("exceptions", [])
    }

    return jsonify({
        "report": report,
        "gate": {
            "exit_code": gate_result.exit_code,
            "failures": gate_result.failures,
            "warnings": gate_result.warnings,
        },
        "accepted_keys": sorted(accepted_keys),
        "used_offline_cache": offline,
    })


@app.route("/api/accept", methods=["POST"])
def accept():
    body = request.get_json(force=True) or {}
    folder = body.get("folder", "")
    package = body.get("package", "")
    version = body.get("version", "")
    reason = body.get("reason", "")
    accepted_by = body.get("accepted_by", "") or "gui user"

    if not package or not version or not reason:
        return jsonify({"error": "Package, version, and reason are all required."}), 400

    entry = accept_risk(
        ignore_file=_ignore_file(folder),
        package=package,
        version=version,
        reason=reason,
        accepted_by=accepted_by,
    )
    return jsonify({"accepted": entry.to_dict()})


@app.route("/api/push", methods=["POST"])
def push():
    body = request.get_json(force=True) or {}
    folder = body.get("folder", "")
    message = body.get("message", "") or "Update dependencies via SecureChain GUI"

    if not Path(folder).is_dir():
        return jsonify({"error": f"{folder} is not a folder on this machine."}), 400

    steps = []
    add_result = _run_git(folder, ["add", "-A"])
    steps.append({"step": "git add", "ok": add_result.returncode == 0, "output": add_result.stderr or add_result.stdout})
    if add_result.returncode != 0:
        return jsonify({"ok": False, "steps": steps})

    commit_result = _run_git(folder, ["commit", "-m", message])
    commit_ok = commit_result.returncode == 0 or "nothing to commit" in (commit_result.stdout + commit_result.stderr).lower()
    steps.append({"step": "git commit", "ok": commit_ok, "output": commit_result.stdout or commit_result.stderr})
    if not commit_ok:
        return jsonify({"ok": False, "steps": steps})

    push_result = _run_git(folder, ["push"])
    steps.append({"step": "git push", "ok": push_result.returncode == 0, "output": push_result.stderr or push_result.stdout})

    return jsonify({"ok": push_result.returncode == 0, "steps": steps})


@app.route("/api/ci-status", methods=["GET"])
def ci_status():
    folder = request.args.get("folder", "")

    remote_result = _run_git(folder, ["config", "--get", "remote.origin.url"])
    if remote_result.returncode != 0 or not remote_result.stdout.strip():
        return jsonify({"status": "no_remote", "message": "No git remote is configured for this folder."})

    parsed = _parse_github_remote(remote_result.stdout.strip())
    if not parsed:
        return jsonify({"status": "not_github", "message": "The configured remote is not a github.com repository."})
    owner, repo = parsed

    sha_result = _run_git(folder, ["rev-parse", "HEAD"])
    if sha_result.returncode != 0:
        return jsonify({"status": "no_commit", "message": "Could not read the current commit."})
    sha = sha_result.stdout.strip()

    try:
        response = requests.get(
            f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}/check-runs",
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload = response.json()
    except (requests.RequestException, ValueError) as exc:
        return jsonify({"status": "unknown", "message": f"Could not reach GitHub. {exc}"})

    runs = payload.get("check_runs", [])
    if not runs:
        return jsonify({"status": "pending", "message": "No check runs reported yet for this commit.", "owner": owner, "repo": repo, "sha": sha})

    if any(r.get("status") != "completed" for r in runs):
        return jsonify({"status": "pending", "message": "GitHub Actions is still running.", "owner": owner, "repo": repo, "sha": sha})

    if any(r.get("conclusion") == "failure" for r in runs):
        return jsonify({"status": "failure", "message": "One or more checks failed on GitHub.", "owner": owner, "repo": repo, "sha": sha})

    return jsonify({"status": "success", "message": "All checks passed on GitHub.", "owner": owner, "repo": repo, "sha": sha})


def create_app() -> Flask:
    return app
